use {
    anchor_lang::{
        prelude::Pubkey,
        solana_program::{instruction::Instruction, system_program},
        InstructionData, ToAccountMetas,
    },
    anchor_spl::{
        associated_token::{self, get_associated_token_address_with_program_id},
        token_2022::spl_token_2022::{
            self,
            extension::{
                confidential_transfer::{ConfidentialTransferAccount, ConfidentialTransferMint},
                BaseStateWithExtensions, StateWithExtensions,
            },
            state::{Account, Mint},
        },
    },
    anyhow::{anyhow, bail, ensure, Context, Result},
    bytemuck::Pod,
    solana_commitment_config::CommitmentConfig,
    solana_keypair::{read_keypair_file, Keypair},
    solana_rpc_client::rpc_client::RpcClient,
    solana_signer::Signer,
    solana_transaction::Transaction,
    solana_zk_elgamal_proof_interface::{
        self as zk,
        instruction::{close_context_state, ContextStateInfo, ProofInstruction},
        proof_data::ZkProofData,
        state::ProofContextState,
    },
    solana_zk_sdk::{
        encryption::{
            auth_encryption::{AeCiphertext, AeKey},
            elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
        },
        zk_elgamal_proof_program::build_pubkey_validity_proof_data,
    },
    spl_token_confidential_transfer_proof_generation::{
        transfer::transfer_split_proof_data, withdraw::withdraw_proof_data,
    },
    std::path::Path,
    token2022_confidential_payments::{accounts, instruction, ID},
};

pub struct Client {
    rpc: RpcClient,
    wallet: Keypair,
}
struct Keys {
    elgamal: ElGamalKeypair,
    aes: AeKey,
}

fn keys(wallet: &Keypair, ata: Pubkey) -> Result<Keys> {
    // The ATA seed makes keys recoverable and account-specific.
    Ok(Keys {
        elgamal: ElGamalKeypair::new_from_signer(wallet, ata.as_ref())
            .map_err(|e| anyhow!(e.to_string()))?,
        aes: AeKey::new_from_signer(wallet, ata.as_ref()).map_err(|e| anyhow!(e.to_string()))?,
    })
}

fn ix(data: impl InstructionData, accounts: impl ToAccountMetas) -> Instruction {
    Instruction::new_with_bytes(ID, &data.data(), accounts.to_account_metas(None))
}

fn available(e: &ConfidentialTransferAccount, keys: &Keys) -> Result<u64> {
    ensure!(
        bytemuck::bytes_of(&e.elgamal_pubkey) == keys.elgamal.pubkey().to_bytes(),
        "Account uses different encryption keys; this CLI uses wallet + ATA derivation"
    );
    ensure!(e.expected_pending_balance_credit_counter == e.actual_pending_balance_credit_counter,
        "AES balance is stale after an apply race. Reconcile the missed credits before spending; automatic reconciliation is not implemented.");
    AeCiphertext::from_bytes(bytemuck::bytes_of(&e.decryptable_available_balance))
        .and_then(|c| c.decrypt(&keys.aes))
        .context("Cannot decrypt available balance")
}

fn pending(e: &ConfidentialTransferAccount, keys: &Keys) -> Result<u64> {
    let decrypt = |bytes| {
        ElGamalCiphertext::from_bytes(bytes).and_then(|c| c.decrypt_u32(keys.elgamal.secret()))
    };
    let lo = decrypt(bytemuck::bytes_of(&e.pending_balance_lo))
        .context("Cannot decrypt pending low component")?;
    let hi = decrypt(bytemuck::bytes_of(&e.pending_balance_hi))
        .context("Pending high component exceeds this CLI's 32-bit decryption range")?;
    lo.checked_add(hi.checked_mul(1 << 16).context("Pending overflow")?)
        .context("Pending overflow")
}

impl Client {
    pub fn new(url: &str, path: &Path) -> Result<Self> {
        let wallet = read_keypair_file(path)
            .map_err(|_| anyhow!("Cannot read wallet keypair at {}", path.display()))?;
        Ok(Self {
            rpc: RpcClient::new_with_commitment(url, CommitmentConfig::confirmed()),
            wallet,
        })
    }
    fn owner(&self) -> Pubkey {
        self.wallet.pubkey()
    }
    fn ata(&self, owner: Pubkey, mint: Pubkey) -> Pubkey {
        get_associated_token_address_with_program_id(&owner, &mint, &spl_token_2022::id())
    }
    fn send(&self, instructions: &[Instruction], extra: &[&Keypair]) -> Result<()> {
        let mut signers = vec![&self.wallet];
        signers.extend_from_slice(extra);
        let tx = Transaction::new_signed_with_payer(
            instructions,
            Some(&self.owner()),
            &signers,
            self.rpc.get_latest_blockhash()?,
        );
        println!("{}", self.rpc.send_and_confirm_transaction(&tx)?);
        Ok(())
    }
    fn account(&self, address: Pubkey) -> Result<(Account, ConfidentialTransferAccount)> {
        let account = self
            .rpc
            .get_account(&address)
            .context("Token account not found")?;
        ensure!(
            account.owner == spl_token_2022::id(),
            "Account is not owned by Token-2022"
        );
        let state = StateWithExtensions::<Account>::unpack(&account.data)?;
        Ok((
            state.base,
            *state
                .get_extension::<ConfidentialTransferAccount>()
                .context("Run configure first")?,
        ))
    }
    fn stage<T: Pod + ZkProofData<U>, U: Pod>(
        &self,
        kind: ProofInstruction,
        proof: &T,
        contexts: &mut Vec<Pubkey>,
    ) -> Result<Pubkey> {
        let context = Keypair::new();
        let size = std::mem::size_of::<ProofContextState<U>>();
        // Track the address before submission in case confirmation is interrupted.
        contexts.push(context.pubkey());
        eprintln!("Proof context: {}", context.pubkey());
        self.send(
            &[solana_system_interface::instruction::create_account(
                &self.owner(),
                &context.pubkey(),
                self.rpc.get_minimum_balance_for_rent_exemption(size)?,
                size as u64,
                &zk::id(),
            )],
            &[&context],
        )?;
        self.send(
            &[kind.encode_verify_proof(
                Some(ContextStateInfo {
                    context_state_account: &context.pubkey(),
                    context_state_authority: &self.owner(),
                }),
                proof,
            )],
            &[],
        )?;
        Ok(context.pubkey())
    }
    fn close_ix(&self, address: &Pubkey) -> Instruction {
        close_context_state(
            ContextStateInfo {
                context_state_account: address,
                context_state_authority: &self.owner(),
            },
            &self.owner(),
        )
    }
    pub fn close_proofs(&self, contexts: &[Pubkey]) -> Result<()> {
        for context in contexts {
            self.send(&[self.close_ix(context)], &[])?;
        }
        Ok(())
    }
    fn with_proofs(
        &self,
        build: impl FnOnce(&mut Vec<Pubkey>) -> Result<Instruction>,
    ) -> Result<()> {
        let mut contexts = vec![];
        let result = (|| {
            let instruction = build(&mut contexts)?;
            let mut instructions = vec![instruction];
            instructions.extend(contexts.iter().map(|c| self.close_ix(c)));
            self.send(&instructions, &[])
        })();
        if result.is_err() {
            for context in contexts {
                if let Ok(account) = self.rpc.get_account(&context) {
                    if account.owner == zk::id() {
                        if let Err(error) = self.close_proofs(&[context]) {
                            eprintln!("Could not close proof context {context}: {error}. An unverified context may require verification before it can be closed.");
                        }
                    }
                }
            }
        }
        result
    }
    pub fn initialize_mint(&self, decimals: u8) -> Result<()> {
        let mint = Keypair::new();
        eprintln!("Mint: {}", mint.pubkey());
        self.send(
            &[ix(
                instruction::InitializeMint { decimals },
                accounts::InitializeMint {
                    payer: self.owner(),
                    mint: mint.pubkey(),
                    authority: self.owner(),
                    token_program: spl_token_2022::id(),
                    system_program: system_program::ID,
                },
            )],
            &[&mint],
        )
    }
    pub fn configure(&self, mint: Pubkey) -> Result<()> {
        let ata = self.ata(self.owner(), mint);
        let keys = keys(&self.wallet, ata)?;
        let proof = build_pubkey_validity_proof_data(&keys.elgamal)?;
        self.with_proofs(|contexts| {
            let context = self.stage(ProofInstruction::VerifyPubkeyValidity, &proof, contexts)?;
            Ok(ix(
                instruction::ConfigureAccount {
                    decryptable_zero_balance: keys.aes.encrypt(0).to_bytes(),
                    maximum_pending_balance_credit_counter: 65_536,
                },
                accounts::ConfigureAccount {
                    payer: self.owner(),
                    owner: self.owner(),
                    mint,
                    token_account: ata,
                    proof_context: context,
                    token_program: spl_token_2022::id(),
                    associated_token_program: associated_token::ID,
                    system_program: system_program::ID,
                },
            ))
        })?;
        println!("Configured ATA: {ata}");
        Ok(())
    }
    pub fn balance(&self, mint: Pubkey) -> Result<()> {
        let ata = self.ata(self.owner(), mint);
        let (base, extension) = self.account(ata)?;
        let keys = keys(&self.wallet, ata)?;
        println!("ATA: {ata}\nPublic (raw): {}", base.amount);
        let amount = available(&extension, &keys)?;
        println!(
            "Available (raw): {amount}\nPending (raw): {}",
            pending(&extension, &keys)?
        );
        Ok(())
    }
    pub fn deposit(&self, mint: Pubkey, amount: u64) -> Result<()> {
        self.send(
            &[ix(
                instruction::Deposit { amount },
                accounts::Deposit {
                    owner: self.owner(),
                    mint,
                    token_account: self.ata(self.owner(), mint),
                    token_program: spl_token_2022::id(),
                },
            )],
            &[],
        )
    }
    pub fn apply_pending(&self, mint: Pubkey) -> Result<()> {
        let ata = self.ata(self.owner(), mint);
        let (_, e) = self.account(ata)?;
        let keys = keys(&self.wallet, ata)?;
        let total = available(&e, &keys)?
            .checked_add(pending(&e, &keys)?)
            .context("Balance overflow")?;
        self.send(
            &[ix(
                instruction::ApplyPending {
                    expected_pending_balance_credit_counter: e
                        .pending_balance_credit_counter
                        .into(),
                    new_decryptable_available_balance: keys.aes.encrypt(total).to_bytes(),
                },
                accounts::ApplyPending {
                    owner: self.owner(),
                    mint,
                    token_account: ata,
                    token_program: spl_token_2022::id(),
                },
            )],
            &[],
        )?;
        available(&self.account(ata)?.1, &keys)?;
        Ok(())
    }
    pub fn transfer(&self, mint: Pubkey, recipient: Pubkey, amount: u64) -> Result<()> {
        let source = self.ata(self.owner(), mint);
        let destination = self.ata(recipient, mint);
        let (_, e) = self.account(source)?;
        let (_, receiver) = self.account(destination)?;
        let keys = keys(&self.wallet, source)?;
        let remaining = available(&e, &keys)?
            .checked_sub(amount)
            .context("Insufficient available funds; apply pending first if needed")?;
        let mint_account = self.rpc.get_account(&mint)?;
        let mint_state = StateWithExtensions::<Mint>::unpack(&mint_account.data)?;
        let config = mint_state.get_extension::<ConfidentialTransferMint>()?;
        if config.auditor_elgamal_pubkey != Default::default() {
            bail!("Auditor-enabled mints are not supported by this CLI yet");
        }
        let data = transfer_split_proof_data(
            &ElGamalCiphertext::from_bytes(bytemuck::bytes_of(&e.available_balance))
                .context("Invalid available ciphertext")?,
            &AeCiphertext::from_bytes(bytemuck::bytes_of(&e.decryptable_available_balance))
                .context("Invalid AES ciphertext")?,
            amount,
            &keys.elgamal,
            &keys.aes,
            &ElGamalPubkey::try_from(bytemuck::bytes_of(&receiver.elgamal_pubkey))?,
            None,
        )?;
        self.with_proofs(|contexts| {
            let equality = self.stage(
                ProofInstruction::VerifyCiphertextCommitmentEquality,
                &data.equality_proof_data,
                contexts,
            )?;
            let validity = self.stage(
                ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity,
                &data
                    .ciphertext_validity_proof_data_with_ciphertext
                    .proof_data,
                contexts,
            )?;
            let range = self.stage(
                ProofInstruction::VerifyBatchedRangeProofU128,
                &data.range_proof_data,
                contexts,
            )?;
            Ok(ix(
                instruction::TransferConfidential {
                    new_source_decryptable_available_balance: keys
                        .aes
                        .encrypt(remaining)
                        .to_bytes(),
                    transfer_amount_auditor_ciphertext_lo: bytemuck::bytes_of(
                        &data
                            .ciphertext_validity_proof_data_with_ciphertext
                            .ciphertext_lo,
                    )
                    .try_into()?,
                    transfer_amount_auditor_ciphertext_hi: bytemuck::bytes_of(
                        &data
                            .ciphertext_validity_proof_data_with_ciphertext
                            .ciphertext_hi,
                    )
                    .try_into()?,
                },
                accounts::TransferConfidential {
                    owner: self.owner(),
                    recipient,
                    mint,
                    source,
                    destination,
                    equality_proof_context: equality,
                    ciphertext_validity_proof_context: validity,
                    range_proof_context: range,
                    token_program: spl_token_2022::id(),
                },
            ))
        })
    }
    pub fn withdraw(&self, mint: Pubkey, amount: u64) -> Result<()> {
        let ata = self.ata(self.owner(), mint);
        let (_, e) = self.account(ata)?;
        let keys = keys(&self.wallet, ata)?;
        let current = available(&e, &keys)?;
        let remaining = current
            .checked_sub(amount)
            .context("Insufficient available funds; apply pending first if needed")?;
        let data = withdraw_proof_data(
            &ElGamalCiphertext::from_bytes(bytemuck::bytes_of(&e.available_balance))
                .context("Invalid available ciphertext")?,
            current,
            amount,
            &keys.elgamal,
        )?;
        self.with_proofs(|contexts| {
            let equality = self.stage(
                ProofInstruction::VerifyCiphertextCommitmentEquality,
                &data.equality_proof_data,
                contexts,
            )?;
            let range = self.stage(
                ProofInstruction::VerifyBatchedRangeProofU64,
                &data.range_proof_data,
                contexts,
            )?;
            Ok(ix(
                instruction::Withdraw {
                    amount,
                    new_decryptable_available_balance: keys.aes.encrypt(remaining).to_bytes(),
                },
                accounts::Withdraw {
                    owner: self.owner(),
                    mint,
                    token_account: ata,
                    equality_proof_context: equality,
                    range_proof_context: range,
                    token_program: spl_token_2022::id(),
                },
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keys_are_recoverable_and_account_specific() {
        let wallet = Keypair::new();
        let ata = Pubkey::new_unique();
        let first = keys(&wallet, ata).unwrap();
        let restored_wallet = Keypair::try_from(wallet.to_bytes().as_slice()).unwrap();
        let restored = keys(&restored_wallet, ata).unwrap();
        assert_eq!(first.elgamal.pubkey(), restored.elgamal.pubkey());
        let ciphertext = first.aes.encrypt(42);
        assert_eq!(ciphertext.decrypt(&restored.aes), Some(42));
        let other = keys(&wallet, Pubkey::new_unique()).unwrap();
        assert_ne!(first.elgamal.pubkey(), other.elgamal.pubkey());
        assert!(ciphertext.decrypt(&other.aes).is_none());
    }

    #[test]
    fn refuses_known_stale_or_unrelated_balance_copies() {
        let wallet = Keypair::new();
        let k = keys(&wallet, Pubkey::new_unique()).unwrap();
        let mut e = ConfidentialTransferAccount {
            elgamal_pubkey: k.elgamal.pubkey().to_bytes().into(),
            decryptable_available_balance: k.aes.encrypt(42).to_bytes().into(),
            ..Default::default()
        };
        assert_eq!(available(&e, &k).unwrap(), 42);
        e.expected_pending_balance_credit_counter = 1.into();
        e.actual_pending_balance_credit_counter = 2.into();
        assert!(available(&e, &k).is_err());
        let other = keys(&wallet, Pubkey::new_unique()).unwrap();
        assert!(available(&e, &other).is_err());
    }
}
