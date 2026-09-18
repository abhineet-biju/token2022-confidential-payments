use {
    anchor_lang::{
        prelude::Pubkey,
        solana_program::{instruction::Instruction, system_program},
        InstructionData, ToAccountMetas,
    },
    anchor_spl::{
        associated_token::{
            self, get_associated_token_address_with_program_id, spl_associated_token_account,
        },
        token_2022::spl_token_2022::{
            self,
            extension::{
                confidential_transfer::ConfidentialTransferAccount, BaseStateWithExtensions,
                StateWithExtensions,
            },
            state::Account,
        },
    },
    litesvm::{
        types::{FailedTransactionMetadata, TransactionMetadata},
        LiteSVM,
    },
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
    solana_zk_sdk::{
        encryption::{
            auth_encryption::{AeCiphertext, AeKey},
            elgamal::ElGamalKeypair,
        },
        zk_elgamal_proof_program::{
            self,
            instruction::{close_context_state, ContextStateInfo, ProofInstruction},
            proof_data::{PubkeyValidityProofContext, PubkeyValidityProofData},
            state::ProofContextState,
        },
    },
};

fn send(
    svm: &mut LiteSVM,
    payer: &Keypair,
    instructions: &[Instruction],
    extra_signers: &[&Keypair],
) -> Result<TransactionMetadata, FailedTransactionMetadata> {
    let mut signers = vec![payer];
    signers.extend_from_slice(extra_signers);
    let message =
        Message::new_with_blockhash(instructions, Some(&payer.pubkey()), &svm.latest_blockhash());
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(message), &signers).unwrap();
    svm.send_transaction(tx)
}

struct Fixture {
    svm: LiteSVM,
    payer: Keypair,
    owner: Keypair,
    mint: Pubkey,
    ata: Pubkey,
    elgamal: ElGamalKeypair,
    aes: AeKey,
    proof_context: Pubkey,
}

impl Fixture {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        svm.add_program(
            token2022_confidential_payments::id(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../target/deploy/token2022_confidential_payments.so"
            )),
        )
        .unwrap();
        let payer = Keypair::new();
        let owner = Keypair::new();
        let mint = Keypair::new();
        svm.airdrop(&payer.pubkey(), 2_000_000_000).unwrap();
        let ix = Instruction::new_with_bytes(
            token2022_confidential_payments::id(),
            &token2022_confidential_payments::instruction::InitializeMint { decimals: 6 }.data(),
            token2022_confidential_payments::accounts::InitializeMint {
                payer: payer.pubkey(),
                mint: mint.pubkey(),
                authority: payer.pubkey(),
                token_program: spl_token_2022::id(),
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        );
        send(&mut svm, &payer, &[ix], &[&mint]).unwrap();

        // Off-chain setup: ephemeral test keys stay in this process. A real client
        // must securely persist or deterministically recover these keys.
        let elgamal = ElGamalKeypair::new_rand();
        let aes = AeKey::new_rand();
        let proof = PubkeyValidityProofData::new(&elgamal).unwrap();
        let proof_context = Keypair::new();
        let size = std::mem::size_of::<ProofContextState<PubkeyValidityProofContext>>();
        let create = solana_system_interface::instruction::create_account(
            &payer.pubkey(),
            &proof_context.pubkey(),
            svm.minimum_balance_for_rent_exemption(size),
            size as u64,
            &zk_elgamal_proof_program::id(),
        );
        let verify = ProofInstruction::VerifyPubkeyValidity.encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: &proof_context.pubkey(),
                context_state_authority: &owner.pubkey(),
            }),
            &proof,
        );
        // The real ZK program verifies the proof; no fabricated context is injected.
        send(&mut svm, &payer, &[create, verify], &[&proof_context]).unwrap();
        let ata = get_associated_token_address_with_program_id(
            &owner.pubkey(),
            &mint.pubkey(),
            &spl_token_2022::id(),
        );
        Self {
            svm,
            payer,
            owner,
            mint: mint.pubkey(),
            ata,
            elgamal,
            aes,
            proof_context: proof_context.pubkey(),
        }
    }

    fn instruction(&self) -> Instruction {
        Instruction::new_with_bytes(
            token2022_confidential_payments::id(),
            &token2022_confidential_payments::instruction::ConfigureAccount {
                decryptable_zero_balance: self.aes.encrypt(0).to_bytes(),
                maximum_pending_balance_credit_counter: 65_536,
            }
            .data(),
            token2022_confidential_payments::accounts::ConfigureAccount {
                payer: self.payer.pubkey(),
                owner: self.owner.pubkey(),
                mint: self.mint,
                token_account: self.ata,
                proof_context: self.proof_context,
                token_program: spl_token_2022::id(),
                associated_token_program: associated_token::ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        )
    }

    fn configure(&mut self) {
        let ix = self.instruction();
        send(&mut self.svm, &self.payer, &[ix], &[&self.owner]).unwrap();
    }

    fn assert_configured(&self, public_amount: u64) {
        let account = self.svm.get_account(&self.ata).unwrap();
        assert_eq!(account.owner, spl_token_2022::id());
        assert!(
            account.lamports
                >= self
                    .svm
                    .minimum_balance_for_rent_exemption(account.data.len())
        );
        let state = StateWithExtensions::<Account>::unpack(&account.data).unwrap();
        assert_eq!(state.base.owner, self.owner.pubkey());
        assert_eq!(state.base.mint, self.mint);
        assert_eq!(state.base.amount, public_amount);
        let extension = state
            .get_extension::<ConfidentialTransferAccount>()
            .unwrap();
        assert!(bool::from(extension.approved));
        assert!(bool::from(extension.allow_confidential_credits));
        assert!(bool::from(extension.allow_non_confidential_credits));
        assert_eq!(extension.elgamal_pubkey, (*self.elgamal.pubkey()).into());
        assert_eq!(extension.pending_balance_lo, Default::default());
        assert_eq!(extension.pending_balance_hi, Default::default());
        assert_eq!(extension.available_balance, Default::default());
        assert_eq!(u64::from(extension.pending_balance_credit_counter), 0);
        assert_eq!(
            u64::from(extension.expected_pending_balance_credit_counter),
            0
        );
        assert_eq!(
            u64::from(extension.actual_pending_balance_credit_counter),
            0
        );
        assert_eq!(
            u64::from(extension.maximum_pending_balance_credit_counter),
            65_536
        );
        let balance: AeCiphertext = extension.decryptable_available_balance.try_into().unwrap();
        assert_eq!(balance.decrypt(&self.aes), Some(0));
    }
}

#[test]
fn creates_confidential_ata_and_closes_verified_proof_context() {
    let mut f = Fixture::new();
    f.configure();
    f.assert_configured(0);
    let rent = f.svm.get_account(&f.proof_context).unwrap().lamports;
    let before = f.svm.get_balance(&f.owner.pubkey()).unwrap_or(0);
    let close = close_context_state(
        ContextStateInfo {
            context_state_account: &f.proof_context,
            context_state_authority: &f.owner.pubkey(),
        },
        &f.owner.pubkey(),
    );
    send(&mut f.svm, &f.payer, &[close], &[&f.owner]).unwrap();
    assert_eq!(f.svm.get_balance(&f.owner.pubkey()).unwrap(), before + rent);
    assert!(f
        .svm
        .get_account(&f.proof_context)
        .is_none_or(|a| a.lamports == 0));
    f.assert_configured(0);
}

#[test]
fn configures_existing_ata_without_changing_public_tokens() {
    let mut f = Fixture::new();
    let create = spl_associated_token_account::instruction::create_associated_token_account(
        &f.payer.pubkey(),
        &f.owner.pubkey(),
        &f.mint,
        &spl_token_2022::id(),
    );
    let mint_to = spl_token_2022::instruction::mint_to_checked(
        &spl_token_2022::id(),
        &f.mint,
        &f.ata,
        &f.payer.pubkey(),
        &[],
        42_000_000,
        6,
    )
    .unwrap();
    send(&mut f.svm, &f.payer, &[create, mint_to], &[]).unwrap();
    f.configure();
    f.assert_configured(42_000_000);
}

#[test]
fn rejects_invalid_proof_and_rolls_back_ata_creation() {
    let mut f = Fixture::new();
    let mut ix = f.instruction();
    // A system-owned account cannot masquerade as a verified proof context.
    ix.accounts
        .iter_mut()
        .find(|a| a.pubkey == f.proof_context)
        .unwrap()
        .pubkey = f.payer.pubkey();
    assert!(send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).is_err());
    assert!(f.svm.get_account(&f.ata).is_none());
}

#[test]
fn rejects_configuration_without_owner_signature() {
    let mut f = Fixture::new();
    let mut ix = f.instruction();
    ix.accounts
        .iter_mut()
        .find(|a| a.pubkey == f.owner.pubkey())
        .unwrap()
        .is_signer = false;
    let error = send(&mut f.svm, &f.payer, &[ix], &[]).unwrap_err();
    assert!(
        error
            .meta
            .logs
            .iter()
            .any(|log| log.contains("AccountNotSigner")),
        "{error:?}"
    );
    assert!(f.svm.get_account(&f.ata).is_none());
}

#[test]
fn rejects_reconfiguration_without_overwriting_keys() {
    let mut f = Fixture::new();
    f.configure();
    let before = f.svm.get_account(&f.ata).unwrap().data;
    f.svm.expire_blockhash();
    let ix = f.instruction();
    assert!(send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).is_err());
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, before);
}
