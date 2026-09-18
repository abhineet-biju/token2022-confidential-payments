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
            instruction::{ContextStateInfo, ProofInstruction},
            proof_data::{PubkeyValidityProofContext, PubkeyValidityProofData},
            state::ProofContextState,
        },
    },
};

pub fn send(
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

pub struct Fixture {
    pub svm: LiteSVM,
    pub payer: Keypair,
    pub owner: Keypair,
    pub mint: Pubkey,
    pub ata: Pubkey,
    pub elgamal: ElGamalKeypair,
    pub aes: AeKey,
    pub proof_context: Pubkey,
}

impl Fixture {
    pub fn new() -> Self {
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

    pub fn instruction(&self) -> Instruction {
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

    pub fn configure(&mut self) {
        let ix = self.instruction();
        send(&mut self.svm, &self.payer, &[ix], &[&self.owner]).unwrap();
    }

    #[allow(dead_code)]
    pub fn assert_configured(&self, public_amount: u64) {
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
        assert_eq!(
            bytemuck::bytes_of(&extension.elgamal_pubkey),
            &self.elgamal.pubkey().to_bytes()
        );
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
        let balance =
            AeCiphertext::from_bytes(bytemuck::bytes_of(&extension.decryptable_available_balance))
                .unwrap();
        assert_eq!(balance.decrypt(&self.aes), Some(0));
    }
}
