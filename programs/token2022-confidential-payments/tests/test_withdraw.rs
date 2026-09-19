mod common;

use {
    anchor_lang::{
        prelude::Pubkey, solana_program::instruction::Instruction, InstructionData, ToAccountMetas,
    },
    anchor_spl::token_2022::spl_token_2022::{
        self,
        extension::{
            confidential_transfer::ConfidentialTransferAccount, BaseStateWithExtensions,
            StateWithExtensions,
        },
        state::Account,
    },
    common::{send, stage_proof, Fixture},
    solana_signer::Signer,
    solana_zk_elgamal_proof_interface::instruction::{
        close_context_state, ContextStateInfo, ProofInstruction,
    },
    solana_zk_sdk::encryption::{auth_encryption::AeCiphertext, elgamal::ElGamalCiphertext},
    spl_token_confidential_transfer_proof_generation::{
        errors::TokenProofGenerationError,
        withdraw::{withdraw_proof_data, WithdrawProofData},
    },
};

fn extension(f: &Fixture) -> ConfidentialTransferAccount {
    let account = f.svm.get_account(&f.ata).unwrap();
    *StateWithExtensions::<Account>::unpack(&account.data)
        .unwrap()
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap()
}

fn deposit(f: &mut Fixture, amount: u64) {
    let ix = Instruction::new_with_bytes(
        token2022_confidential_payments::id(),
        &token2022_confidential_payments::instruction::Deposit { amount }.data(),
        token2022_confidential_payments::accounts::Deposit {
            owner: f.owner.pubkey(),
            mint: f.mint,
            token_account: f.ata,
            token_program: spl_token_2022::id(),
        }
        .to_account_metas(None),
    );
    send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).unwrap();
}

fn setup() -> Fixture {
    let mut f = Fixture::new();
    f.configure();
    let mint = spl_token_2022::instruction::mint_to_checked(
        &spl_token_2022::id(),
        &f.mint,
        &f.ata,
        &f.payer.pubkey(),
        &[],
        15_000_000,
        6,
    )
    .unwrap();
    send(&mut f.svm, &f.payer, &[mint], &[]).unwrap();
    deposit(&mut f, 10_000_000);
    let apply = Instruction::new_with_bytes(
        token2022_confidential_payments::id(),
        &token2022_confidential_payments::instruction::ApplyPending {
            expected_pending_balance_credit_counter: 1,
            new_decryptable_available_balance: f.aes.encrypt(10_000_000).to_bytes(),
        }
        .data(),
        token2022_confidential_payments::accounts::ApplyPending {
            owner: f.owner.pubkey(),
            mint: f.mint,
            token_account: f.ata,
            token_program: spl_token_2022::id(),
        }
        .to_account_metas(None),
    );
    send(&mut f.svm, &f.payer, &[apply], &[&f.owner]).unwrap();
    deposit(&mut f, 2_000_000);
    // Public = 3m, pending = 2m, available = 10m.
    f
}

fn proofs(f: &Fixture, amount: u64) -> Result<WithdrawProofData, TokenProofGenerationError> {
    let e = extension(f);
    assert_eq!(
        e.expected_pending_balance_credit_counter, e.actual_pending_balance_credit_counter,
        "Reconcile the AES balance copy before creating withdrawal proofs"
    );
    let current = AeCiphertext::from_bytes(bytemuck::bytes_of(&e.decryptable_available_balance))
        .unwrap()
        .decrypt(&f.aes)
        .unwrap();
    withdraw_proof_data(
        &ElGamalCiphertext::from_bytes(bytemuck::bytes_of(&e.available_balance)).unwrap(),
        current,
        amount,
        &f.elgamal,
    )
}

fn prepare(f: &mut Fixture, amount: u64) -> (Instruction, [Pubkey; 2]) {
    let data = proofs(f, amount).unwrap();
    let owner = f.owner.pubkey();
    let equality = stage_proof(
        f,
        owner,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &data.equality_proof_data,
    );
    let range = stage_proof(
        f,
        owner,
        ProofInstruction::VerifyBatchedRangeProofU64,
        &data.range_proof_data,
    );
    let current = AeCiphertext::from_bytes(bytemuck::bytes_of(
        &extension(f).decryptable_available_balance,
    ))
    .unwrap()
    .decrypt(&f.aes)
    .unwrap();
    let ix = Instruction::new_with_bytes(
        token2022_confidential_payments::id(),
        &token2022_confidential_payments::instruction::Withdraw {
            amount,
            new_decryptable_available_balance: f
                .aes
                .encrypt(current.checked_sub(amount).unwrap())
                .to_bytes(),
        }
        .data(),
        token2022_confidential_payments::accounts::Withdraw {
            owner,
            mint: f.mint,
            token_account: f.ata,
            equality_proof_context: equality,
            range_proof_context: range,
            token_program: spl_token_2022::id(),
        }
        .to_account_metas(None),
    );
    (ix, [equality, range])
}

fn assert_balances(f: &Fixture, public: u64, pending: u64, available: u64) {
    let account = f.svm.get_account(&f.ata).unwrap();
    let state = StateWithExtensions::<Account>::unpack(&account.data).unwrap();
    assert_eq!(state.base.amount, public);
    let e = state
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap();
    let decrypt = |bytes| {
        ElGamalCiphertext::from_bytes(bytes)
            .unwrap()
            .decrypt_u32(f.elgamal.secret())
            .unwrap()
    };
    assert_eq!(
        decrypt(bytemuck::bytes_of(&e.pending_balance_lo))
            + (decrypt(bytemuck::bytes_of(&e.pending_balance_hi)) << 16),
        pending
    );
    assert_eq!(decrypt(bytemuck::bytes_of(&e.available_balance)), available);
    assert_eq!(
        AeCiphertext::from_bytes(bytemuck::bytes_of(&e.decryptable_available_balance))
            .unwrap()
            .decrypt(&f.aes),
        Some(available)
    );
    assert_eq!(u64::from(e.pending_balance_credit_counter), 1);
}

fn close_proofs(f: &mut Fixture, contexts: [Pubkey; 2]) {
    let rent: u64 = contexts
        .iter()
        .map(|p| f.svm.get_account(p).unwrap().lamports)
        .sum();
    let before = f.svm.get_balance(&f.owner.pubkey()).unwrap_or(0);
    let closes: Vec<_> = contexts
        .iter()
        .map(|p| {
            close_context_state(
                ContextStateInfo {
                    context_state_account: p,
                    context_state_authority: &f.owner.pubkey(),
                },
                &f.owner.pubkey(),
            )
        })
        .collect();
    send(&mut f.svm, &f.payer, &closes, &[&f.owner]).unwrap();
    assert_eq!(f.svm.get_balance(&f.owner.pubkey()).unwrap(), before + rent);
    for p in contexts {
        assert!(f.svm.get_account(&p).is_none_or(|a| a.lamports == 0));
    }
}

#[test]
fn withdraws_partial_then_full_available_preserving_pending_and_supply() {
    let mut f = setup();
    let pending_before = extension(&f);
    let mint_before = f.svm.get_account(&f.mint).unwrap().data;
    let (ix, contexts) = prepare(&mut f, 3_000_001);
    send(&mut f.svm, &f.payer, &[ix.clone()], &[&f.owner]).unwrap();
    assert_balances(&f, 6_000_001, 2_000_000, 6_999_999);
    let current = extension(&f);
    assert_eq!(
        current.pending_balance_lo,
        pending_before.pending_balance_lo
    );
    assert_eq!(
        current.pending_balance_hi,
        pending_before.pending_balance_hi
    );
    assert_eq!(
        current.expected_pending_balance_credit_counter,
        pending_before.expected_pending_balance_credit_counter
    );
    assert_eq!(
        current.actual_pending_balance_credit_counter,
        pending_before.actual_pending_balance_credit_counter
    );
    let before_replay = f.svm.get_account(&f.ata).unwrap().data;
    f.svm.expire_blockhash();
    assert!(send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).is_err());
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, before_replay);
    close_proofs(&mut f, contexts);

    let (ix, contexts) = prepare(&mut f, 6_999_999);
    send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).unwrap();
    assert_balances(&f, 13_000_000, 2_000_000, 0);
    assert_eq!(f.svm.get_account(&f.mint).unwrap().data, mint_before);
    close_proofs(&mut f, contexts);
    // Pending still belongs to the owner, but cannot fund a withdrawal until applied.
    assert!(matches!(
        proofs(&f, 1),
        Err(TokenProofGenerationError::NotEnoughFunds)
    ));
}

#[test]
fn rejects_an_amount_that_does_not_match_the_verified_remaining_balance() {
    let mut f = setup();
    let (mut ix, _) = prepare(&mut f, 1_000_000);
    ix.data = token2022_confidential_payments::instruction::Withdraw {
        amount: 2_000_000,
        new_decryptable_available_balance: f.aes.encrypt(8_000_000).to_bytes(),
    }
    .data();
    let before = f.svm.get_account(&f.ata).unwrap().data;
    assert!(send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).is_err());
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, before);
}

#[test]
fn rejects_missing_owner_signature_and_wrong_context_type() {
    let mut f = setup();
    let (ix, contexts) = prepare(&mut f, 1);
    let before = f.svm.get_account(&f.ata).unwrap().data;
    let mut unsigned = ix.clone();
    unsigned
        .accounts
        .iter_mut()
        .find(|a| a.pubkey == f.owner.pubkey())
        .unwrap()
        .is_signer = false;
    let error = send(&mut f.svm, &f.payer, &[unsigned], &[]).unwrap_err();
    assert!(
        error
            .meta
            .logs
            .iter()
            .any(|l| l.contains("AccountNotSigner")),
        "{error:?}"
    );
    let mut wrong_proof = ix;
    wrong_proof
        .accounts
        .iter_mut()
        .find(|a| a.pubkey == contexts[0])
        .unwrap()
        .pubkey = contexts[1];
    assert!(send(&mut f.svm, &f.payer, &[wrong_proof], &[&f.owner]).is_err());
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, before);
}

#[test]
fn rejects_client_request_exceeding_available_even_when_total_funds_are_sufficient() {
    let f = setup();
    assert!(matches!(
        proofs(&f, 11_000_000),
        Err(TokenProofGenerationError::NotEnoughFunds)
    ));
    assert_balances(&f, 3_000_000, 2_000_000, 10_000_000);
}
