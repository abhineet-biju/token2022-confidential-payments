mod common;

use {
    anchor_lang::{solana_program::instruction::Instruction, InstructionData, ToAccountMetas},
    anchor_spl::{
        associated_token::spl_associated_token_account,
        token_2022::spl_token_2022::{
            self,
            extension::{
                confidential_transfer::ConfidentialTransferAccount, BaseStateWithExtensions,
                StateWithExtensions,
            },
            state::Account,
        },
    },
    common::{send, Fixture},
    solana_signer::Signer,
    solana_zk_sdk::encryption::{auth_encryption::AeCiphertext, elgamal::ElGamalCiphertext},
};

fn funded_account(credit_limit: u64) -> Fixture {
    let mut f = Fixture::new();
    let mut configure = f.instruction();
    configure.data = token2022_confidential_payments::instruction::ConfigureAccount {
        decryptable_zero_balance: f.aes.encrypt(0).to_bytes(),
        maximum_pending_balance_credit_counter: credit_limit,
    }
    .data();
    let mint = spl_token_2022::instruction::mint_to_checked(
        &spl_token_2022::id(),
        &f.mint,
        &f.ata,
        &f.payer.pubkey(),
        &[],
        5_000_000,
        6,
    )
    .unwrap();
    send(&mut f.svm, &f.payer, &[configure, mint], &[&f.owner]).unwrap();
    f
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

fn state(f: &Fixture) -> (u64, ConfidentialTransferAccount) {
    let account = f.svm.get_account(&f.ata).unwrap();
    let state = StateWithExtensions::<Account>::unpack(&account.data).unwrap();
    (
        state.base.amount,
        *state
            .get_extension::<ConfidentialTransferAccount>()
            .unwrap(),
    )
}

fn instruction(f: &Fixture, counter: u64, new_balance: [u8; 36]) -> Instruction {
    Instruction::new_with_bytes(
        token2022_confidential_payments::id(),
        &token2022_confidential_payments::instruction::ApplyPending {
            expected_pending_balance_credit_counter: counter,
            new_decryptable_available_balance: new_balance,
        }
        .data(),
        token2022_confidential_payments::accounts::ApplyPending {
            owner: f.owner.pubkey(),
            mint: f.mint,
            token_account: f.ata,
            token_program: spl_token_2022::id(),
        }
        .to_account_metas(None),
    )
}

// Client-side preparation. Keys and plaintext balances never enter instruction data.
fn prepare_apply(f: &Fixture) -> Instruction {
    let (_, extension) = state(f);
    assert_eq!(
        extension.expected_pending_balance_credit_counter,
        extension.actual_pending_balance_credit_counter,
        "Reconcile a previous apply race before relying on the AES balance copy"
    );
    let low =
        ElGamalCiphertext::from_bytes(bytemuck::bytes_of(&extension.pending_balance_lo)).unwrap();
    let high =
        ElGamalCiphertext::from_bytes(bytemuck::bytes_of(&extension.pending_balance_hi)).unwrap();
    let pending = low
        .decrypt_u32(f.elgamal.secret())
        .unwrap()
        .checked_add(
            high.decrypt_u32(f.elgamal.secret())
                .unwrap()
                .checked_mul(1 << 16)
                .unwrap(),
        )
        .unwrap();
    let available =
        AeCiphertext::from_bytes(bytemuck::bytes_of(&extension.decryptable_available_balance))
            .unwrap()
            .decrypt(&f.aes)
            .unwrap();
    let updated = available.checked_add(pending).unwrap();
    instruction(
        f,
        u64::from(extension.pending_balance_credit_counter),
        f.aes.encrypt(updated).to_bytes(),
    )
}

fn assert_applied(
    f: &Fixture,
    public: u64,
    available: u64,
    aes_amount: u64,
    expected: u64,
    actual: u64,
) {
    let (public_amount, extension) = state(f);
    assert_eq!(public_amount, public);
    assert_eq!(extension.pending_balance_lo, Default::default());
    assert_eq!(extension.pending_balance_hi, Default::default());
    assert_eq!(u64::from(extension.pending_balance_credit_counter), 0);
    assert_eq!(
        u64::from(extension.expected_pending_balance_credit_counter),
        expected
    );
    assert_eq!(
        u64::from(extension.actual_pending_balance_credit_counter),
        actual
    );
    // Small test amounts allow independent decryption of the authoritative balance.
    // A wallet should read the AES copy for ordinary u64 available balances.
    let encrypted =
        ElGamalCiphertext::from_bytes(bytemuck::bytes_of(&extension.available_balance)).unwrap();
    assert_eq!(encrypted.decrypt_u32(f.elgamal.secret()), Some(available));
    let readable =
        AeCiphertext::from_bytes(bytemuck::bytes_of(&extension.decryptable_available_balance))
            .unwrap();
    assert_eq!(readable.decrypt(&f.aes), Some(aes_amount));
}

#[test]
fn applies_accumulated_pending_and_does_not_double_credit_on_repeat() {
    let mut f = funded_account(65_536);
    deposit(&mut f, 1_000_001);
    deposit(&mut f, 2_000_002);
    let mint_before = f.svm.get_account(&f.mint).unwrap().data;
    let ix = prepare_apply(&f);
    send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).unwrap();
    assert_applied(&f, 1_999_997, 3_000_003, 3_000_003, 2, 2);
    assert_eq!(f.svm.get_account(&f.mint).unwrap().data, mint_before);

    let available_before = state(&f).1.available_balance;
    let ix = prepare_apply(&f);
    send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).unwrap();
    assert_applied(&f, 1_999_997, 3_000_003, 3_000_003, 0, 0);
    assert_eq!(state(&f).1.available_balance, available_before);
}

#[test]
fn resets_credit_capacity_and_adds_to_existing_available_balance() {
    let mut f = funded_account(1);
    deposit(&mut f, 100_000);
    let ix = prepare_apply(&f);
    send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).unwrap();
    assert_applied(&f, 4_900_000, 100_000, 100_000, 1, 1);
    assert_eq!(
        u64::from(state(&f).1.maximum_pending_balance_credit_counter),
        1
    );

    // Another deposit now succeeds without raising the configured credit limit.
    deposit(&mut f, 200_000);
    let ix = prepare_apply(&f);
    send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).unwrap();
    assert_applied(&f, 4_700_000, 300_000, 300_000, 1, 1);
}

#[test]
fn records_a_credit_race_and_applies_all_pending_without_rejecting() {
    let mut f = funded_account(65_536);
    deposit(&mut f, 100_000);
    let stale_apply = prepare_apply(&f);
    // A new pending credit lands after the client has encrypted its new total.
    deposit(&mut f, 50_000);
    send(&mut f.svm, &f.payer, &[stale_apply], &[&f.owner]).unwrap();
    // The authoritative balance includes both credits, while the AES copy is stale.
    assert_applied(&f, 4_850_000, 150_000, 100_000, 1, 2);
    let extension = state(&f).1;
    assert_ne!(
        extension.expected_pending_balance_credit_counter,
        extension.actual_pending_balance_credit_counter
    );
}

#[test]
fn rejects_apply_without_the_owner_signature() {
    let mut f = funded_account(65_536);
    deposit(&mut f, 100);
    let before = f.svm.get_account(&f.ata).unwrap().data;
    let mut ix = prepare_apply(&f);
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
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, before);
}

#[test]
fn rejects_apply_by_a_different_signer() {
    let mut f = funded_account(65_536);
    deposit(&mut f, 100);
    let before = f.svm.get_account(&f.ata).unwrap().data;
    let mut ix = prepare_apply(&f);
    ix.accounts
        .iter_mut()
        .find(|a| a.pubkey == f.owner.pubkey())
        .unwrap()
        .pubkey = f.payer.pubkey();
    assert!(send(&mut f.svm, &f.payer, &[ix], &[]).is_err());
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, before);
}

#[test]
fn rejects_apply_on_an_unconfigured_ata() {
    let mut f = Fixture::new();
    let create = spl_associated_token_account::instruction::create_associated_token_account(
        &f.payer.pubkey(),
        &f.owner.pubkey(),
        &f.mint,
        &spl_token_2022::id(),
    );
    send(&mut f.svm, &f.payer, &[create], &[]).unwrap();
    let before = f.svm.get_account(&f.ata).unwrap().data;
    let ix = instruction(&f, 0, f.aes.encrypt(0).to_bytes());
    assert!(send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).is_err());
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, before);
}
