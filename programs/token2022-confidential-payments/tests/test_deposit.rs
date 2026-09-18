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

fn deposit_instruction(f: &Fixture, amount: u64) -> Instruction {
    Instruction::new_with_bytes(
        token2022_confidential_payments::id(),
        &token2022_confidential_payments::instruction::Deposit { amount }.data(),
        token2022_confidential_payments::accounts::Deposit {
            owner: f.owner.pubkey(),
            mint: f.mint,
            token_account: f.ata,
            token_program: spl_token_2022::id(),
        }
        .to_account_metas(None),
    )
}

fn mint_public(f: &mut Fixture, amount: u64) {
    let ix = spl_token_2022::instruction::mint_to_checked(
        &spl_token_2022::id(),
        &f.mint,
        &f.ata,
        &f.payer.pubkey(),
        &[],
        amount,
        6,
    )
    .unwrap();
    send(&mut f.svm, &f.payer, &[ix], &[]).unwrap();
}

fn assert_balances(f: &Fixture, public: u64, pending: u64, credits: u64) {
    let account = f.svm.get_account(&f.ata).unwrap();
    let state = StateWithExtensions::<Account>::unpack(&account.data).unwrap();
    assert_eq!(state.base.amount, public);
    let extension = state
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap();
    let low =
        ElGamalCiphertext::from_bytes(bytemuck::bytes_of(&extension.pending_balance_lo)).unwrap();
    let high =
        ElGamalCiphertext::from_bytes(bytemuck::bytes_of(&extension.pending_balance_hi)).unwrap();
    let recovered = low.decrypt_u32(f.elgamal.secret()).unwrap()
        + (high.decrypt_u32(f.elgamal.secret()).unwrap() << 16);
    assert_eq!(recovered, pending);
    assert_eq!(u64::from(extension.pending_balance_credit_counter), credits);
    // Deposit credits pending only. It must not make funds spendable yet.
    assert_eq!(extension.available_balance, Default::default());
    let available =
        AeCiphertext::from_bytes(bytemuck::bytes_of(&extension.decryptable_available_balance))
            .unwrap();
    assert_eq!(available.decrypt(&f.aes), Some(0));
}

#[test]
fn moves_public_tokens_into_pending_and_accumulates_credits() {
    let mut f = Fixture::new();
    f.configure();
    mint_public(&mut f, 5_000_000);
    let mint_before = f.svm.get_account(&f.mint).unwrap().data;
    let aes_before = {
        let account = f.svm.get_account(&f.ata).unwrap();
        let state = StateWithExtensions::<Account>::unpack(&account.data).unwrap();
        state
            .get_extension::<ConfidentialTransferAccount>()
            .unwrap()
            .decryptable_available_balance
    };
    // Crosses the 16-bit split so both pending components are exercised.
    let ix = deposit_instruction(&f, 1_000_001);
    send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).unwrap();
    assert_balances(&f, 3_999_999, 1_000_001, 1);

    let ix = deposit_instruction(&f, 2_000_002);
    send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).unwrap();
    assert_balances(&f, 1_999_997, 3_000_003, 2);
    assert_eq!(f.svm.get_account(&f.mint).unwrap().data, mint_before);
    let account = f.svm.get_account(&f.ata).unwrap();
    let state = StateWithExtensions::<Account>::unpack(&account.data).unwrap();
    assert_eq!(
        state
            .get_extension::<ConfidentialTransferAccount>()
            .unwrap()
            .decryptable_available_balance,
        aes_before
    );
}

#[test]
fn rejects_insufficient_public_balance_without_mutating_the_account() {
    let mut f = Fixture::new();
    f.configure();
    mint_public(&mut f, 10);
    let before = f.svm.get_account(&f.ata).unwrap().data;
    let ix = deposit_instruction(&f, 11);
    assert!(send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).is_err());
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, before);
}

#[test]
fn rejects_a_signer_who_does_not_own_the_token_account() {
    let mut f = Fixture::new();
    f.configure();
    mint_public(&mut f, 10);
    let before = f.svm.get_account(&f.ata).unwrap().data;
    let mut ix = deposit_instruction(&f, 1);
    ix.accounts
        .iter_mut()
        .find(|a| a.pubkey == f.owner.pubkey())
        .unwrap()
        .pubkey = f.payer.pubkey();
    let error = send(&mut f.svm, &f.payer, &[ix], &[]).unwrap_err();
    assert!(
        error
            .meta
            .logs
            .iter()
            .any(|log| log.contains("ConstraintTokenOwner")),
        "{error:?}"
    );
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, before);
}

#[test]
fn rejects_unconfigured_accounts_without_losing_public_tokens() {
    let mut f = Fixture::new();
    let create = spl_associated_token_account::instruction::create_associated_token_account(
        &f.payer.pubkey(),
        &f.owner.pubkey(),
        &f.mint,
        &spl_token_2022::id(),
    );
    send(&mut f.svm, &f.payer, &[create], &[]).unwrap();
    mint_public(&mut f, 10);
    let before = f.svm.get_account(&f.ata).unwrap().data;
    let ix = deposit_instruction(&f, 1);
    assert!(send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).is_err());
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, before);
}

#[test]
fn rejects_amounts_at_the_48_bit_limit() {
    let mut f = Fixture::new();
    f.configure();
    // Supply enough public tokens so the failure tests the per-deposit limit.
    mint_public(&mut f, 1 << 48);
    let before = f.svm.get_account(&f.ata).unwrap().data;
    let ix = deposit_instruction(&f, 1 << 48);
    assert!(send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).is_err());
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, before);
}

#[test]
fn rejects_deposits_when_pending_credit_limit_is_reached() {
    let mut f = Fixture::new();
    let mut configure = f.instruction();
    configure.data = token2022_confidential_payments::instruction::ConfigureAccount {
        decryptable_zero_balance: f.aes.encrypt(0).to_bytes(),
        maximum_pending_balance_credit_counter: 1,
    }
    .data();
    send(&mut f.svm, &f.payer, &[configure], &[&f.owner]).unwrap();
    mint_public(&mut f, 10);
    let ix = deposit_instruction(&f, 1);
    send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).unwrap();
    assert_balances(&f, 9, 1, 1);
    let before = f.svm.get_account(&f.ata).unwrap().data;
    let ix = deposit_instruction(&f, 2);
    assert!(send(&mut f.svm, &f.payer, &[ix], &[&f.owner]).is_err());
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, before);
}
