mod common;

use {
    anchor_spl::{associated_token::spl_associated_token_account, token_2022::spl_token_2022},
    common::{send, Fixture},
    solana_signer::Signer,
    solana_zk_elgamal_proof_interface::instruction::{close_context_state, ContextStateInfo},
};

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
