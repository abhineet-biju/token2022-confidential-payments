mod common;

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
    common::{send, stage_proof, Fixture},
    solana_keypair::Keypair,
    solana_signer::Signer,
    solana_zk_elgamal_proof_interface::instruction::{
        close_context_state, ContextStateInfo, ProofInstruction,
    },
    solana_zk_sdk::{
        encryption::{
            auth_encryption::{AeCiphertext, AeKey},
            elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
        },
        zk_elgamal_proof_program::build_pubkey_validity_proof_data,
    },
    spl_token_confidential_transfer_proof_generation::{
        errors::TokenProofGenerationError,
        transfer::{transfer_split_proof_data, TransferProofData},
    },
};

struct Recipient {
    owner: Keypair,
    ata: Pubkey,
    elgamal: ElGamalKeypair,
    aes: AeKey,
}

fn recipient(f: &mut Fixture) -> Recipient {
    let owner = Keypair::new();
    let elgamal = ElGamalKeypair::new_rand();
    let aes = AeKey::new_rand();
    let proof = build_pubkey_validity_proof_data(&elgamal).unwrap();
    let context = stage_proof(
        f,
        owner.pubkey(),
        ProofInstruction::VerifyPubkeyValidity,
        &proof,
    );
    let ata = get_associated_token_address_with_program_id(
        &owner.pubkey(),
        &f.mint,
        &spl_token_2022::id(),
    );
    let configure = Instruction::new_with_bytes(
        token2022_confidential_payments::id(),
        &token2022_confidential_payments::instruction::ConfigureAccount {
            decryptable_zero_balance: aes.encrypt(0).to_bytes(),
            maximum_pending_balance_credit_counter: 65_536,
        }
        .data(),
        token2022_confidential_payments::accounts::ConfigureAccount {
            payer: f.payer.pubkey(),
            owner: owner.pubkey(),
            mint: f.mint,
            token_account: ata,
            proof_context: context,
            token_program: spl_token_2022::id(),
            associated_token_program: associated_token::ID,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    );
    let close = close_context_state(
        ContextStateInfo {
            context_state_account: &context,
            context_state_authority: &owner.pubkey(),
        },
        &f.payer.pubkey(),
    );
    send(&mut f.svm, &f.payer, &[configure, close], &[&owner]).unwrap();
    Recipient {
        owner,
        ata,
        elgamal,
        aes,
    }
}

fn extension(f: &Fixture, ata: Pubkey) -> ConfidentialTransferAccount {
    let account = f.svm.get_account(&ata).unwrap();
    *StateWithExtensions::<Account>::unpack(&account.data)
        .unwrap()
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap()
}

fn mint_and_deposit(f: &mut Fixture, amount: u64) {
    let mint = spl_token_2022::instruction::mint_to_checked(
        &spl_token_2022::id(),
        &f.mint,
        &f.ata,
        &f.payer.pubkey(),
        &[],
        amount,
        6,
    )
    .unwrap();
    let deposit = Instruction::new_with_bytes(
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
    send(&mut f.svm, &f.payer, &[mint, deposit], &[&f.owner]).unwrap();
}

fn apply_instruction(
    f: &Fixture,
    owner: Pubkey,
    ata: Pubkey,
    aes: &AeKey,
    total: u64,
) -> Instruction {
    Instruction::new_with_bytes(
        token2022_confidential_payments::id(),
        &token2022_confidential_payments::instruction::ApplyPending {
            expected_pending_balance_credit_counter: extension(f, ata)
                .pending_balance_credit_counter
                .into(),
            new_decryptable_available_balance: aes.encrypt(total).to_bytes(),
        }
        .data(),
        token2022_confidential_payments::accounts::ApplyPending {
            owner,
            mint: f.mint,
            token_account: ata,
            token_program: spl_token_2022::id(),
        }
        .to_account_metas(None),
    )
}

fn setup() -> (Fixture, Recipient) {
    let mut f = Fixture::new();
    f.configure();
    let bob = recipient(&mut f);
    mint_and_deposit(&mut f, 10_000_000);
    let apply = apply_instruction(&f, f.owner.pubkey(), f.ata, &f.aes, 10_000_000);
    send(&mut f.svm, &f.payer, &[apply], &[&f.owner]).unwrap();
    (f, bob)
}

fn proofs(
    f: &Fixture,
    recipient_key: &ElGamalPubkey,
    amount: u64,
) -> Result<TransferProofData, TokenProofGenerationError> {
    let account = extension(f, f.ata);
    assert_eq!(
        account.expected_pending_balance_credit_counter,
        account.actual_pending_balance_credit_counter,
        "Reconcile the AES balance copy before preparing a transfer"
    );
    transfer_split_proof_data(
        &ElGamalCiphertext::from_bytes(bytemuck::bytes_of(&account.available_balance)).unwrap(),
        &AeCiphertext::from_bytes(bytemuck::bytes_of(&account.decryptable_available_balance))
            .unwrap(),
        amount,
        &f.elgamal,
        &f.aes,
        recipient_key,
        None,
    )
}

struct PreparedTransfer {
    instruction: Instruction,
    contexts: [Pubkey; 3],
}

fn prepare(
    f: &mut Fixture,
    bob: &Recipient,
    amount: u64,
    data: TransferProofData,
) -> PreparedTransfer {
    let authority = f.owner.pubkey();
    let equality = stage_proof(
        f,
        authority,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &data.equality_proof_data,
    );
    let validity = stage_proof(
        f,
        authority,
        ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity,
        &data
            .ciphertext_validity_proof_data_with_ciphertext
            .proof_data,
    );
    let range = stage_proof(
        f,
        authority,
        ProofInstruction::VerifyBatchedRangeProofU128,
        &data.range_proof_data,
    );
    let current = AeCiphertext::from_bytes(bytemuck::bytes_of(
        &extension(f, f.ata).decryptable_available_balance,
    ))
    .unwrap()
    .decrypt(&f.aes)
    .unwrap();
    let ix = Instruction::new_with_bytes(
        token2022_confidential_payments::id(),
        &token2022_confidential_payments::instruction::TransferConfidential {
            new_source_decryptable_available_balance: f
                .aes
                .encrypt(current.checked_sub(amount).unwrap())
                .to_bytes(),
            transfer_amount_auditor_ciphertext_lo: bytemuck::bytes_of(
                &data
                    .ciphertext_validity_proof_data_with_ciphertext
                    .ciphertext_lo,
            )
            .try_into()
            .unwrap(),
            transfer_amount_auditor_ciphertext_hi: bytemuck::bytes_of(
                &data
                    .ciphertext_validity_proof_data_with_ciphertext
                    .ciphertext_hi,
            )
            .try_into()
            .unwrap(),
        }
        .data(),
        token2022_confidential_payments::accounts::TransferConfidential {
            owner: authority,
            recipient: bob.owner.pubkey(),
            mint: f.mint,
            source: f.ata,
            destination: bob.ata,
            equality_proof_context: equality,
            ciphertext_validity_proof_context: validity,
            range_proof_context: range,
            token_program: spl_token_2022::id(),
        }
        .to_account_metas(None),
    );
    PreparedTransfer {
        instruction: ix,
        contexts: [equality, validity, range],
    }
}

fn balances(f: &Fixture, ata: Pubkey, key: &ElGamalKeypair, aes: &AeKey) -> (u64, u64, u64, u64) {
    let account = f.svm.get_account(&ata).unwrap();
    let state = StateWithExtensions::<Account>::unpack(&account.data).unwrap();
    let e = state
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap();
    let decrypt = |c| {
        ElGamalCiphertext::from_bytes(c)
            .unwrap()
            .decrypt_u32(key.secret())
            .unwrap()
    };
    let pending = decrypt(bytemuck::bytes_of(&e.pending_balance_lo))
        + (decrypt(bytemuck::bytes_of(&e.pending_balance_hi)) << 16);
    let available = decrypt(bytemuck::bytes_of(&e.available_balance));
    let readable = AeCiphertext::from_bytes(bytemuck::bytes_of(&e.decryptable_available_balance))
        .unwrap()
        .decrypt(aes)
        .unwrap();
    assert_eq!(available, readable);
    (
        state.base.amount,
        pending,
        available,
        u64::from(e.pending_balance_credit_counter),
    )
}

#[test]
fn transfers_to_recipient_pending_then_applies_and_closes_proofs() {
    let (mut f, bob) = setup();
    let data = proofs(&f, bob.elgamal.pubkey(), 3_000_001).unwrap();
    let prepared = prepare(&mut f, &bob, 3_000_001, data);
    // Pending may change after proof generation without invalidating available-balance proofs.
    mint_and_deposit(&mut f, 5);
    let mint_before = f.svm.get_account(&f.mint).unwrap().data;
    // Only Alice signs the transfer; Bob need not be online.
    send(
        &mut f.svm,
        &f.payer,
        &[prepared.instruction.clone()],
        &[&f.owner],
    )
    .unwrap();
    assert_eq!(
        balances(&f, f.ata, &f.elgamal, &f.aes),
        (0, 5, 6_999_999, 1)
    );
    assert_eq!(
        balances(&f, bob.ata, &bob.elgamal, &bob.aes),
        (0, 3_000_001, 0, 1)
    );
    assert_eq!(f.svm.get_account(&f.mint).unwrap().data, mint_before);

    let source_before = f.svm.get_account(&f.ata).unwrap().data;
    let destination_before = f.svm.get_account(&bob.ata).unwrap().data;
    f.svm.expire_blockhash();
    assert!(send(&mut f.svm, &f.payer, &[prepared.instruction], &[&f.owner]).is_err());
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, source_before);
    assert_eq!(
        f.svm.get_account(&bob.ata).unwrap().data,
        destination_before
    );

    let rent: u64 = prepared
        .contexts
        .iter()
        .map(|p| f.svm.get_account(p).unwrap().lamports)
        .sum();
    let before = f.svm.get_balance(&f.owner.pubkey()).unwrap_or(0);
    let closes: Vec<_> = prepared
        .contexts
        .iter()
        .map(|context| {
            close_context_state(
                ContextStateInfo {
                    context_state_account: context,
                    context_state_authority: &f.owner.pubkey(),
                },
                &f.owner.pubkey(),
            )
        })
        .collect();
    send(&mut f.svm, &f.payer, &closes, &[&f.owner]).unwrap();
    assert_eq!(f.svm.get_balance(&f.owner.pubkey()).unwrap(), before + rent);
    for context in prepared.contexts {
        assert!(f.svm.get_account(&context).is_none_or(|a| a.lamports == 0));
    }

    let apply = apply_instruction(&f, bob.owner.pubkey(), bob.ata, &bob.aes, 3_000_001);
    send(&mut f.svm, &f.payer, &[apply], &[&bob.owner]).unwrap();
    assert_eq!(
        balances(&f, bob.ata, &bob.elgamal, &bob.aes),
        (0, 0, 3_000_001, 0)
    );
}

#[test]
fn rejects_proofs_encrypted_for_a_different_recipient() {
    let (mut f, bob) = setup();
    let wrong_key = ElGamalKeypair::new_rand();
    let data = proofs(&f, wrong_key.pubkey(), 1).unwrap();
    let prepared = prepare(&mut f, &bob, 1, data);
    let source = f.svm.get_account(&f.ata).unwrap().data;
    let destination = f.svm.get_account(&bob.ata).unwrap().data;
    assert!(send(&mut f.svm, &f.payer, &[prepared.instruction], &[&f.owner]).is_err());
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, source);
    assert_eq!(f.svm.get_account(&bob.ata).unwrap().data, destination);
}

#[test]
fn rejects_missing_sender_signature_and_wrong_proof_context_type() {
    let (mut f, bob) = setup();
    let data = proofs(&f, bob.elgamal.pubkey(), 1).unwrap();
    let prepared = prepare(&mut f, &bob, 1, data);
    let source = f.svm.get_account(&f.ata).unwrap().data;
    let destination = f.svm.get_account(&bob.ata).unwrap().data;
    let mut unsigned = prepared.instruction.clone();
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
    let mut wrong_context = prepared.instruction;
    wrong_context
        .accounts
        .iter_mut()
        .find(|a| a.pubkey == prepared.contexts[0])
        .unwrap()
        .pubkey = prepared.contexts[2];
    assert!(send(&mut f.svm, &f.payer, &[wrong_context], &[&f.owner]).is_err());
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, source);
    assert_eq!(f.svm.get_account(&bob.ata).unwrap().data, destination);
}

#[test]
fn rejects_preverified_proofs_after_source_available_balance_changes() {
    let (mut f, bob) = setup();
    let data = proofs(&f, bob.elgamal.pubkey(), 1).unwrap();
    let prepared = prepare(&mut f, &bob, 1, data);
    mint_and_deposit(&mut f, 1);
    let apply = apply_instruction(&f, f.owner.pubkey(), f.ata, &f.aes, 10_000_001);
    send(&mut f.svm, &f.payer, &[apply], &[&f.owner]).unwrap();
    let source = f.svm.get_account(&f.ata).unwrap().data;
    assert!(send(&mut f.svm, &f.payer, &[prepared.instruction], &[&f.owner]).is_err());
    assert_eq!(f.svm.get_account(&f.ata).unwrap().data, source);
    assert_eq!(balances(&f, bob.ata, &bob.elgamal, &bob.aes), (0, 0, 0, 0));
}

#[test]
fn client_rejects_spending_more_than_available() {
    let (f, bob) = setup();
    assert!(matches!(
        proofs(&f, bob.elgamal.pubkey(), 10_000_001),
        Err(TokenProofGenerationError::NotEnoughFunds)
    ));
}
