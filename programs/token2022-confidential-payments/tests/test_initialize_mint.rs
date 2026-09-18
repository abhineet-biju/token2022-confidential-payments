use {
    anchor_lang::{
        prelude::Pubkey,
        solana_program::{instruction::Instruction, program_option::COption, system_program},
        InstructionData, ToAccountMetas,
    },
    anchor_spl::token_2022::spl_token_2022::{
        self,
        extension::{
            confidential_transfer::ConfidentialTransferMint, BaseStateWithExtensions,
            ExtensionType, StateWithExtensions,
        },
        state::Mint,
    },
    litesvm::LiteSVM,
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
};

fn setup() -> (LiteSVM, Keypair, Keypair, Keypair) {
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
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();
    (svm, payer, Keypair::new(), Keypair::new())
}

fn initialize_instruction(
    payer: Pubkey,
    mint: Pubkey,
    authority: Pubkey,
    token_program: Pubkey,
    decimals: u8,
) -> Instruction {
    Instruction::new_with_bytes(
        token2022_confidential_payments::id(),
        &token2022_confidential_payments::instruction::InitializeMint { decimals }.data(),
        token2022_confidential_payments::accounts::InitializeMint {
            payer,
            mint,
            authority,
            token_program,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    )
}

fn transaction(
    svm: &LiteSVM,
    payer: &Keypair,
    mint: &Keypair,
    authority: &Keypair,
    instruction: Instruction,
) -> VersionedTransaction {
    let message = Message::new_with_blockhash(
        &[instruction],
        Some(&payer.pubkey()),
        &svm.latest_blockhash(),
    );
    VersionedTransaction::try_new(VersionedMessage::Legacy(message), &[payer, mint, authority])
        .unwrap()
}

#[test]
fn initializes_confidential_mint_and_rejects_reinitialization() {
    let (mut svm, payer, mint, authority) = setup();
    let instruction = initialize_instruction(
        payer.pubkey(),
        mint.pubkey(),
        authority.pubkey(),
        spl_token_2022::id(),
        6,
    );
    let tx = transaction(&svm, &payer, &mint, &authority, instruction.clone());
    svm.send_transaction(tx).unwrap();

    let account = svm.get_account(&mint.pubkey()).unwrap();
    assert_eq!(account.owner, spl_token_2022::id());
    let expected_space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::ConfidentialTransferMint,
    ])
    .unwrap();
    assert_eq!(account.data.len(), expected_space);
    assert!(account.lamports >= svm.minimum_balance_for_rent_exemption(expected_space));
    let state = StateWithExtensions::<Mint>::unpack(&account.data).unwrap();
    assert!(state.base.is_initialized);
    assert_eq!(state.base.decimals, 6);
    assert_eq!(state.base.supply, 0);
    assert_eq!(state.base.mint_authority, COption::Some(authority.pubkey()));
    assert_eq!(state.base.freeze_authority, COption::None);
    let extension = state.get_extension::<ConfidentialTransferMint>().unwrap();
    assert_eq!(
        Option::<Pubkey>::from(extension.authority),
        Some(authority.pubkey())
    );
    assert!(bool::from(extension.auto_approve_new_accounts));
    assert_eq!(extension.auditor_elgamal_pubkey, Default::default());

    // A new blockhash ensures this reaches the program instead of duplicate detection.
    svm.expire_blockhash();
    let tx = transaction(&svm, &payer, &mint, &authority, instruction);
    assert!(svm.send_transaction(tx).is_err());
    assert_eq!(svm.get_account(&mint.pubkey()).unwrap().data, account.data);
}

#[test]
fn rejects_a_different_program_before_creating_the_mint() {
    let (mut svm, payer, mint, authority) = setup();
    let instruction = initialize_instruction(
        payer.pubkey(),
        mint.pubkey(),
        authority.pubkey(),
        system_program::ID,
        6,
    );
    let tx = transaction(&svm, &payer, &mint, &authority, instruction);
    let error = svm.send_transaction(tx).unwrap_err();
    assert!(
        error
            .meta
            .logs
            .iter()
            .any(|log| log.contains("InvalidProgramId")),
        "{error:?}"
    );
    assert!(svm.get_account(&mint.pubkey()).is_none());
}
