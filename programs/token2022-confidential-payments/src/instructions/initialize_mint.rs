use anchor_lang::{
    prelude::*,
    solana_program::program::invoke,
    system_program::{self, CreateAccount},
};
use anchor_spl::token_2022::{
    self,
    spl_token_2022::{
        extension::{confidential_transfer, ExtensionType},
        state::Mint,
    },
    InitializeMint2, Token2022,
};

#[derive(Accounts)]
pub struct InitializeMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(mut)]
    pub mint: Signer<'info>,

    /// Controls token issuance and the confidential-transfer configuration.
    pub authority: Signer<'info>,

    pub token_program: Program<'info, Token2022>,
    pub system_program: Program<'info, System>,
}

impl<'info> InitializeMint<'info> {
    pub fn handler(&mut self, decimals: u8) -> Result<()> {
        let space = ExtensionType::try_calculate_account_len::<Mint>(&[
            ExtensionType::ConfidentialTransferMint,
        ])?;

        // Allocate the full Token-2022 layout.
        system_program::create_account(
            CpiContext::new(
                self.system_program.key(),
                CreateAccount {
                    from: self.payer.to_account_info(),
                    to: self.mint.to_account_info(),
                },
            ),
            Rent::get()?.minimum_balance(space),
            space as u64,
            &self.token_program.key(),
        )?;

        // Extensions must be initialized BEFORE the base mint.
        let initialize_confidential_transfer = confidential_transfer::instruction::initialize_mint(
            &self.token_program.key(),
            &self.mint.key(),
            Some(self.authority.key()),
            true, // Automatically approve newly configured confidential accounts.
            None, // No auditor for the initial learning example.
        )?;
        invoke(
            &initialize_confidential_transfer,
            &[
                self.mint.to_account_info(),
                self.token_program.to_account_info(),
            ],
        )?;

        token_2022::initialize_mint2(
            CpiContext::new(
                self.token_program.key(),
                InitializeMint2 {
                    mint: self.mint.to_account_info(),
                },
            ),
            decimals,
            &self.authority.key(),
            None, // No freeze authority.
        )
    }
}
