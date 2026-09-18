use anchor_lang::{prelude::*, solana_program::program::invoke};
use anchor_spl::{
    token_2022::{spl_token_2022::extension::confidential_transfer, Token2022},
    token_interface::{Mint, TokenAccount},
};

#[derive(Accounts)]
pub struct Deposit<'info> {
    pub owner: Signer<'info>,

    #[account(owner = token_program.key())]
    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
    mut,
    associated_token::mint = mint,
    associated_token::authority = owner,
    associated_token::token_program = token_program,
    )]
    pub token_account: InterfaceAccount<'info, TokenAccount>,

    pub token_program: Program<'info, Token2022>,
}

impl<'info> Deposit<'info> {
    /// Moves a public amount, in raw token units, into this account's encrypted pending balance.
    pub fn handler(&mut self, amount: u64) -> Result<()> {
        let deposit = confidential_transfer::instruction::deposit(
            &self.token_program.key(),
            &self.token_account.key(),
            &self.mint.key(),
            amount,
            self.mint.decimals,
            &self.owner.key(),
            &[],
        )?;
        invoke(
            &deposit,
            &[
                self.token_account.to_account_info(),
                self.mint.to_account_info(),
                self.owner.to_account_info(),
                self.token_program.to_account_info(),
            ],
        )?;
        Ok(())
    }
}
