use anchor_lang::{prelude::*, solana_program::program::invoke};
use anchor_spl::{
    token_2022::{
        spl_token_2022::extension::confidential_transfer::{self, DecryptableBalance},
        Token2022,
    },
    token_interface::{Mint, TokenAccount},
};

#[derive(Accounts)]
pub struct ApplyPending<'info> {
    pub owner: Signer<'info>,

    #[account(mint::token_program = token_program)]
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

impl<'info> ApplyPending<'info> {
    /// Consolidates pending into available
    /// The client supplies the AES-encrypted new total
    pub fn handler(
        &mut self,
        expected_pending_balance_credit_counter: u64,
        new_decryptable_available_balance: [u8; 36],
    ) -> Result<()> {
        let apply_pending = confidential_transfer::instruction::apply_pending_balance(
            &self.token_program.key(),
            &self.token_account.key(),
            expected_pending_balance_credit_counter,
            &DecryptableBalance::from(new_decryptable_available_balance),
            &self.owner.key(),
            &[],
        )?;
        invoke(
            &apply_pending,
            &[
                self.token_account.to_account_info(),
                self.owner.to_account_info(),
                self.token_program.to_account_info(),
            ],
        )?;
        Ok(())
    }
}
