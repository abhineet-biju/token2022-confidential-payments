use anchor_lang::{prelude::*, solana_program::program::invoke};
use anchor_spl::{
    token_2022::{
        spl_token_2022::extension::confidential_transfer::{self, DecryptableBalance},
        Token2022,
    },
    token_interface::{Mint, TokenAccount},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;

#[derive(Accounts)]
pub struct Withdraw<'info> {
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

    /// CHECK: Token-2022 checks ZK ownership and the equality context against the remaining balance.
    pub equality_proof_context: UncheckedAccount<'info>,
    /// CHECK: Token-2022 checks ZK ownership and the range context against the same commitment.
    pub range_proof_context: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token2022>,
}

impl<'info> Withdraw<'info> {
    pub fn handler(
        &mut self,
        amount: u64,
        new_decryptable_available_balance: [u8; 36],
    ) -> Result<()> {
        let withdraw = confidential_transfer::instruction::inner_withdraw(
            &self.token_program.key(),
            &self.token_account.key(),
            &self.mint.key(),
            amount,
            self.mint.decimals,
            &DecryptableBalance::from(new_decryptable_available_balance),
            &self.owner.key(),
            &[],
            ProofLocation::ContextStateAccount(&self.equality_proof_context.key()),
            ProofLocation::ContextStateAccount(&self.range_proof_context.key()),
        )?;
        invoke(
            &withdraw,
            &[
                self.token_account.to_account_info(),
                self.mint.to_account_info(),
                self.equality_proof_context.to_account_info(),
                self.range_proof_context.to_account_info(),
                self.owner.to_account_info(),
                self.token_program.to_account_info(),
            ],
        )?;
        Ok(())
    }
}
