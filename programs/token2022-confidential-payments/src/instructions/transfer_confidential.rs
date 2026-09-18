use anchor_lang::{prelude::*, solana_program::program::invoke};
use anchor_spl::{
    token_2022::{
        spl_token_2022::extension::confidential_transfer::{
            self, DecryptableBalance, EncryptedBalance,
        },
        Token2022,
    },
    token_interface::{Mint, TokenAccount},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;

#[derive(Accounts)]
pub struct TransferConfidential<'info> {
    pub owner: Signer<'info>,

    /// CHECK: Used only as the authority address when validating the destination ATA.
    pub recipient: UncheckedAccount<'info>,

    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = owner,
        associated_token::token_program = token_program,
    )]
    pub source: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = recipient,
        associated_token::token_program = token_program,
    )]
    pub destination: InterfaceAccount<'info, TokenAccount>,

    /// CHECK: The remaining balance ciphertext and new commitment
    /// represent the same number
    pub equality_proof_context: UncheckedAccount<'info>,
    /// CHECK: The payment is consistently encrypted for everyone
    pub ciphertext_validity_proof_context: UncheckedAccount<'info>,
    /// CHECK: The hidden amounts are valid nonnegative integers
    /// within the permitted bounds
    pub range_proof_context: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token2022>,
}

impl<'info> TransferConfidential<'info> {
    pub fn handler(
        &mut self,
        new_source_decryptable_available_balance: [u8; 36],
        transfer_amount_auditor_ciphertext_lo: [u8; 64],
        transfer_amount_auditor_ciphertext_hi: [u8; 64],
    ) -> Result<()> {
        let transfer = confidential_transfer::instruction::inner_transfer(
            &self.token_program.key(),
            &self.source.key(),
            &self.mint.key(),
            &self.destination.key(),
            &DecryptableBalance::from(new_source_decryptable_available_balance),
            &EncryptedBalance::from(transfer_amount_auditor_ciphertext_lo),
            &EncryptedBalance::from(transfer_amount_auditor_ciphertext_hi),
            &self.owner.key(),
            &[],
            ProofLocation::ContextStateAccount(&self.equality_proof_context.key()),
            ProofLocation::ContextStateAccount(&self.ciphertext_validity_proof_context.key()),
            ProofLocation::ContextStateAccount(&self.range_proof_context.key()),
        )?;
        invoke(
            &transfer,
            &[
                self.source.to_account_info(),
                self.mint.to_account_info(),
                self.destination.to_account_info(),
                self.equality_proof_context.to_account_info(),
                self.ciphertext_validity_proof_context.to_account_info(),
                self.range_proof_context.to_account_info(),
                self.owner.to_account_info(),
                self.token_program.to_account_info(),
            ],
        )?;
        Ok(())
    }
}
