pub mod instructions;

use anchor_lang::prelude::*;
pub use instructions::*;

declare_id!("8DXYc6hMDiU9jh5QJSYVR59kkvpoJKCnLWoSUn8V1L27");

#[program]
pub mod token2022_confidential_payments {
    use super::*;

    /// Creates a Token-2022 mint with confidential transfers enabled.
    pub fn initialize_mint(ctx: Context<InitializeMint>, decimals: u8) -> Result<()> {
        ctx.accounts.handler(decimals)
    }

    /// Creates or reuses the owner's ATA and enables its confidential balances.
    pub fn configure_account(
        ctx: Context<ConfigureAccount>,
        decryptable_zero_balance: [u8; 36],
        maximum_pending_balance_credit_counter: u64,
    ) -> Result<()> {
        ctx.accounts.handler(
            decryptable_zero_balance,
            maximum_pending_balance_credit_counter,
        )
    }

    /// Moves public tokens into the owner's confidential pending balance.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        ctx.accounts.handler(amount)
    }

    /// Makes pending confidential funds available for spending.
    pub fn apply_pending(
        ctx: Context<ApplyPending>,
        expected_pending_balance_credit_counter: u64,
        new_decryptable_available_balance: [u8; 36],
    ) -> Result<()> {
        ctx.accounts.handler(
            expected_pending_balance_credit_counter,
            new_decryptable_available_balance,
        )
    }
}
