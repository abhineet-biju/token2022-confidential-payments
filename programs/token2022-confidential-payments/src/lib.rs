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
}
