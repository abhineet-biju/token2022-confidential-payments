mod client;

use anchor_lang::prelude::Pubkey;
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Token-2022 confidential payments. All amounts are raw token units.")]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8899", global = true)]
    url: String,
    /// Solana JSON keypair used for signing and fees.
    #[arg(long)]
    keypair: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a mint with this wallet as mint authority.
    InitMint {
        #[arg(long, default_value_t = 6)]
        decimals: u8,
    },
    /// Configure this wallet's confidential ATA.
    Configure { mint: Pubkey },
    /// Show public, pending, and available balances in raw units.
    Balance { mint: Pubkey },
    /// Move public tokens into pending. Fund the ATA first with spl-token mint/transfer.
    Deposit { mint: Pubkey, amount: u64 },
    /// Consolidate pending into available and update its AES copy.
    ApplyPending { mint: Pubkey },
    /// Send from available to the recipient wallet's configured ATA.
    Transfer {
        mint: Pubkey,
        recipient: Pubkey,
        amount: u64,
    },
    /// Move available tokens back into the public balance; the amount becomes public.
    Withdraw { mint: Pubkey, amount: u64 },
    /// Recover rent from verified proof contexts left by an interrupted command.
    CloseProofs {
        #[arg(required = true, num_args = 1..)]
        contexts: Vec<Pubkey>,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    let client = client::Client::new(&args.url, &args.keypair)?;
    match args.command {
        Command::InitMint { decimals } => client.initialize_mint(decimals),
        Command::Configure { mint } => client.configure(mint),
        Command::Balance { mint } => client.balance(mint),
        Command::Deposit { mint, amount } => client.deposit(mint, amount),
        Command::ApplyPending { mint } => client.apply_pending(mint),
        Command::Transfer {
            mint,
            recipient,
            amount,
        } => client.transfer(mint, recipient, amount),
        Command::Withdraw { mint, amount } => client.withdraw(mint, amount),
        Command::CloseProofs { contexts } => client.close_proofs(&contexts),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_raw_amounts_and_rejects_fractional_input() {
        let mint = Pubkey::new_unique().to_string();
        assert!(Args::try_parse_from([
            "cli",
            "--keypair",
            "wallet.json",
            "deposit",
            &mint,
            "1000000"
        ])
        .is_ok());
        assert!(
            Args::try_parse_from(["cli", "--keypair", "wallet.json", "deposit", &mint, "1.5"])
                .is_err()
        );
    }
}
