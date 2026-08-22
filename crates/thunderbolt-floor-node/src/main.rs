#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]
#![forbid(unsafe_code)]

mod config;
mod error;
mod fs;
mod genesis;
mod node;

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::config::ValidatedConfig;
use crate::error::Result;

#[derive(Debug, Parser)]
#[command(
    name = "thunderbolt-floor-node",
    version,
    about = "Bitcoin Thunderbolt rollback-floor node"
)]
struct Cli {
    /// Absolute path to the owner-only Floor node configuration.
    #[arg(long)]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, Subcommand)]
enum Command {
    /// Validate configuration and public manifests without writing state.
    Check,
    /// Write the canonical CometBFT genesis document to standard output.
    Genesis,
    /// Open the durable Floor application and serve local ABCI.
    Start,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let config = ValidatedConfig::load(&cli.config)?;
    match cli.command {
        Command::Check => {
            config.revalidate()?;
            println!("{}", config.check_json()?);
            Ok(())
        }
        Command::Genesis => {
            config.revalidate()?;
            println!("{}", genesis::canonical_genesis_json(&config)?);
            Ok(())
        }
        Command::Start => node::start(config).await,
    }
}
