//! Opt-in wrapper for the official CometBFT v0.38.25 process gate.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::error::Error;
use std::path::PathBuf;
use std::process::Command;

fn harness() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("live-cometbft-v0.38.25.sh")
}

#[test]
fn shared_harness_rejects_an_unknown_application_mode() -> Result<(), Box<dyn Error>> {
    let status = Command::new("bash")
        .arg(harness())
        .env("THUNDERBOLT_COMETBFT_APP", "not-an-application")
        .status()?;
    assert_eq!(status.code(), Some(2));
    Ok(())
}

#[test]
fn shared_harness_rejects_a_selected_mode_mismatch() -> Result<(), Box<dyn Error>> {
    let status = Command::new("bash")
        .arg(harness())
        .env("THUNDERBOLT_COMETBFT_APP", "ledger")
        .env("THUNDERBOLT_EXPECTED_COMETBFT_APP", "floor")
        .status()?;
    assert_eq!(status.code(), Some(2));
    Ok(())
}

#[test]
#[ignore = "downloads and builds signed CometBFT v0.38.25, then runs four validators"]
fn live_cometbft_v03825_cluster_gate() -> Result<(), Box<dyn Error>> {
    if std::env::var("THUNDERBOLT_COMETBFT_LIVE").as_deref() != Ok("1") {
        return Err("set THUNDERBOLT_COMETBFT_LIVE=1 to authorize the live gate".into());
    }
    let status = Command::new("bash")
        .arg(harness())
        .env("THUNDERBOLT_COMETBFT_APP", "ledger")
        .env("THUNDERBOLT_EXPECTED_COMETBFT_APP", "ledger")
        .status()?;
    if !status.success() {
        return Err(format!("live CometBFT gate exited with {status}").into());
    }
    Ok(())
}
