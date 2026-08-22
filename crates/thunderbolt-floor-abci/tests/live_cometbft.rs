//! Opt-in wrapper for the official CometBFT v0.38.25 Floor smoke gate.

use std::error::Error;
use std::process::Command;

#[test]
#[ignore = "downloads and builds signed CometBFT v0.38.25, then runs four Floor validators"]
fn live_floor_cometbft_v03825_cluster_gate() -> Result<(), Box<dyn Error>> {
    if std::env::var("THUNDERBOLT_COMETBFT_FLOOR_LIVE").as_deref() != Ok("1") {
        return Err("set THUNDERBOLT_COMETBFT_FLOOR_LIVE=1 to authorize the Floor live gate".into());
    }
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("live-cometbft-v0.38.25.sh");
    let status = Command::new("bash")
        .arg(script)
        .env("THUNDERBOLT_COMETBFT_APP", "floor")
        .env("THUNDERBOLT_EXPECTED_COMETBFT_APP", "floor")
        .status()?;
    if !status.success() {
        return Err(format!("Floor CometBFT gate exited with {status}").into());
    }
    Ok(())
}
