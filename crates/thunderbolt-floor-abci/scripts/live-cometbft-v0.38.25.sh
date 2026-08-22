#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${THUNDERBOLT_COMETBFT_FLOOR_LIVE:-}" != "1" ]]; then
    echo "set THUNDERBOLT_COMETBFT_FLOOR_LIVE=1 to authorize the opt-in Floor gate" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEDGER_HARNESS="${SCRIPT_DIR}/../../thunderbolt-ledger-abci/scripts/live-cometbft-v0.38.25.sh"
if [[ ! -f "${LEDGER_HARNESS}" ]]; then
    echo "shared pinned CometBFT harness is unavailable" >&2
    exit 2
fi

export THUNDERBOLT_COMETBFT_APP=floor
export THUNDERBOLT_EXPECTED_COMETBFT_APP=floor
exec bash "${LEDGER_HARNESS}"
