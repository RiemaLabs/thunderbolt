#!/usr/bin/env bash
set -Eeuo pipefail

COMET_VERSION="v0.38.25"
COMET_TAG_OBJECT="330e3d9a1bbd2e92ff67c6e0958582e132849ca3"
COMET_COMMIT="baaa61e6398fa71349f7a1e7f5d3eb17711a584b"
COMET_SIGNER_FINGERPRINT="34E07D0C95A4643DB9937263E2B366778DC37650"
COMET_ARCHIVE_SHA256="4557439c9af26e4bf44008bf196c6437b37e637ab4a957a0071e83823def34d3"
COMET_ARCHIVE_URL="https://github.com/cometbft/cometbft/archive/refs/tags/${COMET_VERSION}.tar.gz"
COMET_GIT_URL="https://github.com/cometbft/cometbft.git"
CHAIN_ID="thunderbolt-live-v2"
CRASH_HEIGHT=2

if [[ "${THUNDERBOLT_COMETBFT_LIVE:-}" != "1" ]]; then
    echo "set THUNDERBOLT_COMETBFT_LIVE=1 to authorize the opt-in live gate" >&2
    exit 2
fi

for command_name in cargo curl diff git go gpg python3 tar; do
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "required command is unavailable: ${command_name}" >&2
        exit 2
    fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SIGNING_KEY="${SCRIPT_DIR}/../tests/fixtures/cometbft-v0.38.25-signing-key.asc"
RUN_BASE="${TMPDIR:-/tmp}"
RUN_BASE="${RUN_BASE%/}"
RUN_ROOT="$(mktemp -d "${RUN_BASE}/thunderbolt-cometbft.XXXXXX")"
chmod 700 "${RUN_ROOT}"

APP_PIDS=()
NODE_PIDS=()

stop_pid() {
    local pid="${1:-}"
    if [[ -z "${pid}" ]] || ! kill -0 "${pid}" 2>/dev/null; then
        return
    fi
    kill "${pid}" 2>/dev/null || true
    local attempt
    for attempt in $(seq 1 50); do
        if ! kill -0 "${pid}" 2>/dev/null; then
            wait "${pid}" 2>/dev/null || true
            return
        fi
        sleep 0.1
    done
    kill -KILL "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
}

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    local pid
    for pid in "${NODE_PIDS[@]:-}"; do
        stop_pid "${pid}"
    done
    for pid in "${APP_PIDS[@]:-}"; do
        stop_pid "${pid}"
    done
    if [[ ${exit_code} -ne 0 && -d "${RUN_ROOT}/logs" ]]; then
        echo "live gate failed; final process logs:" >&2
        while IFS= read -r log_file; do
            echo "== ${log_file##*/} ==" >&2
            tail -40 "${log_file}" >&2 || true
        done < <(find "${RUN_ROOT}/logs" -type f -maxdepth 1 | sort)
    fi
    case "${RUN_ROOT}" in
        "${RUN_BASE}"/thunderbolt-cometbft.*) ;;
        *)
            echo "refusing to clean unexpected path: ${RUN_ROOT}" >&2
            exit 1
            ;;
    esac
    chmod -R u+w "${RUN_ROOT}" 2>/dev/null || true
    rm -rf -- "${RUN_ROOT}"
    if [[ -e "${RUN_ROOT}" ]]; then
        echo "live gate temporary directory was not removed: ${RUN_ROOT}" >&2
        exit 1
    fi
    if [[ ${exit_code} -eq 0 ]]; then
        echo "cleanup verified: all child processes stopped and temporary files removed"
    fi
    exit "${exit_code}"
}
trap cleanup EXIT INT TERM

mkdir -p "${RUN_ROOT}/logs" "${RUN_ROOT}/gpg" "${RUN_ROOT}/go-cache" \
    "${RUN_ROOT}/go-mod-cache" "${RUN_ROOT}/go-path"
chmod 700 "${RUN_ROOT}/gpg"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

echo "verifying official CometBFT ${COMET_VERSION} source"
ARCHIVE="${RUN_ROOT}/cometbft-${COMET_VERSION}.tar.gz"
curl --fail --location --proto '=https' --retry 3 --silent --show-error \
    --output "${ARCHIVE}" "${COMET_ARCHIVE_URL}"
ACTUAL_ARCHIVE_SHA256="$(sha256_file "${ARCHIVE}")"
if [[ "${ACTUAL_ARCHIVE_SHA256}" != "${COMET_ARCHIVE_SHA256}" ]]; then
    echo "CometBFT source archive checksum mismatch" >&2
    exit 1
fi

export GNUPGHOME="${RUN_ROOT}/gpg"
gpg --batch --quiet --import "${SIGNING_KEY}"
ACTUAL_FINGERPRINT="$(gpg --batch --with-colons --fingerprint | awk -F: '$1 == "fpr" { print $10; exit }')"
if [[ "${ACTUAL_FINGERPRINT}" != "${COMET_SIGNER_FINGERPRINT}" ]]; then
    echo "CometBFT signer fingerprint mismatch" >&2
    exit 1
fi

VERIFY_REPO="${RUN_ROOT}/signed-tag"
git init --quiet "${VERIFY_REPO}"
git -C "${VERIFY_REPO}" remote add origin "${COMET_GIT_URL}"
git -C "${VERIFY_REPO}" -c protocol.version=2 fetch --quiet --depth 1 origin \
    "refs/tags/${COMET_VERSION}:refs/tags/${COMET_VERSION}"
if [[ "$(git -C "${VERIFY_REPO}" rev-parse "refs/tags/${COMET_VERSION}")" != "${COMET_TAG_OBJECT}" ]]; then
    echo "CometBFT tag object differs from the pin" >&2
    exit 1
fi
if [[ "$(git -C "${VERIFY_REPO}" rev-parse "refs/tags/${COMET_VERSION}^{}")" != "${COMET_COMMIT}" ]]; then
    echo "CometBFT tag commit differs from the pin" >&2
    exit 1
fi
git -C "${VERIFY_REPO}" -c gpg.program=gpg verify-tag "${COMET_VERSION}" >/dev/null
git -C "${VERIFY_REPO}" checkout --quiet --detach "${COMET_VERSION}"

SOURCE_DIR="${RUN_ROOT}/source"
mkdir -p "${SOURCE_DIR}"
tar -xzf "${ARCHIVE}" -C "${SOURCE_DIR}" --strip-components=1
if ! diff -qr -x .git "${SOURCE_DIR}" "${VERIFY_REPO}" >/dev/null; then
    echo "checksummed archive differs from the signed Git tag" >&2
    exit 1
fi

export GOCACHE="${RUN_ROOT}/go-cache"
export GOMODCACHE="${RUN_ROOT}/go-mod-cache"
export GOPATH="${RUN_ROOT}/go-path"
export GOWORK=off
COMET_BIN="${RUN_ROOT}/bin/cometbft"
mkdir -p "${RUN_ROOT}/bin"
(
    cd "${SOURCE_DIR}"
    go build -mod=readonly -trimpath -o "${COMET_BIN}" ./cmd/cometbft
)
COMET_REPORTED_VERSION="$("${COMET_BIN}" version)"
if [[ "${COMET_REPORTED_VERSION}" != "0.38.25" && "${COMET_REPORTED_VERSION}" != "v0.38.25" ]]; then
    echo "built CometBFT reports unexpected version: ${COMET_REPORTED_VERSION}" >&2
    exit 1
fi

echo "building feature-gated insecure ABCI test process"
export CARGO_TARGET_DIR="${RUN_ROOT}/cargo-target"
cargo build --quiet --locked --release --manifest-path \
    "${REPO_ROOT}/crates/thunderbolt-ledger-abci/Cargo.toml" \
    --features insecure-live-test --bin thunderbolt-ledger-abci-live-test
APP_BIN="${CARGO_TARGET_DIR}/release/thunderbolt-ledger-abci-live-test"

PORTS=( $(python3 - <<'PY'
import socket

sockets = []
for _ in range(12):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
for sock in sockets:
    sock.close()
PY
) )
if [[ ${#PORTS[@]} -ne 12 ]]; then
    echo "could not allocate isolated loopback ports" >&2
    exit 1
fi

NETWORK_DIR="${RUN_ROOT}/network"
"${COMET_BIN}" testnet --v 4 --n 0 --o "${NETWORK_DIR}" --populate-persistent-peers=false >/dev/null

NODE_IDS=()
for index in 0 1 2 3; do
    NODE_IDS[${index}]="$("${COMET_BIN}" show-node-id --home "${NETWORK_DIR}/node${index}")"
done

for index in 0 1 2 3; do
    P2P_PORT="${PORTS[$((index * 3))]}"
    RPC_PORT="${PORTS[$((index * 3 + 1))]}"
    ABCI_PORT="${PORTS[$((index * 3 + 2))]}"
    PEERS=""
    for peer in 0 1 2 3; do
        if [[ ${peer} -eq ${index} ]]; then
            continue
        fi
        PEER_PORT="${PORTS[$((peer * 3))]}"
        if [[ -n "${PEERS}" ]]; then
            PEERS+=","
        fi
        PEERS+="${NODE_IDS[${peer}]}@127.0.0.1:${PEER_PORT}"
    done
    NODE_HOME="${NETWORK_DIR}/node${index}"
    python3 - "${NODE_HOME}/config/config.toml" "${ABCI_PORT}" "${RPC_PORT}" \
        "${P2P_PORT}" "${PEERS}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
abci_port, rpc_port, p2p_port, peers = sys.argv[2:]
lines = path.read_text().splitlines()
section = ""
seen = set()
for position, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        section = stripped[1:-1]
        continue
    key = stripped.split("=", 1)[0].strip() if "=" in stripped else ""
    replacement = None
    marker = (section, key)
    if section == "" and key == "proxy_app":
        replacement = f'proxy_app = "tcp://127.0.0.1:{abci_port}"'
    elif section == "rpc" and key == "laddr":
        replacement = f'laddr = "tcp://127.0.0.1:{rpc_port}"'
    elif section == "rpc" and key == "pprof_laddr":
        replacement = 'pprof_laddr = ""'
    elif section == "p2p" and key == "laddr":
        replacement = f'laddr = "tcp://127.0.0.1:{p2p_port}"'
    elif section == "p2p" and key == "persistent_peers":
        replacement = f'persistent_peers = "{peers}"'
    elif section == "p2p" and key == "allow_duplicate_ip":
        replacement = "allow_duplicate_ip = true"
    elif section == "p2p" and key == "addr_book_strict":
        replacement = "addr_book_strict = false"
    elif section == "consensus" and key == "timeout_commit":
        replacement = 'timeout_commit = "250ms"'
    elif section == "consensus" and key == "create_empty_blocks":
        replacement = "create_empty_blocks = true"
    elif section == "consensus" and key == "create_empty_blocks_interval":
        replacement = 'create_empty_blocks_interval = "2s"'
    elif section == "instrumentation" and key == "prometheus":
        replacement = "prometheus = false"
    if replacement is not None:
        lines[position] = replacement
        seen.add(marker)

required = {
    ("", "proxy_app"),
    ("rpc", "laddr"),
    ("rpc", "pprof_laddr"),
    ("p2p", "laddr"),
    ("p2p", "persistent_peers"),
    ("p2p", "allow_duplicate_ip"),
    ("p2p", "addr_book_strict"),
    ("consensus", "timeout_commit"),
    ("consensus", "create_empty_blocks"),
    ("consensus", "create_empty_blocks_interval"),
    ("instrumentation", "prometheus"),
}
if seen != required:
    raise SystemExit(f"missing CometBFT config keys: {sorted(required - seen)}")
path.write_text("\n".join(lines) + "\n")
PY
done

GENESIS_PROFILE="$("${APP_BIN}" profile --chain-id "${CHAIN_ID}")"
python3 - "${NETWORK_DIR}" "${CHAIN_ID}" "${GENESIS_PROFILE}" <<'PY'
import json
import pathlib
import sys

network = pathlib.Path(sys.argv[1])
chain_id = sys.argv[2]
profile = json.loads(sys.argv[3])
for path in sorted(network.glob("node*/config/genesis.json")):
    genesis = json.loads(path.read_text())
    genesis["chain_id"] = chain_id
    genesis["app_hash"] = ""
    genesis["app_state"] = profile
    path.write_text(json.dumps(genesis, sort_keys=True, separators=(",", ":")) + "\n")
PY

wait_for_port() {
    local port="$1"
    local deadline=$((SECONDS + 60))
    while (( SECONDS < deadline )); do
        if python3 - "${port}" <<'PY' >/dev/null 2>&1
import socket
import sys

with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2):
    pass
PY
        then
            return
        fi
        sleep 0.1
    done
    echo "port did not become ready: ${port}" >&2
    return 1
}

start_app() {
    local index="$1"
    local fault="${2:-none}"
    local port="${PORTS[$((index * 3 + 2))]}"
    local command=("${APP_BIN}" serve --listen "127.0.0.1:${port}" \
        --db "${RUN_ROOT}/apps/node${index}.sqlite3" --chain-id "${CHAIN_ID}")
    case "${fault}" in
        before)
            command+=(--crash-before-commit-height "${CRASH_HEIGHT}" \
                --crash-before-commit-marker "${RUN_ROOT}/crash-before-commit.marker")
            ;;
        after)
            command+=(--crash-after-commit-height 3 \
                --crash-after-commit-marker "${RUN_ROOT}/crash-after-commit.marker")
            ;;
        info)
            command+=(--crash-on-info-marker "${RUN_ROOT}/crash-on-info.marker")
            ;;
        none) ;;
        *)
            echo "unknown live-test fault mode: ${fault}" >&2
            return 1
            ;;
    esac
    "${command[@]}" >"${RUN_ROOT}/logs/app${index}.log" 2>&1 &
    APP_PIDS[${index}]=$!
    wait_for_port "${port}"
}

start_node() {
    local index="$1"
    "${COMET_BIN}" start --home "${NETWORK_DIR}/node${index}" \
        >"${RUN_ROOT}/logs/node${index}.log" 2>&1 &
    NODE_PIDS[${index}]=$!
    wait_for_port "${PORTS[$((index * 3 + 1))]}"
}

rpc_url() {
    local index="$1"
    printf 'http://127.0.0.1:%s' "${PORTS[$((index * 3 + 1))]}"
}

abci_info_field() {
    local index="$1"
    local field="$2"
    curl --fail --silent --show-error --max-time 3 "$(rpc_url "${index}")/abci_info" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["response"][sys.argv[1]])' "${field}"
}

abci_info_hash() {
    local index="$1"
    curl --fail --silent --show-error --max-time 3 "$(rpc_url "${index}")/abci_info" \
        | python3 -c 'import base64,json,sys; value=json.load(sys.stdin)["result"]["response"]["last_block_app_hash"]; print(base64.b64decode(value).hex())'
}

latest_height() {
    local index="$1"
    curl --fail --silent --show-error --max-time 3 "$(rpc_url "${index}")/status" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["sync_info"]["latest_block_height"])'
}

wait_for_height() {
    local index="$1"
    local minimum="$2"
    local deadline=$((SECONDS + 120))
    while (( SECONDS < deadline )); do
        local height
        height="$(latest_height "${index}" 2>/dev/null || true)"
        if [[ "${height}" =~ ^[0-9]+$ ]] && (( height >= minimum )); then
            return
        fi
        sleep 0.2
    done
    echo "node ${index} did not reach height ${minimum}" >&2
    return 1
}

wait_for_equal_app_state() {
    local minimum="$1"
    local deadline=$((SECONDS + 120))
    while (( SECONDS < deadline )); do
        local heights=()
        local hashes=()
        local index
        local complete=1
        for index in 0 1 2 3; do
            heights[${index}]="$(abci_info_field "${index}" last_block_height 2>/dev/null || true)"
            hashes[${index}]="$(abci_info_hash "${index}" 2>/dev/null || true)"
            if [[ ! "${heights[${index}]}" =~ ^[0-9]+$ ]]; then
                complete=0
            fi
        done
        if [[ ${complete} -eq 1 ]] \
            && (( heights[0] >= minimum )) \
            && [[ "${heights[0]}" == "${heights[1]}" ]] \
            && [[ "${heights[0]}" == "${heights[2]}" ]] \
            && [[ "${heights[0]}" == "${heights[3]}" ]] \
            && [[ "${hashes[0]}" == "${hashes[1]}" ]] \
            && [[ "${hashes[0]}" == "${hashes[2]}" ]] \
            && [[ "${hashes[0]}" == "${hashes[3]}" ]] \
            && [[ -n "${hashes[0]}" ]]; then
            printf '%s %s\n' "${heights[0]}" "${hashes[0]}"
            return
        fi
        sleep 0.1
    done
    echo "four application replicas did not converge above height ${minimum}" >&2
    return 1
}

echo "starting four independent ABCI applications and validators"
start_app 0 before
start_app 1
start_app 2
start_app 3
start_node 0
start_node 1
start_node 2
start_node 3

CRASH_DEADLINE=$((SECONDS + 120))
while [[ ! -f "${RUN_ROOT}/crash-before-commit.marker" ]] && (( SECONDS < CRASH_DEADLINE )); do
    sleep 0.1
done
if [[ ! -f "${RUN_ROOT}/crash-before-commit.marker" ]]; then
    echo "ABCI process did not crash before Commit at height ${CRASH_HEIGHT}" >&2
    exit 1
fi
if wait "${APP_PIDS[0]}"; then
    echo "fault-injected ABCI process exited successfully instead of crashing" >&2
    exit 1
else
    CRASH_STATUS=$?
fi
APP_PIDS[0]=""
if [[ ${CRASH_STATUS} -ne 86 ]]; then
    echo "fault-injected ABCI process exited with ${CRASH_STATUS}, expected 86" >&2
    exit 1
fi

PRECOMMIT_STATUS="$("${APP_BIN}" status --db "${RUN_ROOT}/apps/node0.sqlite3" \
    --chain-id "${CHAIN_ID}")"
PRECOMMIT_HEIGHT="$(printf '%s' "${PRECOMMIT_STATUS}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["last_height"])')"
if [[ "${PRECOMMIT_HEIGHT}" != "$((CRASH_HEIGHT - 1))" ]]; then
    echo "FinalizeBlock crash advanced durable state to ${PRECOMMIT_HEIGHT}" >&2
    exit 1
fi

start_app 0
stop_pid "${NODE_PIDS[0]}"
NODE_PIDS[0]=""
start_node 0
wait_for_height 0 3

for index in 0 1 2 3; do
    APP_VERSION="$(abci_info_field "${index}" app_version)"
    if [[ "${APP_VERSION}" != "2" ]]; then
        echo "node ${index} reported application version ${APP_VERSION}" >&2
        exit 1
    fi
done

INVALID_RESPONSE="$(curl --fail --silent --show-error --max-time 5 \
    --header 'content-type: application/json' --request POST "$(rpc_url 0)" \
    --data '{"jsonrpc":"2.0","id":1,"method":"broadcast_tx_sync","params":{"tx":"bm90LWpzb24="}}')"
INVALID_CODE="$(printf '%s' "${INVALID_RESPONSE}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["code"])')"
if [[ "${INVALID_CODE}" == "0" ]]; then
    echo "invalid transaction was accepted by CheckTx" >&2
    exit 1
fi

read -r EXECUTED_HEIGHT EXECUTED_HASH < <(wait_for_equal_app_state 3)
NEXT_HEIGHT=$((EXECUTED_HEIGHT + 1))
for index in 0 1 2 3; do
    wait_for_height "${index}" "${NEXT_HEIGHT}"
    HEADER_APP_HASH="$(curl --fail --silent --show-error --max-time 5 \
        "$(rpc_url "${index}")/block?height=${NEXT_HEIGHT}" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["block"]["header"]["app_hash"].lower())')"
    if [[ "${HEADER_APP_HASH}" != "${EXECUTED_HASH}" ]]; then
        echo "height ${NEXT_HEIGHT} header does not carry height ${EXECUTED_HEIGHT} app hash" >&2
        exit 1
    fi
done

echo "restarting one validator and one independent ABCI application"
stop_pid "${NODE_PIDS[1]}"
NODE_PIDS[1]=""
start_node 1
wait_for_height 1 "${NEXT_HEIGHT}"

stop_pid "${APP_PIDS[2]}"
APP_PIDS[2]=""
start_app 2
if ! kill -0 "${NODE_PIDS[2]}" 2>/dev/null; then
    wait "${NODE_PIDS[2]}" 2>/dev/null || true
    start_node 2
fi
wait_for_height 2 "${NEXT_HEIGHT}"

read -r FINAL_HEIGHT FINAL_HASH < <(wait_for_equal_app_state "${NEXT_HEIGHT}")

for index in 0 1 2 3; do
    kill "${NODE_PIDS[${index}]}" 2>/dev/null || true
done
for index in 0 1 2 3; do
    stop_pid "${NODE_PIDS[${index}]}"
    NODE_PIDS[${index}]=""
done
for index in 0 1 2 3; do
    stop_pid "${APP_PIDS[${index}]}"
    APP_PIDS[${index}]=""
done

for index in 0 1 2 3; do
    DURABLE_STATUS="$("${APP_BIN}" status --db "${RUN_ROOT}/apps/node${index}.sqlite3" \
        --chain-id "${CHAIN_ID}")"
    DURABLE_HEIGHT="$(printf '%s' "${DURABLE_STATUS}" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["last_height"])')"
    DURABLE_HASH="$(printf '%s' "${DURABLE_STATUS}" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["last_app_hash"].lower())')"
    if [[ "${DURABLE_HEIGHT}" != "${FINAL_HEIGHT}" || "${DURABLE_HASH}" != "${FINAL_HASH}" ]]; then
        echo "replica ${index} durable state differs after restart gate" >&2
        exit 1
    fi
done

echo "live CometBFT gate passed: version=${COMET_REPORTED_VERSION} replicas=4 height=${FINAL_HEIGHT} app_version=2"
echo "verified: signed tag, archive checksum, H-to-H+1 app hash, invalid tx rejection, crash replay, restarts, deterministic replicas"
