#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 OUTPUT_DIRECTORY" >&2
    echo "OUTPUT_DIRECTORY must not already exist." >&2
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="$1"

if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
    echo "cargo-cyclonedx is required; install the version pinned in release/toolchain-pins.toml" >&2
    exit 1
fi
if [[ -e "${output_dir}" ]]; then
    echo "refusing to replace existing SBOM output: ${output_dir}" >&2
    exit 1
fi
if ! cargo metadata --locked --format-version 1 --no-deps --manifest-path "${repo_root}/Cargo.toml" >/dev/null; then
    echo "SBOM generation requires a current locked dependency graph" >&2
    exit 1
fi
if ! git -C "${repo_root}" diff --quiet || ! git -C "${repo_root}" diff --cached --quiet; then
    echo "SBOM generation requires tracked files to match HEAD" >&2
    exit 1
fi
python3 "${repo_root}/scripts/check-default-binary-graph.py"

mkdir -p "$(dirname "${output_dir}")"
mkdir "${output_dir}"
output_dir="$(cd "${output_dir}" && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bitcoin-thunderbolt-sbom.XXXXXX")"
cleanup() {
    rm -rf "${work_dir}"
}
trap cleanup EXIT INT TERM

mkdir "${work_dir}/workspace"
git -C "${repo_root}" archive HEAD | tar -x -C "${work_dir}/workspace"

source_date_epoch="$(git -C "${repo_root}" log -1 --format=%ct 2>/dev/null || date +%s)"
export SOURCE_DATE_EPOCH="${source_date_epoch}"
export CARGO_TARGET_DIR="${work_dir}/target"
host="$(rustc -vV | sed -n 's/^host: //p')"
if [[ -z "${host}" ]]; then
    echo "could not determine the Rust host triple" >&2
    exit 1
fi
binary_manifest="${repo_root}/release/default-binaries.txt"
if ! awk '
    /^[[:space:]]*#/ || NF == 0 { next }
    NF != 2 { exit 1 }
    $1 !~ /^[a-z0-9][a-z0-9-]*$/ || $2 !~ /^[a-z0-9][a-z0-9-]*$/ { exit 1 }
    $1 ~ /(legacy|live-test)/ || $2 ~ /(legacy|live-test)/ { exit 1 }
    seen_package[$1]++ || seen_binary[$2]++ { exit 1 }
    $1 == "thunderboltd" && $2 == "thunderboltd" { daemon = 1 }
    $1 == "thunderbolt-cli" && $2 == "thunderbolt-cli" { cli = 1 }
    $1 == "thunderbolt-floor-node" && $2 == "thunderbolt-floor-node" { floor = 1 }
    END { if (!daemon || !cli || !floor) exit 1 }
' "${binary_manifest}"; then
    echo "release/default-binaries.txt is invalid" >&2
    exit 1
fi

while read -r package binary extra; do
    if [[ -z "${package}" || "${package}" == \#* ]]; then
        continue
    fi
    crate_manifest="${work_dir}/workspace/crates/${package}/Cargo.toml"
    cargo cyclonedx \
        --manifest-path "${crate_manifest}" \
        --format json \
        --describe binaries \
        --no-default-features \
        --target "${host}" \
        --spec-version 1.5 \
        --license-strict \
        --license-accept-named "MIT/Apache-2.0"

    generated="${work_dir}/workspace/crates/${package}/${binary}_bin.cdx.json"
    if [[ ! -f "${generated}" ]]; then
        echo "cargo-cyclonedx did not produce the expected file for ${package}" >&2
        exit 1
    fi
    if ! cmp -s "${repo_root}/Cargo.lock" "${work_dir}/workspace/Cargo.lock"; then
        echo "cargo-cyclonedx attempted to change the locked dependency graph" >&2
        exit 1
    fi
    python3 - "${generated}" "${binary}" <<'PY'
import json
import sys

path, expected = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    document = json.load(handle)
root = document.get("metadata", {}).get("component", {})
if root.get("name") != expected:
    raise SystemExit(f"SBOM root changed: expected {expected}, found {root.get('name')}")

forbidden = {"thunderbolt-config", "thunderbolt-node", "thunderbolt-storage"}
pending = list(document.get("components", []))
names = set()
while pending:
    component = pending.pop()
    name = component.get("name")
    if isinstance(name, str):
        names.add(name)
    pending.extend(component.get("components", []))
bad = sorted(names & forbidden)
if bad:
    raise SystemExit(f"default binary SBOM contains legacy application crates: {bad}")
PY
    cp "${generated}" "${output_dir}/${binary}.cdx.json"
done < "${binary_manifest}"

expected_count="$(awk '/^[[:space:]]*#/ || NF == 0 { next } { count++ } END { print count + 0 }' "${binary_manifest}")"
actual_count="$(find "${output_dir}" -maxdepth 1 -type f -name '*.cdx.json' | wc -l | tr -d '[:space:]')"
if [[ "${actual_count}" != "${expected_count}" ]]; then
    echo "SBOM output count does not match release/default-binaries.txt" >&2
    exit 1
fi

printf 'wrote SBOMs to %s\n' "${output_dir}"
