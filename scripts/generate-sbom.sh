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

mkdir -p "$(dirname "${output_dir}")"
mkdir "${output_dir}"
output_dir="$(cd "${output_dir}" && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bitcoin-thunderbolt-sbom.XXXXXX")"
cleanup() {
    rm -rf "${work_dir}"
}
trap cleanup EXIT INT TERM

mkdir "${work_dir}/workspace"
cp "${repo_root}/Cargo.toml" "${repo_root}/Cargo.lock" "${repo_root}/rust-toolchain" "${work_dir}/workspace/"
cp -R "${repo_root}/crates" "${work_dir}/workspace/crates"

source_date_epoch="$(git -C "${repo_root}" log -1 --format=%ct 2>/dev/null || date +%s)"
export SOURCE_DATE_EPOCH="${source_date_epoch}"
export CARGO_TARGET_DIR="${work_dir}/target"

for package in thunderboltd thunderbolt-cli; do
    manifest="${work_dir}/workspace/crates/${package}/Cargo.toml"
    cargo cyclonedx \
        --manifest-path "${manifest}" \
        --format json \
        --all-features \
        --target all \
        --spec-version 1.5 \
        --license-strict \
        --license-accept-named "MIT/Apache-2.0" \
        --override-filename "${package}.cdx"

    generated="${work_dir}/workspace/crates/${package}/${package}.cdx.json"
    if [[ ! -f "${generated}" ]]; then
        echo "cargo-cyclonedx did not produce the expected file for ${package}" >&2
        exit 1
    fi
    if ! cmp -s "${repo_root}/Cargo.lock" "${work_dir}/workspace/Cargo.lock"; then
        echo "cargo-cyclonedx attempted to change the locked dependency graph" >&2
        exit 1
    fi
    cp "${generated}" "${output_dir}/${package}.cdx.json"
done

printf 'wrote SBOMs to %s\n' "${output_dir}"
