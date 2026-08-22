#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 vMAJOR.MINOR.PATCH[-PRERELEASE] OUTPUT_DIRECTORY" >&2
    echo "OUTPUT_DIRECTORY must not already exist and the Git worktree must be clean." >&2
}

if [[ $# -ne 2 ]]; then
    usage
    exit 2
fi

version="$1"
output_dir="$2"
if [[ ! "${version}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "invalid release version: ${version}" >&2
    exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

if [[ -n "$(git status --porcelain=v1 --untracked-files=normal)" ]]; then
    echo "release packaging requires a clean Git worktree" >&2
    exit 1
fi
if [[ -e "${output_dir}" ]]; then
    echo "refusing to replace existing release output: ${output_dir}" >&2
    exit 1
fi

software_version="${version#v}"
daemon_version="$(cargo pkgid --package thunderboltd | sed 's/.*#//')"
cli_version="$(cargo pkgid --package thunderbolt-cli | sed 's/.*#//')"
if [[ "${daemon_version}" != "${software_version}" || "${cli_version}" != "${software_version}" ]]; then
    echo "tag ${version} does not match daemon (${daemon_version}) and CLI (${cli_version}) versions" >&2
    exit 1
fi

commit="$(git rev-parse --verify HEAD)"
host="$(rustc -vV | sed -n 's/^host: //p')"
if [[ -z "${host}" ]]; then
    echo "could not determine the Rust host triple" >&2
    exit 1
fi

cargo build --locked --release --package thunderboltd --package thunderbolt-cli

mkdir "${output_dir}"
output_dir="$(cd "${output_dir}" && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bitcoin-thunderbolt-release.XXXXXX")"
cleanup() {
    rm -rf "${work_dir}"
}
trap cleanup EXIT INT TERM

binary_name="bitcoin-thunderbolt-${software_version}-${host}"
stage="${work_dir}/${binary_name}"
install -d -m 0755 "${stage}/bin" "${stage}/config" "${stage}/systemd" "${stage}/docs"
install -m 0755 target/release/thunderboltd target/release/thunderbolt-cli "${stage}/bin/"
install -m 0644 LICENSE NOTICE CHANGELOG.md README.md "${stage}/"
install -m 0644 deploy/regtest/thunderbolt.toml "${stage}/config/regtest.toml"
install -m 0644 deploy/systemd/thunderbolt.toml "${stage}/config/signet.toml"
install -m 0644 deploy/systemd/thunderboltd.service deploy/systemd/thunderbolt.sysusers "${stage}/systemd/"
cp -R docs/. "${stage}/docs/"

printf '%s\n' \
    "name=bitcoin-thunderbolt" \
    "version=${software_version}" \
    "commit=${commit}" \
    "rust_host=${host}" \
    "rustc=$(rustc --version)" \
    "cargo=$(cargo --version)" \
    > "${stage}/BUILD-METADATA"

binary_archive="${output_dir}/${binary_name}.tar.gz"
source_archive="${output_dir}/bitcoin-thunderbolt-${software_version}-source.tar.gz"
source_zip="${output_dir}/bitcoin-thunderbolt-${software_version}-source.zip"

COPYFILE_DISABLE=1 tar -C "${work_dir}" -cf - "${binary_name}" | gzip -n -9 > "${binary_archive}"
git archive --format=tar --prefix="bitcoin-thunderbolt-${software_version}-source/" HEAD | gzip -n -9 > "${source_archive}"
git archive --format=zip --prefix="bitcoin-thunderbolt-${software_version}-source/" --output "${source_zip}" HEAD

"${repo_root}/scripts/generate-sbom.sh" "${work_dir}/sbom"
cp "${work_dir}/sbom/"*.cdx.json "${output_dir}/"
install -m 0644 release/signing-policy.txt "${output_dir}/SIGNING-INSTRUCTIONS.txt"

(
    cd "${output_dir}"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum ./*.tar.gz ./*.zip ./*.cdx.json SIGNING-INSTRUCTIONS.txt | sed 's#  \./#  #'
    else
        shasum -a 256 ./*.tar.gz ./*.zip ./*.cdx.json SIGNING-INSTRUCTIONS.txt | sed 's#  \./#  #'
    fi
) > "${output_dir}/SHA256SUMS"

printf 'release artifacts written to %s\n' "${output_dir}"
printf 'sign SHA256SUMS only after independent review: scripts/sign-release.sh %s KEY_FINGERPRINT\n' "${output_dir}"
