#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 RELEASE_DIRECTORY GPG_SECRET_KEY_FINGERPRINT" >&2
    echo "The script creates SHA256SUMS.asc and never replaces an existing signature." >&2
}

if [[ $# -ne 2 ]]; then
    usage
    exit 2
fi

release_dir="$1"
fingerprint="$2"
checksums="${release_dir}/SHA256SUMS"
signature="${release_dir}/SHA256SUMS.asc"

if [[ ! -f "${checksums}" || -L "${checksums}" ]]; then
    echo "missing regular checksum manifest: ${checksums}" >&2
    exit 1
fi
if [[ -e "${signature}" ]]; then
    echo "refusing to replace existing signature: ${signature}" >&2
    exit 1
fi
if ! command -v gpg >/dev/null 2>&1; then
    echo "gpg is required" >&2
    exit 1
fi

resolved_fingerprint="$(gpg --batch --with-colons --list-secret-keys "${fingerprint}" | awk -F: '$1 == "fpr" { print $10; exit }')"
if [[ -z "${resolved_fingerprint}" || "${resolved_fingerprint}" != "${fingerprint}" ]]; then
    echo "use the full fingerprint of an available GPG secret key" >&2
    exit 1
fi

set -o noclobber
gpg --batch --armor --detach-sign --local-user "${fingerprint}" --output - "${checksums}" > "${signature}"
set +o noclobber

printf 'created %s with key %s\n' "${signature}" "${fingerprint}"
