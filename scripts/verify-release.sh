#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 [--checksums-only] RELEASE_DIRECTORY [EXPECTED_GPG_FINGERPRINT]" >&2
    echo "Without --checksums-only, a detached signature and exact signer fingerprint are required." >&2
}

checksums_only=false
if [[ "${1:-}" == "--checksums-only" ]]; then
    checksums_only=true
    shift
fi
if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage
    exit 2
fi

release_dir="$1"
expected_fingerprint="${2:-}"
if [[ ! -d "${release_dir}" || -L "${release_dir}" ]]; then
    echo "release directory is missing or unsafe: ${release_dir}" >&2
    exit 1
fi
release_dir="$(cd "${release_dir}" && pwd)"
checksums="${release_dir}/SHA256SUMS"
if [[ ! -f "${checksums}" || -L "${checksums}" ]]; then
    echo "missing regular checksum manifest: ${checksums}" >&2
    exit 1
fi

if ! awk '
    NF != 2 { exit 1 }
    length($1) != 64 { exit 1 }
    {
        digest = $1
        gsub(/[0-9A-Fa-f]/, "", digest)
        if (digest != "" || $2 == "" || $2 ~ /\// || $2 == "SHA256SUMS" || $2 == "SHA256SUMS.asc") {
            exit 1
        }
    }
' "${checksums}"; then
    echo "checksum manifest has an invalid digest or non-local filename" >&2
    exit 1
fi

while read -r _digest name; do
    if [[ ! -f "${release_dir}/${name}" || -L "${release_dir}/${name}" ]]; then
        echo "checksum manifest names a missing or unsafe file: ${name}" >&2
        exit 1
    fi
done < "${checksums}"

while IFS= read -r candidate; do
    echo "release directory contains a non-regular entry: ${candidate}" >&2
    exit 1
done < <(find "${release_dir}" -mindepth 1 -maxdepth 1 ! -type f -print)

while IFS= read -r candidate; do
    name="$(basename "${candidate}")"
    if [[ "${name}" == "SHA256SUMS" || "${name}" == "SHA256SUMS.asc" ]]; then
        continue
    fi
    if ! awk -v expected="${name}" '$2 == expected { found = 1 } END { exit !found }' "${checksums}"; then
        echo "release file is not covered by SHA256SUMS: ${name}" >&2
        exit 1
    fi
done < <(find "${release_dir}" -maxdepth 1 -type f -print)

(
    cd "${release_dir}"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum --check --strict SHA256SUMS
    else
        shasum -a 256 --check SHA256SUMS
    fi
)

while IFS= read -r archive; do
    while IFS= read -r entry; do
        case "${entry}" in
            /*|../*|*/../*|*/..)
                echo "unsafe archive path in ${archive}: ${entry}" >&2
                exit 1
                ;;
        esac
    done < <(tar -tzf "${archive}")
done < <(find "${release_dir}" -maxdepth 1 -type f -name '*.tar.gz' -print)

if ! command -v unzip >/dev/null 2>&1; then
    echo "unzip is required to inspect release zip paths" >&2
    exit 1
fi
while IFS= read -r archive; do
    while IFS= read -r entry; do
        case "${entry}" in
            /*|../*|*/../*|*/..)
                echo "unsafe archive path in ${archive}: ${entry}" >&2
                exit 1
                ;;
        esac
    done < <(unzip -Z1 "${archive}")
done < <(find "${release_dir}" -maxdepth 1 -type f -name '*.zip' -print)

if [[ "${checksums_only}" == true ]]; then
    echo "checksums and archive paths verified; signature verification was explicitly skipped"
    exit 0
fi

signature="${release_dir}/SHA256SUMS.asc"
if [[ -z "${expected_fingerprint}" || ! "${expected_fingerprint}" =~ ^[0-9A-Fa-f]{40,64}$ ]]; then
    echo "an exact GPG signer fingerprint is required" >&2
    exit 2
fi
if [[ ! -f "${signature}" || -L "${signature}" ]]; then
    echo "missing regular detached signature: ${signature}" >&2
    exit 1
fi
if ! command -v gpg >/dev/null 2>&1; then
    echo "gpg is required" >&2
    exit 1
fi

status="$(gpg --batch --status-fd=1 --verify "${signature}" "${checksums}" 2>/dev/null)"
actual_fingerprint="$(printf '%s\n' "${status}" | awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $3; exit }')"
actual_upper="$(printf '%s' "${actual_fingerprint}" | tr '[:lower:]' '[:upper:]')"
expected_upper="$(printf '%s' "${expected_fingerprint}" | tr '[:lower:]' '[:upper:]')"
if [[ "${actual_upper}" != "${expected_upper}" ]]; then
    echo "signature is valid but signer fingerprint does not match" >&2
    exit 1
fi

printf 'release checksums and signature verified for signer %s\n' "${actual_fingerprint}"
