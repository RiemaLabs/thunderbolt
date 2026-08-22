#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 [--checksums-only] RELEASE_DIRECTORY [EXPECTED_GPG_FINGERPRINT]" >&2
    echo "Without --checksums-only, a detached signature and exact signer fingerprint are required." >&2
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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

binary_archive_count="$(find "${release_dir}" -maxdepth 1 -type f -name '*.tar.gz' ! -name '*-source.tar.gz' | wc -l | tr -d '[:space:]')"
if [[ "${binary_archive_count}" != 1 ]]; then
    echo "expected exactly one binary archive, found ${binary_archive_count}" >&2
    exit 1
fi
binary_archive="$(find "${release_dir}" -maxdepth 1 -type f -name '*.tar.gz' ! -name '*-source.tar.gz' -print)"
archive_root="$(tar -tzf "${binary_archive}" | awk -F/ 'NF > 0 { print $1; exit }')"
if [[ -z "${archive_root}" ]]; then
    echo "binary archive is empty" >&2
    exit 1
fi
archive_entries="$(tar -tzf "${binary_archive}")"
if ! printf '%s\n' "${archive_entries}" | awk -F/ -v root="${archive_root}" '$1 != root { exit 1 }'; then
    echo "binary archive contains more than one top-level directory" >&2
    exit 1
fi
for required in \
    "${archive_root}/systemd/thunderboltd.service" \
    "${archive_root}/systemd/thunderbolt-floor-node.service" \
    "${archive_root}/systemd/thunderbolt.sysusers" \
    "${archive_root}/systemd/README.md" \
    "${archive_root}/BINARY-MANIFEST" \
    "${archive_root}/BUILD-METADATA"; do
    if ! printf '%s\n' "${archive_entries}" | grep -Fqx "${required}"; then
        echo "binary archive is missing required entry: ${required}" >&2
        exit 1
    fi
done
while read -r package binary extra; do
    if [[ -z "${package}" || "${package}" == \#* ]]; then
        continue
    fi
    required="${archive_root}/bin/${binary}"
    if ! printf '%s\n' "${archive_entries}" | grep -Fqx "${required}"; then
        echo "binary archive is missing release-manifest entry: ${required}" >&2
        exit 1
    fi
done < "${binary_manifest}"
if ! cmp -s "${binary_manifest}" <(tar -xOzf "${binary_archive}" "${archive_root}/BINARY-MANIFEST"); then
    echo "binary archive manifest does not match release/default-binaries.txt" >&2
    exit 1
fi
binary_entry_count="$(printf '%s\n' "${archive_entries}" | awk -v prefix="${archive_root}/bin/" 'index($0, prefix) == 1 && $0 != prefix { count++ } END { print count + 0 }')"
expected_binary_count="$(awk '/^[[:space:]]*#/ || NF == 0 { next } { count++ } END { print count + 0 }' "${binary_manifest}")"
if [[ "${binary_entry_count}" != "${expected_binary_count}" ]]; then
    echo "binary archive executable count does not match release/default-binaries.txt" >&2
    exit 1
fi
while IFS= read -r entry; do
    case "${entry}" in
        "${archive_root}/config"|"${archive_root}/config/"*|"${archive_root}/bin/"*legacy*|"${archive_root}/bin/"*live-test*)
            echo "binary archive contains configuration material or a compatibility binary" >&2
            exit 1
            ;;
    esac
done <<< "${archive_entries}"

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
