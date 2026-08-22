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
python3 scripts/check-default-binary-graph.py

software_version="${version#v}"
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
    package_version="$(cargo pkgid --package "${package}" | sed 's/.*#//')"
    if [[ "${package_version}" != "${software_version}" ]]; then
        echo "tag ${version} does not match ${package} (${package_version})" >&2
        exit 1
    fi
done < "${binary_manifest}"

commit="$(git rev-parse --verify HEAD)"
host="$(rustc -vV | sed -n 's/^host: //p')"
if [[ -z "${host}" ]]; then
    echo "could not determine the Rust host triple" >&2
    exit 1
fi

while read -r package binary extra; do
    if [[ -z "${package}" || "${package}" == \#* ]]; then
        continue
    fi
    cargo build --locked --release --no-default-features --package "${package}" --bin "${binary}"
    "target/release/${binary}" --help >/dev/null
done < "${binary_manifest}"

mkdir "${output_dir}"
output_dir="$(cd "${output_dir}" && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bitcoin-thunderbolt-release.XXXXXX")"
cleanup() {
    rm -rf "${work_dir}"
}
trap cleanup EXIT INT TERM

binary_name="bitcoin-thunderbolt-${software_version}-${host}"
stage="${work_dir}/${binary_name}"
install -d -m 0755 "${stage}/bin" "${stage}/systemd" "${stage}/docs"
while read -r package binary extra; do
    if [[ -z "${package}" || "${package}" == \#* ]]; then
        continue
    fi
    install -m 0755 "target/release/${binary}" "${stage}/bin/${binary}"
done < "${binary_manifest}"
install -m 0644 LICENSE NOTICE CHANGELOG.md README.md "${stage}/"
install -m 0644 "${binary_manifest}" "${stage}/BINARY-MANIFEST"
install -m 0644 \
    deploy/systemd/thunderboltd.service \
    deploy/systemd/thunderbolt-floor-node.service \
    deploy/systemd/thunderbolt.sysusers \
    deploy/systemd/README.md \
    "${stage}/systemd/"
cp -R docs/. "${stage}/docs/"
install -m 0644 deploy/regtest/README.md "${stage}/docs/container.md"
expected_binary_count="$(awk '/^[[:space:]]*#/ || NF == 0 { next } { count++ } END { print count + 0 }' "${binary_manifest}")"
actual_binary_count="$(find "${stage}/bin" -maxdepth 1 -type f | wc -l | tr -d '[:space:]')"
if [[ "${actual_binary_count}" != "${expected_binary_count}" ]]; then
    echo "staged binary count does not match release/default-binaries.txt" >&2
    exit 1
fi

printf '%s\n' \
    "name=bitcoin-thunderbolt" \
    "version=${software_version}" \
    "commit=${commit}" \
    "operator_runtime_capability=live-not-ready" \
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
