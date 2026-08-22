#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest_writer="$script_dir/ct-input-manifest.sh"
if [[ ! -x "$manifest_writer" ]]; then
    echo "input-manifest writer is missing or not executable" >&2
    exit 2
fi

fixture="$(mktemp -d "${TMPDIR:-/tmp}/thunderbolt-ct-input-seal.XXXXXX")"
cleanup() {
    rm -rf "$fixture"
}
trap cleanup EXIT

source_root="$fixture/sealed-source"
toolchain_root="$fixture/toolchain"
mkdir -p "$source_root/.cargo" "$source_root/vendor/dependency/src" \
    "$source_root/scripts" "$source_root/input-boundary" \
    "$toolchain_root/bin" "$toolchain_root/lib"
printf '[package]\nname = "fixture"\nversion = "1.0.0"\n' > "$source_root/Cargo.toml"
printf 'version = 4\n' > "$source_root/Cargo.lock"
printf '[net]\noffline = true\n' > "$source_root/.cargo/config.toml"
printf 'fn main() {}\n' > "$source_root/vendor/dependency/build.rs"
printf 'pub fn dependency() {}\n' > "$source_root/vendor/dependency/src/lib.rs"
printf '{"files":{}}\n' > "$source_root/vendor/dependency/.cargo-checksum.json"
printf '{ print }\n' > "$source_root/scripts/ct-scan.awk"
printf 'target=x86_64-unknown-linux-gnu\n' > "$source_root/input-boundary/target-cfg.txt"
printf 'CARGO_HOME=/isolated/cargo-home\n' > "$source_root/input-boundary/build-env.txt"
printf 'mock rustc\n' > "$toolchain_root/bin/rustc"
printf 'mock cargo\n' > "$toolchain_root/bin/cargo"
printf 'mock std\n' > "$toolchain_root/lib/libstd.rlib"
printf 'mock cc\n' > "$fixture/cc-real"
ln -s cc-real "$fixture/cc"

write_manifest() {
    destination="$1"
    "$manifest_writer" "$destination" \
        "source=$source_root" \
        "toolchain-bin=$toolchain_root/bin" \
        "toolchain-lib=$toolchain_root/lib" \
        "system-cc=$fixture/cc"
}

baseline="$fixture/baseline.sha256"
write_manifest "$baseline"

assert_mutation_detected() {
    relative="$1"
    path="$fixture/$relative"
    backup="$fixture/backup"
    cp "$path" "$backup"
    printf '\nmutation\n' >> "$path"
    candidate="$fixture/candidate.sha256"
    write_manifest "$candidate"
    if cmp -s "$baseline" "$candidate"; then
        echo "input mutation was not detected: $relative" >&2
        exit 1
    fi
    mv "$backup" "$path"
    rm "$candidate"
}

assert_mutation_detected "sealed-source/Cargo.toml"
assert_mutation_detected "sealed-source/Cargo.lock"
assert_mutation_detected "sealed-source/.cargo/config.toml"
assert_mutation_detected "sealed-source/vendor/dependency/build.rs"
assert_mutation_detected "sealed-source/vendor/dependency/src/lib.rs"
assert_mutation_detected "sealed-source/scripts/ct-scan.awk"
assert_mutation_detected "sealed-source/input-boundary/target-cfg.txt"
assert_mutation_detected "sealed-source/input-boundary/build-env.txt"
assert_mutation_detected "toolchain/bin/rustc"
assert_mutation_detected "toolchain/lib/libstd.rlib"
assert_mutation_detected "cc-real"

added="$source_root/vendor/path-patch/src/new.rs"
mkdir -p "$(dirname "$added")"
printf 'pub fn added() {}\n' > "$added"
candidate="$fixture/added-file.sha256"
write_manifest "$candidate"
if cmp -s "$baseline" "$candidate"; then
    echo "added path-patch input was not detected" >&2
    exit 1
fi

echo "CT_INPUT_MANIFEST_SELF_TEST_PASS"
