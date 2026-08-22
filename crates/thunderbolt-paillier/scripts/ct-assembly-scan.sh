#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 TARGET O0|O3 OUTPUT_DIRECTORY" >&2
    echo "TARGET must be x86_64/aarch64 for Linux or macOS." >&2
}

if [[ $# -ne 3 ]]; then
    usage
    exit 2
fi

target="$1"
optimization="$2"
output_dir="$3"
case "$target" in
    x86_64-unknown-linux-gnu|x86_64-apple-darwin)
        architecture="x86_64"
        ;;
    aarch64-unknown-linux-gnu|aarch64-apple-darwin)
        architecture="aarch64"
        ;;
    *)
        usage
        exit 2
        ;;
esac
case "$optimization" in
    O0|O3) ;;
    *)
        usage
        exit 2
        ;;
esac

if [[ -e "$output_dir" ]]; then
    echo "refusing to replace existing evidence directory: $output_dir" >&2
    exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate_dir="$(cd "$script_dir/.." && pwd)"
repository_root="$(git -C "$crate_dir" rev-parse --show-toplevel 2>/dev/null || true)"
output_parent="$(cd "$(dirname "$output_dir")" && pwd -P)"
output_dir="$output_parent/$(basename "$output_dir")"
case "$output_dir" in
    "$crate_dir"|"$crate_dir"/*)
        echo "evidence output must be outside the source crate" >&2
        exit 2
        ;;
esac
if [[ -n "$repository_root" ]]; then
    repository_root="$(cd "$repository_root" && pwd -P)"
    case "$output_dir" in
        "$repository_root"|"$repository_root"/*)
            echo "evidence output must be outside the live repository" >&2
            exit 2
            ;;
    esac
    for cargo_config in "$repository_root/.cargo/config" "$repository_root/.cargo/config.toml"; do
        if [[ -e "$cargo_config" ]]; then
            echo "refusing live-workspace Cargo config during package generation: $cargo_config" >&2
            exit 2
        fi
    done
fi

manifest="$crate_dir/Cargo.toml"
if [[ ! -f "$manifest" ]]; then
    echo "crate manifest is missing" >&2
    exit 2
fi

build_jobs="${THUNDERBOLT_CT_BUILD_JOBS:-4}"
if [[ ! "$build_jobs" =~ ^[1-4]$ ]]; then
    echo "THUNDERBOLT_CT_BUILD_JOBS must be an integer in 1..=4" >&2
    exit 2
fi

while IFS='=' read -r ambient_name _; do
    case "$ambient_name" in
        CARGO_*|RUSTFLAGS|RUSTDOCFLAGS|RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|RUSTUP_TOOLCHAIN|\
        AR|AR_*|CC|CC_*|CFLAGS|CFLAGS_*|CXX|CXX_*|CXXFLAGS|CXXFLAGS_*|LD|LD_*|LDFLAGS|\
        MACOSX_DEPLOYMENT_TARGET|SDKROOT|PKG_CONFIG|PKG_CONFIG_*)
            echo "refusing ambient build override: $ambient_name" >&2
            exit 2
            ;;
    esac
done < <(env)

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

canonical_file() {
    candidate="$1"
    parent="$(cd "$(dirname "$candidate")" && pwd -P)"
    printf '%s/%s\n' "$parent" "$(basename "$candidate")"
}

resolve_program() {
    candidate="$1"
    if [[ "$candidate" == */* ]]; then
        canonical_file "$candidate"
    else
        canonical_file "$(command -v "$candidate")"
    fi
}

bootstrap_rustc="$(command -v rustc)"
toolchain_sysroot="$($bootstrap_rustc --print sysroot)"
toolchain_sysroot="$(cd "$toolchain_sysroot" && pwd -P)"
rustc_driver="$toolchain_sysroot/bin/rustc"
cargo_driver="$toolchain_sysroot/bin/cargo"
if [[ ! -x "$rustc_driver" || ! -x "$cargo_driver" ]]; then
    echo "resolved toolchain does not contain executable rustc and cargo" >&2
    exit 2
fi
rustc_commit="$($rustc_driver -Vv | awk '/^commit-hash:/ {print $2}')"
host_triple="$($rustc_driver -Vv | awk '/^host:/ {print $2}')"
if [[ -z "$rustc_commit" || -z "$host_triple" ]]; then
    echo "rustc did not report a commit hash and host triple" >&2
    exit 2
fi
target_libdir="$($rustc_driver --print target-libdir --target "$target")"
if [[ ! -d "$target_libdir" ]]; then
    echo "target standard library is not installed: $target" >&2
    exit 2
fi

system_manifest_args=()
platform_build_env=()
if [[ "$(uname -s)" == "Darwin" ]]; then
    xcrun_driver="$(canonical_file "$(command -v xcrun)")"
    system_cc="$(canonical_file "$("$xcrun_driver" --find clang)")"
    system_ld="$(canonical_file "$("$xcrun_driver" --find ld)")"
    system_ar="$(canonical_file "$("$xcrun_driver" --find ar)")"
    sdk_root="$("$xcrun_driver" --show-sdk-path)"
    sdk_root="$(cd "$sdk_root" && pwd -P)"
    platform_build_env+=("SDKROOT=$sdk_root")
    system_manifest_args+=("system-xcrun=$xcrun_driver")
    if [[ -d "$sdk_root/usr/lib" ]]; then
        system_manifest_args+=("system-sdk-usr-lib=$sdk_root/usr/lib")
    fi
    if [[ -d "$sdk_root/System/Library/Frameworks" ]]; then
        system_manifest_args+=("system-sdk-frameworks=$sdk_root/System/Library/Frameworks")
    fi
else
    system_cc="$(resolve_program "$(command -v cc)")"
    system_ld="$(resolve_program "$(cc -print-prog-name=ld)")"
    system_ar="$(resolve_program "$(command -v ar)")"
    for compiler_component in cc1 collect2 as; do
        component="$(cc -print-prog-name="$compiler_component" 2>/dev/null || true)"
        if [[ -n "$component" ]]; then
            resolved_component="$(resolve_program "$component" 2>/dev/null || true)"
            if [[ -n "$resolved_component" && -f "$resolved_component" ]]; then
                system_manifest_args+=("system-$compiler_component=$resolved_component")
            fi
        fi
    done
fi
for system_tool in "$system_cc" "$system_ld" "$system_ar"; do
    if [[ ! -x "$system_tool" ]]; then
        echo "required system build tool is missing: $system_tool" >&2
        exit 2
    fi
done

default_registry="$HOME/.cargo/registry"
if [[ ! -d "$default_registry" ]]; then
    echo "the local Cargo registry cache is required for an offline package and vendor step" >&2
    exit 2
fi

mkdir -p "$output_dir"
package_target="$output_dir/package-target"
preparation_home="$output_dir/preparation-cargo-home"
preparation_tmp="$output_dir/preparation-tmp"
mkdir -p "$package_target" "$preparation_home" "$preparation_tmp" "$output_dir/preparation-home"
ln -s "$default_registry" "$preparation_home/registry"

preparation_path="$toolchain_sysroot/bin:/usr/bin:/bin"
package_log="$output_dir/package.log"
env -i \
    HOME="$output_dir/preparation-home" \
    CARGO_HOME="$preparation_home" \
    TMPDIR="$preparation_tmp" \
    PATH="$preparation_path" \
    LANG=C LC_ALL=C CARGO_TERM_COLOR=never \
    "$cargo_driver" package \
    --manifest-path "$manifest" \
    --package thunderbolt-paillier \
    --allow-dirty \
    --no-verify \
    --frozen \
    --target-dir "$package_target" \
    --jobs "$build_jobs" 2>&1 | tee "$package_log"

archive_count="$(find "$package_target/package" -maxdepth 1 -type f -name 'thunderbolt-paillier-*.crate' -print | wc -l | tr -d ' ')"
if [[ "$archive_count" != "1" ]]; then
    echo "expected exactly one packaged thunderbolt-paillier archive, found $archive_count" >&2
    exit 1
fi
generated_archive="$(find "$package_target/package" -maxdepth 1 -type f -name 'thunderbolt-paillier-*.crate' -print -quit)"
archive="$output_dir/thunderbolt-paillier.crate"
cp "$generated_archive" "$archive"
archive_hash="$(hash_file "$archive")"

if tar -tzf "$archive" | awk '$0 ~ /^\// || $0 ~ /(^|\/)\.\.(\/|$)/ { bad = 1 } END { exit !bad }'; then
    echo "packaged archive contains an unsafe path" >&2
    exit 1
fi

sealed_parent="$output_dir/sealed-package"
mkdir -p "$sealed_parent"
tar -xzf "$archive" -C "$sealed_parent"
package_root_count="$(find "$sealed_parent" -mindepth 1 -maxdepth 1 -type d -print | wc -l | tr -d ' ')"
if [[ "$package_root_count" != "1" ]]; then
    echo "expected exactly one packaged source root, found $package_root_count" >&2
    exit 1
fi
package_root="$(find "$sealed_parent" -mindepth 1 -maxdepth 1 -type d -print -quit)"
package_root="$(cd "$package_root" && pwd -P)"
package_manifest="$package_root/Cargo.toml"
package_lock="$package_root/Cargo.lock"
if [[ ! -f "$package_manifest" || ! -f "$package_root/Cargo.toml.orig" || ! -f "$package_lock" ]]; then
    echo "standalone package is missing its normalized manifest or lock" >&2
    exit 1
fi
unexpected_source="$(sed -n 's/^source = "\(.*\)"$/\1/p' "$package_lock" | \
    LC_ALL=C sort -u | grep -v '^registry+https://github.com/rust-lang/crates.io-index$' || true)"
if [[ -n "$unexpected_source" ]]; then
    echo "standalone lock contains a non-crates.io source: $unexpected_source" >&2
    exit 1
fi
if ! awk '
    /^\[\[package\]\]$/ {
        if (seen && source && !checksum) exit 1
        seen = 1; source = 0; checksum = 0; next
    }
    /^source = / { source = 1 }
    /^checksum = / { checksum = 1 }
    END { if (seen && source && !checksum) exit 1 }
' "$package_lock"; then
    echo "registry package without a locked checksum" >&2
    exit 1
fi

vendor_log="$output_dir/vendor.log"
env -i \
    HOME="$output_dir/preparation-home" \
    CARGO_HOME="$preparation_home" \
    TMPDIR="$preparation_tmp" \
    PATH="$preparation_path" \
    LANG=C LC_ALL=C CARGO_TERM_COLOR=never \
    "$cargo_driver" vendor \
    --manifest-path "$package_manifest" \
    --versioned-dirs \
    --frozen \
    "$package_root/vendor" > "$vendor_log" 2>&1

mkdir -p "$package_root/.cargo" "$package_root/input-boundary"
{
    echo '[source.crates-io]'
    echo 'replace-with = "vendored-sources"'
    echo
    echo '[source.vendored-sources]'
    printf 'directory = "%s"\n' "$package_root/vendor"
    echo
    echo '[net]'
    echo 'offline = true'
    echo
    printf '[target.%s]\n' "$host_triple"
    printf 'linker = "%s"\n' "$system_cc"
    if [[ "$target" != "$host_triple" ]]; then
        echo
        printf '[target.%s]\n' "$target"
        printf 'linker = "%s"\n' "$system_cc"
    fi
} > "$package_root/.cargo/config.toml"
{
    echo
    echo '[profile.dev]'
    echo 'opt-level = 0'
    echo 'debug = 2'
    echo 'strip = "none"'
    echo 'debug-assertions = false'
    echo 'overflow-checks = true'
    echo 'lto = false'
    echo 'panic = "unwind"'
    echo 'incremental = false'
    echo 'codegen-units = 1'
    echo
    echo '[profile.release]'
    echo 'opt-level = 3'
    echo 'debug = false'
    echo 'strip = "none"'
    echo 'debug-assertions = false'
    echo 'overflow-checks = true'
    echo 'lto = false'
    echo 'panic = "unwind"'
    echo 'incremental = false'
    echo 'codegen-units = 1'
} >> "$package_manifest"

if [[ -n "$(find "$package_root" -type l -print -quit)" ]]; then
    echo "sealed package or vendor tree contains a symlink" >&2
    exit 1
fi

sealed_script_dir="$package_root/scripts"
scanner="$sealed_script_dir/ct-scan.awk"
scanner_self_test="$sealed_script_dir/ct-scan-self-test.sh"
manifest_writer="$sealed_script_dir/ct-input-manifest.sh"
manifest_self_test="$sealed_script_dir/ct-input-manifest-self-test.sh"
for sealed_tool in "$scanner" "$scanner_self_test" "$manifest_writer" "$manifest_self_test"; do
    if [[ ! -f "$sealed_tool" ]]; then
        echo "sealed package is missing evidence tool: $sealed_tool" >&2
        exit 1
    fi
done

build_home="$output_dir/build-home"
build_cargo_home="$output_dir/build-cargo-home"
build_tmp="$output_dir/build-tmp"
cargo_target="$output_dir/cargo-target"
mkdir -p "$build_home" "$build_cargo_home" "$build_tmp" "$cargo_target"
build_path="$toolchain_sysroot/bin:$(dirname "$system_cc"):/usr/bin:/bin"
remap_flag="--remap-path-prefix=$package_root=/thunderbolt-paillier-source"
profile="dev"
profile_dir="debug"
if [[ "$optimization" == "O3" ]]; then
    profile="release"
    profile_dir="release"
fi
{
    echo "environment_version=1"
    echo "HOME=$build_home"
    echo "CARGO_HOME=$build_cargo_home"
    echo "TMPDIR=$build_tmp"
    echo "PATH=$build_path"
    echo "LANG=C"
    echo "LC_ALL=C"
    echo "CARGO_TERM_COLOR=never"
    echo "RUSTC=$rustc_driver"
    echo "RUSTFLAGS=$remap_flag"
    if [[ -n "${sdk_root:-}" ]]; then
        echo "SDKROOT=$sdk_root"
    fi
    echo "cargo_network=frozen_offline_vendored"
    echo "cargo_jobs=$build_jobs"
    echo "cargo_profile=$profile"
} > "$package_root/input-boundary/build-env.txt"
"$rustc_driver" --print cfg --target "$target" > "$package_root/input-boundary/target-cfg.txt"
{
    echo "target=$target"
    echo "target_libdir=$target_libdir"
    echo "host=$host_triple"
    "$rustc_driver" -Vv | sed 's/^/rustc_/'
    "$cargo_driver" -V | sed 's/^/cargo_/'
    "$system_cc" --version 2>&1 | sed 's/^/cc_/'
    "$system_ld" -v 2>&1 | sed 's/^/ld_/' || true
    "$system_ar" -V 2>&1 | sed 's/^/ar_/' || true
    if [[ -n "${sdk_root:-}" ]]; then
        echo "sdk_root=$sdk_root"
    fi
} > "$package_root/input-boundary/toolchain.txt"

scanner_self_test_log="$output_dir/scanner-self-test.txt"
input_self_test_log="$output_dir/input-manifest-self-test.txt"
env -i PATH="$build_path" TMPDIR="$build_tmp" LANG=C LC_ALL=C \
    bash "$scanner_self_test" | tee "$scanner_self_test_log"
env -i PATH="$build_path" TMPDIR="$build_tmp" LANG=C LC_ALL=C \
    bash "$manifest_self_test" | tee "$input_self_test_log"

metadata="$output_dir/metadata.txt"
scan_report="$output_dir/scan.txt"
input_manifest_pre="$output_dir/compile-inputs.pre.sha256"
input_manifest_post="$output_dir/compile-inputs.post.sha256"
manifest_args=(
    "source=$package_root"
    "toolchain-bin=$toolchain_sysroot/bin"
    "toolchain-lib=$toolchain_sysroot/lib"
    "system-cc=$system_cc"
    "system-ld=$system_ld"
    "system-ar=$system_ar"
    "${system_manifest_args[@]}"
)
"$manifest_writer" "$input_manifest_pre" "${manifest_args[@]}"

{
    echo "ct_evidence_version=3"
    echo "generated_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "boundary=standalone-packaged-vendored-source"
    echo "source_archive=$archive"
    echo "source_archive_sha256=$archive_hash"
    echo "source_root=$package_root"
    echo "target=$target"
    echo "architecture=$architecture"
    echo "optimization=$optimization"
    echo "cargo_profile=$profile"
    echo "debug_assertions=off"
    echo "build_jobs=$build_jobs"
    echo "network=offline"
    echo "uname=$(uname -a)"
    echo "cargo_driver=$cargo_driver"
    echo "cargo_driver_sha256=$(hash_file "$cargo_driver")"
    echo "cargo=$($cargo_driver -V)"
    echo "rustc_driver=$rustc_driver"
    echo "rustc_driver_sha256=$(hash_file "$rustc_driver")"
    echo "rustc_commit=$rustc_commit"
    "$rustc_driver" -Vv | sed 's/^/rustc_/'
    echo "system_cc=$system_cc"
    echo "system_cc_sha256=$(hash_file "$system_cc")"
    echo "system_ld=$system_ld"
    echo "system_ld_sha256=$(hash_file "$system_ld")"
    echo "system_ar=$system_ar"
    echo "system_ar_sha256=$(hash_file "$system_ar")"
    echo "packaged_cargo_lock_sha256=$(hash_file "$package_lock")"
    echo "sealed_scanner_sha256=$(hash_file "$scanner")"
    echo "sealed_scanner_self_test_sha256=$(hash_file "$scanner_self_test")"
    echo "sealed_manifest_writer_sha256=$(hash_file "$manifest_writer")"
    echo "sealed_manifest_self_test_sha256=$(hash_file "$manifest_self_test")"
    echo "launcher_sha256=$(hash_file "$script_dir/ct-assembly-scan.sh")"
    echo "git_commit=$(git -C "$crate_dir" rev-parse HEAD 2>/dev/null || echo unavailable)"
    echo "git_crate_status_begin"
    git -C "$crate_dir" status --short -- "$crate_dir" 2>/dev/null || true
    echo "git_crate_status_end"
    echo "compile_input_manifest=$input_manifest_pre"
    echo "compile_input_manifest_sha256=$(hash_file "$input_manifest_pre")"
    echo "compile_input_manifest_entries=$(wc -l < "$input_manifest_pre" | tr -d ' ')"
} | tee "$metadata"

cargo_log="$output_dir/cargo-rustc.txt"
(
    cd "$package_root"
    env -i \
        HOME="$build_home" \
        CARGO_HOME="$build_cargo_home" \
        TMPDIR="$build_tmp" \
        PATH="$build_path" \
        LANG=C LC_ALL=C CARGO_TERM_COLOR=never \
        "${platform_build_env[@]}" \
        RUSTC="$rustc_driver" \
        RUSTFLAGS="$remap_flag" \
        "$cargo_driver" rustc \
        --frozen \
        --manifest-path "$package_manifest" \
        --target "$target" \
        --lib \
        --profile "$profile" \
        --jobs "$build_jobs" \
        --target-dir "$cargo_target" \
        -- --emit=asm 2>&1 | tee "$cargo_log"
)

assembly_source="$(find "$cargo_target/$target/$profile_dir/deps" -maxdepth 1 -type f \
    -name 'thunderbolt_paillier-*.s' -print -quit)"
if [[ -z "$assembly_source" ]]; then
    echo "no thunderbolt-paillier assembly output found" >&2
    exit 1
fi
assembly="$output_dir/thunderbolt-paillier-$target-$optimization.s"
cp "$assembly_source" "$assembly"
assembly_hash="$(hash_file "$assembly")"

awk -v arch="$architecture" -v target_triple="$target" -v optimization="$optimization" \
    -v compiler_commit="$rustc_commit" -v assembly_sha256="$assembly_hash" \
    -f "$scanner" "$assembly" | tee "$scan_report"
"$manifest_writer" "$input_manifest_post" "${manifest_args[@]}"
if ! cmp -s "$input_manifest_pre" "$input_manifest_post"; then
    echo "sealed source, vendor, config, toolchain, or system build tool changed during the scan" >&2
    diff -u "$input_manifest_pre" "$input_manifest_post" >&2 || true
    exit 1
fi
{
    echo "assembly=$assembly"
    echo "assembly_sha256=$assembly_hash"
    echo "scan_report_sha256=$(hash_file "$scan_report")"
    echo "compile_input_manifest_sha256=$(hash_file "$input_manifest_post")"
    echo "ct_evidence_status=scan_passed"
} | tee -a "$metadata"

echo "CT_SCAN_COMPLETE metadata=$metadata scan=$scan_report assembly=$assembly"
