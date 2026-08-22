#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 OUTPUT LABEL=PATH [LABEL=PATH ...]" >&2
}

if [[ $# -lt 2 ]]; then
    usage
    exit 2
fi

output="$1"
shift
if [[ -e "$output" ]]; then
    echo "refusing to replace input manifest: $output" >&2
    exit 2
fi

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

hash_text() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    else
        shasum -a 256 | awk '{print $1}'
    fi
}

hash_null_list() {
    if command -v sha256sum >/dev/null 2>&1; then
        xargs -0 sha256sum
    else
        xargs -0 shasum -a 256
    fi
}

resolve_symlink_path() {
    local current="$1"
    local target
    local parent
    local depth=0
    while [[ -L "$current" ]]; do
        depth=$((depth + 1))
        if [[ "$depth" -gt 40 ]]; then
            echo "symlink chain is too deep: $1" >&2
            return 2
        fi
        target="$(readlink "$current")"
        if [[ "$target" == /* ]]; then
            current="$target"
        else
            current="$(dirname "$current")/$target"
        fi
        parent="$(cd "$(dirname "$current")" && pwd -P)"
        current="$parent/$(basename "$current")"
    done
    printf '%s\n' "$current"
}

emit_directory() {
    label="$1"
    root="$(cd "$2" && pwd -P)"
    printf 'ROOT %s %s\n' "$label" "$root"
    while IFS= read -r -d '' path; do
        if [[ "$path" == *$'\n'* ]]; then
            echo "newline in sealed input path is not supported: $path" >&2
            exit 2
        fi
        if [[ -x "$path" ]]; then
            printf 'MODE executable %s\n' "$path"
        else
            printf 'MODE non-executable %s\n' "$path"
        fi
    done < <(find "$root" -type f -print0 | LC_ALL=C sort -z)
    if [[ -n "$(find "$root" -type f -print -quit)" ]]; then
        find "$root" -type f -print0 | LC_ALL=C sort -z | hash_null_list
    fi
    while IFS= read -r -d '' path; do
        if [[ "$path" == *$'\n'* ]]; then
            echo "newline in sealed input path is not supported: $path" >&2
            exit 2
        fi
        target="$(readlink "$path")"
        digest="$(printf '%s' "$target" | hash_text)"
        printf 'LINK %s %s -> %s\n' "$digest" "$path" "$target"
        resolved="$(resolve_symlink_path "$path")"
        case "$resolved" in
            "$root"|"$root"/*) ;;
            *)
                echo "sealed directory contains an external symlink: $path -> $resolved" >&2
                exit 2
                ;;
        esac
    done < <(find "$root" -type l -print0 | LC_ALL=C sort -z)
}

emit_file() {
    label="$1"
    path="$2"
    parent="$(cd "$(dirname "$path")" && pwd -P)"
    canonical="$parent/$(basename "$path")"
    if [[ "$canonical" == *$'\n'* ]]; then
        echo "newline in sealed input path is not supported: $canonical" >&2
        exit 2
    fi
    if [[ -L "$canonical" ]]; then
        target="$(readlink "$canonical")"
        digest="$(printf '%s' "$target" | hash_text)"
        printf 'LINK %s %s %s -> %s\n' "$digest" "$label" "$canonical" "$target"
        resolved="$(resolve_symlink_path "$canonical")"
        if [[ ! -f "$resolved" ]]; then
            echo "sealed file symlink does not resolve to a regular file: $canonical" >&2
            exit 2
        fi
        if [[ -x "$resolved" ]]; then
            mode="executable"
        else
            mode="non-executable"
        fi
        printf 'LINK_TARGET %s %s %s %s\n' "$mode" "$(hash_file "$resolved")" "$label" "$resolved"
    elif [[ -f "$canonical" ]]; then
        if [[ -x "$canonical" ]]; then
            mode="executable"
        else
            mode="non-executable"
        fi
        printf 'FILE %s %s %s %s\n' "$mode" "$(hash_file "$canonical")" "$label" "$canonical"
    else
        echo "unsupported sealed input type: $canonical" >&2
        exit 2
    fi
}

temporary="${output}.tmp.$$"
trap 'rm -f "$temporary"' EXIT
{
    for specification in "$@"; do
        if [[ "$specification" != *=* ]]; then
            usage
            exit 2
        fi
        label="${specification%%=*}"
        path="${specification#*=}"
        if [[ ! "$label" =~ ^[a-z0-9][a-z0-9._-]*$ ]]; then
            echo "invalid input label: $label" >&2
            exit 2
        fi
        if [[ ! -e "$path" && ! -L "$path" ]]; then
            echo "sealed input does not exist: $path" >&2
            exit 2
        fi
        if [[ -d "$path" ]]; then
            emit_directory "$label" "$path"
        else
            emit_file "$label" "$path"
        fi
    done
} | LC_ALL=C sort > "$temporary"
mv "$temporary" "$output"
trap - EXIT
