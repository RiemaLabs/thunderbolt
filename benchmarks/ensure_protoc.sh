#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${SCRIPT_DIR}/.tools"
PROTOC_VERSION="${PROTOC_VERSION:-29.3}"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    ARCHIVE="protoc-${PROTOC_VERSION}-osx-aarch_64.zip"
    ;;
  Darwin-x86_64)
    ARCHIVE="protoc-${PROTOC_VERSION}-osx-x86_64.zip"
    ;;
  Linux-x86_64)
    ARCHIVE="protoc-${PROTOC_VERSION}-linux-x86_64.zip"
    ;;
  *)
    echo "unsupported platform for automatic protoc bootstrap: $(uname -s)-$(uname -m)" >&2
    exit 1
    ;;
esac

INSTALL_DIR="${TOOLS_DIR}/protoc-${PROTOC_VERSION}"
PROTOC_BIN="${INSTALL_DIR}/bin/protoc"

if [[ -x "${PROTOC_BIN}" ]]; then
  echo "${PROTOC_BIN}"
  exit 0
fi

mkdir -p "${TOOLS_DIR}"
ARCHIVE_PATH="${TOOLS_DIR}/${ARCHIVE}"
URL="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/${ARCHIVE}"

curl -L --fail "${URL}" -o "${ARCHIVE_PATH}"
rm -rf "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
unzip -q "${ARCHIVE_PATH}" -d "${INSTALL_DIR}"
chmod +x "${PROTOC_BIN}"
echo "${PROTOC_BIN}"
