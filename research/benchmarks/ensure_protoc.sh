#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${SCRIPT_DIR}/.tools"
PROTOC_VERSION="29.3"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    ARCHIVE="protoc-${PROTOC_VERSION}-osx-aarch_64.zip"
    EXPECTED_SHA256="2b8a3403cd097f95f3ba656e14b76c732b6b26d7f183330b11e36ef2bc028765"
    ;;
  Darwin-x86_64)
    ARCHIVE="protoc-${PROTOC_VERSION}-osx-x86_64.zip"
    EXPECTED_SHA256="9a788036d8f9854f7b03c305df4777cf0e54e5b081e25bf15252da87e0e90875"
    ;;
  Linux-x86_64)
    ARCHIVE="protoc-${PROTOC_VERSION}-linux-x86_64.zip"
    EXPECTED_SHA256="3e866620c5be27664f3d2fa2d656b5f3e09b5152b42f1bedbf427b333e90021a"
    ;;
  Linux-aarch64)
    ARCHIVE="protoc-${PROTOC_VERSION}-linux-aarch_64.zip"
    EXPECTED_SHA256="6427349140e01f06e049e707a58709a4f221ae73ab9a0425bc4a00c8d0e1ab32"
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

if [[ ! -f "${ARCHIVE_PATH}" ]]; then
  curl -L --fail --proto '=https' --tlsv1.2 "${URL}" -o "${ARCHIVE_PATH}.partial"
  mv "${ARCHIVE_PATH}.partial" "${ARCHIVE_PATH}"
fi

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256="$(sha256sum "${ARCHIVE_PATH}" | awk '{print $1}')"
else
  actual_sha256="$(shasum -a 256 "${ARCHIVE_PATH}" | awk '{print $1}')"
fi
if [[ "${actual_sha256}" != "${EXPECTED_SHA256}" ]]; then
  echo "protoc archive checksum mismatch: ${ARCHIVE_PATH}" >&2
  exit 1
fi

if [[ -e "${INSTALL_DIR}" ]]; then
  echo "refusing to replace incomplete protoc directory: ${INSTALL_DIR}" >&2
  exit 1
fi

TEMP_INSTALL_DIR="$(mktemp -d "${TOOLS_DIR}/protoc-install.XXXXXX")"
unzip -q "${ARCHIVE_PATH}" -d "${TEMP_INSTALL_DIR}"
mv "${TEMP_INSTALL_DIR}" "${INSTALL_DIR}"
chmod +x "${PROTOC_BIN}"
echo "${PROTOC_BIN}"
