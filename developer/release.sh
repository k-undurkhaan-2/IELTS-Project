#!/bin/bash
# IELTS Practice App - Unix standalone release builder.
#
# Usage:
#   bash developer/release.sh
#   bash developer/release.sh 1.0.0
#
# Output:
#   dist/ielts-practice-{version}.zip
#   dist/ielts-practice-{version}.release-receipt.json
#
# Node.js is required while packaging bundles and enforcing the checked-in
# positive release manifest. It is not required after users extract the ZIP.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

if [ $# -ge 1 ]; then
    VERSION="$1"
elif command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
    VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo 'snapshot')"
else
    VERSION="snapshot"
fi
VERSION="$(printf '%s' "${VERSION}" | sed 's#[^A-Za-z0-9._-]#-#g')"

DIST_DIR="dist"
ZIP_NAME="ielts-practice-${VERSION}.zip"
ZIP_PATH="${DIST_DIR}/${ZIP_NAME}"
ZIP_ABSOLUTE_PATH="${PROJECT_ROOT}/${ZIP_PATH}"
RECEIPT_NAME="ielts-practice-${VERSION}.release-receipt.json"
RECEIPT_PATH="${PROJECT_ROOT}/${DIST_DIR}/${RECEIPT_NAME}"
MANIFEST_HELPER="${PROJECT_ROOT}/developer/standalone-release-manifest.mjs"

if ! command -v node >/dev/null 2>&1; then
    echo "ERROR: node is required to build bundles and enforce the standalone release manifest."
    exit 1
fi
if ! command -v zip >/dev/null 2>&1; then
    echo "ERROR: zip is required to create the release archive."
    exit 1
fi
if ! command -v zipinfo >/dev/null 2>&1; then
    echo "ERROR: zipinfo is required to verify the release archive."
    exit 1
fi

echo "============================================"
echo " IELTS Practice App - Release Builder"
echo " Version : ${VERSION}"
echo " Output  : ${ZIP_PATH}"
echo "============================================"

echo ""
echo "[1/2] Building bundles..."
if [ ! -f "scripts/build-bundles.mjs" ]; then
    echo "ERROR: scripts/build-bundles.mjs not found!"
    exit 1
fi
node scripts/build-bundles.mjs
echo "       Bundles generated: js/bundles/"

echo ""
echo "[2/2] Validating the release manifest and creating the ZIP..."

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

STAGING_DIR=""
ZIP_LIST=""

cleanup_stage() {
    if [ -z "${STAGING_DIR}" ]; then
        return
    fi
    case "${STAGING_DIR}" in
        */ielts-standalone-release-*/payload)
            local stage_root="${STAGING_DIR%/payload}"
            rm -rf -- "${stage_root}"
            ;;
        *)
            echo "ERROR: refusing to clean unexpected staging directory: ${STAGING_DIR}" >&2
            return 1
            ;;
    esac
    STAGING_DIR=""
}

on_exit() {
    local status=$?
    trap - EXIT
    cleanup_stage || status=1
    if [ -n "${ZIP_LIST}" ] && [ -f "${ZIP_LIST}" ]; then
        rm -f -- "${ZIP_LIST}"
    fi
    if [ "${status}" -ne 0 ]; then
        rm -f -- "${ZIP_ABSOLUTE_PATH}"
    fi
    exit "${status}"
}
trap on_exit EXIT

STAGING_DIR="$(node "${MANIFEST_HELPER}" stage --project-root "${PROJECT_ROOT}" --receipt "${RECEIPT_PATH}")"
if [ -z "${STAGING_DIR}" ] || [ ! -d "${STAGING_DIR}" ]; then
    echo "ERROR: standalone release manifest helper returned an invalid staging directory: ${STAGING_DIR}"
    exit 1
fi

(
    cd "${STAGING_DIR}"
    node "${MANIFEST_HELPER}" archive-paths --receipt "${RECEIPT_PATH}" \
        | zip -q "${ZIP_ABSOLUTE_PATH}" -@
)

cleanup_stage
zip -T "${ZIP_ABSOLUTE_PATH}" >/dev/null

ZIP_LIST="$(mktemp)"
zipinfo -1 "${ZIP_ABSOLUTE_PATH}" > "${ZIP_LIST}"
node "${MANIFEST_HELPER}" verify-archive-list \
    --receipt "${RECEIPT_PATH}" \
    --archive-list "${ZIP_LIST}"

DUPLICATE_ENTRY="$(LC_ALL=C sort "${ZIP_LIST}" | uniq -d | head -1)"
if [ -n "${DUPLICATE_ENTRY}" ]; then
    echo "ERROR: release zip contains duplicate entry: ${DUPLICATE_ENTRY}"
    exit 1
fi

if grep -Eq '(^/|^[A-Za-z]:[\\/]|\\|(^|/)\.\.(/|$))' "${ZIP_LIST}"; then
    echo "ERROR: release zip contains an unsafe entry path"
    grep -E '(^/|^[A-Za-z]:[\\/]|\\|(^|/)\.\.(/|$))' "${ZIP_LIST}" | head -20
    exit 1
fi

reject_entry_prefix() {
    local prefix="$1"
    if grep -q "^${prefix}" "${ZIP_LIST}"; then
        echo "ERROR: release zip contains forbidden path prefix: ${prefix}"
        grep "^${prefix}" "${ZIP_LIST}" | head -20
        exit 1
    fi
}

reject_entry_pattern() {
    local pattern="$1"
    if grep -Eq "${pattern}" "${ZIP_LIST}"; then
        echo "ERROR: release zip contains forbidden entries matching: ${pattern}"
        grep -E "${pattern}" "${ZIP_LIST}" | head -20
        exit 1
    fi
}

reject_entry_prefix "templates/"
reject_entry_prefix "ListeningPractice/"
reject_entry_prefix "assets/generated/listening-exams/"
reject_entry_prefix ".git/"
reject_entry_prefix "node_modules/"
reject_entry_prefix "developer/tests/"
reject_entry_prefix "backend/"
reject_entry_pattern '(^|/)\.env($|\.)'
reject_entry_pattern '(^|/)[^/]*\.(key|pem|p12|pfx|kdbx|log|tmp|temp|bak)$'
reject_entry_pattern '(^|/)\.ssh(/|$)'
reject_entry_pattern '(^|/)~\$[^/]*$'
reject_entry_pattern '^assets/scripts/.*\.py$'
reject_entry_pattern '^js/(app|core|data|runtime|services|utils|components|presentation|views)/'

rm -f -- "${ZIP_LIST}"
ZIP_LIST=""

echo ""
echo "============================================"
echo " Done: ${ZIP_PATH}"
echo " Size : $(du -h "${ZIP_ABSOLUTE_PATH}" | cut -f1)"
echo " Receipt: ${DIST_DIR}/${RECEIPT_NAME}"
echo ""
echo " Extract the archive and open index.html directly."
echo " Node.js and build tools are not required after packaging."
echo "============================================"
