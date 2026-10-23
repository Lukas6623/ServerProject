#!/usr/bin/env bash
set -Eeuo pipefail

MANIFEST_URL="https://serverguard.site/downloads/manifest.json"
MAX_MANIFEST_BYTES=1048576
MAX_PACKAGE_BYTES=536870912

log() { printf '[ServerGuard Updater] %s\n' "$*"; }
fail() { log "ERROR: $*"; exit 1; }

for cmd in curl python3 sha256sum stat; do
    command -v "$cmd" >/dev/null 2>&1 ||
        fail "Required command $cmd was not found. Install it using your system package manager."
done

if [[ "$(id -u)" -eq 0 ]]; then
    SUDO=()
else
    command -v sudo >/dev/null 2>&1 ||
        fail "Root privileges or sudo are required to install updates."
    log "A sudo password may be required."
    sudo -v || fail "Failed to obtain administrator privileges."
    SUDO=(sudo)
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/serverguard-update.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

MANIFEST="$TMP_DIR/manifest.json"
PACKAGE="$TMP_DIR/package"

log "Downloading update manifest..."

curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 60 \
    --max-filesize "$MAX_MANIFEST_BYTES" \
    "$MANIFEST_URL" -o "$MANIFEST" ||
    fail "Failed to download the manifest."

# Select the package based on the detected OS and architecture.
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "Only the x86_64/amd64 architecture is supported." ;;
esac

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
else
    fail "Could not detect the Linux distribution."
fi

case "${ID:-}" in
    ubuntu|debian|kali)
        PKG_TYPE="deb"
        ;;
    fedora|rhel|centos|rocky|almalinux)
        PKG_TYPE="rpm"
        ;;
    arch|manjaro|endeavouros)
        PKG_TYPE="pacman"
        ;;
    *)
        case "${ID_LIKE:-}" in
            *debian*) PKG_TYPE="deb" ;;
            *fedora*|*rhel*) PKG_TYPE="rpm" ;;
            *) fail "Distribution '${ID:-unknown}' is not currently supported." ;;
        esac
        ;;
esac

# The manifest is parsed as JSON and is never executed as code.
readarray -t META < <(python3 - "$MANIFEST" "$PKG_TYPE" <<'PY'
import json, sys
from urllib.parse import urlparse

manifest_path, kind = sys.argv[1], sys.argv[2]

with open(manifest_path, "r", encoding="utf-8") as f:
    data = json.load(f)

if data.get("schema") != 1 or data.get("product") != "serverguard":
    raise SystemExit("Invalid ServerGuard manifest")

version = data.get("latest")
if not isinstance(version, str) or not version or len(version) > 64:
    raise SystemExit("Invalid version")

package = data.get("packages", {}).get(kind)
if not isinstance(package, dict):
    raise SystemExit("Manifest has no package for " + kind)

url = package.get("url")
digest = package.get("sha256")
size = package.get("size")

if not isinstance(url, str) or urlparse(url).scheme != "https":
    raise SystemExit("Package URL must use HTTPS")
if urlparse(url).hostname != "serverguard.site":
    raise SystemExit("Unexpected package domain")
if not isinstance(digest, str) or len(digest) != 64:
    raise SystemExit("Invalid SHA-256 digest")
try:
    int(digest, 16)
except ValueError:
    raise SystemExit("Invalid SHA-256 digest")
if not isinstance(size, int) or size <= 0 or size > 536870912:
    raise SystemExit("Invalid package size")

print(version)
print(url)
print(digest.lower())
print(size)
PY
) || fail "Manifest contains invalid data."

[[ "${#META[@]}" -eq 4 ]] || fail "Could not read update metadata."

VERSION="${META[0]}"
URL="${META[1]}"
EXPECTED_SHA="${META[2]}"
EXPECTED_SIZE="${META[3]}"

log "Latest version: $VERSION"
log "Package type: $PKG_TYPE"
log "Downloading package..."

curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 300 \
    --max-filesize "$MAX_PACKAGE_BYTES" \
    "$URL" -o "$PACKAGE" ||
    fail "Failed to download the package."

ACTUAL_SIZE="$(stat -c '%s' "$PACKAGE")"
[[ "$ACTUAL_SIZE" == "$EXPECTED_SIZE" ]] ||
    fail "Package size does not match the manifest."

ACTUAL_SHA="$(sha256sum "$PACKAGE" | awk '{print tolower($1)}')"
[[ "$ACTUAL_SHA" == "$EXPECTED_SHA" ]] ||
    fail "Package SHA-256 mismatch. Installation cancelled."

log "SHA-256 verification passed."
log "Installing ServerGuard $VERSION..."

case "$PKG_TYPE" in
    deb)
        command -v apt-get >/dev/null 2>&1 ||
            fail "apt-get was not found."
        "${SUDO[@]}" apt-get install -y "$PACKAGE"
        ;;
    rpm)
        if command -v dnf >/dev/null 2>&1; then
            "${SUDO[@]}" dnf install -y "$PACKAGE"
        elif command -v yum >/dev/null 2>&1; then
            "${SUDO[@]}" yum install -y "$PACKAGE"
        else
            fail "Neither dnf nor yum was found."
        fi
        ;;
    pacman)
        command -v pacman >/dev/null 2>&1 ||
            fail "pacman was not found."
        "${SUDO[@]}" pacman -U --needed --noconfirm "$PACKAGE"
        ;;
esac

log "Update completed successfully."
log "Start ServerGuard again using: serverguard"
