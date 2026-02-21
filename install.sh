#!/bin/bash
# ============================================================================
# Installer for Universal Web Security Scanner
# Installs the scanner globally so it can be used from anywhere
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/usr/local/bin"
LIB_INSTALL_DIR="/usr/local/lib/webscan"
SCRIPT_NAME="webscan"
CONFIG_DIR="${HOME}/.config/webscan"
CONFIG_FILE="${CONFIG_DIR}/config"
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_SCRIPT="${SOURCE_DIR}/website-security-script.sh"

info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()   { echo -e "${RED}[ERROR]${NC} $1"; }

# ── Check prerequisites ─────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This installer must be run as root (use sudo)"
    echo "  sudo bash $0"
    exit 1
fi

if [[ ! -f "$SOURCE_SCRIPT" ]]; then
    err "Cannot find website-security-script.sh in the same directory as this installer"
    exit 1
fi

# ── Detect the actual user (when run with sudo) ─────────────────────────────
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~${REAL_USER}")
CONFIG_DIR="${REAL_HOME}/.config/webscan"
CONFIG_FILE="${CONFIG_DIR}/config"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       Universal Web Security Scanner - Installer     ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Install the script and modules ───────────────────────────────────────────
info "Installing webscan to ${INSTALL_DIR}/${SCRIPT_NAME}..."
cp "$SOURCE_SCRIPT" "${INSTALL_DIR}/${SCRIPT_NAME}"
chmod 755 "${INSTALL_DIR}/${SCRIPT_NAME}"
ok "Installed to ${INSTALL_DIR}/${SCRIPT_NAME}"

info "Installing lib/ and scans/ modules to ${LIB_INSTALL_DIR}..."
mkdir -p "${LIB_INSTALL_DIR}"
cp -r "${SOURCE_DIR}/lib" "${LIB_INSTALL_DIR}/"
cp -r "${SOURCE_DIR}/scans" "${LIB_INSTALL_DIR}/"
chmod -R 755 "${LIB_INSTALL_DIR}"
ok "Modules installed to ${LIB_INSTALL_DIR}"

# Patch installed script to use LIB_INSTALL_DIR instead of SCRIPT_DIR
sed -i "s|^SCRIPT_DIR=.*|SCRIPT_DIR=\"${LIB_INSTALL_DIR}\"|" "${INSTALL_DIR}/${SCRIPT_NAME}"
ok "Script configured to use installed modules"

# ── Create default config if it doesn't exist ───────────────────────────────
if [[ ! -f "$CONFIG_FILE" ]]; then
    info "Creating default config at ${CONFIG_FILE}..."
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" << 'DEFAULTCONFIG'
# ============================================================================
# Web Security Scanner Configuration
# Edit this file or use: webscan --set-<option> <value>
# ============================================================================

# Email notification recipient
NOTIFY_EMAIL=""

# Enable email notifications (true/false)
EMAIL_ENABLED=false

# Webhook endpoint URL
WEBHOOK_URL=""

# API key for webhook authentication
API_KEY=""

# Default exclude pattern (regex)
# EXCLUDE_PATTERN='node_modules|vendor/|\.git/|venv/|__pycache__|dist/|build/|\.next/|cache/|\.svn/|\.hg/'

# Max file size to scan
# MAX_FILE_SIZE="10M"

# Per-operation timeout (seconds)
# TIMEOUT_CMD="timeout 30"

# Total scan timeout (seconds)
# SCAN_TIMEOUT=300

# ── Scan Mode ─────────────────────────────────────────────────────────────────
# Controls which category of checks runs by default.
# Override on the command line with: webscan /path --mode files
#
#   all    = run all 15 scan sections (default — full audit)
#   files  = file-based checks only — no root/server access needed.
#            Safe on shared hosting. Skips sections 8,10,12,13,14,15.
#   server = server-level checks only — requires server/root access.
#            Skips sections 1-7, 9, 11 (file scans).
#
# SCAN_MODE=all

# ── Module Toggles ────────────────────────────────────────────────────────────
# Uncomment and set to false to permanently disable individual scan sections.
# Useful when certain checks don't apply to your environment.
#
# FILE-BASED scans — analyse files on disk; work on any hosting:
# SCAN_01_MALWARE=true
# SCAN_02_SUSPICIOUS=true
# SCAN_03_OBFUSCATION=true
# SCAN_04_INTEGRITY=true
# SCAN_05_FRAMEWORK=true
# SCAN_06_DEPENDENCIES=true
# SCAN_07_PERMISSIONS=true
# SCAN_09_SECRETS=true
# SCAN_11_MODIFIED_FILES=true
#
# SERVER-LEVEL scans — require access to server config, ports, processes.
# On shared hosting the server is managed by your host; disable these to
# avoid false-positives and wasted scan time:
# SCAN_08_SERVER_CONFIG=false
# SCAN_10_NETWORK=false
# SCAN_12_SSL=false
# SCAN_13_DATABASE=false
# SCAN_14_CONTAINER=false
# SCAN_15_LOGGING=false
DEFAULTCONFIG
    chown -R "${REAL_USER}:$(id -gn "$REAL_USER")" "$CONFIG_DIR"
    ok "Config created at ${CONFIG_FILE}"
else
    warn "Config already exists at ${CONFIG_FILE} - keeping existing"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
ok "Installation complete!"
echo ""
echo -e "  ${BOLD}Usage:${NC}"
echo "    webscan /path/to/website              Scan a website directory (full scan)"
echo "    webscan /path --mode files            File-based scan — safe on shared hosting"
echo "    webscan /path --mode server           Server-level audit (needs root access)"
echo "    webscan /path --skip database         Skip the database scan module"
echo "    webscan /path --only malware          Run malware check only"
echo "    webscan --set-email you@example.com   Set default email"
echo "    webscan --enable-email                Enable email notifications"
echo "    webscan --disable-email               Disable email notifications"
echo "    webscan --set-webhook <url>           Set default webhook URL"
echo "    webscan --set-api-key <key>           Set default API key"
echo "    webscan --show-config                 Show current configuration"
echo "    webscan --edit-config                 Open config in editor"
echo ""
echo -e "  ${BOLD}Override on the fly:${NC}"
echo "    webscan /path --email other@mail.com  Use a different email for this scan"
echo "    webscan /path --no-email              Skip email for this scan"
echo ""
