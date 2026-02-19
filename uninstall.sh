#!/bin/bash
# Uninstaller for Universal Web Security Scanner

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

INSTALL_PATH="/usr/local/bin/webscan"
LIB_DIR="/usr/local/lib/webscan"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This uninstaller must be run as root (use sudo)"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~${REAL_USER}")
CONFIG_DIR="${REAL_HOME}/.config/webscan"

if [[ -f "$INSTALL_PATH" ]]; then
    rm -f "$INSTALL_PATH"
    echo -e "${GREEN}[OK]${NC} Removed ${INSTALL_PATH}"
else
    echo -e "${YELLOW}[WARN]${NC} ${INSTALL_PATH} not found - already uninstalled?"
fi

if [[ -d "$LIB_DIR" ]]; then
    rm -rf "$LIB_DIR"
    echo -e "${GREEN}[OK]${NC} Removed ${LIB_DIR}"
fi

if [[ -d "$CONFIG_DIR" ]]; then
    read -rp "Remove config directory ${CONFIG_DIR}? [y/N] " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        echo -e "${GREEN}[OK]${NC} Removed ${CONFIG_DIR}"
    else
        echo -e "${YELLOW}[KEPT]${NC} Config preserved at ${CONFIG_DIR}"
    fi
fi

echo -e "${GREEN}[OK]${NC} Uninstall complete."
