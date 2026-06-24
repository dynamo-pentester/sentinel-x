#!/bin/bash
# =============================================================
#  SENTINEL-X Setup Script
#  Tested on: Ubuntu 24.04 LTS / Kali 2025 (kernel 6.17-6.18)
#  Run as: bash setup.sh
# =============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

KERNEL=$(uname -r)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

banner() {
    echo -e "${CYAN}${BOLD}"
    echo "  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      ██╗  ██╗"
    echo "  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║      ╚██╗██╔╝"
    echo "  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║       ╚███╔╝ "
    echo "  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║       ██╔██╗ "
    echo "  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗ ██╔╝ ██╗"
    echo "  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═╝  ╚═╝"
    echo -e "${RESET}"
    echo -e "${BOLD}  Cross-Platform Kernel Integrity Monitor + Blockchain Forensics${RESET}"
    echo -e "  Kernel: ${CYAN}$KERNEL${RESET}"
    echo
}

step() { echo -e "\n${GREEN}[+]${RESET} ${BOLD}$1${RESET}"; }
warn() { echo -e "${YELLOW}[!]${RESET} $1"; }
err()  { echo -e "${RED}[✗]${RESET} $1"; exit 1; }
ok()   { echo -e "${GREEN}[✓]${RESET} $1"; }

# ---------------------------------------------------------------
# 1. Check root
# ---------------------------------------------------------------
banner

if [ "$EUID" -ne 0 ]; then
    err "Please run as root: sudo bash setup.sh"
fi

# ---------------------------------------------------------------
# 2. Check OS
# ---------------------------------------------------------------
step "Checking environment..."

if ! grep -qE "Ubuntu|Kali|Debian" /etc/os-release 2>/dev/null; then
    warn "Unknown distro — proceeding anyway"
fi

MAJOR=$(echo "$KERNEL" | cut -d. -f1)
MINOR=$(echo "$KERNEL" | cut -d. -f2)
ok "Kernel $KERNEL (${MAJOR}.${MINOR})"

if [ "$MAJOR" -lt 5 ] || ([ "$MAJOR" -eq 5 ] && [ "$MINOR" -lt 8 ]); then
    err "Kernel too old. Need 5.8+. You have $KERNEL"
fi

# ---------------------------------------------------------------
# 3. Install dependencies
# ---------------------------------------------------------------
step "Installing build dependencies..."

apt-get update -qq
apt-get install -y \
    linux-headers-$(uname -r) \
    build-essential \
    git \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    dkms 2>&1 | grep -E "Setting up|already|error" || true

ok "Dependencies installed"

# ---------------------------------------------------------------
# 4. Generate unlock key for sentinelx
# ---------------------------------------------------------------
step "Generating sentinelx unlock key..."

KEY=$(cat /dev/urandom | tr -dc 'a-f0-9' | head -c 32)
echo "#define UNLOCK_KEY \"$KEY\"" > "$SCRIPT_DIR/sentinelx/sentinelx_key.h"

echo
echo -e "  ${RED}${BOLD}╔══════════════════════════════════════════╗${RESET}"
echo -e "  ${RED}${BOLD}║   UNLOCK KEY — WRITE THIS DOWN NOW!     ║${RESET}"
echo -e "  ${RED}${BOLD}║                                          ║${RESET}"
echo -e "  ${RED}${BOLD}║   $KEY   ║${RESET}"
echo -e "  ${RED}${BOLD}║                                          ║${RESET}"
echo -e "  ${RED}${BOLD}║   You need this to unload sentinelx      ║${RESET}"
echo -e "  ${RED}${BOLD}╚══════════════════════════════════════════╝${RESET}"
echo
read -p "  Press ENTER once you have written down the key..."

# ---------------------------------------------------------------
# 5. Build sentinelx
# ---------------------------------------------------------------
step "Building sentinelx..."

cd "$SCRIPT_DIR/sentinelx"
make clean 2>/dev/null || true
make

if [ -f sentinelx.ko ]; then
    ok "sentinelx.ko built successfully"
else
    err "sentinelx build failed"
fi

# ---------------------------------------------------------------
# 6. Build test rootkit
# ---------------------------------------------------------------
step "Building sentinel_test_rootkit..."

cd "$SCRIPT_DIR/rootkit-test"
make clean 2>/dev/null || true
make

if [ -f sentinel_test_rootkit.ko ]; then
    ok "sentinel_test_rootkit.ko built successfully"
else
    err "rootkit build failed"
fi

# ---------------------------------------------------------------
# 7. Set up Python venv (for bridge/daemon later)
# ---------------------------------------------------------------
step "Setting up Python virtual environment..."

cd "$SCRIPT_DIR"
python3 -m venv venv
venv/bin/pip install --quiet --upgrade pip
ok "Python venv created at $SCRIPT_DIR/venv"

step "Installing Python dependencies..."
venv/bin/pip install --quiet cryptography web3 eth-account python-dotenv
ok "Python dependencies installed (cryptography, web3, eth-account, python-dotenv)"

# ---------------------------------------------------------------
# 8. Configure .env
# ---------------------------------------------------------------
step "Setting up environment config..."

if [ ! -f "$SCRIPT_DIR/.env" ]; then
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
    warn ".env created from .env.example — edit it before running the daemon:"
    warn "  PRIVATE_KEY, INFURA_SEPOLIA_URL, CONTRACT_ADDR, SENTINEL_NODE_ID"
else
    ok ".env already exists"
fi
# ---------------------------------------------------------------
echo
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║           SENTINEL-X SETUP COMPLETE             ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo
echo -e "  ${BOLD}Built modules:${RESET}"
echo -e "    ${CYAN}$SCRIPT_DIR/sentinelx/sentinelx.ko${RESET}"
echo -e "    ${CYAN}$SCRIPT_DIR/rootkit-test/sentinel_test_rootkit.ko${RESET}"
echo
echo -e "  ${BOLD}Quick test:${RESET}"
echo -e "    ${YELLOW}# Terminal 1 — monitor:${RESET}"
echo -e "    sudo dmesg | grep -E 'krt:|sentinelx:'"
echo
echo -e "    ${YELLOW}# Terminal 2 — load sentinelx:${RESET}"
echo -e "    sudo insmod $SCRIPT_DIR/sentinelx/sentinelx.ko anti_unload=0"
echo
echo -e "    ${YELLOW}# Terminal 2 — test stage 1 (SCT hook):${RESET}"
echo -e "    sudo insmod $SCRIPT_DIR/rootkit-test/sentinel_test_rootkit.ko stage=1"
echo -e "    sudo dmesg | grep -E 'krt:|sentinelx:' | tail -20"
echo -e "    sudo rmmod sentinel_test_rootkit"
echo
echo -e "    ${YELLOW}# Unload sentinelx when done:${RESET}"
echo -e "    sudo rmmod sentinelx   ${RED}# only works with anti_unload=0${RESET}"
echo
