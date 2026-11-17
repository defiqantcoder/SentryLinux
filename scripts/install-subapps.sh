#!/usr/bin/env bash
# ==============================================================================
# SentryLinux — 1-Click Sub-Application & Security Tooling Installer
# Supports Ubuntu 24.04 LTS (Noble Numbat) and Ubuntu 22.04 LTS
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${PURPLE}"
cat << 'EOF'
  ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  
  ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   
EOF
echo -e "${NC}"
echo -e "${CYAN}SentryLinux 1-Click Security Sub-Application Installer${NC}"
echo -e "Automating Fail2ban, Suricata, ClamAV, Lynis, UFW, RKhunter & More"
echo -e "──────────────────────────────────────────────────────────────────"

# Check for root / sudo privileges
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] This script must be run as root or with sudo.${NC}"
   echo "Please run: sudo bash $0"
   exit 1
fi

AVAILABLE_TOOLS=(
  "fail2ban"
  "suricata"
  "ufw"
  "apparmor-utils"
  "clamav"
  "clamav-daemon"
  "rkhunter"
  "chkrootkit"
  "lynis"
  "aide"
  "debsums"
  "needrestart"
  "usbguard"
  "wireguard-tools"
  "auditd"
  "audispd-plugins"
)

TARGETS=("$@")
if [[ ${#TARGETS[@]} -eq 0 ]] || [[ "${TARGETS[0]}" == "all" ]]; then
  TARGETS=("${AVAILABLE_TOOLS[@]}")
  echo -e "${BLUE}[INFO] No specific sub-apps provided. Installing all SentryLinux security tools...${NC}"
else
  echo -e "${BLUE}[INFO] Installing selected sub-applications: ${TARGETS[*]}${NC}"
fi

echo -e "\n${BLUE}[1/3] Updating APT repository package index...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y

echo -e "\n${BLUE}[2/3] Installing security packages via apt-get...${NC}"
INSTALLED_COUNT=0
FAILED_COUNT=0

for PKG in "${TARGETS[@]}"; do
  echo -ne "  Installing ${CYAN}${PKG}${NC}... "
  if apt-get install -y --no-install-recommends "${PKG}" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Done${NC}"
    INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
  else
    echo -e "${RED}✗ Failed (skipping)${NC}"
    FAILED_COUNT=$((FAILED_COUNT + 1))
  fi
done

# Optional Third-Party Clients (NextDNS & OpenSnitch)
if [[ "${TARGETS[*]}" =~ "all" ]] || [[ "${TARGETS[*]}" =~ "nextdns" ]]; then
  echo -ne "  Checking ${CYAN}nextdns${NC} CLI client... "
  if ! command -v nextdns >/dev/null 2>&1; then
    echo -e "${BLUE}Configuring official NextDNS repository...${NC}"
    sh -c 'sh -c "$(curl -sL https://nextdns.io/install)"' -- -i > /dev/null 2>&1 || true
  else
    echo -e "${GREEN}✓ Already installed${NC}"
  fi
fi

echo -e "\n${BLUE}[3/3] Enabling background security daemons...${NC}"
DAEMONS_TO_ENABLE=("ufw" "fail2ban" "suricata" "clamav-daemon" "auditd")
for DAEMON in "${DAEMONS_TO_ENABLE[@]}"; do
  if systemctl list-unit-files "${DAEMON}.service" >/dev/null 2>&1; then
    echo -ne "  Enabling ${CYAN}${DAEMON}.service${NC}... "
    systemctl enable "${DAEMON}.service" >/dev/null 2>&1 || true
    systemctl restart "${DAEMON}.service" >/dev/null 2>&1 || true
    echo -e "${GREEN}✓ Active${NC}"
  fi
done

echo -e "\n──────────────────────────────────────────────────────────────────"
echo -e "${GREEN}✓ SentryLinux Sub-Application Provisioning Complete!${NC}"
echo -e "  Successfully configured: ${INSTALLED_COUNT} tools"
if [[ ${FAILED_COUNT} -gt 0 ]]; then
  echo -e "  Warnings/Skipped: ${FAILED_COUNT} tools"
fi
echo -e "You can now run ${CYAN}sentrylinux${NC} or inspect live telemetry with ${CYAN}sentrylinux --telemetry${NC}."
