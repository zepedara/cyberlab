#!/usr/bin/env bash
# LAB-LINUX provisioner — SIFT + REMnux (add-on) + selected Kali tools on Ubuntu 22.04.
# Idempotent: safe to re-run. Snapshot the VM at 'clean-baseline' after first success.
set -euo pipefail
log(){ echo "[lab-linux] $*"; }

log "1/3 SIFT Workstation (SANS DFIR toolset)"
if ! command -v sift >/dev/null 2>&1; then
  wget -q -O /tmp/sift https://github.com/teamdfir/sift-cli/releases/latest/download/sift-cli-linux
  sudo install /tmp/sift /usr/local/bin/sift
fi
sudo sift install --mode=server || sift install

log "2/3 REMnux (malware-analysis toolset, add-on mode onto SIFT)"
if ! command -v remnux >/dev/null 2>&1; then
  wget -q -O /tmp/remnux https://REMnux.org/remnux-cli
  chmod +x /tmp/remnux && sudo mv /tmp/remnux /usr/local/bin/remnux
fi
sudo remnux install --mode=addon

log "3/3 selected Kali/forensics + offensive tools (via apt)"
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
  sleuthkit autopsy volatility3 bulk-extractor binwalk foremost scalpel \
  yara radare2 wireshark tshark nmap netcat-openbsd hydra john hashcat \
  ettercap-graphical exiftool clamav ssdeep || true

log "done. Verify: dpkg -l | wc -l ; volatility3 -h ; sift --version"
