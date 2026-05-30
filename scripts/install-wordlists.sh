#!/usr/bin/env bash
#
# OhSINT — install the wordlists used by the takeover + js-analysis pipelines.
#   - SecLists           -> /opt/SecLists        (Change 2: API-doc path source)
#   - n0kovo_subdomains  -> /opt/wordlists/...    (Change 1: DNS brute-force)
#
# Idempotent — checks first, only clones what's missing. Safe to re-run.
# Run on the Kali VM:  bash scripts/install-wordlists.sh
#
set -uo pipefail

SECLISTS_DIR="/opt/SecLists"
WORDLISTS_DIR="/opt/wordlists"
N0KOVO_DIR="$WORDLISTS_DIR/n0kovo_subdomains"

echo "==> Installing OhSINT wordlists"
sudo mkdir -p "$WORDLISTS_DIR"

# SecLists — prefer existing apt install at /usr/share/seclists if present
if [ -d /usr/share/seclists ] && [ ! -d "$SECLISTS_DIR" ]; then
  echo "    SecLists found at /usr/share/seclists (apt) — symlinking to $SECLISTS_DIR"
  sudo ln -sf /usr/share/seclists "$SECLISTS_DIR"
elif [ -d "$SECLISTS_DIR" ]; then
  echo "    [OK] SecLists already at $SECLISTS_DIR"
else
  echo "    -> cloning SecLists (shallow) to $SECLISTS_DIR"
  sudo git clone --depth 1 https://github.com/danielmiessler/SecLists "$SECLISTS_DIR"
fi

# n0kovo subdomains
if [ -d "$N0KOVO_DIR" ]; then
  echo "    [OK] n0kovo already at $N0KOVO_DIR"
else
  echo "    -> cloning n0kovo_subdomains to $N0KOVO_DIR"
  sudo git clone --depth 1 https://github.com/n0kovo/n0kovo_subdomains "$N0KOVO_DIR"
fi

echo "==> Verify (the two files OhSINT actually reads):"
ls -d "$SECLISTS_DIR/Discovery/Web-Content/api/api-endpoints.txt" \
      "$N0KOVO_DIR/n0kovo_subdomains_huge.txt" 2>&1

echo ""
echo "==> Done. Confirm with:  ohsint install-check   (see the WORDLISTS section)"
