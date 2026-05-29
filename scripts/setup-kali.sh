#!/usr/bin/env bash
#
# OhSINT — Kali VM one-shot setup script
#
# Installs every tool binary the 5 pipelines need, in the correct way,
# avoiding the gotchas documented in tasks/lessons.md:
#   - Go builds write scratch to a tmpfs /tmp (954M) → overflow. Fixed via TMPDIR.
#   - Go installs to ~/go/bin which isn't on the MCP server's PATH → symlink to /usr/local/bin.
#   - trufflehog can't `go install` (replace directives) → official install script.
#   - gitleaks module path is zricethezav/gitleaks, not gitleaks/gitleaks.
#   - LinkFinder / SecretFinder aren't pip packages → git clone + symlink.
#   - js-beautify via pip jsbeautifier (no Node needed); getjs skipped (subjs covers it).
#
# Idempotent — safe to re-run. Run from the repo root: bash scripts/setup-kali.sh
#
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPS_DIR="$HOME/Tools/osint-deps"
GOBIN="$(go env GOPATH 2>/dev/null)/bin"

echo "==> OhSINT Kali setup starting"
echo "    repo: $REPO_DIR"
echo "    go bin: $GOBIN"

# ---------------------------------------------------------------------------
# 0. Prerequisites
# ---------------------------------------------------------------------------
command -v go >/dev/null   || { echo "ERROR: Go not installed. Run: sudo apt install -y golang-go"; exit 1; }
command -v pip >/dev/null  || { echo "ERROR: pip not installed. Run: sudo apt install -y python3-pip"; exit 1; }
command -v git >/dev/null  || { echo "ERROR: git not installed."; exit 1; }

# Go build scratch on the real disk, NOT the 954M tmpfs /tmp
mkdir -p "$HOME/.gotmp"
export TMPDIR="$HOME/.gotmp"
export PATH="$PATH:$GOBIN"

# ---------------------------------------------------------------------------
# 1. Go binaries
# ---------------------------------------------------------------------------
echo "==> Installing Go binaries (this takes several minutes)..."

GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/projectdiscovery/uncover/cmd/uncover@latest"
  "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
  "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
  "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
  "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
  "github.com/projectdiscovery/cvemap/cmd/cvemap@latest"
  "github.com/projectdiscovery/alterx/cmd/alterx@latest"
  "github.com/projectdiscovery/notify/cmd/notify@latest"
  "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  "github.com/PentestPad/subzy@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/lc/subjs@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/tomnomnom/gf@latest"
  "github.com/zricethezav/gitleaks/v8@latest"
)

for tool in "${GO_TOOLS[@]}"; do
  echo "    -> go install $tool"
  go install "$tool" || echo "    !! FAILED: $tool (continuing)"
done

# katana needs CGO
echo "    -> go install katana (CGO)"
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest || echo "    !! FAILED: katana"

# ---------------------------------------------------------------------------
# 2. Symlink Go binaries to /usr/local/bin (on the MCP server's PATH)
# ---------------------------------------------------------------------------
echo "==> Symlinking Go binaries to /usr/local/bin"
if [ -d "$GOBIN" ]; then
  sudo ln -sf "$GOBIN"/* /usr/local/bin/
fi

# ---------------------------------------------------------------------------
# 3. trufflehog (official install script — can't go install due to replace directives)
# ---------------------------------------------------------------------------
echo "==> Installing trufflehog"
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
  | sudo sh -s -- -b /usr/local/bin || echo "    !! trufflehog install failed"

# ---------------------------------------------------------------------------
# 4. pip tools
# ---------------------------------------------------------------------------
echo "==> Installing pip tools"
pip install --break-system-packages \
  waymore h8mail maigret holehe sherlock-project crosslinked jsbeautifier \
  || echo "    !! some pip tools failed (mitmproxy conflict warnings are harmless)"

# ---------------------------------------------------------------------------
# 5. Git-clone tools (LinkFinder, SecretFinder — not on PyPI)
# ---------------------------------------------------------------------------
echo "==> Installing LinkFinder + SecretFinder"
mkdir -p "$DEPS_DIR"

if [ ! -d "$DEPS_DIR/LinkFinder" ]; then
  git clone https://github.com/GerbenJavado/LinkFinder.git "$DEPS_DIR/LinkFinder"
fi
pip install "$DEPS_DIR/LinkFinder" --break-system-packages || true
chmod +x "$DEPS_DIR/LinkFinder/linkfinder.py"
sudo ln -sf "$DEPS_DIR/LinkFinder/linkfinder.py" /usr/local/bin/linkfinder

if [ ! -d "$DEPS_DIR/SecretFinder" ]; then
  git clone https://github.com/m4ll0k/SecretFinder.git "$DEPS_DIR/SecretFinder"
fi
pip install requests jsbeautifier --break-system-packages || true
chmod +x "$DEPS_DIR/SecretFinder/SecretFinder.py"
sudo ln -sf "$DEPS_DIR/SecretFinder/SecretFinder.py" /usr/local/bin/SecretFinder

# ---------------------------------------------------------------------------
# 6. nuclei templates + gf patterns
# ---------------------------------------------------------------------------
echo "==> Updating nuclei templates"
nuclei -update-templates -silent || echo "    !! nuclei template update failed"

echo "==> Installing gf patterns"
mkdir -p "$HOME/.gf"
cp "$REPO_DIR"/configs/gf_patterns/*.json "$HOME/.gf/" 2>/dev/null || echo "    !! gf patterns not found in repo"

# ---------------------------------------------------------------------------
# 7. Persist PATH for future shells
# ---------------------------------------------------------------------------
SHELL_RC="$HOME/.zshrc"
[ -f "$SHELL_RC" ] || SHELL_RC="$HOME/.bashrc"
if ! grep -q 'OhSINT PATH' "$SHELL_RC" 2>/dev/null; then
  {
    echo ""
    echo "# OhSINT PATH (Go bins + build scratch off tmpfs)"
    echo "export PATH=\$PATH:$GOBIN:/usr/local/bin"
    echo "export TMPDIR=\$HOME/.gotmp"
  } >> "$SHELL_RC"
  echo "==> Added PATH + TMPDIR to $SHELL_RC"
fi

echo ""
echo "==> Setup complete."
echo "    Verify with:  ohsint install-check"
echo "    Start MCP:    ohsint-mcp --host <vm-ip>   (see docs/mcp-setup.md)"
echo ""
echo "    NOT installed (need accounts/contracts/manual):"
echo "      - FCRA commercial tools (whitepages_pro, beenverified, lexisnexis, tlo, clear, tracers, idi, smartmove)"
echo "      - LinkedIn tools (inspy, linkedin2username, linkedint)"
echo "      - getjs (npm; redundant with subjs), vcsmap (ruby gem)"
