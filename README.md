# OhSINT

Unified OSINT reconnaissance orchestrator that wraps 15 open-source intelligence tools behind a single CLI and MCP server. Designed to run on Kali Linux and connect to Claude Desktop on a Windows host via SSE.

## Tools

### Tier 1 — CLI-Native, Actively Maintained

| Tool | Description | Install Method |
|------|-------------|----------------|
| theHarvester | Harvest emails, subdomains, IPs from search engines | `apt` (Kali) |
| SpiderFoot | Automated OSINT with 200+ modules | `apt` (Kali) |
| recon-ng | Modular web reconnaissance framework | `apt` (Kali) |
| Metagoofil | Document metadata harvesting | git clone |
| Shodan | Internet-connected device search | `pip` |
| ExifTool | File metadata extraction | `apt` |
| github-dorks | GitHub sensitive information scanner | git clone |

### Tier 2 — CLI-Compatible

| Tool | Description | Install Method |
|------|-------------|----------------|
| Brave Search | Web search API for OSINT recon (replaces Bing) | API-based (httpx) |
| XRay | Network reconnaissance (Go, archived) | git clone + go build |
| GooDork | Google dorking (Python, not Go) | git clone |
| dork-cli | Google dork query runner | git clone |
| DataSploit | OSINT visualizer | git clone |
| Snitch | Information gathering via dorks | git clone |
| VcsMap | Version control system mapper | `gem` (Ruby) |
| Creepy | Geolocation OSINT | git clone |

## Scan Profiles

| Profile | Description |
|---------|-------------|
| `passive` | Zero interaction with target infrastructure |
| `active` | Direct interaction with target (inherits passive) |
| `metadata` | Document and metadata focused |
| `social` | People and social media focused |
| `full` | All tools, all modules (inherits active) |

Profiles are defined in `configs/scan_profiles.yaml`.

## Architecture

```
src/
├── cli.py              # Click CLI (osint-orchestrator)
├── config.py           # Config loader (API keys, profiles)
├── models.py           # Pydantic models (ToolResult, IntelFinding, ReconReport)
├── orchestrator.py     # Parallel/sequential tool execution engine
├── registry.py         # Tool registration decorator
├── report.py           # Report save/load utilities
├── target.py           # Target type detection
├── mcp/
│   └── server.py       # MCP server (ohsint-mcp) — SSE transport
└── tools/
    ├── base.py         # BaseTool ABC
    ├── brave_search.py # Brave Search API
    ├── theharvester.py
    ├── spiderfoot.py
    ├── recon_ng.py
    ├── metagoofil.py
    ├── shodan_tool.py
    ├── exiftool.py
    ├── github_dorks.py
    ├── xray.py
    ├── goodork.py
    ├── dork_cli.py
    ├── datasploit.py
    ├── snitch.py
    ├── vcsmap.py
    └── creepy.py
```

## Setup

### Prerequisites

- **Kali Linux** (bare metal, VM, or WSL2)
- **Python 3.10+**
- **Go** (for xray)
- **Ruby** (for vcsmap)

### 1. Install OhSINT

```bash
# Clone the repo
git clone https://github.com/GetSomeKelso/OhSINT.git ~/Tools/OhSINT
cd ~/Tools/OhSINT

# Create a virtual environment (required on modern Debian/Kali)
python3 -m venv .venv
source .venv/bin/activate

# Install OhSINT
pip install -e .
```

> **Important:** Always activate the venv before running OhSINT:
> ```bash
> source ~/Tools/OhSINT/.venv/bin/activate
> ```

### 2. Install OSINT Tools

#### Via apt (Kali has most of these)

```bash
sudo apt install -y libimage-exiftool-perl golang-go ruby ruby-dev theharvester recon-ng spiderfoot
```

#### Via pip (inside the venv)

```bash
pip install shodan
```

#### From source (git clone)

```bash
mkdir -p ~/Tools/osint-deps && cd ~/Tools/osint-deps

# metagoofil — document metadata harvester
git clone https://github.com/opsdisk/metagoofil.git
pip install -r metagoofil/requirements.txt

# github-dorks — GitHub secret scanner
# NOTE: main script is github-dork.py (singular, not github-dorks.py)
git clone https://github.com/techgaun/github-dorks.git
pip install -r github-dorks/requirements.txt

# dork-cli — Google dorking
# NOTE: main script is dork-cli.py
git clone https://github.com/jgor/dork-cli.git

# GooDork — Google dorking (Python, despite the name)
git clone https://github.com/k3170makan/GooDork.git
pip install beautifulsoup4

# datasploit — OSINT visualizer
git clone https://github.com/upgoingstar/datasploit.git

# snitch — dork-based info gathering
git clone https://github.com/Smaash/snitch.git

# creepy — geolocation OSINT
# NOTE: CreepyMain.py is inside the nested creepy/creepy/ directory
git clone https://github.com/ilektrojohn/creepy.git
```

#### Go tools

```bash
# xray — network recon (archived, go install doesn't work)
git clone https://github.com/evilsocket/xray.git ~/Tools/osint-deps/xray
cd ~/Tools/osint-deps/xray && go build -o xray ./cmd/xray/
sudo cp xray /usr/local/bin/
```

#### Ruby tools

```bash
gem install vcsmap
```

> **Note:** If gem warns about PATH, add the gem bin directory:
> ```bash
> echo 'export PATH="$HOME/.local/share/gem/ruby/3.3.0/bin:$PATH"' >> ~/.zshrc
> source ~/.zshrc
> ```
> Adjust the Ruby version (`3.3.0`) to match yours (`ruby --version`).

### 3. Verify Installation

```bash
cd ~/Tools/OhSINT
source .venv/bin/activate
osint-orchestrator install-check
```

All 15 tools should show ✓.

### 4. Configure API Keys

```bash
cp configs/api_keys.yaml.example configs/api_keys.yaml
nano configs/api_keys.yaml
```

#### Priority keys (start with these)

| Key | Where to Get It | Tools Unlocked |
|-----|----------------|----------------|
| **Shodan** `api_key` | https://account.shodan.io | shodan, xray, recon_ng, datasploit |
| **GitHub** `github_token` | https://github.com/settings/tokens | github_dorks, theharvester, recon_ng |
| **Brave** `api_key` | https://brave.com/search/api/ | brave_search |

GitHub token scopes needed: `public_repo`, `read:org`, `read:user` (read-only, no write permissions).

#### Optional keys (add later for better coverage)

| Key | Where to Get It |
|-----|----------------|
| Hunter `hunter_api` | https://hunter.io/api_key |
| SecurityTrails `securitytrails_api` | https://securitytrails.com/app/account |
| IntelX `intelx_api` | https://intelx.io/account?tab=developer |
| VirusTotal `virustotal` | https://www.virustotal.com/gui/my-apikey |
| Censys `censys_id` / `censys_secret` | https://search.censys.io/account/api |
| IPinfo `ipinfo` | https://ipinfo.io/account/token |

Check key status:

```bash
osint-orchestrator api-keys
```

API keys can also be set via environment variables: `OSINT_<TOOL>_<KEY>` (uppercased).

### 5. Connect to Claude Desktop (Optional)

#### VM Port Forwarding

**Hyper-V:** Use the Default Switch (NAT) and find the VM's IP with `ip addr` on the guest. No port forwarding needed — the host can reach the VM IP directly. Use the VM's IP instead of `127.0.0.1` in the Claude Desktop config below.

Alternatively, create an Internal or External virtual switch if you need a static IP.

**VirtualBox:** Settings → Network → Advanced → Port Forwarding

| Name | Protocol | Host IP | Host Port | Guest IP | Guest Port |
|------|----------|---------|-----------|----------|------------|
| mcp  | TCP      | 127.0.0.1 | 8055    |          | 8055       |

**VMware:** NAT settings → Port Forwarding → add `127.0.0.1:8055 → :8055`

#### Start the MCP Server

```bash
source ~/Tools/OhSINT/.venv/bin/activate
ohsint-mcp
```

Listens on `127.0.0.1:8055` with SSE transport by default.

> **Hyper-V users:** Bind to `0.0.0.0` so the host can reach the server:
> ```bash
> ohsint-mcp --host 0.0.0.0
> ```

#### Claude Desktop Config

On Windows, edit `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ohsint": {
      "url": "http://127.0.0.1:8055/sse"
    }
  }
}
```

> **Hyper-V users:** Replace `127.0.0.1` with your VM's IP (run `ip addr` on the guest):
> ```json
> "url": "http://<VM-IP>:8055/sse"
> ```
```

Restart Claude Desktop. The OhSINT tools will appear in the tool list.

## CLI Usage

```bash
# Dry run first — see what would execute
osint-orchestrator full-recon -t example.com -p passive --authorization --dry-run

# Full passive recon
osint-orchestrator full-recon -t example.com -p passive --authorization

# Active recon (direct interaction with target)
osint-orchestrator full-recon -t example.com -p active --authorization

# Single tool
osint-orchestrator tool -t example.com theharvester --authorization

# List tools and installation status
osint-orchestrator list-tools

# Check everything is configured
osint-orchestrator install-check

# Show API key status
osint-orchestrator api-keys
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--authorization` | Confirm written permission to scan the target |
| `-o, --output DIR` | Output directory (default: `results/<target>/<timestamp>/`) |
| `-f, --format` | Report format: `json`, `md`, `html`, `all` (default: `all`) |
| `--timeout SECS` | Per-tool timeout (default: 300) |
| `-P / --no-parallel` | Enable/disable parallel execution (default: parallel) |
| `-v, --verbose` | Verbose output |
| `--dry-run` | Show what would execute without running |

## MCP Tools

When connected via Claude Desktop, the following tools are available:

| MCP Tool | Description |
|----------|-------------|
| `osint_full_recon` | Run a full scan profile against a target |
| `osint_theharvester` | Harvest emails, subdomains, IPs |
| `osint_spiderfoot` | Automated OSINT scan (200+ modules) |
| `osint_recon_ng` | Run recon-ng modules |
| `osint_metagoofil` | Harvest and analyze document metadata |
| `osint_shodan` | Search Shodan for devices and services |
| `osint_exiftool` | Extract metadata from files |
| `osint_github_dorks` | Scan GitHub for sensitive info leaks |
| `osint_google_dorks` | Run Google dork queries |
| `osint_brave_search` | Web search via Brave Search API |
| `osint_xray` | Network recon with XRay |
| `osint_datasploit` | OSINT visualizer |
| `osint_list_tools` | List tools and installation status |
| `osint_install_check` | Verify tools and API keys |
| `osint_report` | Generate report from existing results |

All scan tools require `authorization_confirmed: true` to execute.

## Reports

Reports are saved in three formats under `results/<target>/<timestamp>/`:

- `report.json` — machine-readable, full structured data
- `report.md` — markdown summary with findings tables
- `report.html` — styled dark-theme HTML report

Findings are deduplicated across tools and normalized into types: email, subdomain, IP address, person, document, credential, technology, vulnerability, social profile, geolocation, metadata, DNS record, port/service, ASN, sensitive file.

## Docker (Alternative)

If you prefer Docker over a full VM:

```bash
cd docker
docker compose up --build
```

This builds a Kali-based container with all tools pre-installed and runs the CLI. See `docker/Dockerfile` and `docker/docker-compose.yml`.

## Legal

You **must** have written authorization from the target owner before running any scan. Every CLI command and MCP tool call requires explicit authorization confirmation. Unauthorized reconnaissance is illegal.
