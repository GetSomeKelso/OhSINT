# OhSINT

Unified OSINT reconnaissance orchestrator that wraps 14 open-source intelligence tools behind a single CLI and MCP server. Designed to run on Kali or Parrot Linux and connect to Claude Desktop on a Windows host via SSE.

## Tools

### Tier 1 — CLI-Native, Actively Maintained

| Tool | Binary | Description |
|------|--------|-------------|
| theHarvester | `theHarvester` | Harvest emails, subdomains, IPs from search engines |
| SpiderFoot | `spiderfoot` | Automated OSINT with 200+ modules |
| recon-ng | `recon-ng` | Modular web reconnaissance framework |
| Metagoofil | `metagoofil` | Document metadata harvesting |
| Shodan | `shodan` | Internet-connected device search |
| ExifTool | `exiftool` | File metadata extraction |
| github-dorks | `github-dorks` | GitHub sensitive information scanner |

### Tier 2 — CLI-Compatible, May Need Wrapper Logic

| Tool | Binary | Description |
|------|--------|-------------|
| XRay | `xray` | Network reconnaissance (Go, archived) |
| GooDork | `GooDork.py` | Google dorking (Python) |
| dork-cli | `dork-cli` | Google dork query runner |
| DataSploit | `datasploit` | OSINT visualizer |
| Snitch | `snitch` | Information gathering via dorks |
| VcsMap | `vcsmap` | Version control system mapper (Ruby) |
| Creepy | `creepy` | Geolocation OSINT |

## Scan Profiles

Profiles define which tools run and with what options. They support inheritance.

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
├── mcp/
│   └── server.py       # MCP server (ohsint-mcp) — SSE transport
└── tools/
    ├── base.py         # BaseTool ABC
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

### 1. Install on Kali/Parrot VM

```bash
# Clone the repo
git clone https://github.com/GetSomeKelso/OhSINT.git ~/Tools/OhSINT
cd ~/Tools/OhSINT

# Create a virtual environment and activate it
python3 -m venv .venv
source .venv/bin/activate

# Install the Python package (editable mode)
pip install -e .

# Install OSINT tools
# --- Available via pip ---
pip install shodan

# --- Available via apt (Kali) ---
sudo apt install libimage-exiftool-perl golang-go ruby ruby-dev theharvester recon-ng spiderfoot

# --- Install from source ---
mkdir -p ~/Tools/osint-deps && cd ~/Tools/osint-deps
git clone https://github.com/opsdisk/metagoofil.git && pip install -r metagoofil/requirements.txt
git clone https://github.com/techgaun/github-dorks.git && pip install -r github-dorks/requirements.txt
git clone https://github.com/jgor/dork-cli.git
git clone https://github.com/k3170makan/GooDork.git && pip install beautifulsoup4

# --- Go tools ---
git clone https://github.com/evilsocket/xray.git ~/Tools/osint-deps/xray
cd ~/Tools/osint-deps/xray && go build -o xray ./cmd/xray/ && sudo cp xray /usr/local/bin/
cd ~/Tools/osint-deps

# --- Ruby tools ---
gem install vcsmap

cd ~/Tools/OhSINT

# Verify installation
osint-orchestrator install-check
```

> **Note:** Always activate the venv (`source .venv/bin/activate`) before running `osint-orchestrator` or `ohsint-mcp`.

### 2. Configure API Keys

```bash
cp configs/api_keys.yaml.example configs/api_keys.yaml
```

Edit `configs/api_keys.yaml` with your keys:

- **Shodan** — `api_key`
- **theHarvester** — `github_token`, `hunter_api`, `intelx_api`, `securitytrails_api`
- **SpiderFoot** — `virustotal`, `censys_id`, `censys_secret`, `fullcontact`, `hunter`, `ipinfo`
- **recon-ng** — `builtwith_api`, `github_api`, `google_api`, `shodan_api`, `virustotal_api`, etc.
- **github-dorks** — `github_token`

API keys can also be set via environment variables: `OSINT_<TOOL>_<KEY>` (uppercased).

### 3. Connect to Claude Desktop

#### VM Port Forwarding

In your hypervisor (VirtualBox, VMware, etc.), forward the guest port to the Windows host:

**VirtualBox:** Settings → Network → Advanced → Port Forwarding

| Name | Protocol | Host IP | Host Port | Guest IP | Guest Port |
|------|----------|---------|-----------|----------|------------|
| mcp  | TCP      | 127.0.0.1 | 8055    |          | 8055       |

**VMware:** NAT settings → Port Forwarding → add `127.0.0.1:8055 → :8055`

#### Start the MCP Server

On the Kali/Parrot VM:

```bash
ohsint-mcp
```

Listens on `127.0.0.1:8055` with SSE transport.

#### Claude Desktop Config

On Windows, edit your Claude Desktop config (`%APPDATA%\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ohsint": {
      "url": "http://127.0.0.1:8055/sse"
    }
  }
}
```

Restart Claude Desktop. The OhSINT tools will appear in the tool list.

## CLI Usage

The CLI (`osint-orchestrator`) can be used directly on the VM for manual runs.

```bash
# Full passive recon
osint-orchestrator full-recon -t example.com -p passive --authorization

# Active recon (requires explicit auth)
osint-orchestrator full-recon -t example.com -p active --authorization

# Single tool
osint-orchestrator tool -t example.com theharvester --authorization

# Dry run — show what would execute
osint-orchestrator full-recon -t example.com -p full --authorization --dry-run

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
