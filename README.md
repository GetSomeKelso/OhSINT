# OhSINT

Unified OSINT reconnaissance orchestrator that wraps 28 open-source intelligence tools behind a single CLI and MCP server. Designed to run on Kali Linux and connect to Claude Desktop on a Windows host via SSE.

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

### LinkedIn / People Recon

| Tool | Description | Install Method |
|------|-------------|----------------|
| CrossLinked | LinkedIn employee enum via search engine scraping (passive) | `pip` |
| InSpy | Employee enumeration + tech stack from job listings | git clone |
| linkedin2username | Authenticated LinkedIn scraping via Selenium | git clone |
| Sherlock | Username search across 400+ social media sites | `pip` |
| Maigret | Username search across 3,000+ sites with profile data extraction | `pip` |
| Holehe | Email-to-platform registration check via password reset endpoints | `pip` |
| LinkedInt | LinkedIn profile deep-scraping (archived, Tier 2) | git clone |

### Passive Infrastructure

| Tool | Description | Install Method |
|------|-------------|----------------|
| Subfinder | Fast passive subdomain enumeration via 40+ APIs | `go install` |
| crt.sh | Certificate Transparency log search | API-based (httpx) |
| WHOIS | Domain registration and ownership lookup | `apt` (pre-installed on Kali) |

### Threat Intel & Breach Data

| Tool | Description | Install Method |
|------|-------------|----------------|
| VirusTotal | Domain/IP threat reputation — malicious scores, DNS, categories | API-based (httpx) |
| h8mail | Email breach hunting — HIBP, Snusbase, LeakLookup, Dehashed | `pip` |
| waymore | Web archive URL extraction — Wayback Machine, Common Crawl, OTX | `pip` |

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
| `infrastructure` | Passive domain intel — subdomains, certificates, WHOIS, DNS |
| `threat-intel` | Threat reputation, breach exposure, archived attack surface |
| `active` | Direct interaction with target (inherits passive) |
| `metadata` | Document and metadata focused |
| `social` | People and social media focused |
| `people` | LinkedIn enumeration, username discovery, social profile mapping |
| `full` | All tools, all modules (inherits active) |

Profiles are defined in `configs/scan_profiles.yaml`.

## Architecture

```
src/
├── cli.py              # Click CLI (ohsint)
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
    ├── crosslinked.py  # LinkedIn employee enum (passive)
    ├── inspy.py        # EmpSpy + TechSpy
    ├── linkedin2username.py  # Authenticated LinkedIn scraping
    ├── sherlock_tool.py      # Username search (400+ sites)
    ├── linkedint.py    # LinkedIn deep-scraping (archived)
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
pip install shodan crosslinked sherlock-project
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

# InSpy — LinkedIn employee + tech stack enumeration
git clone https://github.com/jobroche/InSpy.git
pip install -r InSpy/requirements.txt

# linkedin2username — authenticated LinkedIn scraping
git clone https://github.com/initstring/linkedin2username.git
pip install -r linkedin2username/requirements.txt

# LinkedInt — LinkedIn deep-scraping (archived, may not work)
git clone https://github.com/mdsecactivebreach/LinkedInt.git
```

> **Note:** linkedin2username requires a browser for Selenium:
> ```bash
> sudo apt install -y chromium chromium-driver
> ```

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
ohsint install-check
```

All 20 tools should show ✓ (LinkedInt may show as non-functional — this is expected).

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
ohsint api-keys
```

API keys can also be set via environment variables: `OSINT_<TOOL>_<KEY>` (uppercased).

### 5. Connect to Claude Desktop (Optional)

#### VM Port Forwarding

**Hyper-V (Default Switch):**

No port forwarding needed. The host can reach the VM directly by IP.

1. Find the VM's IP on Kali: `ip addr show eth0 | grep inet` (typically `172.x.x.x`)
2. The server must bind to `0.0.0.0` (not `127.0.0.1`) so the host can reach it
3. Use the VM's IP in the Claude Desktop config

> **Warning:** Default Switch assigns a **dynamic IP** that changes on VM reboot.
> You'll need to update the Claude Desktop config each time the IP changes.
> For a stable IP, create an Internal virtual switch with a fixed subnet (see below).

**Hyper-V (Static IP with Internal Switch — recommended):**

Create a dedicated virtual switch with a fixed subnet so the VM IP never changes:

On Windows (PowerShell as Admin):
```powershell
# Create an internal switch
New-VMSwitch -Name "OhSINT" -SwitchType Internal

# Find the new adapter's interface index
Get-NetAdapter | Where-Object { $_.Name -match "OhSINT" }

# Assign a static IP to the Windows side (use ifIndex from above)
New-NetIPAddress -IPAddress 192.168.50.1 -PrefixLength 24 -InterfaceIndex <ifIndex>

# Enable NAT so the VM can still reach the internet
New-NetNat -Name "OhSINTNAT" -InternalIPInterfaceAddressPrefix 192.168.50.0/24
```

Then in Hyper-V Manager, add the "OhSINT" switch as a network adapter on your Kali VM.

On the Kali VM, configure the new adapter with a static IP:
```bash
# Find the new interface name (e.g., eth1)
ip link show

# Edit network config
sudo nano /etc/network/interfaces
```

Add:
```
auto eth1
iface eth1 inet static
    address 192.168.50.10
    netmask 255.255.255.0
    gateway 192.168.50.1
    dns-nameservers 8.8.8.8
```

```bash
sudo systemctl restart networking
```

Your permanent MCP URL becomes `http://192.168.50.10:8055/sse` — no more IP changes.

**VirtualBox:** Settings → Network → Advanced → Port Forwarding

| Name | Protocol | Host IP | Host Port | Guest IP | Guest Port |
|------|----------|---------|-----------|----------|------------|
| mcp  | TCP      | 127.0.0.1 | 8055    |          | 8055       |

**VMware:** NAT settings → Port Forwarding → add `127.0.0.1:8055 → :8055`

#### Start the MCP Server

On the Kali VM:

```bash
source ~/Tools/OhSINT/.venv/bin/activate

# VirtualBox / VMware (localhost only, port forwarded to host)
ohsint-mcp

# Hyper-V (must bind to all interfaces)
ohsint-mcp --host 0.0.0.0
```

Available flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `127.0.0.1` | Bind address (`0.0.0.0` for Hyper-V) |
| `--port` | `8055` | Listen port |

#### Claude Desktop Config

On Windows, edit `%APPDATA%\Claude\claude_desktop_config.json` and add `ohsint` to the `mcpServers` block:

**VirtualBox / VMware** (port forwarded):
```json
"ohsint": {
  "url": "http://127.0.0.1:8055/sse"
}
```

**Hyper-V Default Switch** (use VM's IP):
```json
"ohsint": {
  "url": "http://<VM-IP>:8055/sse"
}
```

**Hyper-V Internal Switch** (static IP):
```json
"ohsint": {
  "url": "http://192.168.50.10:8055/sse"
}
```

> **Note:** This uses the SSE `"url"` format, not the `"command"` / `"args"` format used by stdio-based MCP servers.

Restart Claude Desktop. The OhSINT tools will appear in the tool list.

#### Claude Code Config

To use OhSINT tools from Claude Code, add a `.mcp.json` file in the project root.

Claude Code requires `mcp-remote` to bridge SSE servers (needs Node.js/npx):

```json
{
  "mcpServers": {
    "ohsint": {
      "command": "npx",
      "args": ["mcp-remote", "http://<VM-IP>:8055/sse", "--allow-http"]
    }
  }
}
```

> **Note:** `--allow-http` is required for non-HTTPS connections. For static IP setups, replace `<VM-IP>` with `192.168.50.10`.

Restart Claude Code for the tools to load.

## CLI Usage

```bash
# Dry run first — see what would execute
ohsint full-recon -t example.com -p passive --authorization --dry-run

# Full passive recon
ohsint full-recon -t example.com -p passive --authorization

# Active recon (direct interaction with target)
ohsint full-recon -t example.com -p active --authorization

# Single tool
ohsint tool -t example.com theharvester --authorization

# List tools and installation status
ohsint list-tools

# Check everything is configured
ohsint install-check

# Show API key status
ohsint api-keys
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
| `osint_subfinder` | Fast passive subdomain enumeration via 40+ APIs |
| `osint_crtsh` | Certificate Transparency log search |
| `osint_whois` | WHOIS domain registration lookup |
| `osint_virustotal` | Domain/IP threat reputation via VirusTotal |
| `osint_h8mail` | Email breach hunting (HIBP, Snusbase, etc.) |
| `osint_waymore` | Web archive URL extraction (Wayback, Common Crawl) |
| `osint_maigret` | Username search across 3,000+ sites (better than Sherlock) |
| `osint_holehe` | Email-to-platform registration check (120+ sites) |
| `osint_crosslinked` | LinkedIn employee enum via search engines (passive) |
| `osint_inspy` | Employee + tech stack enumeration (EmpSpy/TechSpy) |
| `osint_linkedin2username` | Authenticated LinkedIn scraping (requires credentials) |
| `osint_sherlock` | Username search across 400+ social media sites |
| `osint_people_recon` | Full people recon pipeline (composite tool) |
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

Findings are deduplicated across tools and normalized into types: email, subdomain, IP address, person, document, credential, technology, vulnerability, social profile, geolocation, metadata, DNS record, port/service, ASN, sensitive file, username.

## Security

OhSINT has been audited against OWASP MCP Top 10 and OWASP LLM Top 10.

### Bearer Token Authentication (MCP07)

The MCP server supports bearer token auth to prevent unauthorized tool invocation.

Generate a token:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Add it to `configs/api_keys.yaml`:

```yaml
mcp_server:
  bearer_token: "your-token-here"
```

Start the server with auth:

```bash
ohsint-mcp --host 0.0.0.0 --token your-token-here
```

Set the token on the client side (Windows):

```bash
# Set environment variable (PowerShell)
$env:OHSINT_MCP_TOKEN = "your-token-here"

# Or permanently via System Properties > Environment Variables
```

The `.mcp.json` passes it automatically via `--header "Authorization:Bearer ${OHSINT_MCP_TOKEN}"`.

### Audit Log (MCP08)

All MCP tool invocations are logged to `results/audit.jsonl` with timestamp, tool name, target, success/failure, and execution time.

### DNS Rebinding Protection (LLM06)

When binding to `0.0.0.0`, the server restricts Host headers to private/RFC1918 networks only (10/8, 172.16/12, 192.168/16, 127/8). Add custom allowed hosts:

```bash
ohsint-mcp --host 0.0.0.0 --allowed-hosts "203.0.113.0/24,10.50.0.0/16"
```

### Command Sanitization (MCP01)

API keys and credentials are automatically redacted from subprocess command logs.

### Input Validation (MCP05)

All targets are validated against shell injection, path traversal, null bytes, and newline injection before execution.

## Docker (Alternative)

If you prefer Docker over a full VM:

```bash
cd docker
docker compose up --build
```

This builds a Kali-based container with all tools pre-installed and runs the CLI. See `docker/Dockerfile` and `docker/docker-compose.yml`.

## Legal

You **must** have written authorization from the target owner before running any scan. Every CLI command and MCP tool call requires explicit authorization confirmation. Unauthorized reconnaissance is illegal.
