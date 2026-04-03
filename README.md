# OhSINT

Unified OSINT reconnaissance orchestrator that wraps 28 open-source intelligence tools behind a single CLI and MCP server. Designed to run on Kali Linux and connect to Claude Desktop on a Windows host via SSE.

## Tools

### Tier 1 — CLI-Native, Actively Maintained

| Tool | Description | Install | API Key |
|------|-------------|---------|---------|
| theHarvester | Harvest emails, subdomains, IPs from search engines | `apt` (Kali) | Optional (GitHub, Hunter, IntelX, SecurityTrails) |
| SpiderFoot | Automated OSINT with 200+ modules | `apt` (Kali) | Optional (VirusTotal, Censys, Hunter, IPinfo) |
| recon-ng | Modular web reconnaissance framework | `apt` (Kali) | Optional (Shodan, BuiltWith, GitHub, Google) |
| Metagoofil | Document metadata harvesting | git clone | None |
| Shodan | Internet-connected device search | `pip` | **Required** (`shodan.api_key`) |
| ExifTool | File metadata extraction | `apt` | None |
| github-dorks | GitHub sensitive information scanner | git clone | **Required** (`github_dorks.github_token`) |

### LinkedIn / People Recon

| Tool | Description | Install | API Key |
|------|-------------|---------|---------|
| CrossLinked | LinkedIn employee enum via search engine scraping (passive) | `pip` | None |
| InSpy | Employee enumeration + tech stack from job listings | git clone | Optional (Hunter.io) |
| linkedin2username | Authenticated LinkedIn scraping via Selenium | git clone | **Required** (`linkedin.email`, `linkedin.password`) |
| Sherlock | Username search across 400+ social media sites | `pip` | None |
| Maigret | Username search across 3,000+ sites with profile data extraction | `pip` | None |
| Holehe | Email-to-platform registration check via password reset endpoints | `pip` | None |
| LinkedInt | LinkedIn profile deep-scraping (archived, Tier 2) | git clone | **Required** (`linkedin.email`, `linkedin.password`) |

### Passive Infrastructure

| Tool | Description | Install | API Key |
|------|-------------|---------|---------|
| Subfinder | Fast passive subdomain enumeration via 40+ APIs | `go install` | Optional (improves results with SecurityTrails, Censys, etc.) |
| crt.sh | Certificate Transparency log search | API-based (httpx) | None |
| WHOIS | Domain registration and ownership lookup | `apt` (Kali) | None |

### Threat Intel & Breach Data

| Tool | Description | Install | API Key |
|------|-------------|---------|---------|
| VirusTotal | Domain/IP threat reputation — malicious scores, DNS, categories | API-based (httpx) | **Required** (`virustotal.api_key`) |
| h8mail | Email breach hunting — HIBP, Snusbase, LeakLookup, Dehashed | `pip` | Optional (HIBP, Snusbase, LeakLookup keys improve results) |
| waymore | Web archive URL extraction — Wayback Machine, Common Crawl, OTX | `pip` | None |

### Tier 2 — CLI-Compatible

| Tool | Description | Install | API Key |
|------|-------------|---------|---------|
| Brave Search | Web search API for OSINT recon (replaces Bing) | API-based (httpx) | **Required** (`brave.api_key`) |
| XRay | Network reconnaissance (Go, archived) | git clone + go build | **Required** (`shodan.api_key`) |
| GooDork | Google dorking (Python, not Go) | git clone | None |
| dork-cli | Google dork query runner | git clone | None |
| DataSploit | OSINT visualizer | git clone | Optional (Shodan) |
| Snitch | Information gathering via dorks | git clone | None |
| VcsMap | Version control system mapper | `gem` (Ruby) | None |
| Creepy | Geolocation OSINT | git clone | None |

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
┌─────────────────────┐     SSE / mcp-remote      ┌─────────────────────────┐
│   Windows Host      │◄──────────────────────────►│   Kali Linux VM         │
│                     │    http://<IP>:8055/sse     │                         │
│  Claude Desktop     │                            │  ohsint-mcp server      │
│  Claude Code        │                            │    ├── Bearer token auth │
│  .mcp.json          │                            │    ├── Audit log         │
│                     │                            │    └── DNS rebinding     │
└─────────────────────┘                            │                         │
                                                   │  ohsint CLI             │
                                                   │    └── 28 tool wrappers │
                                                   └─────────────────────────┘
```

### Source Layout

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
    ├── base.py              # BaseTool ABC (is_passive, validate_target, _sanitize_command)
    ├── brave_search.py      # Brave Search API
    ├── crtsh.py             # Certificate Transparency log search (API)
    ├── subfinder.py         # Passive subdomain enumeration (40+ APIs)
    ├── whois_tool.py        # WHOIS/RDAP domain registration lookup
    ├── virustotal.py        # Domain/IP threat reputation (API)
    ├── h8mail.py            # Email breach hunting
    ├── waymore.py           # Web archive URL extraction
    ├── maigret_tool.py      # Username search (3,000+ sites)
    ├── holehe_tool.py       # Email-to-platform registration check
    ├── theharvester.py      # Emails, subdomains, IPs from search engines
    ├── spiderfoot.py        # Multi-source OSINT automation (200+ modules)
    ├── recon_ng.py          # Modular recon framework (Metasploit-style)
    ├── metagoofil.py        # Document metadata harvesting from domains
    ├── shodan_tool.py       # Internet-connected device search (API)
    ├── exiftool.py          # File metadata extraction (EXIF, GPS, author)
    ├── github_dorks.py      # GitHub repo scanning for leaked secrets
    ├── crosslinked.py       # LinkedIn employee enum via search engines (passive)
    ├── inspy.py             # Employee enumeration + tech stack from job listings
    ├── linkedin2username.py # Authenticated LinkedIn scraping via Selenium
    ├── sherlock_tool.py     # Username search across 400+ sites
    ├── linkedint.py         # LinkedIn profile deep-scraping (archived)
    ├── xray.py              # Network recon from public networks (archived)
    ├── goodork.py           # Google dorking from CLI (Python)
    ├── dork_cli.py          # Google dork queries with rate limiting
    ├── datasploit.py        # OSINT visualizer (Shodan, Censys, Clearbit)
    ├── snitch.py            # Information gathering via dorks
    ├── vcsmap.py            # Version control system mapper (Ruby)
    └── creepy.py            # Geolocation OSINT from social media
```

## Setup

### Prerequisites

- **Kali Linux** (bare metal, VM, or WSL2)
- **Python 3.10+**
- **Go 1.21+** (for subfinder, xray)
- **Ruby** (for vcsmap)
- **Node.js/npx** (for Claude Code MCP bridge via `mcp-remote`)

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
pip install shodan crosslinked sherlock-project maigret holehe h8mail waymore
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
# subfinder — passive subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

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

All 28 tools should show ✓ (LinkedInt may show as non-functional — this is expected).

### 4. Configure API Keys

```bash
cp configs/api_keys.yaml.example configs/api_keys.yaml
nano configs/api_keys.yaml
```

#### Required keys

| Config Key | Where to Get It | Tools Unlocked | Free Tier |
|------------|----------------|----------------|-----------|
| `shodan.api_key` | https://account.shodan.io | Shodan, XRay, recon-ng, DataSploit | $49 one-time |
| `github_dorks.github_token` | https://github.com/settings/tokens | github-dorks, theHarvester, recon-ng | Free |
| `brave.api_key` | https://brave.com/search/api/ | Brave Search | 2,000 req/mo free |
| `virustotal.api_key` | https://www.virustotal.com/gui/my-apikey | VirusTotal | 4 req/min, 500/day |
| `mcp_server.bearer_token` | Self-generated (see Security section) | MCP server auth | N/A |

GitHub token scopes needed: `public_repo`, `read:org`, `read:user` (read-only, no write permissions).

#### Required for active recon only

| Config Key | Where to Get It | Tools Unlocked | Notes |
|------------|----------------|----------------|-------|
| `linkedin.email` | Your LinkedIn account | linkedin2username, LinkedInt | Use a dedicated research account |
| `linkedin.password` | Your LinkedIn account | linkedin2username, LinkedInt | Never use your personal account |

#### Optional keys (improve coverage)

| Config Key | Where to Get It | Tools Improved |
|------------|----------------|----------------|
| `theharvester.hunter_api` | https://hunter.io/api_key | theHarvester email verification |
| `theharvester.securitytrails_api` | https://securitytrails.com/app/account | theHarvester subdomain/DNS history |
| `theharvester.intelx_api` | https://intelx.io/account?tab=developer | theHarvester leaked data search |
| `spiderfoot.virustotal` | Same as above | SpiderFoot threat enrichment |
| `spiderfoot.censys_id` / `censys_secret` | https://search.censys.io/account/api | SpiderFoot certificate analysis |
| `spiderfoot.hunter` | Same as above | SpiderFoot email verification |
| `spiderfoot.ipinfo` | https://ipinfo.io/account/token | SpiderFoot IP geolocation |
| `hunter_io.api_key` | https://hunter.io/api_key | InSpy email verification |
| `recon_ng.shodan_api` | Same as Shodan above | recon-ng Shodan modules |
| `recon_ng.github_api` | Same as GitHub above | recon-ng GitHub modules |

#### Check key status

```bash
ohsint api-keys
```

API keys can also be set via environment variables: `OSINT_<TOOL>_<KEY>` (uppercased).

### 5. Connect to Claude (Optional)

OhSINT exposes all tools as MCP tools via an SSE server. See **[docs/mcp-setup.md](docs/mcp-setup.md)** for full setup instructions covering:

- Hyper-V / VirtualBox / VMware port forwarding
- Static IP configuration
- Claude Desktop and Claude Code config
- Bearer token authentication
- Troubleshooting

Quick start:

```bash
# On Kali VM
ohsint-mcp --host 0.0.0.0 --token YOUR_TOKEN
```

```json
// .mcp.json on Windows (Claude Code)
{
  "mcpServers": {
    "ohsint": {
      "command": "npx",
      "args": ["mcp-remote", "http://<VM-IP>:8055/sse", "--allow-http",
               "--header", "Authorization:Bearer ${OHSINT_MCP_TOKEN}"]
    }
  }
}
```

## CLI Usage

```bash
# Passive recon — no authorization needed (queries public sources only)
ohsint full-recon -t example.com -p passive
ohsint full-recon -t example.com -p infrastructure
ohsint full-recon -t example.com -p threat-intel
ohsint full-recon -t example.com -p social

# Active recon — requires explicit authorization
ohsint full-recon -t example.com -p active --authorization
ohsint full-recon -t example.com -p full --authorization

# Single tool (passive tools run without --authorization)
ohsint tool -t example.com theharvester
ohsint tool -t example.com subfinder
ohsint tool -t user@example.com holehe

# Single tool (active tools require --authorization)
ohsint tool -t "Company Name" spiderfoot --authorization

# Dry run — see what would execute without running
ohsint full-recon -t example.com -p full --authorization --dry-run

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

32 MCP tools are available when connected via Claude Desktop or Claude Code. See **[docs/mcp-setup.md](docs/mcp-setup.md)** for the full tool list, setup instructions, and troubleshooting.

**Passive tools** run without `authorization_confirmed`. **Active tools** (spiderfoot, recon-ng, linkedin2username, xray, linkedint) require `authorization_confirmed: true`.

## Reports

Reports are saved in three formats under `results/<target>/<timestamp>/`:

- `report.json` — machine-readable, full structured data
- `report.md` — markdown summary with findings tables
- `report.html` — styled dark-theme HTML report

Findings are deduplicated across tools and normalized into types: email, subdomain, IP address, person, document, credential, technology, vulnerability, social profile, geolocation, metadata, DNS record, port/service, ASN, sensitive file, username, certificate, WHOIS record, breach, reputation.

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
