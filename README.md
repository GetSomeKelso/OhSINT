# OhSINT

Unified OSINT reconnaissance orchestrator that wraps 43 open-source intelligence tools behind a single CLI and MCP server. Runs on a Kali Linux VM and connects to Claude Desktop or Claude Code on a Windows host via SSE.

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
                                                   │    └── 43 tool wrappers │
                                                   └─────────────────────────┘
```

## Documentation

| Doc | What's In It |
|-----|-------------|
| **[docs/tools.md](docs/tools.md)** | All 43 tools — descriptions, repo links, install, API keys, CLI usage |
| **[docs/mcp-setup.md](docs/mcp-setup.md)** | Connecting to Claude — Hyper-V/VirtualBox/VMware, port forwarding, config |
| **[docs/security.md](docs/security.md)** | OWASP MCP/LLM Top 10 hardening — auth, audit log, DNS rebinding, input validation |
| **[CLAUDE.md](CLAUDE.md)** | How Claude should use these tools — chaining workflows, Burp integration, rules |

## Quick Start

```bash
# Clone and install
git clone https://github.com/GetSomeKelso/OhSINT.git ~/Tools/OhSINT
cd ~/Tools/OhSINT
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Install tools (see docs/tools.md for per-tool details)
sudo apt install -y libimage-exiftool-perl golang-go ruby ruby-dev theharvester recon-ng spiderfoot
pip install shodan crosslinked sherlock-project maigret holehe h8mail waymore
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Phone & Identity tools are API-based (httpx) — no extra install needed.
# Just configure API keys for: numverify, twilio, censys, intelx, virustotal
# See docs/tools.md for per-tool API key setup and free tier limits.

# Configure API keys
cp configs/api_keys.yaml.example configs/api_keys.yaml
nano configs/api_keys.yaml

# Verify
ohsint install-check
```

> Always activate the venv first: `source ~/Tools/OhSINT/.venv/bin/activate`

## API Keys

```bash
ohsint api-keys   # check status
```

#### Core keys (start with these)

| Config Key | Where to Get It | Free Tier |
|------------|----------------|-----------|
| `shodan.api_key` | [account.shodan.io](https://account.shodan.io) | $49 one-time |
| `github_dorks.github_token` | [github.com/settings/tokens](https://github.com/settings/tokens) | Free |
| `brave.api_key` | [brave.com/search/api](https://brave.com/search/api/) | 2,000 req/mo |
| `virustotal.api_key` | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | 4 req/min |
| `mcp_server.bearer_token` | Self-generated ([docs/security.md](docs/security.md)) | N/A |

GitHub token scopes: `public_repo`, `read:org`, `read:user` (read-only).

#### Phone & Identity keys

| Config Key | Where to Get It | Free Tier |
|------------|----------------|-----------|
| `numverify.api_key` | [numverify.com](https://numverify.com/) | 100 req/mo |
| `twilio.account_sid` + `auth_token` | [console.twilio.com](https://console.twilio.com/) | ~$0.005/lookup |
| `censys.api_id` + `api_secret` | [search.censys.io/account/api](https://search.censys.io/account/api) | 250 req/mo |
| `intelx.api_key` | [intelx.io/account](https://intelx.io/account?tab=developer) | ~10 searches/day |
| `whitepages_pro.api_key` | [pro.whitepages.com](https://pro.whitepages.com/) | Subscription (FCRA) |

Optional keys and per-tool API requirements are documented in **[docs/tools.md](docs/tools.md)**.

Keys can also be set via environment variables: `OSINT_<TOOL>_<KEY>` (uppercased).

## Scan Profiles

| Profile | Tools | Auth Required |
|---------|-------|---------------|
| `standard` | 15 tools — core passive recon (default) | No |
| `passive` | 23 tools — all passive tools, zero target interaction | No |
| `infrastructure` | 6 tools — subfinder, crtsh, whois, theHarvester, shodan, brave_search | No |
| `threat-intel` | 4 tools — virustotal, h8mail, waymore, shodan | No |
| `social` | 8 tools — theHarvester, spiderfoot, creepy, crosslinked, inspy, sherlock, maigret, holehe | No |
| `people` | 6 tools — crosslinked, inspy, sherlock, maigret, holehe, theHarvester | No |
| `metadata` | 5 tools — metagoofil, exiftool, dork_cli, brave_search, inspy (techspy) | No |
| `phone` | 5 tools — numverify, twilio, intelx, hudson_rock, consumer ID links | No |
| `identity` | 7 tools — intelx, hudson_rock, numverify, twilio, consumer ID, holehe, h8mail | No |
| `commercial_identity` | 2 tools — whitepages_pro, beenverified | **Yes + FCRA** |
| `active` | 5 tools — spiderfoot (all), recon-ng, xray, linkedin2username, linkedint | **Yes** |
| `full` | 43 tools — all passive + all active combined | **Yes** |

Profiles are defined in `configs/scan_profiles.yaml`.

## CLI Usage

```bash
# Passive recon — no authorization needed
ohsint full-recon -t example.com                        # standard (default, 15 tools)
ohsint full-recon -t example.com -p passive             # all 23 passive tools
ohsint full-recon -t example.com -p infrastructure      # subdomains, certs, WHOIS
ohsint full-recon -t example.com -p threat-intel        # reputation, breaches, archives
ohsint full-recon -t example.com -p social              # people + social media

# Active recon — requires explicit authorization
ohsint full-recon -t example.com -p active --authorization
ohsint full-recon -t example.com -p full --authorization

# Single tool
ohsint tool -t example.com subfinder
ohsint tool -t user@example.com holehe
ohsint tool -t "Company Name" spiderfoot --authorization

# Dry run
ohsint full-recon -t example.com -p full --authorization --dry-run

# Utilities
ohsint list-tools        # show all tools + passive/active status
ohsint install-check     # verify tools + API keys
ohsint api-keys          # show key configuration status
```

| Flag | Description |
|------|-------------|
| `--authorization` | Confirm written permission (required for active tools only) |
| `-o, --output DIR` | Output directory (default: `results/<target>/<timestamp>/`) |
| `-f, --format` | Report format: `json`, `md`, `html`, `all` (default: `all`) |
| `--timeout SECS` | Per-tool timeout (default: 300) |
| `-P / --no-parallel` | Enable/disable parallel execution (default: parallel) |
| `-v, --verbose` | Verbose output |
| `--dry-run` | Show what would execute without running |

## Reports

Reports are saved under `results/<target>/<timestamp>/`:

- `report.json` — machine-readable, full structured data
- `report.md` — markdown summary with findings tables
- `report.html` — styled dark-theme HTML report

Findings are deduplicated across tools and normalized into 20 types: email, subdomain, IP address, person, document, credential, technology, vulnerability, social profile, geolocation, metadata, DNS record, port/service, ASN, sensitive file, username, certificate, WHOIS record, breach, reputation.

## Connect to Claude

See **[docs/mcp-setup.md](docs/mcp-setup.md)** for the full guide. Quick start:

```bash
# On Kali VM
ohsint-mcp --host 0.0.0.0 --token YOUR_TOKEN
```

```json
// .mcp.json on Windows
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

40+ MCP tools available. Passive tools run freely; active tools require `authorization_confirmed: true`.

## Burp Suite Integration

OhSINT works alongside the Burp Suite MCP server for active validation of passive findings. OhSINT discovers the attack surface; Burp validates it. **Requires explicit authorization.**

| OhSINT Finds | Burp Validates |
|-------------|----------------|
| Subdomains (subfinder, crtsh) | `send_http1_request` — probe for live responses |
| Archived URLs (waymore) | `create_repeater_tab` — stage for manual testing |
| Tech stack (InSpy) | `send_http1_request` — confirm via response headers |
| Hosts (theHarvester) | `send_http1_request` — check security headers |

See **[CLAUDE.md](CLAUDE.md)** for the full chaining workflow and rules.

## Docker

```bash
cd docker && docker compose up --build
```

Builds a Kali-based container with all tools pre-installed. See `docker/Dockerfile`.

## Legal

You **must** have written authorization from the target owner before running any active reconnaissance scan. Passive tools query public data sources only. Unauthorized scanning is illegal.
