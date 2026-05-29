# OhSINT — OSINT Reconnaissance Orchestrator

**73 tools. 5 pipelines. One interface. CLI + MCP server.**

Unified OSINT reconnaissance for authorized engagements. Wraps 73 tools behind smart target detection, parallel execution, deduplication, and multi-format reporting (JSON / Markdown / HTML). Runs on Kali Linux; connects to Claude Desktop/Code via an MCP server.

## Pipelines

Five multi-stage pipelines chain tools with data flowing between stages:

| Pipeline | Command | What it does |
|----------|---------|--------------|
| Subdomain Takeover | `ohsint takeover` | subfinder + crt.sh → dnsx CNAME → provider filter → subzy + nuclei → cross-validate |
| Historical URL Harvest | `ohsint url-harvest` | gau + waybackurls + waymore → dedupe → gf pattern match → robots.txt history |
| Secret Surface | `ohsint secret-surface` | GitHub / Docker Hub / Postman search → TruffleHog + Gitleaks → cross-validate |
| JS Analysis | `ohsint js-analysis` | subjs + katana → download → beautify → LinkFinder + SecretFinder → source maps → Swagger |
| Full Passive | `ohsint passive-full` | chains all 4 above with cross-pipeline data flow |

## Quick Start

```bash
# Install the CLI + MCP entry points
pip install -e . --break-system-packages

# Install all tool binaries (Kali VM — handles every install gotcha)
bash scripts/setup-kali.sh

# Verify tools, API keys, OPSEC config
ohsint install-check
ohsint opsec-check

# Run a pipeline
ohsint takeover -t example.com
ohsint passive-full -t example.com

# Multi-target / scope file
ohsint takeover --scope-file hackerone_scope.txt
ohsint takeover -t a.com -t b.com -t c.com

# Start the MCP server (see docs/mcp-setup.md for binding/IP)
ohsint-mcp --host <vm-ip>
```

## OPSEC / Analyst Protection

Optional protection layer, configured in `configs/opsec.yaml`:

- **Request hygiene** — User-Agent rotation, per-host rate limiting, cookie suppression on all direct HTTP calls
- **Proxy egress** — optional SOCKS5/HTTP/Tor routing for tool subprocesses
- **Session isolation** — random-suffixed output dirs so concurrent scans don't collide

Verify with `ohsint opsec-check`. For container-based isolation, see [docs/kasm-deployment.md](docs/kasm-deployment.md).

## Authorization

Passive tools run freely. Active tools (httpx, naabu, shuffledns, interactsh, spiderfoot, recon-ng, xray, linkedin2username, linkedint) require `--authorization`. FCRA-gated commercial identity tools require `--fcra-permissible-purpose`.

## Docs

- Tool reference: [docs/tools.md](docs/tools.md)
- MCP setup & Kali install: [docs/mcp-setup.md](docs/mcp-setup.md)
- Deployment gotchas: [tasks/lessons.md](tasks/lessons.md)
- Usage guidelines & tool chaining: [CLAUDE.md](CLAUDE.md)

## API Keys

Configure in `configs/api_keys.yaml` (copy from `configs/api_keys.yaml.example`). Check status: `ohsint api-keys`.

## License

MIT
