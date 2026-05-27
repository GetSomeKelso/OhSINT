# OhSINT — OPSEC / Analyst Protection Layer: Claude Code Spec
## Context
OhSINT runs passive OSINT recon. Every HTTP request the tool makes — even "passive" ones — is
observable by the target. A crt.sh query leaks nothing, but a direct HTTP probe of a discovered
host, a GitHub code search, or a Docker Hub API call can log your real IP. At scale across
multiple targets, a consistent source IP is a fingerprint that links your investigations.
This spec adds an **analyst protection layer** — session isolation, egress routing, and request
hygiene — as an optional infrastructure wrapper around OhSINT's existing tool invocations.
This is defensive infrastructure for the analyst. It does not add offensive capability.
---
## What the Video Covers (and What's Relevant)
**Core insight from the source material:**
VPNs mask IP but not browser fingerprint. When you probe a target's infrastructure repeatedly
from different IPs with the same fingerprint, a sophisticated target sees the pattern. The
solution is disposable, isolated containers with per-session egress routing.
**What maps to OhSINT:**
| OPSEC Concern | In a Browser | In OhSINT |
|---|---|---|
| IP leakage | VPN | Proxy/Tor egress per tool invocation |
| Fingerprint consistency | Fresh browser container | Randomized User-Agent + TLS fingerprint rotation |
| Cross-investigation contamination | One container per target | Isolated working directory + separate process per scan |
| Session persistence | Disposable container | No cookies/session state between scans |
| DNS leakage | Container DNS routing | DNS-over-HTTPS or resolver config per invocation |
OhSINT doesn't have a browser fingerprint, but it does have:
- A consistent `User-Agent` string across all HTTP requests
- A consistent source IP for all tool invocations
- Potential DNS leakage (system resolver used by default)
- No isolation between concurrent scans of different targets
---
## Scope — What to Build
### Module 1: Request Hygiene (no external deps)
Randomized User-Agent rotation and request header normalization for all direct HTTP calls
OhSINT makes (crt.sh, Wayback CDX API, GitHub API, Docker Hub API, Postman API).
### Module 2: Proxy Egress Support
Optional SOCKS5/HTTP proxy configuration that gets passed through to subprocess tool
invocations (curl, TruffleHog, gau, etc.). Supports Tor, commercial proxies, or
organizational proxies.
### Module 3: Scan Session Isolation
Per-target working directory isolation and process namespace separation so concurrent scans
of different targets cannot cross-contaminate findings.
### Module 4: Kasm Workspaces integration note (documentation only)
OhSINT itself runs inside Kasm containers as a natural fit — document the recommended
Kasm workspace image configuration. No code changes needed.
---
## Module 1: Request Hygiene
### User-Agent rotation
All HTTP requests OhSINT makes directly (not via subprocess tools) must rotate User-Agent
from a realistic pool. Add to `configs/opsec.yaml`:
```yaml
request_hygiene:
  rotate_user_agent: true
  user_agents:
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    - "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    - "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"
    - "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0"
  request_delay_min_seconds: 1.0
  request_delay_max_seconds: 3.0
  randomize_delay: true
```
Implement a shared `OhSINTHTTPClient` wrapper (not a new class file — add to an existing
utilities module) that:
- Picks a random User-Agent from the pool per request
- Adds a randomized delay between requests to the same host
- Passes proxy config if Module 2 is enabled
- Never stores cookies between requests (`Cookie` jar disabled)
- Sets `Accept-Language: en-US,en;q=0.9` (consistent, not fingerprinting)
All existing direct HTTP calls (crt.sh query, Wayback CDX, GitHub search, Docker Hub, Postman)
must route through `OhSINTHTTPClient`.
### Rate limiting per host
Add per-host rate limiting to `OhSINTHTTPClient`:
- Default: max 10 requests/minute per host
- Configurable per-host overrides in `configs/opsec.yaml`
- crt.sh override: max 2 requests/minute (they are a free public service)
- Wayback CDX override: max 5 requests/minute
---
## Module 2: Proxy Egress Support
### Config
Add to `configs/opsec.yaml`:
```yaml
egress:
  enabled: false
  proxy_type: "socks5"    # socks5 | http | tor
  proxy_host: "127.0.0.1"
  proxy_port: 9050        # Tor default; change for commercial proxy
  proxy_username: ""      # optional, for authenticated proxies
  proxy_password: ""      # optional
  
  # Per-tool overrides (some tools have their own proxy flags)
  tool_overrides:
    curl: "--socks5-hostname {host}:{port}"
    gau: "--proxy socks5://{host}:{port}"
    trufflehog: ""         # trufflehog respects HTTP_PROXY env var
    
  # DNS leak prevention
  dns_over_proxy: true    # for socks5, use remote DNS resolution
```
### Proxy injection into subprocess calls
The async subprocess orchestrator must inject proxy config into tool invocations when
`egress.enabled: true`. Implement as an environment variable injection approach — most
Go and Python tools respect these:
```python
proxy_env = {}
if config.egress.enabled:
    proxy_url = f"{config.egress.proxy_type}://{config.egress.proxy_host}:{config.egress.proxy_port}"
    proxy_env = {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "ALL_PROXY": proxy_url,
        # Force remote DNS for SOCKS5
        "SOCKS5_RESOLVE": "1" if config.egress.proxy_type == "socks5" else "0",
    }
# Merge into subprocess env
env = {**os.environ, **proxy_env}
subprocess.run(cmd, env=env, ...)
```
### Tor-specific setup
If `proxy_type: tor`, add an install-check that verifies:
- `tor` is installed and running (`systemctl is-active tor` or `nc -z 127.0.0.1 9050`)
- DNS leak test: resolve a known hostname via the SOCKS5 proxy and verify it returns
Document in README: Tor adds significant latency (5-30s per request). Not recommended for
large-scale scans — use for high-sensitivity single-target investigations only.
### Proxy verification
Add `ohsint opsec-check` command that:
1. Makes a request to `https://api.ipify.org` without proxy -> logs IP (local only, not stored)
2. Makes a request to `https://api.ipify.org` through proxy -> logs IP
3. Confirms they are different
4. Tests DNS resolution through proxy
5. Outputs pass/fail — does not send results anywhere
---
## Module 3: Scan Session Isolation
### Per-target working directories
Every scan must write to an isolated directory:
```
results/
  {target}_{timestamp}_{random_8char}/
    scan_config.json
    audit.jsonl
    findings/
      report.json
      report.md
      report.html
    intermediate/
      subs.txt
      live_hosts.txt
      js_files/
      ...
```
The `random_8char` suffix prevents two concurrent scans of the same target from colliding.
Implement as a `ScanSession` context manager that:
- Creates the directory on entry
- Sets all tool output paths relative to that directory
- On exit: optionally compresses the directory to `.tar.gz` (`AUTO_ARCHIVE: true` in config)
- Never writes to a shared temp directory
### No cross-scan state
Verify that no global state leaks between scan sessions:
- No shared in-memory cache of findings
- No shared HTTP session/cookie jar
- No shared temp files in `/tmp` without session prefix
- Each subprocess invocation gets its own `cwd` set to the session directory
### Concurrent scan support
Concurrent scans of different targets must be safe. Each `ScanSession` is fully self-contained.
The MCP server can handle multiple simultaneous tool invocations — verify this doesn't cause
output file collisions by checking for the `random_8char` suffix logic.
---
## Module 4: Kasm Workspaces Integration (Documentation Only)
No code changes. Add `docs/kasm-deployment.md` with:
### Recommended Kasm workspace image
The natural home for OhSINT is a Kasm workspace container. Recommended setup:
```
Base image: kasmweb/ubuntu-jammy-desktop:1.16.0
Installed tools: all OhSINT dependencies (see install-check)
Persistent profile: disabled (disposable by default)
Egress: configure NordVPN or similar OpenVPN egress in Kasm admin
```
### Why Kasm + OhSINT is the right architecture
- **IP isolation**: each Kasm session gets a fresh VPN egress — OhSINT scans from a different
  IP each time without any per-tool proxy config
- **Fingerprint isolation**: OhSINT has no browser fingerprint, but the analyst's manual
  follow-up browsing (confirming findings) happens in the same isolated container
- **Zero host traces**: OhSINT output lives inside the container; destroyed on session close
  unless explicitly exported
- **Per-investigation containers**: one Kasm session per target = natural implementation of
  Module 3 session isolation at the OS level
### Kasm egress setup summary (from source material)
1. Get OpenVPN config files from provider (NordVPN UDP configs recommended)
2. Admin -> Infrastructure -> Egress Providers -> Add provider (OpenVPN)
3. Add egress gateways per location (e.g. `NordVPN_IE`, `NordVPN_US`)
4. Assign to All Users group
5. When launching OhSINT workspace: select egress location -> fresh IP per session
### Verification before use
Before running any scan from a Kasm container:
- `ohsint opsec-check` — verify proxy egress is working (Module 2)
- Visit `browserleaks.com` from the container's browser — confirm IP matches egress location
- Confirm canvas fingerprint differs from host machine
---
## New Config File: `configs/opsec.yaml`
```yaml
# OhSINT OPSEC / Analyst Protection Configuration
# All settings default to safe/off — opt-in to enable
request_hygiene:
  rotate_user_agent: true
  user_agents:
    # Keep this list updated — pull from whatismybrowser.com top agents
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ..."
    - "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ..."
    - "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ..."
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"
    - "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0"
  request_delay_min_seconds: 1.0
  request_delay_max_seconds: 3.0
  randomize_delay: true
  cookies_disabled: true
  
  rate_limits:
    default_rpm: 10
    per_host:
      "crt.sh": 2
      "web.archive.org": 5
      "api.github.com": 30
      "hub.docker.com": 20
      "api.postman.com": 10
egress:
  enabled: false
  proxy_type: "socks5"    # socks5 | http | tor
  proxy_host: "127.0.0.1"
  proxy_port: 9050
  proxy_username: ""
  proxy_password: ""
  dns_over_proxy: true
session:
  output_base_dir: "results"
  random_suffix: true
  auto_archive: false
  archive_format: "tar.gz"
```
---
## install-check additions
```
OPSEC:
  [✓] configs/opsec.yaml present
  [✓] User-Agent pool: 5 agents configured
  [✗] Egress proxy: disabled (enable in configs/opsec.yaml)
  [✓] Session isolation: random suffix enabled
  [-] Tor: not checked (egress.proxy_type != tor)
```
Add `ohsint opsec-check` as a new CLI command (separate from install-check).
---
## Acceptance Criteria
- [ ] `OhSINTHTTPClient` used for all direct HTTP calls — verified by grep for bare `requests.get`
- [ ] `ohsint opsec-check` passes with proxy enabled (test with local Tor or mitmproxy)
- [ ] Two concurrent scans of different targets produce fully isolated output directories
- [ ] `--dry-run` shows proxy env vars injected into subprocess commands when egress enabled
- [ ] No cookies stored between requests — verified by inspecting session object
- [ ] `docs/kasm-deployment.md` present and complete
---
## Workflow Reminders
- Plan mode first — `tasks/todo.md` before any code
- Module 1 first (no external deps), then 2, then 3 — don't batch
- Module 4 is docs only — one file, no code changes
- Simplicity first — `OhSINTHTTPClient` should wrap the existing HTTP library, not replace it
- Flag before touching orchestrator.py (Module 2 proxy injection may require it)
- Update `tasks/lessons.md` after corrections
