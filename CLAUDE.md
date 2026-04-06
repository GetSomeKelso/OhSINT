# OhSINT — CLAUDE.md

## What This Is

OhSINT is a unified OSINT reconnaissance orchestrator with 28 tools behind a CLI (`ohsint`) and MCP server (`ohsint-mcp`). It runs on a Kali Linux VM and connects to Claude Desktop/Code on a Windows host via SSE.

The operator (SheriffBart) is an IT Director / Security Architect / Penetration Tester who uses this tool for authorized engagements.

## Docs

- **[docs/tools.md](docs/tools.md)** — All 28 tools with repo links, install, API keys, CLI usage
- **[docs/mcp-setup.md](docs/mcp-setup.md)** — Connecting Claude to the Kali VM
- **[docs/security.md](docs/security.md)** — OWASP hardening, bearer token auth, audit log

## Rules

### Authorization

- **Passive tools (23)** run without authorization. They query public data sources and never touch the target.
- **Active tools (5)** require explicit authorization before execution: spiderfoot, recon-ng, xray, linkedin2username, linkedint.
- Never run an active tool without the user confirming they have written authorization.
- When in doubt, ask. Do not assume authorization carries over from a previous request.

### Accuracy

- Parse real tool output. Never fabricate or assume findings.
- If a tool fails, report the failure — don't substitute made-up data.
- Confidence scores must reflect actual source reliability, not optimism.
- Deduplicate findings across tools. If subfinder and crtsh both find `api.example.com`, report it once with both sources listed and the higher confidence.

### Reporting

- Always offer to generate a report after a scan completes.
- Reports go to `results/<target>/<timestamp>/` in JSON, Markdown, and HTML.
- Summarize findings by type (subdomains, emails, breaches, etc.) with counts.
- Flag high-severity findings (breached credentials, exposed secrets, malicious reputation) prominently.

## Tool Chaining — Passive Workflows

These are the recommended pipelines. When the user asks for recon on a target, follow these chains rather than running tools randomly.

### Domain Recon Pipeline

```
subfinder ─┐
crtsh     ─┼──► deduplicate subdomains ──► virustotal (reputation check)
whois      │                               waymore (archived URLs)
theHarvester ──► emails found ──► h8mail (breach check)
                                   holehe (platform registration)
brave_search ──► exposed files, login pages, configs
metagoofil ──► download docs ──► exiftool (metadata extraction)
github_dorks ──► leaked secrets, keys, configs
```

### People Recon Pipeline

```
crosslinked ──┐
inspy        ─┼──► deduplicate names ──► generate usernames ──► sherlock (400+ sites)
theHarvester ─┘                                                  maigret (3,000+ sites)
                   emails found ──► holehe (platform check)
                                    h8mail (breach check)
```

### Threat Intel Pipeline

```
target domain/IP ──► virustotal (reputation, DNS, categories)
                     shodan (indexed services, banners)
                     waymore (archived attack surface)
emails found ──► h8mail (breach exposure)
```

## Burp Suite Integration

A Burp Suite MCP server is available alongside OhSINT. Burp is an **active** web application testing tool. Use it to extend OhSINT's findings into active validation — but only with explicit authorization.

### When to use OhSINT + Burp together

| Scenario | OhSINT Provides | Burp Does | Authorization |
|----------|----------------|-----------|---------------|
| **Subdomain validation** | subfinder/crtsh find subdomains | `send_http1_request` probes each for live responses, status codes, headers | **Required** |
| **Endpoint investigation** | waymore finds archived URLs | `create_repeater_tab` stages interesting endpoints for manual testing | **Required** |
| **Tech confirmation** | InSpy finds tech stack from job listings | `send_http1_request` confirms versions via Server/X-Powered-By headers | **Required** |
| **Header analysis** | theHarvester/subfinder find hosts | `send_http1_request` checks security headers (HSTS, CSP, X-Frame-Options) | **Required** |
| **Certificate inspection** | crtsh finds certificates | `send_http1_request` fetches live cert details for comparison | **Required** |

### How to chain them

When the user asks to "investigate", "validate", or "deep dive" on findings from a passive scan:

1. **Confirm authorization** — active Burp requests touch the target directly
2. **Select findings to validate** — pick subdomains, endpoints, or hosts from OhSINT results
3. **Use Burp's `send_http1_request`** to probe each target:
   ```
   GET / HTTP/1.1
   Host: <subdomain>
   User-Agent: Mozilla/5.0
   ```
4. **Use `create_repeater_tab`** to stage interesting endpoints for the user to test manually
5. **Cross-reference** Burp responses with OhSINT's VirusTotal/Shodan data

### What NOT to do with Burp

- Never use `send_to_intruder` or fuzzing without the user explicitly requesting it
- Never use Burp's scanner — that's a separate engagement phase
- Never send credentials found by h8mail through Burp — credential testing requires separate authorization
- Never proxy OhSINT's passive tools through Burp — that defeats the "passive" classification
- Burp's encoding tools (`base64_encode`, `url_decode`, etc.) are fine to use anytime — they're local operations

### Burp MCP tools reference

| Burp Tool | Use Case with OhSINT |
|-----------|---------------------|
| `send_http1_request` | Validate discovered subdomains/endpoints are live |
| `create_repeater_tab` | Stage endpoints from waymore/brave_search for manual testing |
| `get_proxy_http_history` | Review requests made during active validation |
| `base64_encode` / `base64_decode` | Decode encoded strings found in OSINT data |
| `url_encode` / `url_decode` | Handle URL-encoded findings |

## Scan Profiles

| Profile | Tools | Auth | Use When |
|---------|-------|------|----------|
| `standard` | 15 | No | Default quick scan |
| `passive` | 23 | No | Comprehensive passive — all passive tools |
| `active` | 5 | **Yes** | Active tools only |
| `full` | 28 | **Yes** | Everything — passive + active |
| `infrastructure` | 6 | No | Domain-focused — subdomains, certs, WHOIS |
| `threat-intel` | 4 | No | Reputation, breaches, archives |
| `social` | 8 | No | People + social media |
| `people` | 6 | No | LinkedIn enum, username search |
| `metadata` | 5 | No | Documents + file metadata |

## API Keys

Required: `shodan.api_key`, `github_dorks.github_token`, `brave.api_key`, `virustotal.api_key`, `mcp_server.bearer_token`

Check status: `ohsint api-keys`

Full key list: see [docs/tools.md](docs/tools.md)
