# OhSINT Security

OhSINT has been audited against the OWASP MCP Top 10 and OWASP LLM Top 10. This document covers the security controls implemented.

---

## Bearer Token Authentication (MCP07)

The MCP server supports bearer token auth to prevent unauthorized tool invocation.

### Generate a token

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Configure on the server (Kali VM)

Add to `configs/api_keys.yaml`:

```yaml
mcp_server:
  bearer_token: "your-token-here"
```

Or pass directly:

```bash
ohsint-mcp --host 0.0.0.0 --token your-token-here
```

Or set via environment variable:

```bash
export OHSINT_MCP_TOKEN="your-token-here"
ohsint-mcp --host 0.0.0.0
```

### Configure on the client (Windows)

Set the environment variable before launching Claude:

```powershell
# PowerShell — current session
$env:OHSINT_MCP_TOKEN = "your-token-here"

# Or permanently via System Properties > Environment Variables
```

The `.mcp.json` passes it automatically via `--header "Authorization:Bearer ${OHSINT_MCP_TOKEN}"`.

### Behavior

- **Token configured:** All requests must include `Authorization: Bearer <token>`. Requests without it or with the wrong token get HTTP 401.
- **No token configured:** Server starts with a WARNING log but runs unauthenticated (backward compatible).

---

## Audit Log (MCP08)

All MCP tool invocations are logged to `results/audit.jsonl` in append-only JSON-lines format.

Each entry records:

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 timestamp |
| `tool_name` | Which tool was invoked |
| `target` | The target passed to the tool |
| `initiator` | Always `mcp_client` for MCP invocations |
| `authorization_confirmed` | Whether auth was provided |
| `success` | Whether the tool completed without errors |
| `execution_time_seconds` | How long it took |
| `error` | Error message (truncated to 500 chars) if failed |

Audit logging is non-fatal — if the write fails (e.g., disk full), the tool still executes.

---

## DNS Rebinding Protection (LLM06)

When binding to `0.0.0.0` (required for Hyper-V), the MCP server validates the `Host` header on incoming requests.

### Default behavior

Only requests from private/RFC1918 networks are allowed:

| Network | Range |
|---------|-------|
| Class A private | `10.0.0.0/8` |
| Class B private | `172.16.0.0/12` |
| Class C private | `192.168.0.0/16` |
| Loopback | `127.0.0.0/8` |
| `localhost` | Always allowed |

### Custom allowed hosts

Add extra CIDRs or IPs:

```bash
ohsint-mcp --host 0.0.0.0 --allowed-hosts "203.0.113.0/24,10.50.0.0/16"
```

### Why this matters

Without this protection, an attacker could use DNS rebinding to make a browser send requests to `localhost:8055` with a spoofed Host header, tricking the MCP server into executing tools on the attacker's behalf.

---

## Command Sanitization (MCP01)

API keys and credentials are automatically redacted from subprocess command logs.

The `_sanitize_command()` function in `src/tools/base.py` detects sensitive flags and redacts their values:

**Redacted flags:** `--api-key`, `--token`, `--password`, `-shodan-key`, `--secret`, `--key`, and `=` delimited variants.

**Before:** `xray -target example.com -shodan-key abc123secret`
**After:** `xray -target example.com -shodan-key [REDACTED]`

---

## Input Validation (MCP05)

All targets are validated in `validate_target()` before execution. Rejected patterns:

| Pattern | Why |
|---------|-----|
| Shell metacharacters (`` ; ` $ \| > < & ``) | Prevent command injection |
| Path traversal (`../`, `..\`) | Prevent file system escape |
| Null bytes (`\x00`) | Prevent null byte injection |
| Newlines (`\n`, `\r`) | Prevent log/header injection |
| Targets > 500 chars | Prevent buffer abuse |
| Empty targets | Prevent tool errors |

---

## Passive / Active Authorization Split

Tools are classified as passive or active via `BaseTool.is_passive`:

- **Passive tools** (23 of 28) query public data sources and run without authorization
- **Active tools** (5 of 28) interact with target infrastructure or authenticate to third-party services and require `--authorization` or `authorization_confirmed: true`

**Active tools:** spiderfoot, recon-ng, linkedin2username, xray, linkedint

---

## Secure Temporary Files (MCP10)

Tools that write temporary output (Sherlock, h8mail) use `tempfile.mkdtemp()` with `0700` permissions (owner-only access) instead of the world-readable `/tmp` directory. Temporary directories are cleaned up after parsing.

---

## OWASP Audit Summary

| OWASP Risk | Status | Control |
|-----------|--------|---------|
| MCP01 — Token/Secret Exposure | Mitigated | Command sanitization, credential cleanup |
| MCP05 — Command Injection | Mitigated | Input validation, `shell=False` |
| MCP07 — Insufficient Auth | Mitigated | Bearer token auth |
| MCP08 — Lack of Audit | Mitigated | JSON-lines audit log |
| MCP10 — Context Over-Sharing | Mitigated | Secure temp files, error sanitization |
| LLM06 — Excessive Agency | Mitigated | DNS rebinding protection, passive/active split |
