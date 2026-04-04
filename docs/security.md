# OhSINT Security

OhSINT has been audited against the OWASP MCP Top 10 and OWASP LLM Top 10. This document covers the security controls implemented.

---

## Bearer Token Authentication (MCP07)

The MCP server supports bearer token auth to prevent unauthorized tool invocation. Without it, anyone on your network who can reach port 8055 can run any OSINT tool. Follow these steps in order.

### Step 1: Generate a token on the Kali VM

Open a terminal on your Kali VM and run:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

This prints a random 32-character token like `xK9m2Fq_7bR3vLpN...`. **Copy this token** — you'll need it in the next two steps. Keep it private.

### Step 2: Configure the token on the Kali VM (server side)

You have two options. Pick one:

**Option A — Save it in the config file (recommended, persists across restarts):**

```bash
nano ~/Tools/OhSINT/configs/api_keys.yaml
```

Find or add this section at the top of the file:

```yaml
mcp_server:
  bearer_token: "PASTE_YOUR_TOKEN_HERE"
```

Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X` in nano).

Now start the server — it will read the token from the config automatically:

```bash
source ~/Tools/OhSINT/.venv/bin/activate
ohsint-mcp --host 0.0.0.0
```

You should see: `Bearer token authentication ENABLED` in the output.

**Option B — Pass it directly on the command line (simpler, but you must type it every time):**

```bash
source ~/Tools/OhSINT/.venv/bin/activate
ohsint-mcp --host 0.0.0.0 --token PASTE_YOUR_TOKEN_HERE
```

### Step 3: Configure the same token on Windows (client side)

Claude Desktop and Claude Code need the same token to connect. You must set it as an environment variable on Windows.

**For the current PowerShell session only (temporary):**

```powershell
$env:OHSINT_MCP_TOKEN = "PASTE_YOUR_TOKEN_HERE"
```

Then launch Claude Desktop or Claude Code from that same PowerShell window.

**To set it permanently (survives reboots):**

1. Press `Win + R`, type `sysdm.cpl`, press Enter
2. Click the **Advanced** tab
3. Click **Environment Variables**
4. Under "User variables", click **New**
5. Variable name: `OHSINT_MCP_TOKEN`
6. Variable value: paste your token
7. Click OK, OK, OK
8. Restart Claude Desktop / Claude Code

The `.mcp.json` file already includes `--header "Authorization:Bearer ${OHSINT_MCP_TOKEN}"` which automatically reads this environment variable and sends it with every request.

### How to verify it's working

**On the Kali VM**, you should see this line when the server starts:

```
INFO     Bearer token authentication ENABLED
```

**On Windows**, test the connection:

```powershell
# This should FAIL (no token):
Invoke-WebRequest -Uri "http://<VM-IP>:8055/sse" -UseBasicParsing

# This should SUCCEED (with token):
Invoke-WebRequest -Uri "http://<VM-IP>:8055/sse" -UseBasicParsing -Headers @{Authorization="Bearer YOUR_TOKEN_HERE"}
```

### What happens without a token

If you skip token setup, the server still works but logs a warning:

```
WARNING  No bearer token configured — MCP server is UNAUTHENTICATED
```

This means anyone on your network can invoke OhSINT tools. Fine for testing on an isolated lab network, but not recommended for any shared environment.

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
