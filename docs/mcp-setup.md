# MCP Server Setup — Connecting OhSINT to Claude

OhSINT exposes all 43 tools as MCP tools via an SSE server (`ohsint-mcp`). This guide covers connecting it to Claude Desktop and Claude Code from a Windows host.

## VM Port Forwarding

### Hyper-V (Default Switch)

No port forwarding needed. The host can reach the VM directly by IP.

1. Find the VM's IP on Kali: `ip addr show eth0 | grep inet` (typically `172.x.x.x`)
2. The server must bind to `0.0.0.0` (not `127.0.0.1`) so the host can reach it
3. Use the VM's IP in the Claude config

> **Warning:** Default Switch assigns a **dynamic IP** that changes on VM reboot.
> You'll need to update the config each time the IP changes.
> For a stable IP, create an Internal virtual switch (see below).

### Hyper-V (Static IP with Internal Switch — recommended)

Create a dedicated virtual switch with a fixed subnet so the VM IP never changes.

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

### VirtualBox

Settings > Network > Advanced > Port Forwarding:

| Name | Protocol | Host IP | Host Port | Guest IP | Guest Port |
|------|----------|---------|-----------|----------|------------|
| mcp  | TCP      | 127.0.0.1 | 8055    |          | 8055       |

### VMware

NAT settings > Port Forwarding > add `127.0.0.1:8055 -> :8055`

---

## Start the MCP Server

On the Kali VM:

```bash
source ~/Tools/OhSINT/.venv/bin/activate

# VirtualBox / VMware (localhost only, port forwarded to host)
ohsint-mcp

# Hyper-V (must bind to all interfaces)
ohsint-mcp --host 0.0.0.0

# With bearer token authentication (recommended)
ohsint-mcp --host 0.0.0.0 --token YOUR_TOKEN_HERE
```

### Server Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `127.0.0.1` | Bind address (`0.0.0.0` for Hyper-V) |
| `--port` | `8055` | Listen port |
| `--token` | None | Bearer token for auth (or set `OHSINT_MCP_TOKEN` env var) |
| `--allowed-hosts` | RFC1918 | Comma-separated extra allowed hosts/CIDRs for DNS rebinding |

---

## Claude Desktop Config

On Windows, edit `%APPDATA%\Claude\claude_desktop_config.json` and add `ohsint` to the `mcpServers` block:

**VirtualBox / VMware** (port forwarded):

```json
"ohsint": {
  "command": "npx",
  "args": ["mcp-remote", "http://127.0.0.1:8055/sse", "--allow-http"]
}
```

**Hyper-V Default Switch** (use VM's IP):

```json
"ohsint": {
  "command": "npx",
  "args": ["mcp-remote", "http://<VM-IP>:8055/sse", "--allow-http"]
}
```

**Hyper-V Internal Switch** (static IP):

```json
"ohsint": {
  "command": "npx",
  "args": ["mcp-remote", "http://192.168.50.10:8055/sse", "--allow-http"]
}
```

**With bearer token auth**, set the environment variable first:

```powershell
# PowerShell — set for current session
$env:OHSINT_MCP_TOKEN = "your-token-here"

# Or permanently via System Properties > Environment Variables
```

Then add the header to the args:

```json
"ohsint": {
  "command": "npx",
  "args": [
    "mcp-remote",
    "http://192.168.50.10:8055/sse",
    "--allow-http",
    "--header",
    "Authorization:Bearer ${OHSINT_MCP_TOKEN}"
  ]
}
```

Restart Claude Desktop. The OhSINT tools will appear in the tool list.

---

## Claude Code Config

Add a `.mcp.json` file in your project root:

```json
{
  "mcpServers": {
    "ohsint": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://<VM-IP>:8055/sse",
        "--allow-http",
        "--header",
        "Authorization:Bearer ${OHSINT_MCP_TOKEN}"
      ]
    }
  }
}
```

> **Note:** `--allow-http` is required for non-HTTPS connections. Replace `<VM-IP>` with your VM's IP or `192.168.50.10` for static setups.

Set the token environment variable before launching Claude Code:

```powershell
$env:OHSINT_MCP_TOKEN = "your-token-here"
```

Restart Claude Code for the tools to load.

---

## MCP Tools Available

Once connected, 40+ MCP tools are available. **Passive tools** run without `authorization_confirmed`. **Active tools** (spiderfoot, recon-ng, linkedin2username, xray, linkedint) require `authorization_confirmed: true`. **FCRA-gated tools** (whitepages_pro, beenverified) additionally require `fcra_purpose`.

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
| `osint_maigret` | Username search across 3,000+ sites |
| `osint_holehe` | Email-to-platform registration check (120+ sites) |
| `osint_crosslinked` | LinkedIn employee enum via search engines (passive) |
| `osint_inspy` | Employee + tech stack enumeration (EmpSpy/TechSpy) |
| `osint_linkedin2username` | Authenticated LinkedIn scraping (requires credentials) |
| `osint_sherlock` | Username search across 400+ social media sites |
| `osint_people_recon` | Full people recon pipeline (composite tool) |
| `osint_xray` | Network recon with XRay |
| `osint_datasploit` | OSINT visualizer |
| `osint_snitch` | Information gathering via dorks |
| `osint_vcsmap` | Version control system scanning |
| `osint_creepy` | Geolocation OSINT from social media |
| `osint_goodork` | Google dorking from CLI |
| `osint_numverify` | Phone validation — carrier, line type, location |
| `osint_twilio_lookup` | Phone CNAM caller ID, line type (~$0.005/call) |
| `osint_censys` | Internet device/cert search + VoIP infra |
| `osint_intelx` | Leaked data/dark web search (Intelligence X) |
| `osint_hudson_rock` | Infostealer credential lookup (free) |
| `osint_consumer_identity_links` | Generate lookup URLs for manual investigation |
| `osint_whitepages_pro` | Reverse phone/identity (FCRA-gated) |
| `osint_phone_recon` | Full phone recon pipeline (composite tool) |
| `osint_list_tools` | List tools and installation status |
| `osint_install_check` | Verify tools and API keys |
| `osint_report` | Generate report from existing results |

---

## Troubleshooting

### "Invalid Host header"
The MCP server's DNS rebinding protection is blocking your request. Use `--host 0.0.0.0` on the server and ensure your Windows IP is in a private RFC1918 range. Add custom ranges with `--allowed-hosts`.

### "Unauthorized" (401)
Bearer token mismatch. Check that `OHSINT_MCP_TOKEN` is set on the Windows side and matches the `--token` value on the server.

### Tools not appearing in Claude
1. Verify `ohsint-mcp` is running on Kali
2. Test connectivity: `curl http://<VM-IP>:8055/sse` from Windows
3. Check `.mcp.json` has `--allow-http` flag
4. Restart Claude Desktop/Code after config changes

### IP changed after reboot (Hyper-V Default Switch)
Run `ip addr show eth0` on Kali and update the IP in `.mcp.json` and/or `claude_desktop_config.json`. Consider switching to the Internal Switch setup for a permanent IP.
