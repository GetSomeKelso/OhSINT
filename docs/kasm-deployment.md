# OhSINT — Kasm Workspaces Deployment Guide

## Why Kasm + OhSINT

Kasm Workspaces provides disposable, isolated containers with per-session VPN egress. This is the natural deployment model for OhSINT:

- **IP isolation**: each Kasm session gets a fresh VPN egress IP. OhSINT scans from a different IP each time without per-tool proxy config.
- **Fingerprint isolation**: no persistent browser fingerprint. Manual follow-up browsing (confirming findings) happens in the same isolated container.
- **Zero host traces**: OhSINT output lives inside the container. Destroyed on session close unless explicitly exported.
- **Per-investigation containers**: one Kasm session per target = natural session isolation at the OS level.

## Recommended Workspace Image

```
Base image: kasmweb/ubuntu-jammy-desktop:1.16.0
Installed tools: all OhSINT dependencies (verify with ohsint install-check)
Persistent profile: disabled (disposable by default)
Egress: configure NordVPN or similar OpenVPN egress in Kasm admin
```

### Building the Image

1. Start from `kasmweb/ubuntu-jammy-desktop:1.16.0`
2. Install Go, Node.js, Python 3.10+
3. Clone OhSINT repo and run `pip install -e .`
4. Install all Go binaries (see `tasks/todo.md` Kali VM batch install section)
5. Install npm packages: `npm install -g getjs js-beautify`
6. Install Python tools: `pip install waymore linkfinder SecretFinder`
7. Copy `configs/api_keys.yaml.example` to `configs/api_keys.yaml` and configure keys
8. Run `ohsint install-check` to verify

## Kasm Egress Setup

### OpenVPN Provider Configuration

1. Get OpenVPN config files from your provider (NordVPN UDP configs recommended)
2. In Kasm Admin: Infrastructure > Egress Providers > Add Provider (OpenVPN)
3. Upload `.ovpn` config files
4. Add egress gateways per location:
   - `NordVPN_IE` (Ireland)
   - `NordVPN_US` (United States)
   - `NordVPN_DE` (Germany)
   - etc.
5. Assign gateways to the All Users group (or a dedicated OSINT group)
6. When launching an OhSINT workspace: select the egress location for that investigation

### Per-Investigation Workflow

1. Launch a fresh Kasm workspace
2. Select the appropriate egress location for the target's geography
3. Run `ohsint opsec-check` to verify:
   - Proxy/VPN is active
   - IP differs from your real IP
   - UA rotation is enabled
4. Run your scans
5. Export results if needed
6. Close the session (container is destroyed)

## Verification Before Scanning

Before running any scan from a Kasm container:

```bash
# Verify OPSEC configuration
ohsint opsec-check

# Verify all tools are installed
ohsint install-check

# From the container's browser, verify:
# - IP matches egress location (visit api.ipify.org)
# - Canvas fingerprint differs from host (visit browserleaks.com)
```

## OhSINT OPSEC Config for Kasm

When running inside Kasm with VPN egress, you can simplify `configs/opsec.yaml`:

```yaml
request_hygiene:
  rotate_user_agent: true
  # ... keep UA rotation even inside Kasm

egress:
  enabled: false  # Kasm handles egress at the network level — no per-tool proxy needed

session:
  random_suffix: true
  auto_archive: true  # Archive results before container destruction
```

The VPN egress at the Kasm infrastructure level replaces Module 2's per-tool proxy injection. Keep Module 1 (request hygiene) active for UA rotation and rate limiting regardless.
