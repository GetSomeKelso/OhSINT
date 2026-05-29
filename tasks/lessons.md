# OhSINT — Lessons Learned

Gotchas discovered during Kali VM deployment. The `scripts/setup-kali.sh` script
encodes all of these — this doc explains *why* each step exists.

## Kali VM tool installation

### 1. `/tmp` is a tmpfs (RAM-backed), only ~954M
Go builds write compiler scratch to `/tmp/go-build*`. Large builds (katana, nuclei,
trufflehog) overflow the 954M tmpfs and fail with `no space left on device` — even
though the real disk (`/`) has tens of GB free.
**Fix:** `export TMPDIR=$HOME/.gotmp` (a dir on the real disk) before `go install`.

### 2. `~/go/bin` is not on the MCP server's PATH
`go install` drops binaries in `$(go env GOPATH)/bin` (`~/go/bin`). The OhSINT MCP
server resolves tools with `shutil.which()`, which reads the server process's PATH.
If the server was launched from a shell without `~/go/bin` on PATH, every Go tool
shows MISSING even though the binary exists.
**Fix:** `sudo ln -sf ~/go/bin/* /usr/local/bin/` — `/usr/local/bin` is already on
the server's PATH. No server restart needed; `shutil.which()` re-scans PATH per call.

### 3. trufflehog can't be `go install`-ed
`go install github.com/trufflesecurity/trufflehog/v3@latest` fails: the module's
go.mod contains `replace` directives, which Go refuses for `go install`.
**Fix:** official installer →
`curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin`

### 4. gitleaks module path mismatch
The repo moved to the `gitleaks` GitHub org but its go.mod still declares the path
`github.com/zricethezav/gitleaks/v8`. Installing via `github.com/gitleaks/gitleaks/v8`
fails with "module declares its path as...".
**Fix:** `go install github.com/zricethezav/gitleaks/v8@latest`

### 5. LinkFinder / SecretFinder are not on PyPI
`pip install linkfinder` / `pip install SecretFinder` fail — these are GitHub-only.
**Fix:** git clone + symlink the script onto PATH. LinkFinder has a console-script
installer (`pip install .`); SecretFinder is script-only (symlink `SecretFinder.py`).

### 6. getjs needs Node; js-beautify does not
`getjs` is npm-only and Kali's apt node index is often stale (404s). getjs is
**redundant with subjs** (already a Go tool) — skip it. `js-beautify` is available
via the pip package `jsbeautifier`, no Node required.

### 7. pip mitmproxy conflict warnings are harmless
Installing our tools bumps shared deps (asgiref, tornado, etc.) that Kali's
pre-installed mitmproxy pins. pip prints dependency-conflict warnings but our
packages still install. We don't use mitmproxy — ignore.

## MCP server connectivity

### 8. Host-header rejection when binding to a specific IP
MCP 1.26+ validates the HTTP Host header. The DNS-rebinding allowlist was originally
only installed when binding to `0.0.0.0`; binding to a specific private IP
(e.g. a Hyper-V address like `192.168.x.x`) skipped it, so the default validator
rejected the Host header with `421 Misdirected Request`.
**Fix (committed):** `server.py` now installs the private-network allowlist for any
non-localhost bind, and always adds the exact bound host to the allowed networks.

### 9. VM IP changes between boots
The Hyper-V NAT address can change on reboot. Update `.mcp.json` on the Windows host
to the current `eth0` IP, and launch with `ohsint-mcp --host <that-ip>`.

### 10. Editable install means git pull is enough
OhSINT is installed with `pip install -e .`. After `git pull` on the VM, the new code
is live — no reinstall. But the **running MCP server must be restarted** to load new
tool registrations / MCP endpoints (the process snapshots the registry at startup).
