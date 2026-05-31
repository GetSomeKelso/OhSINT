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

## Config / wordlist integration

### 11. Wordlist paths live in configs/paths.yaml, not api_keys.yaml
The wordlist-integration addendum suggested putting SecLists/n0kovo paths in
`api_keys.yaml`. But `api_keys.yaml` is gitignored (only `.example` is committed), so
paths there would be invisible to every fresh clone — bad for replication. Filesystem
paths aren't secrets. They live in committed `configs/paths.yaml`, resolved by
`Config.get_path()` with priority **config file → `OHSINT_SECLISTS_PATH` /
`OHSINT_WORDLISTS_PATH` env var → default (`/opt/SecLists`, `/opt/wordlists`)**.
Blank a value in paths.yaml to let the env var/default take over. Tokens
`{WORDLISTS_PATH}` / `{SECLISTS_PATH}` interpolate from the resolved roots.

### 12. dnsx brute-force uses `-d DOMAIN -w WORDLIST`, not `-l`
The addendum's documented invocation mixed `-l <hosts>` with `-w <wordlist> -d <domain>`.
dnsx brute-force mode generates `<word>.<domain>` and resolves it via
`dnsx -d <domain> -w <wordlist> -t <concurrency> -silent`; `-l` is for resolving an
existing host list (a different mode). The TakeoverPipeline uses the brute-force form,
filters stdout to in-scope FQDNs, and merges them into the subdomain set (set union =
automatic dedup) before the CNAME stage. Off by default; `ohsint takeover --dns-bruteforce`.

### 13. Stage-7 swagger discovery had a latent no-op
`js_analysis._swagger_discovery` referenced `OhSINTHTTPClient` without importing it, so
the whole stage silently returned `[]` (NameError swallowed by a broad except). Fixed
while wiring in the SecLists `api-endpoints.txt` / `swagger.txt` path source (with the
hardcoded `swagger_common_paths` retained as fallback when SecLists isn't installed).

## Wiki / episodic memory

### 14. Passive pipelines must persist subdomains as findings (Decision 2)
A live loop test exposed the gap: takeover found 11 real subdomains via crt.sh but
the wiki recorded ZERO — subdomains were intermediate data, only SUBDOMAIN_TAKEOVER
findings reached the report. A "clean" target wrote an empty wiki despite real intel.
Fix: `TakeoverPipeline._subdomain_findings()` emits informational SUBDOMAIN findings
(confidence 0.8, tags [subdomain, enumerated]) for every enumerated subdomain, kept
TYPE-DISTINCT from SUBDOMAIN_TAKEOVER so the takeover verdict/summary is unaffected.
This is what makes cross-engagement correlation (shared IPs/certs/subdomains) possible.
Deliberately scoped: persist subdomains (bounded, high-value, cross-linkable); do NOT
persist the high-volume URL firehose from url-harvest (would blow past the ~100-item
personal-wiki scale the Karpathy video warns about).
