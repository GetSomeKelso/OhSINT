# OhSINT — Wordlist Integration Addendum

Small addendums to existing pipelines. Three targeted changes — no re-architecture.

> **Note on referenced specs:** this addendum references `tasks/subdomain-takeover-spec.md`
> (which never existed) and treats `tasks/osint-pipelines-spec.md` as the pipeline spec
> (it is actually the OPSEC spec). The three changes below were implemented directly
> against the live code rather than against those spec docs.

## Change 1 — n0kovo optional DNS brute-force (subdomain takeover)
Optional fourth enumeration source: passive DNS brute-force via `dnsx` against the
n0kovo_subdomains wordlist (prefixes extracted from valid TLS certs across the entire
IPv4 space — every entry was proven live somewhere; higher signal than permutation lists).

- Config: `configs/scan_profiles.yaml` → `subdomain_takeover.optional_dns_bruteforce`
  (`enabled: false`, `wordlist`, `concurrency: 100`).
- Off by default (3M entries, 30–90 min). Enable per-run: `ohsint takeover --dns-bruteforce`.
- Implementation: `TakeoverPipeline._dns_bruteforce()` runs
  `dnsx -d <domain> -w <wordlist> -t <concurrency> -silent`, filters in-scope FQDNs,
  and set-unions them into the subdomain set before the CNAME stage (auto-dedup).

## Change 2 — SecLists api-endpoints as API-doc path source (JS analysis)
Replace the hardcoded Swagger/OpenAPI path list with SecLists as the configured source,
keeping the hardcoded list as fallback.

- Sources: `{SECLISTS}/Discovery/Web-Content/swagger.txt` and
  `{SECLISTS}/Discovery/Web-Content/api/api-endpoints.txt`.
- Implementation: `JsAnalysisPipeline._load_api_doc_paths()` = hardcoded ∪ SecLists,
  deduped, capped by `js_analysis.seclists_api_max_paths` (default 1000). Falls back to
  hardcoded `swagger_common_paths` when SecLists is missing (logs a clear warning).
- Still passive — probes API-doc paths only on hosts already known live.

## Change 3 — Shared paths config
- New committed `configs/paths.yaml` with a `paths:` block (seclists, wordlists,
  n0kovo_subdomains). (Chosen over `api_keys.yaml`, which is gitignored — see lessons.md #11.)
- `Config.get_path(name)` resolution priority: **config file → env var
  (`OHSINT_SECLISTS_PATH` / `OHSINT_WORDLISTS_PATH`) → default** (`/opt/SecLists`,
  `/opt/wordlists`). `{WORDLISTS_PATH}` / `{SECLISTS_PATH}` tokens interpolate.
- `ohsint install-check` shows a WORDLISTS section (warns, does not fail, when missing).

## What was NOT changed
No CeWL, no rockyou/CrackStation, no raft directory brute-force, no LFI/fuzzing payloads.
The SecLists API-doc check probes known-live hosts only — not general directory brute-force.

## Acceptance — status
- [x] `ohsint install-check` shows SecLists + n0kovo path status
- [x] n0kovo brute-force skipped by default, runs with `--dns-bruteforce`
- [x] API-doc check uses SecLists, falls back to hardcoded when missing
- [x] Path config resolves from config file, env var, and default (7 unit tests)
- [x] `--dry-run` shows resolved wordlist paths for takeover and js-analysis
