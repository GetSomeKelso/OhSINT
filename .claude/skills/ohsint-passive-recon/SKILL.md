---
name: ohsint-passive-recon
description: Run OhSINT's passive reconnaissance pipelines against a domain — subdomain takeover, historical URL harvest, secret surface discovery, JS analysis, or the full passive sweep. Use for any "recon this domain" / "what's exposed" request that should NOT touch the target. No authorization gate.
---

# OhSINT — Passive Reconnaissance

Passive pipelines query public data sources; they do not touch the target, so no
authorization gate. Pick the pipeline by intent:

| Want | Command |
|------|---------|
| Dangling-CNAME takeover risk | `ohsint takeover -t <domain>` |
| Historical URLs / attack surface | `ohsint url-harvest -t <domain>` |
| Leaked secrets (GitHub/Docker/Postman) | `ohsint secret-surface -t <domain>` |
| JS endpoints + secrets | `ohsint js-analysis -t <domain>` |
| Everything passive (30–90 min) | `ohsint passive-full -t <domain>` |

## Steps

1. Confirm scope (which domain[s]); multi-target via `-t a -t b` or `--scope-file`.
2. Run the matching command above. Use `--dry-run` first if the user wants a preview.
3. **Ingest** (mandatory): `ohsint wiki-ingest results/.../report.json`
4. Drive the wiki synthesis pass (see `ohsint-wiki-ingest` skill).
5. Summarize by finding type; flag high-severity (breaches, secrets, takeovers).

## Notes
- `secret-surface` is degraded without `postman.api_key` (Postman tools no-op).
- Always end with wiki-ingest — passive findings are episodic memory too.
