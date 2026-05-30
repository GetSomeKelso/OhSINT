---
name: ohsint-active-recon
description: Run OhSINT's ACTIVE reconnaissance funnel (subfinder/crtsh → naabu → httpx → katana → nuclei) against an authorized target. Use ONLY when the user wants active scanning that touches the target directly AND has written authorization. Touches the target — requires a stated authorization reason.
---

# OhSINT — Active Recon (AUTHORIZATION-GATED)

The only OhSINT pipeline that sends traffic to the target. Every stage touches it.

## Gate (intent validation — do this FIRST, never skip)

Before running, obtain and record a **structured authorization reason**:
- engagement ID or scope-file reference, and
- explicit confirmation of written authorization from the target owner.

If the user has not provided this, STOP and ask. Do not run with a bare "yes" —
capture *why* (e.g. `engagement=ACME-2026-Q2, scope=hackerone_acme.txt`). This
reason is logged to the audit trail and surfaced in the report provenance.

## Steps

1. **Gate** — confirm + record the authorization reason (above). Refuse otherwise.
2. Run: `ohsint active-recon --authorization -t <target>`
   - `--brute` only if the user explicitly wants slow/loud DNS brute-force.
   - `--top-ports`, `--nuclei-severity`, `--crawl-depth` as requested; defaults are
     top-100 / high,critical / depth 2.
3. Note the funnel narrows each stage to confirmed-live (naabu→httpx→katana→nuclei).
4. **Ingest** (mandatory): `ohsint wiki-ingest results/.../report.json`
5. Drive the wiki synthesis pass (see `ohsint-wiki-ingest` skill).
6. Summarize: live hosts, open ports, tech, endpoints, vulns. Flag high-severity.

## Never
- Run without the recorded authorization reason.
- Exploit findings — this is recon, not exploitation.
- Skip the wiki-ingest step (episodic memory must capture every engagement).
