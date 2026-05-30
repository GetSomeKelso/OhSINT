---
name: ohsint-vendor-risk
description: Assess a vendor or third party's external security posture as a graded A–F risk scorecard. Use when the user wants to evaluate a counterparty/supplier rather than hunt bugs. Passive — no authorization gate.
---

# OhSINT — Vendor Risk Assessment

Runs the passive recon toolchain against a vendor domain, then scores findings as
a risk-to-you scorecard (breach exposure, leaked secrets, attack surface,
vulnerabilities, hygiene) → letter grade. Passive: assessing a counterparty's
public footprint needs no authorization.

## Steps

1. Confirm the vendor domain(s).
2. Run: `ohsint vendor-risk -t <vendor-domain>`
3. **Ingest** (mandatory): `ohsint wiki-ingest results/.../report.json`
4. Drive the wiki synthesis pass (see `ohsint-wiki-ingest` skill).
5. Report the grade + category breakdown + top risks. Frame as "risk to us,"
   not a bug-bounty finding list.

## Notes
- Rubric weights are tunable in `configs/pipeline_defaults.yaml` under `vendor_risk`.
- Same tools as `passive-full`, different lens — never present as an attack.
