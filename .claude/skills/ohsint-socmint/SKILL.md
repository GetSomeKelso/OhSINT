---
name: ohsint-socmint
description: Profile an individual from a username, email, or full-name seed using OhSINT (sherlock + maigret + holehe). Use when the user wants to build a subject profile of a specific person. Passive, but profiling a person requires a stated consent reason.
---

# OhSINT — SOCMINT Individual Profiling (CONSENT-GATED)

Profiles one person from a seed identifier. Passive (public-profile enumeration,
no target traffic) — but profiling a *person* carries a consent obligation.

## Gate (intent validation — do this FIRST, never skip)

Before running, obtain and record a **structured consent reason**:
- engagement ID / scope, OR explicit statement that the subject is the user's own
  account(s) / within authorized engagement scope.

If not provided, STOP and ask *why* this person may be profiled. Do not run on a
bare "yes." The reason is logged to the audit trail and report provenance.

## Steps

1. **Gate** — confirm + record the consent reason (above). Refuse otherwise.
2. Run: `ohsint socmint --consent -s "<seed>"`
   - Seed auto-routes: email → holehe + h8mail + derive username; username →
     sherlock + maigret; name → derive candidates → sherlock + maigret.
   - `--no-breach` to skip h8mail; `--max-usernames N` to widen/narrow derivation.
3. **Ingest** (mandatory): `ohsint wiki-ingest results/.../report.json`
4. Drive the wiki synthesis pass (see `ohsint-wiki-ingest` skill).
5. Summarize social profiles, platform registrations, breach exposure, and any
   recovery identifiers surfaced for follow-up.

## Never
- Run without the recorded consent reason.
- Scrape or analyze facial images (prohibited).
- Store full secrets/credentials — only the redacted form OhSINT emits.
- Skip the wiki-ingest step.
