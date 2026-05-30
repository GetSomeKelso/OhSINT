---
name: ohsint-wiki-ingest
description: Ingest an OhSINT report.json into the persistent wiki knowledge base and drive the LLM synthesis pass. Use after ANY scan completes, or when the user wants findings added to the wiki / cross-correlated with past engagements. This is OhSINT's episodic memory.
---

# OhSINT — Wiki Ingest + Synthesis (episodic memory)

Two-pass hybrid. The code pass scaffolds reliably; the LLM pass (you) synthesizes.

## Pass 1 — code (deterministic)

Run: `ohsint wiki-ingest <path/to/report.json>`
This scaffolds pages (target, engagement, finding-types, entities, index) with
findings rendered between `<!-- ohsint:auto -->` markers, and computes the delta
(new / resolved findings vs. the target's prior scan).

## Pass 2 — LLM synthesis (you do this every time, never skip)

Per the vault schema (`OhSINT MCP.md`), edit pages ONLY OUTSIDE the
`<!-- ohsint:auto -->` markers (edits inside get overwritten on re-ingest). Add:
1. **Target page** — a 2–3 sentence narrative summary of the posture.
2. **Cross-links** — connect this target's IPs/ASNs/certs/entities to other
   targets that share them (`[[wikilinks]]`). This is the whole point — correlation.
3. **Entity pages** — for any person/org/IOC seen across >1 engagement, note the
   linkage.
4. **Deltas** — call out NEW high-severity findings and anything that went `gone`.

## Pass 3 — lint (periodic)

Run `ohsint wiki-lint` to surface orphan pages, dangling links, stale findings,
and missing provenance. Fix what it reports.

## Guardrails
- NEVER edit files under `raw/` — read-only provenance.
- NEVER write inside `<!-- ohsint:auto -->` blocks — code owns those.
- Cite every synthesized claim back to an engagement + tool.
