# OhSINT Agent Orchestrator — Architecture Spec (CoALA + Agentic Storage)

> **Status:** design. No orchestrator code lands until this is sanity-checked.
> **Goal (operator's words):** "harness the LLM to ensure it follows the entire
> workflow every time."
>
> **Sources:** Princeton CoALA framework (IBM "Four Types of AI Agent Memory")
> + IBM "Agentic Storage" (storage designed for autonomous agents). This spec maps
> both onto OhSINT and shows what already exists vs. what's missing.

---

## The one-sentence architecture

> OhSINT's agent = **working memory** (context) + **semantic memory** (CLAUDE.md /
> wiki schema) + **procedural memory** (pipelines-as-skills) + **episodic memory**
> (the wiki) — operating over **agentic storage** (`raw/` + `wiki/`) protected by
> **versioning**, **sandboxing**, and **intent-validation** guardrails.

Not six ad-hoc features — one coherent system. We are ~halfway there already.

---

## Current state — what exists vs. what's missing

| CoALA / storage piece | OhSINT today | Status |
|---|---|---|
| **Working memory** (context window) | the LLM session itself | ✅ inherent |
| **Semantic memory** (facts/rules) | `CLAUDE.md` + vault `OhSINT MCP.md` schema | ✅ done |
| **Episodic memory** (distilled past) | the **wiki** (`src/wiki.py`) — deduped, delta'd findings across engagements | ✅ done (v1) |
| **Procedural memory** (how-to) | pipelines exist as *code*, not as agent-loadable **skills** | ❌ **the gap** |
| **Sandboxing** | `raw/` read-only convention; auth/consent/FCRA gates | 🟡 partial |
| **Immutable versioning** | wiki `<!-- ohsint:auto -->` edit-preservation; reports timestamped but not versioned | 🟡 partial |
| **Intent validation** | boolean `--authorization` / `--consent` flags | 🟡 weak (boolean, not reasoned) |

The orchestrator's job is to fill the ❌ and harden the 🟡s into one loop.

---

## Layer 1 — Procedural Memory: pipelines as skills

**The heart of "follow the workflow every time."** Each OhSINT pipeline becomes a
skill with explicit step-by-step instructions and its gate baked in, so the LLM
can't skip stages or forget the auth check.

### Design
- One skill folder per pipeline: `skills/<name>/skill.md` (the agent-skills `skill.md`
  convention from the video). Candidates: `takeover`, `url-harvest`, `secret-surface`,
  `js-analysis`, `passive-full`, `vendor-risk`, `socmint`, `active-recon`,
  plus meta-skills `wiki-ingest`, `wiki-lint`.
- **Progressive disclosure:** the orchestrator advertises a lightweight index
  (name + one-line description + gate) — ~100 tokens/skill. Full instructions load
  only when a task matches. This mirrors the video exactly and keeps working-memory
  budget sane across 10 skills.
- Each `skill.md` encodes: trigger, required inputs, **gate** (none / consent /
  authorization / FCRA), ordered steps, the post-run **wiki-ingest** step, and the
  expected output. The gate is *in the skill*, so the workflow literally cannot
  proceed past it un-satisfied.

### Why this is the answer to the stated goal
Today the LLM *can* run `ohsint takeover` and forget to ingest into the wiki, or
run an active tool without surfacing the auth requirement. As a skill, the
ingest + gate are steps 0 and N of the procedure — not optional.

---

## Layer 2 — Episodic Memory: the wiki (already built, extend)

`src/wiki.py` is OhSINT's episodic memory and it already does the hard part the
video calls out: **distillation, not raw transcripts** (dedup + temporal delta,
not a dump of every report). Extensions the orchestrator needs:

- **Auto-synthesis trigger:** after each `wiki-ingest` (code pass), the orchestrator
  drives the LLM synthesis/cross-link pass automatically — closing the manual gap
  noted in the wiki commit. Synthesis writes only *outside* `<!-- ohsint:auto -->`.
- **"What's worth remembering":** the lint freshness window already encodes
  obsolescence; orchestrator should act on it (prompt re-scan of stale targets).

No rebuild — this layer is live. The orchestrator consumes it.

---

## Layer 3 — Semantic Memory: schema as the contract

`CLAUDE.md` (repo) + `OhSINT MCP.md` (vault) are the always-loaded rules. The
orchestrator treats these as the **contract it validates skills against** — e.g.
a skill that writes findings must follow the page-formatting + provenance rules in
the schema. Already loaded at session start (the video's exact `CLAUDE.md` pattern).

---

## Layer 4 — Agentic Storage guardrails

The three safety layers from "Agentic Storage," scoped to OhSINT:

### A. Sandboxing (harden the 🟡)
- `raw/` stays read-only (already convention) — enforce in the ingest code path:
  WikiBuilder must refuse to write under `raw/`.
- Skills declare their writable scope (`wiki/` only); orchestrator denies writes
  outside it. Prevents the "confused deputy" — a socmint skill can't touch
  active-recon's output, the wiki can't overwrite raw provenance.

### B. Immutable versioning (fill the 🟡)
- Reports are timestamped but overwriteable. Add: ingest **never deletes** a wiki
  finding — a finding that disappears becomes `status: gone (since <date>)` (the
  delta logic already computes this; make it write-once/append-only).
- Audit trail: every ingest already logs to the engagement changelog. Extend to a
  vault-level `wiki/.audit.jsonl` — append-only record of every orchestrator action.

### C. Intent validation (the sharpest upgrade — fill the 🟡)
This is the strongest idea from video 1 for OhSINT. Replace boolean gates with
**reason-required** gates for high-impact ops:
- Before `active-recon` (touches target) or `socmint` (profiles a person), the
  orchestrator requires a stated **reason** (engagement ID / scope / "my own
  accounts") — not just `authorization_confirmed=true`.
- The reason is logged to the audit trail and surfaced in the report's provenance.
- This is a superset of today's flags: the flag becomes "reason provided and
  recorded," which is both stronger (accountability) and exactly what FCRA
  permissible-purpose already models — generalize that pattern to all active/PII ops.

---

## Build order (incremental — each step ships independently)

1. **Skills scaffold** — `skills/<name>/skill.md` for all 10, with the progressive-
   disclosure index. (Procedural memory.) *Highest ROI — directly the stated goal.*
2. **Auto-synthesis** — orchestrator drives the LLM wiki pass after ingest. (Closes
   the episodic gap.)
3. **Intent-validation gates** — reason-required wrapper over active/PII skills,
   audit-logged. (Guardrail C.)
4. **Sandboxing enforcement** — write-scope checks; `raw/` write-refusal. (Guardrail A.)
5. **Versioning + audit trail** — append-only wiki findings + `wiki/.audit.jsonl`.
   (Guardrail B.)

Each is testable alone; together they are the orchestrator.

---

## Open questions for the operator

- **Skill runtime:** are skills authored for Claude Code's native agent-skills
  system (`skill.md` discovered by the harness), or driven by an OhSINT-internal
  orchestrator loop? (Changes where `skill.md` lives + how progressive disclosure works.)
- **Intent reason granularity:** free-text reason, or structured (engagement-ID +
  scope-file reference)? Structured is auditable; free-text is faster.
- **Audit trail location:** in-vault (`wiki/.audit.jsonl`, travels with the wiki) vs.
  repo (`results/.audit.jsonl`, with the code)?

---
*Spec v1 · grounds: CoALA (working/semantic/procedural/episodic) + Agentic Storage
(versioning/sandboxing/intent-validation) · ~50% of the architecture already shipped.*
