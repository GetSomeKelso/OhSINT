"""OhSINT Wiki — deterministic report → markdown-wiki ingest (hybrid model).

Adapted from Karpathy's "LLM Wiki" pattern. This is the CODE pass: it scaffolds
interlinked Obsidian-style markdown pages straight from a ReconReport, so findings
are never hallucinated or dropped. An LLM synthesis pass layers narrative and
cross-links on top — strictly OUTSIDE the `<!-- ohsint:auto -->` markers, so a
re-ingest never clobbers human/LLM edits.

Three layers (see the schema note `OhSINT MCP.md` in the vault):
  raw/   — read-only report.json source of truth
  wiki/  — pages built/maintained here
  schema — the rules note

Page types: index, targets/<domain>, engagements/<date>-<target>,
findings/<type>, entities/<name>.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.models import IntelFinding, IntelType, ReconReport
from src.report import load_report

AUTO_START = "<!-- ohsint:auto:{key} -->"
AUTO_END = "<!-- /ohsint:auto:{key} -->"

# IntelTypes that are high-severity → ⚠ flagged on index + their pages
HIGH_SEVERITY_TYPES = {
    IntelType.BREACH,
    IntelType.CREDENTIAL,
    IntelType.LEAKED_SECRET,
    IntelType.SUBDOMAIN_TAKEOVER,
    IntelType.INFOSTEALER,
}

# Friendly slugs for finding-type pages
TYPE_SLUGS = {
    IntelType.BREACH: "breaches",
    IntelType.LEAKED_SECRET: "leaked-secrets",
    IntelType.SUBDOMAIN_TAKEOVER: "subdomain-takeovers",
    IntelType.VULNERABILITY: "vulnerabilities",
    IntelType.SUBDOMAIN: "subdomains",
}


def _slug(text: str) -> str:
    s = text.strip().lower()
    s = re.sub(r"[^a-z0-9._-]+", "-", s)
    return s.strip("-") or "unknown"


def _type_slug(t: IntelType) -> str:
    return TYPE_SLUGS.get(t, _slug(t.value))


def _replace_auto_block(content: str, key: str, new_body: str) -> str:
    """Replace the content between auto markers for `key`, preserving everything else.

    If the markers don't exist yet, append a fresh block. This is what makes
    re-ingest safe: only the fenced auto region changes; LLM/human prose survives.
    """
    start = AUTO_START.format(key=key)
    end = AUTO_END.format(key=key)
    block = f"{start}\n{new_body}\n{end}"
    pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.DOTALL)
    if pattern.search(content):
        return pattern.sub(lambda _: block, content)
    return content.rstrip() + "\n\n" + block + "\n"


class WikiBuilder:
    """Renders ReconReport(s) into the vault's wiki/ pages, idempotently."""

    def __init__(self, vault_root: Path, freshness_days: int = 90):
        self.vault = Path(vault_root)
        self.wiki = self.vault / "wiki"
        self.freshness_days = freshness_days

    # ── public API ─────────────────────────────────────────────────────

    def ingest_report(self, report: ReconReport) -> dict:
        """Ingest one report. Returns a summary of pages written + delta."""
        targets = [t.strip() for t in report.target.split(",") if t.strip()]
        primary = targets[0] if targets else report.target
        eng_date = report.start_time.strftime("%Y%m%d_%H%M%S")

        written: list[str] = []

        # 1. delta vs. the target's prior auto-state (before we overwrite it)
        delta = self._compute_delta(primary, report)

        # 2. per-target page (merge findings, keep first-seen)
        for tgt in targets:
            p = self._upsert_target_page(tgt, report)
            written.append(str(p))

        # 3. engagement page (provenance + delta)
        written.append(str(self._write_engagement_page(primary, eng_date, report, delta)))

        # 4. finding-type pages
        by_type: dict[IntelType, list[IntelFinding]] = defaultdict(list)
        for f in report.findings:
            by_type[f.type].append(f)
        for t, items in by_type.items():
            written.append(str(self._upsert_findingtype_page(t, items, primary, eng_date)))

        # 5. entity pages (IPs, ASNs, persons, orgs)
        for ent_name, ent_findings in self._extract_entities(report).items():
            written.append(str(self._upsert_entity_page(ent_name, ent_findings, primary, eng_date)))

        # 6. index refresh
        written.append(str(self._refresh_index(primary, eng_date, report, delta)))

        return {
            "pages_written": written,
            "delta": delta,
            "engagement": f"{eng_date}-{_slug(primary)}",
            "findings": len(report.findings),
        }

    def ingest_path(self, report_path: Path) -> dict:
        return self.ingest_report(load_report(report_path))

    # ── page writers ───────────────────────────────────────────────────

    def _read(self, path: Path) -> str:
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def _write(self, path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def _today(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _upsert_target_page(self, target: str, report: ReconReport) -> Path:
        path = self.wiki / "targets" / f"{_slug(target)}.md"
        existing = self._read(path)
        if not existing:
            existing = (
                f"# Target: {target}\n\n"
                f"> Summary of all reconnaissance against `{target}`. "
                f"Add notes/synthesis below — they survive re-ingest.\n\n"
                f"_last-updated: {self._today()}_\n"
            )
        # auto block: findings grouped by type with provenance
        by_type: dict[IntelType, list[IntelFinding]] = defaultdict(list)
        for f in report.findings:
            by_type[f.type].append(f)
        lines = [f"_Findings as of engagement {report.start_time.strftime('%Y-%m-%d')}_\n"]
        for t in sorted(by_type, key=lambda x: x.value):
            flag = " ⚠" if t in HIGH_SEVERITY_TYPES else ""
            lines.append(f"### {t.value}{flag}  ([[{_type_slug(t)}]])")
            for f in by_type[t][:50]:
                lines.append(f"- {f.value}  _({f.source_tool})_")
            if len(by_type[t]) > 50:
                lines.append(f"- … +{len(by_type[t]) - 50} more")
            lines.append("")
        body = _replace_auto_block(existing, "findings", "\n".join(lines).rstrip())
        body = re.sub(r"_last-updated: .*_", f"_last-updated: {self._today()}_", body)
        return self._write(path, body)

    def _write_engagement_page(self, primary: str, eng_date: str,
                               report: ReconReport, delta: dict) -> Path:
        path = self.wiki / "engagements" / f"{eng_date}-{_slug(primary)}.md"
        sev = sum(1 for f in report.findings if f.type in HIGH_SEVERITY_TYPES)
        lines = [
            f"# Engagement: {primary} — {report.start_time.strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            f"> Scan provenance + delta. Source: [[{_slug(primary)}|target page]].",
            "",
            f"- **Profile:** {report.scan_profile}",
            f"- **Tools run:** {', '.join(report.tools_executed) or 'none'}",
            f"- **Tools failed:** {', '.join(report.tools_failed) or 'none'}",
            f"- **Findings:** {len(report.findings)} ({sev} high-severity)",
            f"- **Authorized:** {report.authorization_confirmed}",
            "",
            "## Findings by type",
            "",
        ]
        for t, n in sorted(report.summary.items()):
            lines.append(f"- {t}: {n}")
        lines.append("")
        lines.append("## Delta vs. prior state")
        lines.append("")
        if delta["new"]:
            lines.append(f"**🆕 New ({len(delta['new'])}):**")
            lines += [f"- {v}" for v in delta["new"][:30]]
        if delta["resolved"]:
            lines.append(f"**✓ Resolved/gone ({len(delta['resolved'])}):**")
            lines += [f"- {v}" for v in delta["resolved"][:30]]
        if not delta["new"] and not delta["resolved"]:
            lines.append("_First scan of this target, or no change._")
        lines.append("")
        lines.append(f"## Changelog\n\n- {self._today()}: ingested {len(report.findings)} findings.")
        return self._write(path, "\n".join(lines))

    def _upsert_findingtype_page(self, t: IntelType, items: list[IntelFinding],
                                 primary: str, eng_date: str) -> Path:
        slug = _type_slug(t)
        path = self.wiki / "findings" / f"{slug}.md"
        existing = self._read(path)
        flag = " ⚠" if t in HIGH_SEVERITY_TYPES else ""
        if not existing:
            existing = (
                f"# Finding type: {t.value}{flag}\n\n"
                f"> All `{t.value}` findings across engagements. "
                f"Synthesis below survives re-ingest.\n\n"
                f"_last-updated: {self._today()}_\n"
            )
        lines = [f"_From [[{_slug(primary)}]] @ {eng_date}_\n"]
        for f in items[:200]:
            lines.append(f"- {f.value}  _({f.source_tool} · [[{_slug(primary)}]])_")
        key = f"items-{_slug(primary)}"
        body = _replace_auto_block(existing, key, "\n".join(lines).rstrip())
        body = re.sub(r"_last-updated: .*_", f"_last-updated: {self._today()}_", body)
        return self._write(path, body)

    def _upsert_entity_page(self, name: str, findings: list[IntelFinding],
                            primary: str, eng_date: str) -> Path:
        path = self.wiki / "entities" / f"{_slug(name)}.md"
        existing = self._read(path)
        if not existing:
            existing = (
                f"# Entity: {name}\n\n"
                f"> Cross-engagement entity. Seen in targets below.\n\n"
                f"_last-updated: {self._today()}_\n"
            )
        lines = [f"_Seen via [[{_slug(primary)}]] @ {eng_date}_\n"]
        for f in findings[:50]:
            lines.append(f"- {f.type.value}: {f.value}  _({f.source_tool})_")
        key = f"seen-{_slug(primary)}"
        body = _replace_auto_block(existing, key, "\n".join(lines).rstrip())
        body = re.sub(r"_last-updated: .*_", f"_last-updated: {self._today()}_", body)
        return self._write(path, body)

    def _refresh_index(self, primary: str, eng_date: str,
                       report: ReconReport, delta: dict) -> Path:
        path = self.wiki / "index.md"
        existing = self._read(path)
        if not existing:
            existing = "# OhSINT Wiki — Index\n\n_last-updated: pending_\n"

        # targets block — append/refresh this target's line
        tgt_line = f"- [[{_slug(primary)}|{primary}]] — last scan {report.start_time.strftime('%Y-%m-%d')}, {len(report.findings)} findings"
        existing = self._append_unique_line(existing, "targets", tgt_line, key_prefix=f"[[{_slug(primary)}|")

        # engagement log
        eng_line = f"- [[{eng_date}-{_slug(primary)}|{primary} @ {report.start_time.strftime('%Y-%m-%d %H:%M')}]] — {len(report.findings)} findings"
        existing = self._prepend_line(existing, "engagements", eng_line)

        # high-severity callouts
        sev_items = [f for f in report.findings if f.type in HIGH_SEVERITY_TYPES]
        if sev_items:
            callout = f"- ⚠ **{primary}** ({report.start_time.strftime('%Y-%m-%d')}): " + \
                      ", ".join(f"{t}×{n}" for t, n in sorted(_count_types(sev_items).items()))
            existing = self._prepend_line(existing, "callouts", callout)

        existing = re.sub(r"last-updated: .*", f"last-updated: {self._today()}", existing, count=1)
        return self._write(path, existing)

    # ── helpers ────────────────────────────────────────────────────────

    def _append_unique_line(self, content: str, key: str, line: str, key_prefix: str) -> str:
        block = self._extract_block(content, key)
        kept = [ln for ln in block.splitlines() if ln.strip() and key_prefix not in ln
                and not ln.lstrip().startswith("_")]
        kept.append(line)
        return _replace_auto_block(content, key, "\n".join(sorted(set(kept))))

    def _prepend_line(self, content: str, key: str, line: str) -> str:
        block = self._extract_block(content, key)
        kept = [ln for ln in block.splitlines()
                if ln.strip() and not ln.lstrip().startswith("_")]
        kept = [line] + [ln for ln in kept if ln != line]
        return _replace_auto_block(content, key, "\n".join(kept[:100]))

    def _extract_block(self, content: str, key: str) -> str:
        start = AUTO_START.format(key=key)
        end = AUTO_END.format(key=key)
        m = re.search(re.escape(start) + r"\n(.*?)\n" + re.escape(end), content, re.DOTALL)
        return m.group(1) if m else ""

    def _compute_delta(self, primary: str, report: ReconReport) -> dict:
        """Compare this report's finding values against the target page's prior auto-state."""
        path = self.wiki / "targets" / f"{_slug(primary)}.md"
        prior_text = self._read(path)
        prior_vals = set(re.findall(r"^- (.+?)  _\(", prior_text, re.MULTILINE))
        curr_vals = {f.value for f in report.findings}
        return {
            "new": sorted(curr_vals - prior_vals),
            "resolved": sorted(prior_vals - curr_vals),
        }

    def _extract_entities(self, report: ReconReport) -> dict[str, list[IntelFinding]]:
        """Pull cross-engagement entities (IPs, ASNs, persons, orgs) for entity pages."""
        entity_types = {IntelType.IP_ADDRESS, IntelType.ASN, IntelType.PERSON}
        out: dict[str, list[IntelFinding]] = defaultdict(list)
        for f in report.findings:
            if f.type in entity_types:
                # normalise the entity key (strip URL noise from IPs/hosts)
                name = f.value.split()[0].rstrip("/:") if f.value else ""
                if name:
                    out[name].append(f)
        return out


def _count_types(findings: list[IntelFinding]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for f in findings:
        out[f.type.value] += 1
    return dict(out)


def lint_wiki(vault_root: Path, freshness_days: int = 90) -> dict[str, list[str]]:
    """Health-check the wiki: orphans, dangling links, stale findings, missing provenance.

    Mirrors Karpathy's "lint the wiki" idea. Returns {category: [issue strings]}.
    """
    wiki = Path(vault_root) / "wiki"
    issues: dict[str, list[str]] = {
        "orphan_pages": [],
        "dangling_links": [],
        "stale_findings": [],
        "missing_provenance": [],
    }
    if not wiki.exists():
        return issues

    pages = list(wiki.rglob("*.md"))
    page_names = {p.stem for p in pages}
    link_re = re.compile(r"\[\[([^\]|#]+)")

    # collect all inbound link targets
    linked_to: set[str] = set()
    for p in pages:
        text = p.read_text(encoding="utf-8", errors="replace")
        for m in link_re.findall(text):
            linked_to.add(m.strip())

    now = datetime.now(timezone.utc)
    for p in pages:
        name = p.stem
        text = p.read_text(encoding="utf-8", errors="replace")

        # orphan: not the index, and nothing links to it
        if name not in ("index",) and name not in linked_to:
            issues["orphan_pages"].append(f"{p.relative_to(wiki)}")

        # dangling links: [[target]] with no matching page
        for tgt in link_re.findall(text):
            tgt = tgt.strip()
            if tgt and tgt not in page_names and tgt != "OhSINT MCP":
                issues["dangling_links"].append(f"{p.relative_to(wiki)} → [[{tgt}]]")

        # stale: last-updated older than freshness window
        m = re.search(r"last-updated: (\d{4}-\d{2}-\d{2})", text)
        if m:
            try:
                d = datetime.strptime(m.group(1), "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if (now - d).days > freshness_days:
                    issues["stale_findings"].append(
                        f"{p.relative_to(wiki)} (last-updated {m.group(1)}, "
                        f">{freshness_days}d)"
                    )
            except ValueError:
                pass

        # missing provenance: finding pages with auto items lacking a source tag
        if p.parent.name in ("findings", "targets"):
            auto_items = re.findall(r"^- (.+)$", text, re.MULTILINE)
            for it in auto_items:
                if "_(" not in it and not it.startswith("…") and "[[" not in it:
                    issues["missing_provenance"].append(f"{p.relative_to(wiki)}: {it[:60]}")
                    break  # one flag per page is enough

    # de-dupe + bound
    for k in issues:
        issues[k] = sorted(set(issues[k]))
    return issues
