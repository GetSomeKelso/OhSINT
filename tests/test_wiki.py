"""Tests for the OhSINT wiki ingest (hybrid code pass) + lint."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.models import IntelFinding, IntelType, ReconReport
from src.wiki import WikiBuilder, lint_wiki, _replace_auto_block, _slug


def _report(target="acme.com", findings=None, when=None):
    return ReconReport(
        target=target,
        scan_profile="takeover",
        start_time=when or datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
        end_time=when or datetime(2026, 1, 1, 12, 5, tzinfo=timezone.utc),
        authorization_confirmed=True,
        tools_executed=["subfinder", "crtsh"],
        tools_failed=[],
        findings=findings or [],
        summary={},
    )


def _f(t, value, tool="subfinder"):
    return IntelFinding(type=t, value=value, source_tool=tool, confidence=0.9)


def test_auto_block_preserves_surrounding_text():
    content = "# Page\n\nMy notes.\n\n<!-- ohsint:auto:x -->\nold\n<!-- /ohsint:auto:x -->\n\nMore notes."
    out = _replace_auto_block(content, "x", "new")
    assert "My notes." in out
    assert "More notes." in out
    assert "new" in out
    assert "old" not in out


def test_auto_block_appends_when_missing():
    out = _replace_auto_block("# Page\n\ntext", "y", "body")
    assert "<!-- ohsint:auto:y -->" in out
    assert "body" in out


def test_ingest_writes_pages(tmp_path):
    vault = tmp_path / "OhSINT"
    builder = WikiBuilder(vault_root=vault)
    rep = _report(findings=[
        _f(IntelType.SUBDOMAIN, "api.acme.com"),
        _f(IntelType.LEAKED_SECRET, "AKIA… in repo x", tool="trufflehog_github"),
    ])
    result = builder.ingest_report(rep)
    assert result["findings"] == 2
    assert (vault / "wiki" / "targets" / "acme.com.md").exists()
    assert (vault / "wiki" / "findings" / "leaked-secrets.md").exists()
    assert (vault / "wiki" / "index.md").exists()
    # engagement page named by date+target
    engs = list((vault / "wiki" / "engagements").glob("*.md"))
    assert len(engs) == 1


def test_high_severity_flagged_on_index(tmp_path):
    vault = tmp_path / "OhSINT"
    builder = WikiBuilder(vault_root=vault)
    builder.ingest_report(_report(findings=[_f(IntelType.LEAKED_SECRET, "secret1")]))
    index = (vault / "wiki" / "index.md").read_text(encoding="utf-8")
    assert "⚠" in index
    assert "acme.com" in index


def test_delta_detects_new_and_resolved(tmp_path):
    vault = tmp_path / "OhSINT"
    builder = WikiBuilder(vault_root=vault)
    # first scan
    builder.ingest_report(_report(findings=[
        _f(IntelType.SUBDOMAIN, "a.acme.com"),
        _f(IntelType.SUBDOMAIN, "b.acme.com"),
    ]))
    # second scan: b gone, c new
    later = datetime(2026, 2, 1, 12, 0, tzinfo=timezone.utc)
    result = builder.ingest_report(_report(findings=[
        _f(IntelType.SUBDOMAIN, "a.acme.com"),
        _f(IntelType.SUBDOMAIN, "c.acme.com"),
    ], when=later))
    assert "c.acme.com" in result["delta"]["new"]
    assert "b.acme.com" in result["delta"]["resolved"]


def test_reingest_is_idempotent_and_preserves_edits(tmp_path):
    vault = tmp_path / "OhSINT"
    builder = WikiBuilder(vault_root=vault)
    rep = _report(findings=[_f(IntelType.SUBDOMAIN, "a.acme.com")])
    builder.ingest_report(rep)

    # simulate LLM/human synthesis OUTSIDE the auto markers
    tgt = vault / "wiki" / "targets" / "acme.com.md"
    text = tgt.read_text(encoding="utf-8")
    tgt.write_text(text + "\n## Analyst notes\n\nThis target is high priority.\n", encoding="utf-8")

    # re-ingest same report
    builder.ingest_report(rep)
    after = tgt.read_text(encoding="utf-8")
    assert "This target is high priority." in after  # edit survived
    assert after.count("a.acme.com") >= 1


def test_takeover_persists_subdomains_distinct_from_takeovers():
    """Decision 2: enumerated subdomains become SUBDOMAIN findings, kept distinct
    from SUBDOMAIN_TAKEOVER so the takeover verdict is unaffected."""
    from src.pipelines.takeover import TakeoverPipeline
    p = TakeoverPipeline()
    fds = p._subdomain_findings({"a.ex.com", "b.ex.com"}, {"a.ex.com": "ex.com"})
    assert len(fds) == 2
    assert all(f.type == IntelType.SUBDOMAIN for f in fds)
    assert not any(f.type == IntelType.SUBDOMAIN_TAKEOVER for f in fds)
    assert fds[0].raw_data.get("parent_domain") == "ex.com"
    # informational confidence, not risk-level
    assert all(f.confidence < 0.9 for f in fds)


def test_lint_flags_dangling_link(tmp_path):
    vault = tmp_path / "OhSINT"
    wiki = vault / "wiki"
    wiki.mkdir(parents=True)
    (wiki / "index.md").write_text("# Index\n\n[[nonexistent-page]]\n", encoding="utf-8")
    issues = lint_wiki(vault)
    assert any("nonexistent-page" in d for d in issues["dangling_links"])
