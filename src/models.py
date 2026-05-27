"""Unified intelligence models for OSINT Orchestrator."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    """Return timezone-aware UTC now (avoids deprecated datetime.utcnow())."""
    return datetime.now(timezone.utc)


class IntelType(str, Enum):
    EMAIL = "email"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    PERSON = "person"
    DOCUMENT = "document"
    CREDENTIAL = "credential"
    TECHNOLOGY = "technology"
    VULNERABILITY = "vulnerability"
    SOCIAL_PROFILE = "social_profile"
    GEOLOCATION = "geolocation"
    METADATA = "metadata"
    DNS_RECORD = "dns_record"
    PORT_SERVICE = "port_service"
    ASN = "asn"
    SENSITIVE_FILE = "sensitive_file"
    USERNAME = "username"
    CERTIFICATE = "certificate"
    WHOIS_RECORD = "whois_record"
    BREACH = "breach"
    REPUTATION = "reputation"
    PHONE_INFO = "phone_info"
    INFOSTEALER = "infostealer"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    LEAKED_SECRET = "leaked_secret"
    JS_ENDPOINT = "js_endpoint"
    EXPOSED_API_DOC = "exposed_api_doc"


class ToolResult(BaseModel):
    """Raw result from a single tool execution."""

    tool_name: str
    target: str
    raw_output: str
    structured_data: dict = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    execution_time_seconds: float = 0.0


class IntelFinding(BaseModel):
    """A single normalized intelligence finding."""

    type: IntelType
    value: str
    source_tool: str
    confidence: float = Field(ge=0.0, le=1.0)
    raw_data: Optional[dict] = None
    first_seen: datetime = Field(default_factory=_utcnow)
    tags: List[str] = Field(default_factory=list)

    def merge_with(self, other: IntelFinding) -> IntelFinding:
        """Merge with a duplicate finding, keeping higher confidence and combining sources."""
        if self.value != other.value or self.type != other.type:
            raise ValueError("Cannot merge findings with different type/value")
        sources = f"{self.source_tool},{other.source_tool}"
        combined_tags = list(set(self.tags + other.tags))
        return IntelFinding(
            type=self.type,
            value=self.value,
            source_tool=sources,
            confidence=max(self.confidence, other.confidence),
            raw_data=self.raw_data or other.raw_data,
            first_seen=min(self.first_seen, other.first_seen),
            tags=combined_tags,
        )


class ReconReport(BaseModel):
    """Consolidated report from a full reconnaissance run."""

    target: str
    resolved_target: Optional[Dict[str, str]] = None
    scan_profile: str
    start_time: datetime
    end_time: datetime
    authorization_confirmed: bool
    tools_executed: List[str] = Field(default_factory=list)
    tools_failed: List[str] = Field(default_factory=list)
    findings: List[IntelFinding] = Field(default_factory=list)
    summary: Dict[str, int] = Field(default_factory=dict)

    def deduplicate(self) -> ReconReport:
        """Merge duplicate findings from multiple tools, keeping highest confidence."""
        seen: Dict[str, IntelFinding] = {}
        for finding in self.findings:
            key = f"{finding.type.value}:{finding.value.lower().strip()}"
            if key in seen:
                seen[key] = seen[key].merge_with(finding)
            else:
                seen[key] = finding
        deduped = list(seen.values())
        summary = {}
        for f in deduped:
            summary[f.type.value] = summary.get(f.type.value, 0) + 1
        return self.model_copy(update={"findings": deduped, "summary": summary})

    def to_markdown(self) -> str:
        """Generate a structured markdown report."""
        lines = [
            f"# OSINT Reconnaissance Report",
            f"",
            f"**Target:** {self.target}",
        ]
        if self.resolved_target:
            rt = self.resolved_target
            lines.append(f"**Detected as:** {rt.get('detected_type', 'unknown')} ({rt.get('confidence', '?')})")
            for key in ("domain", "github_handle", "org_name", "person_name", "username", "email"):
                if rt.get(key):
                    label = key.replace("_", " ").title()
                    lines.append(f"**{label}:** {rt[key]}")
        lines.extend([
            f"**Profile:** {self.scan_profile}",
            f"**Period:** {self.start_time:%Y-%m-%d %H:%M} → {self.end_time:%Y-%m-%d %H:%M}",
            f"**Authorization Confirmed:** {self.authorization_confirmed}",
            f"",
            f"## Tools",
            f"",
            f"**Executed:** {', '.join(self.tools_executed) or 'None'}",
            f"**Failed:** {', '.join(self.tools_failed) or 'None'}",
            f"",
            f"## Summary",
            f"",
            f"| Type | Count |",
            f"|------|-------|",
        ])
        for intel_type, count in sorted(self.summary.items()):
            lines.append(f"| {intel_type} | {count} |")

        lines.extend(["", "## Findings", ""])
        grouped: Dict[str, List[IntelFinding]] = {}
        for f in self.findings:
            grouped.setdefault(f.type.value, []).append(f)

        for intel_type, findings in sorted(grouped.items()):
            if intel_type == "subdomain_takeover":
                lines.extend(self._takeover_markdown(findings))
                continue
            if intel_type == "leaked_secret":
                lines.extend(self._secret_markdown(findings))
                continue
            lines.append(f"### {intel_type.replace('_', ' ').title()}")
            lines.append("")
            lines.append("| Value | Source | Confidence | Tags |")
            lines.append("|-------|--------|------------|------|")
            for f in sorted(findings, key=lambda x: -x.confidence):
                tags = ", ".join(f.tags) if f.tags else "-"
                lines.append(
                    f"| `{f.value}` | {f.source_tool} | {f.confidence:.0%} | {tags} |"
                )
            lines.append("")

        return "\n".join(lines)

    def _takeover_markdown(self, findings: List[IntelFinding]) -> List[str]:
        """Render subdomain takeover findings with impact assessment."""
        lines = [
            "### Subdomain Takeover Assessment",
            "",
            "| Subdomain | CNAME Target | Provider | Status | Severity | Confidence |",
            "|-----------|-------------|----------|--------|----------|------------|",
        ]
        for f in sorted(findings, key=lambda x: -x.confidence):
            rd = f.raw_data or {}
            status = "Confirmed" if "confirmed" in f.tags else (
                "Unconfirmed" if "unconfirmed" in f.tags else "CNAME-only"
            )
            lines.append(
                f"| `{f.value}` | `{rd.get('cname_target', '?')}` "
                f"| {rd.get('provider_name', '?')} | {status} "
                f"| {rd.get('severity', '?')} | {f.confidence:.0%} |"
            )
        lines.append("")

        confirmed = [f for f in findings if "confirmed" in f.tags]
        if confirmed:
            # Use the first confirmed finding for the impact template
            apex = self.target.split(",")[0].strip() if self.target else "target.com"
            lines.extend([
                "#### Impact Assessment",
                "",
                "- **Content injection / phishing:** Attacker can serve arbitrary content on a "
                "trusted company subdomain, enabling high-credibility phishing attacks.",
                f"- **Cookie theft:** If the parent domain sets cookies scoped to `*.{apex}`, "
                "attacker-controlled content can read those cookies, enabling session hijacking.",
                "- **OAuth/CORS abuse (verify manually):** Check whether the affected subdomains "
                "appear in OAuth redirect whitelists or CORS `Access-Control-Allow-Origin` headers.",
                "",
                "#### Proof of Concept (no resource claiming required)",
                "",
                "1. Screenshot of the fingerprint error response",
                "2. DNS record showing the dangling CNAME (`dig CNAME <subdomain>`)",
                "3. For most programs, steps 1+2 are sufficient without registering the resource",
                "",
                "#### Suggested Severity",
                "",
                "Medium to High depending on cookie scope and OAuth whitelist presence. "
                "Escalate to Critical if session cookies are confirmed in scope.",
                "",
            ])

        # PoC approaches per finding
        poc_findings = [f for f in findings if (f.raw_data or {}).get("poc_approach")]
        if poc_findings:
            lines.extend(["#### PoC Approach per Finding", ""])
            for f in poc_findings:
                rd = f.raw_data or {}
                lines.append(f"- **{f.value}** ({rd.get('provider_name', '?')}): {rd.get('poc_approach', '')}")
            lines.append("")

        return lines

    def _takeover_html(self, findings: List[IntelFinding], html_mod) -> str:
        """Render subdomain takeover findings as HTML with impact assessment."""
        rows = ""
        for f in sorted(findings, key=lambda x: -x.confidence):
            rd = f.raw_data or {}
            status = "Confirmed" if "confirmed" in f.tags else (
                "Unconfirmed" if "unconfirmed" in f.tags else "CNAME-only"
            )
            sev = rd.get("severity", "?")
            sev_color = {"high": "var(--red)", "critical": "var(--red)",
                         "medium": "var(--yellow)", "low": "var(--text)"}.get(sev, "var(--text)")
            status_color = {"Confirmed": "var(--red)", "Unconfirmed": "var(--yellow)",
                            "CNAME-only": "var(--text)"}.get(status, "var(--text)")
            rows += (
                f"<tr><td><code>{html_mod.escape(f.value)}</code></td>"
                f"<td><code>{html_mod.escape(rd.get('cname_target', '?'))}</code></td>"
                f"<td>{html_mod.escape(rd.get('provider_name', '?'))}</td>"
                f"<td style=\"color:{status_color};font-weight:600\">{status}</td>"
                f"<td style=\"color:{sev_color}\">{sev}</td>"
                f"<td>{f.confidence:.0%}</td>"
                f"<td>{html_mod.escape(rd.get('poc_approach', '-'))}</td></tr>\n"
            )

        confirmed = [f for f in findings if "confirmed" in f.tags]
        impact_html = ""
        if confirmed:
            apex = html_mod.escape(self.target.split(",")[0].strip()) if self.target else "target.com"
            impact_html = f"""
            <div style="background:rgba(248,81,73,0.08);border:1px solid var(--red);border-radius:6px;padding:1rem 1.5rem;margin:1rem 0">
            <h4 style="color:var(--red);margin-bottom:0.5rem">Impact Assessment</h4>
            <ul style="margin:0.5rem 0;padding-left:1.5rem">
            <li><strong>Content injection / phishing:</strong> Attacker can serve arbitrary content on a trusted company subdomain.</li>
            <li><strong>Cookie theft:</strong> If cookies are scoped to <code>*.{apex}</code>, session hijacking is possible.</li>
            <li><strong>OAuth/CORS abuse:</strong> Verify whether affected subdomains appear in OAuth redirect whitelists or CORS headers.</li>
            </ul>
            <h4 style="color:var(--accent);margin:1rem 0 0.5rem">Proof of Concept</h4>
            <ol style="margin:0.5rem 0;padding-left:1.5rem">
            <li>Screenshot of the fingerprint error response</li>
            <li>DNS record showing the dangling CNAME</li>
            <li>Steps 1+2 are sufficient for most programs without claiming the resource</li>
            </ol>
            </div>
            """

        return f"""
        <h3 style="color:var(--red)">Subdomain Takeover Assessment ({len(findings)})</h3>
        <table>
            <thead><tr>
                <th>Subdomain</th><th>CNAME Target</th><th>Provider</th>
                <th>Status</th><th>Severity</th><th>Confidence</th><th>PoC Approach</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>
        {impact_html}
        """

    def _secret_markdown(self, findings: List[IntelFinding]) -> List[str]:
        """Render leaked secret findings with redacted previews."""
        lines = [
            "### Leaked Secret Discovery",
            "",
            "| Source | Secret Type | Redacted Preview | Verified | Platform | Confidence |",
            "|--------|-------------|-----------------|----------|----------|------------|",
        ]
        for f in sorted(findings, key=lambda x: -x.confidence):
            rd = f.raw_data or {}
            verified = "Yes" if rd.get("verified") else "No"
            lines.append(
                f"| `{f.value[:60]}` | {rd.get('secret_type', '?')} "
                f"| `{rd.get('raw_secret_redacted', '?')}` | {verified} "
                f"| {rd.get('source_platform', '?')} | {f.confidence:.0%} |"
            )
        lines.append("")

        verified_count = sum(1 for f in findings if (f.raw_data or {}).get("verified"))
        if verified_count:
            lines.extend([
                "#### Blast Radius Assessment",
                "",
                "Verified secrets have been confirmed live by TruffleHog's `--only-verified` mode.",
                "This performs a single non-destructive API check — it does NOT authenticate or exploit.",
                "",
            ])
            for f in findings:
                rd = f.raw_data or {}
                if rd.get("verified") and rd.get("blast_radius_hint"):
                    lines.append(f"- **{rd.get('secret_type', '?')}** at `{f.value[:40]}...`: {rd['blast_radius_hint']}")
            lines.append("")

        lines.extend([
            "#### Recommendations",
            "",
            "1. Rotate all verified secrets immediately",
            "2. Audit access logs for unauthorized usage during exposure window",
            "3. Review commit history for additional exposed credentials",
            "4. Never store raw secrets in findings — only redacted previews shown above",
            "",
        ])
        return lines

    def _secret_html(self, findings: List[IntelFinding], html_mod) -> str:
        """Render leaked secret findings as HTML."""
        rows = ""
        for f in sorted(findings, key=lambda x: -x.confidence):
            rd = f.raw_data or {}
            verified = rd.get("verified", False)
            v_badge = '<span style="color:var(--red);font-weight:600">VERIFIED</span>' if verified else '<span style="color:var(--text)">unverified</span>'
            rows += (
                f"<tr><td><code>{html_mod.escape(f.value[:60])}</code></td>"
                f"<td>{html_mod.escape(rd.get('secret_type', '?'))}</td>"
                f"<td><code>{html_mod.escape(rd.get('raw_secret_redacted', '?'))}</code></td>"
                f"<td>{v_badge}</td>"
                f"<td>{html_mod.escape(rd.get('source_platform', '?'))}</td>"
                f"<td>{f.confidence:.0%}</td></tr>\n"
            )

        return f"""
        <h3 style="color:var(--red)">Leaked Secret Discovery ({len(findings)})</h3>
        <table>
            <thead><tr>
                <th>Source</th><th>Secret Type</th><th>Redacted Preview</th>
                <th>Verified</th><th>Platform</th><th>Confidence</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>
        """

    def to_html(self) -> str:
        """Generate a styled HTML report with findings tables."""
        import html as html_mod

        # Build summary rows
        summary_rows = ""
        for intel_type, count in sorted(self.summary.items()):
            label = intel_type.replace("_", " ").title()
            summary_rows += f"<tr><td>{label}</td><td>{count}</td></tr>\n"

        # Build finding sections
        grouped: Dict[str, List[IntelFinding]] = {}
        for f in self.findings:
            grouped.setdefault(f.type.value, []).append(f)

        finding_sections = ""
        for intel_type, findings in sorted(grouped.items()):
            if intel_type == "subdomain_takeover":
                finding_sections += self._takeover_html(findings, html_mod)
                continue
            if intel_type == "leaked_secret":
                finding_sections += self._secret_html(findings, html_mod)
                continue
            label = intel_type.replace("_", " ").title()
            rows = ""
            for f in sorted(findings, key=lambda x: -x.confidence):
                tags = ", ".join(f.tags) if f.tags else "-"
                val = html_mod.escape(f.value)
                rows += (
                    f"<tr><td><code>{val}</code></td>"
                    f"<td>{html_mod.escape(f.source_tool)}</td>"
                    f"<td>{f.confidence:.0%}</td>"
                    f"<td>{html_mod.escape(tags)}</td></tr>\n"
                )
            finding_sections += f"""
            <h3>{label} ({len(findings)})</h3>
            <table>
                <thead><tr><th>Value</th><th>Source</th><th>Confidence</th><th>Tags</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
            """

        tools_ok = ", ".join(self.tools_executed) or "None"
        tools_fail = ", ".join(self.tools_failed) or "None"
        target_esc = html_mod.escape(self.target)

        # Build resolved-target HTML rows
        resolved_html = ""
        if self.resolved_target:
            rt = self.resolved_target
            resolved_html += f"<p><strong>Detected as:</strong> {html_mod.escape(rt.get('detected_type', 'unknown'))} ({html_mod.escape(rt.get('confidence', '?'))})</p>"
            for key in ("domain", "github_handle", "org_name", "person_name", "username", "email"):
                if rt.get(key):
                    label = key.replace("_", " ").title()
                    resolved_html += f"<p><strong>{label}:</strong> {html_mod.escape(rt[key])}</p>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OhSINT Report - {target_esc}</title>
<style>
:root {{ --bg: #0d1117; --surface: #161b22; --border: #30363d; --text: #c9d1d9;
         --accent: #58a6ff; --green: #3fb950; --red: #f85149; --yellow: #d29922; }}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
        background: var(--bg); color: var(--text); line-height: 1.6; }}
.container {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }}
h1 {{ color: var(--accent); margin-bottom: 0.5rem; font-size: 1.8rem; }}
h2 {{ color: var(--text); margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }}
h3 {{ color: var(--accent); margin: 1.5rem 0 0.5rem; font-size: 1.1rem; }}
.meta {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
         padding: 1rem 1.5rem; margin: 1rem 0 2rem; }}
.meta p {{ margin: 0.25rem 0; }}
.meta strong {{ color: var(--accent); }}
.badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 12px; font-size: 0.8rem; font-weight: 600; }}
.badge-ok {{ background: rgba(63,185,80,0.15); color: var(--green); }}
.badge-fail {{ background: rgba(248,81,73,0.15); color: var(--red); }}
table {{ width: 100%; border-collapse: collapse; margin: 0.5rem 0 1.5rem; background: var(--surface);
         border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }}
thead {{ background: rgba(88,166,255,0.08); }}
th {{ text-align: left; padding: 0.6rem 0.8rem; font-weight: 600; color: var(--accent);
      border-bottom: 2px solid var(--border); }}
td {{ padding: 0.5rem 0.8rem; border-bottom: 1px solid var(--border); }}
tr:last-child td {{ border-bottom: none; }}
tr:hover {{ background: rgba(88,166,255,0.04); }}
code {{ background: rgba(110,118,129,0.15); padding: 0.15rem 0.4rem; border-radius: 4px;
        font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.9em; word-break: break-all; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 0.75rem; margin: 1rem 0; }}
.summary-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
                 padding: 0.8rem 1rem; text-align: center; }}
.summary-card .count {{ font-size: 1.8rem; font-weight: 700; color: var(--accent); }}
.summary-card .label {{ font-size: 0.85rem; color: #8b949e; text-transform: uppercase; }}
footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: #8b949e; font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="container">
    <h1>OhSINT Reconnaissance Report</h1>
    <div class="meta">
        <p><strong>Target:</strong> {target_esc}</p>
        {resolved_html}
        <p><strong>Profile:</strong> {html_mod.escape(self.scan_profile)}</p>
        <p><strong>Period:</strong> {self.start_time:%Y-%m-%d %H:%M UTC} &rarr; {self.end_time:%Y-%m-%d %H:%M UTC}</p>
        <p><strong>Authorization:</strong> <span class="badge badge-ok">Confirmed</span></p>
    </div>

    <h2>Tools</h2>
    <p><span class="badge badge-ok">Executed</span> {html_mod.escape(tools_ok)}</p>
    <p style="margin-top:0.5rem"><span class="badge badge-fail">Failed</span> {html_mod.escape(tools_fail)}</p>

    <h2>Summary ({len(self.findings)} findings)</h2>
    <div class="summary-grid">
        {"".join(f'<div class="summary-card"><div class="count">{count}</div><div class="label">{itype.replace("_"," ")}</div></div>' for itype, count in sorted(self.summary.items()))}
    </div>

    <h2>Findings</h2>
    {finding_sections}

    <footer>Generated by OhSINT Orchestrator</footer>
</div>
</body>
</html>"""
