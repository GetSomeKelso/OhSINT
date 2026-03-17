"""MCP server for OSINT Orchestrator — exposes all tools to Claude Desktop/Code."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Force UTF-8 on Windows
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

from mcp.server.fastmcp import FastMCP

from src.config import Config, DEFAULT_RESULTS_DIR, DEFAULT_TIMEOUT
from src.orchestrator import Orchestrator

mcp = FastMCP("OhSINT OSINT Orchestrator")

# Shared state
_config = Config()
_orchestrator = Orchestrator(config=_config, verbose=True)


def _require_auth(authorization_confirmed: bool) -> None:
    """Raise if authorization not confirmed."""
    if not authorization_confirmed:
        raise ValueError(
            "Authorization not confirmed. You must have WRITTEN AUTHORIZATION "
            "from the target owner before running any scan."
        )


# ---------------------------------------------------------------------------
# Full recon
# ---------------------------------------------------------------------------
@mcp.tool()
def osint_full_recon(
    target: str,
    profile: str = "passive",
    authorization_confirmed: bool = False,
    output_format: str = "all",
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """Run full OSINT reconnaissance against a target using a scan profile.

    Profiles: passive, active, full, metadata, social.
    Requires written authorization from target owner.
    """
    _require_auth(authorization_confirmed)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
    output_dir = DEFAULT_RESULTS_DIR / safe_target / timestamp

    orchestrator = Orchestrator(config=_config, timeout=timeout, verbose=True)
    report = orchestrator.run_profile(target, profile, output_dir)

    # Save reports
    output_dir.mkdir(parents=True, exist_ok=True)
    if output_format in ("json", "all"):
        (output_dir / "report.json").write_text(report.model_dump_json(indent=2))
    if output_format in ("md", "all"):
        (output_dir / "report.md").write_text(report.to_markdown())
    if output_format in ("html", "all"):
        (output_dir / "report.html").write_text(report.to_html())

    return report.to_markdown()


# ---------------------------------------------------------------------------
# Individual tool wrappers
# ---------------------------------------------------------------------------
@mcp.tool()
def osint_theharvester(
    domain: str,
    sources: str = "all",
    limit: int = 500,
    authorization_confirmed: bool = False,
) -> str:
    """Harvest emails, subdomains, IPs from search engines for a domain."""
    _require_auth(authorization_confirmed)
    result = _orchestrator.run_tool(
        "theharvester", domain, sources=sources, limit=limit
    )
    return _format_result(result)


@mcp.tool()
def osint_spiderfoot(
    target: str,
    use_case: str = "all",
    output_format: str = "json",
    authorization_confirmed: bool = False,
) -> str:
    """Run SpiderFoot automated OSINT scan (200+ modules).

    use_case options: all, footprint, investigate, passive.
    """
    _require_auth(authorization_confirmed)
    result = _orchestrator.run_tool(
        "spiderfoot", target, use_case=use_case, output_format=output_format
    )
    return _format_result(result)


@mcp.tool()
def osint_recon_ng(
    target: str,
    modules: str = "passive",
    authorization_confirmed: bool = False,
) -> str:
    """Run recon-ng modules against a target.

    modules options: passive, active_set.
    """
    _require_auth(authorization_confirmed)
    result = _orchestrator.run_tool("recon_ng", target, modules=modules)
    return _format_result(result)


@mcp.tool()
def osint_metagoofil(
    domain: str,
    filetypes: str = "pdf,doc,xls,ppt,docx,xlsx,pptx",
    max_results: int = 100,
    authorization_confirmed: bool = False,
) -> str:
    """Harvest and analyze document metadata from a domain."""
    _require_auth(authorization_confirmed)
    result = _orchestrator.run_tool(
        "metagoofil", domain, filetypes=filetypes, max_results=max_results
    )
    return _format_result(result)


@mcp.tool()
def osint_shodan(
    query: str,
    mode: str = "search",
    authorization_confirmed: bool = False,
) -> str:
    """Search Shodan for internet-connected devices and services.

    mode options: search, host, domain.
    """
    _require_auth(authorization_confirmed)
    result = _orchestrator.run_tool("shodan", query, mode=mode)
    return _format_result(result)


@mcp.tool()
def osint_exiftool(
    directory: str,
    filter_fields: str = "Author|Creator|Email|Producer|Template|Software",
    authorization_confirmed: bool = False,
) -> str:
    """Extract metadata from downloaded files in a directory."""
    _require_auth(authorization_confirmed)
    result = _orchestrator.run_tool(
        "exiftool", directory, filter_fields=filter_fields
    )
    return _format_result(result)


@mcp.tool()
def osint_github_dorks(
    target: str,
    dork_file: str = "",
    authorization_confirmed: bool = False,
) -> str:
    """Scan GitHub repos/orgs for sensitive information leaks."""
    _require_auth(authorization_confirmed)
    kwargs = {}
    if dork_file:
        kwargs["dork_file"] = dork_file
    result = _orchestrator.run_tool("github_dorks", target, **kwargs)
    return _format_result(result)


@mcp.tool()
def osint_google_dorks(
    domain: str,
    dork_category: str = "all",
    authorization_confirmed: bool = False,
) -> str:
    """Run Google dork queries against a target domain.

    Categories: all, ghdb_passive, filetype_dorks, login_dorks, sensitive_dorks, directories.
    """
    _require_auth(authorization_confirmed)
    result = _orchestrator.run_tool(
        "dork_cli", domain, dork_category=dork_category
    )
    return _format_result(result)


@mcp.tool()
def osint_xray(
    target: str,
    mode: str = "full",
    authorization_confirmed: bool = False,
) -> str:
    """Run XRay network recon against a target."""
    _require_auth(authorization_confirmed)
    result = _orchestrator.run_tool("xray", target, mode=mode)
    return _format_result(result)


@mcp.tool()
def osint_datasploit(
    target: str,
    target_type: str = "domain",
    authorization_confirmed: bool = False,
) -> str:
    """Run DataSploit OSINT visualizer. target_type: domain, email, ip, person."""
    _require_auth(authorization_confirmed)
    result = _orchestrator.run_tool(
        "datasploit", target, target_type=target_type
    )
    return _format_result(result)


@mcp.tool()
def osint_report(
    results_dir: str,
    format: str = "all",
) -> str:
    """Generate a consolidated report from scan results in a directory."""
    from src.report import load_report, save_report

    path = Path(results_dir)
    json_file = path / "report.json"
    if not json_file.exists():
        return f"No report.json found in {results_dir}"

    report = load_report(json_file)
    save_report(report, path, format)
    return report.to_markdown()


# ---------------------------------------------------------------------------
# Utility tools
# ---------------------------------------------------------------------------
@mcp.tool()
def osint_list_tools() -> str:
    """List all available OSINT tools and their installation status."""
    lines = ["| Tool | Installed | Description |", "|------|-----------|-------------|"]
    for t in _orchestrator.all_tools():
        status = "Yes" if t.is_installed() else "No"
        lines.append(f"| {t.name} | {status} | {t.description} |")
    return "\n".join(lines)


@mcp.tool()
def osint_install_check() -> str:
    """Check which tools are installed and which API keys are configured."""
    lines = ["## Tool Installation"]
    for t in _orchestrator.all_tools():
        icon = "[OK]" if t.is_installed() else "[MISSING]"
        lines.append(f"  {icon} {t.name} ({t.binary_name})")
        if not t.is_installed():
            lines.append(f"        Install: {t.install_cmd}")

    lines.append("\n## API Keys")
    if not _config.api_keys_file_exists():
        lines.append("  [WARN] No api_keys.yaml found")
    else:
        for t in _orchestrator.all_tools():
            missing = t.check_api_keys()
            if missing:
                lines.append(f"  [WARN] {t.name} missing: {', '.join(missing)}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _format_result(result: Any) -> str:
    """Format a ToolResult for MCP response."""
    from src.models import ToolResult

    if not isinstance(result, ToolResult):
        return str(result)

    parts = [f"## {result.tool_name} Results"]
    parts.append(f"**Target:** {result.target}")
    parts.append(f"**Time:** {result.execution_time_seconds:.1f}s")

    if result.errors:
        parts.append(f"\n### Errors")
        for err in result.errors:
            parts.append(f"- {err}")

    data = result.structured_data
    if data:
        # Show key counts
        for key, value in data.items():
            if key == "findings":
                parts.append(f"\n**Findings:** {len(value)}")
            elif isinstance(value, list):
                parts.append(f"**{key}:** {len(value)} items")
            elif isinstance(value, (str, int, float)):
                parts.append(f"**{key}:** {value}")

        # Show findings detail
        findings = data.get("findings", [])
        if findings:
            parts.append("\n| Type | Value | Confidence |")
            parts.append("|------|-------|------------|")
            for f in findings[:50]:  # Cap at 50 for readability
                ftype = f.get("type", "unknown")
                if hasattr(ftype, "value"):
                    ftype = ftype.value
                val = str(f.get("value", ""))[:80]
                conf = f.get("confidence", 0)
                parts.append(f"| {ftype} | `{val}` | {conf:.0%} |")
            if len(findings) > 50:
                parts.append(f"\n*...and {len(findings) - 50} more findings*")

    return "\n".join(parts)


def main():
    """Run the MCP server over SSE on 127.0.0.1:8055.

    Designed to run inside a Kali/Parrot VM with port forwarding
    to the Windows host where Claude Desktop connects.
    """
    mcp.run(transport="sse", host="127.0.0.1", port=8055)


if __name__ == "__main__":
    main()
