"""MCP server for OSINT Orchestrator — exposes all tools to Claude Desktop/Code."""

from __future__ import annotations

import asyncio
import logging
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
from src.report import save_report

logger = logging.getLogger("ohsint.mcp")

mcp = FastMCP("OhSINT OSINT Orchestrator")

# Shared state — lazy-initialized on first use so config can be loaded after import
_config: Config | None = None
_orchestrator: Orchestrator | None = None


def _get_config() -> Config:
    global _config
    if _config is None:
        _config = Config()
    return _config


def _get_orchestrator() -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator(config=_get_config(), verbose=True)
    return _orchestrator


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
async def osint_full_recon(
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

    orchestrator = Orchestrator(config=_get_config(), timeout=timeout, verbose=True)
    report = await asyncio.to_thread(
        orchestrator.run_profile, target, profile, output_dir
    )

    # Save reports using centralized helper
    save_report(report, output_dir, output_format)
    logger.info("Full recon complete: %d findings for %s", len(report.findings), target)

    return report.to_markdown()


# ---------------------------------------------------------------------------
# Individual tool wrappers
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_theharvester(
    domain: str,
    sources: str = "all",
    limit: int = 500,
    authorization_confirmed: bool = False,
) -> str:
    """Harvest emails, subdomains, IPs from search engines for a domain."""
    _require_auth(authorization_confirmed)
    result = await asyncio.to_thread(
        _get_orchestrator().run_tool_resolved,
        "theharvester", domain, sources=sources, limit=limit,
    )
    return _format_result(result)


@mcp.tool()
async def osint_spiderfoot(
    target: str,
    use_case: str = "all",
    output_format: str = "json",
    authorization_confirmed: bool = False,
) -> str:
    """Run SpiderFoot automated OSINT scan (200+ modules).

    use_case options: all, footprint, investigate, passive.
    """
    _require_auth(authorization_confirmed)
    result = await asyncio.to_thread(
        _get_orchestrator().run_tool_resolved,
        "spiderfoot", target, use_case=use_case, output_format=output_format,
    )
    return _format_result(result)


@mcp.tool()
async def osint_recon_ng(
    target: str,
    modules: str = "passive",
    authorization_confirmed: bool = False,
) -> str:
    """Run recon-ng modules against a target.

    modules options: passive, active_set.
    """
    _require_auth(authorization_confirmed)
    result = await asyncio.to_thread(
        _get_orchestrator().run_tool_resolved,
        "recon_ng", target, modules=modules,
    )
    return _format_result(result)


@mcp.tool()
async def osint_metagoofil(
    domain: str,
    filetypes: str = "pdf,doc,xls,ppt,docx,xlsx,pptx",
    max_results: int = 100,
    authorization_confirmed: bool = False,
) -> str:
    """Harvest and analyze document metadata from a domain."""
    _require_auth(authorization_confirmed)
    result = await asyncio.to_thread(
        _get_orchestrator().run_tool_resolved,
        "metagoofil", domain, filetypes=filetypes, max_results=max_results,
    )
    return _format_result(result)


@mcp.tool()
async def osint_shodan(
    query: str,
    mode: str = "search",
    authorization_confirmed: bool = False,
) -> str:
    """Search Shodan for internet-connected devices and services.

    mode options: search, host, domain.
    """
    _require_auth(authorization_confirmed)
    result = await asyncio.to_thread(
        _get_orchestrator().run_tool_resolved,
        "shodan", query, mode=mode,
    )
    return _format_result(result)


@mcp.tool()
async def osint_exiftool(
    directory: str,
    filter_fields: str = "Author|Creator|Email|Producer|Template|Software",
    authorization_confirmed: bool = False,
) -> str:
    """Extract metadata from downloaded files in a directory."""
    _require_auth(authorization_confirmed)
    result = await asyncio.to_thread(
        _get_orchestrator().run_tool_resolved,
        "exiftool", directory, filter_fields=filter_fields,
    )
    return _format_result(result)


@mcp.tool()
async def osint_github_dorks(
    target: str,
    dork_file: str = "",
    authorization_confirmed: bool = False,
) -> str:
    """Scan GitHub repos/orgs for sensitive information leaks."""
    _require_auth(authorization_confirmed)
    kwargs = {}
    if dork_file:
        kwargs["dork_file"] = dork_file
    result = await asyncio.to_thread(
        _get_orchestrator().run_tool_resolved,
        "github_dorks", target, **kwargs,
    )
    return _format_result(result)


@mcp.tool()
async def osint_google_dorks(
    domain: str,
    dork_category: str = "all",
    authorization_confirmed: bool = False,
) -> str:
    """Run Google dork queries against a target domain.

    Categories: all, ghdb_passive, filetype_dorks, login_dorks, sensitive_dorks, directories.
    """
    _require_auth(authorization_confirmed)
    result = await asyncio.to_thread(
        _get_orchestrator().run_tool_resolved,
        "dork_cli", domain, dork_category=dork_category,
    )
    return _format_result(result)


@mcp.tool()
async def osint_brave_search(
    target: str,
    queries: str = "all",
    count: int = 20,
    authorization_confirmed: bool = False,
) -> str:
    """Search the web via Brave Search API for OSINT reconnaissance.

    Runs OSINT-focused dork queries (subdomains, documents, login pages,
    exposed files, directory listings, config exposure, error pages, API endpoints).

    queries: all, subdomains, documents, login_pages, exposed_files,
             directory_listings, config_exposure, error_pages, api_endpoints.
    """
    _require_auth(authorization_confirmed)
    result = await asyncio.to_thread(
        _get_orchestrator().run_tool_resolved,
        "brave_search", target, queries=queries, count=count,
    )
    return _format_result(result)


@mcp.tool()
async def osint_xray(
    target: str,
    mode: str = "full",
    authorization_confirmed: bool = False,
) -> str:
    """Run XRay network recon against a target."""
    _require_auth(authorization_confirmed)
    result = await asyncio.to_thread(
        _get_orchestrator().run_tool_resolved,
        "xray", target, mode=mode,
    )
    return _format_result(result)


@mcp.tool()
async def osint_datasploit(
    target: str,
    target_type: str = "domain",
    authorization_confirmed: bool = False,
) -> str:
    """Run DataSploit OSINT visualizer. target_type: domain, email, ip, person."""
    _require_auth(authorization_confirmed)
    result = await asyncio.to_thread(
        _get_orchestrator().run_tool_resolved,
        "datasploit", target, target_type=target_type,
    )
    return _format_result(result)


# --- Previously missing tool endpoints ---


@mcp.tool()
async def osint_snitch(
    target: str,
    authorization_confirmed: bool = False,
) -> str:
    """Run Snitch information gathering via dorks against a target."""
    _require_auth(authorization_confirmed)
    result = await asyncio.to_thread(
        _get_orchestrator().run_tool_resolved,
        "snitch", target,
    )
    return _format_result(result)


@mcp.tool()
async def osint_vcsmap(
    target: str,
    mode: str = "full",
    authorization_confirmed: bool = False,
) -> str:
    """Scan public version control systems for sensitive info about a target."""
    _require_auth(authorization_confirmed)
    result = await asyncio.to_thread(
        _get_orchestrator().run_tool_resolved,
        "vcsmap", target, mode=mode,
    )
    return _format_result(result)


@mcp.tool()
async def osint_creepy(
    target: str,
    mode: str = "social",
    authorization_confirmed: bool = False,
) -> str:
    """Geolocation OSINT from social media profiles."""
    _require_auth(authorization_confirmed)
    result = await asyncio.to_thread(
        _get_orchestrator().run_tool_resolved,
        "creepy", target, mode=mode,
    )
    return _format_result(result)


@mcp.tool()
async def osint_goodork(
    target: str,
    query: str = "",
    pages: int = 3,
    authorization_confirmed: bool = False,
) -> str:
    """Run GooDork Google dorking from CLI against a target."""
    _require_auth(authorization_confirmed)
    kwargs: dict[str, Any] = {"pages": pages}
    if query:
        kwargs["query"] = query
    result = await asyncio.to_thread(
        _get_orchestrator().run_tool_resolved,
        "goodork", target, **kwargs,
    )
    return _format_result(result)


@mcp.tool()
async def osint_report(
    results_dir: str,
    output_format: str = "all",
) -> str:
    """Generate a consolidated report from scan results in a directory."""
    from src.report import load_report

    path = Path(results_dir)
    json_file = path / "report.json"
    if not json_file.exists():
        return f"No report.json found in {results_dir}"

    report = load_report(json_file)
    save_report(report, path, output_format)
    return report.to_markdown()


# ---------------------------------------------------------------------------
# Utility tools
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_list_tools() -> str:
    """List all available OSINT tools and their installation status."""
    lines = ["| Tool | Installed | Description |", "|------|-----------|-------------|"]
    for t in _get_orchestrator().all_tools():
        status = "Yes" if t.is_installed() else "No"
        lines.append(f"| {t.name} | {status} | {t.description} |")
    return "\n".join(lines)


@mcp.tool()
async def osint_install_check() -> str:
    """Check which tools are installed and which API keys are configured."""
    lines = ["## Tool Installation"]
    for t in _get_orchestrator().all_tools():
        icon = "[OK]" if t.is_installed() else "[MISSING]"
        lines.append(f"  {icon} {t.name} ({t.binary_name})")
        if not t.is_installed():
            lines.append(f"        Install: {t.install_cmd}")

    lines.append("\n## API Keys")
    config = _get_config()
    if not config.api_keys_file_exists():
        lines.append("  [WARN] No api_keys.yaml found")
    else:
        for t in _get_orchestrator().all_tools():
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
        parts.append("")
        parts.append("### Errors")
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
    """Run the MCP server over SSE.

    Designed to run inside a Kali/Parrot VM with port forwarding
    to the Windows host where Claude Desktop connects.

    Usage:
        ohsint-mcp                    # binds to 127.0.0.1:8055
        ohsint-mcp --host 0.0.0.0     # binds to all interfaces (Hyper-V)
        ohsint-mcp --port 9000        # custom port
    """
    import argparse

    parser = argparse.ArgumentParser(description="OhSINT MCP Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1, use 0.0.0.0 for Hyper-V)")
    parser.add_argument("--port", type=int, default=8055, help="Port (default: 8055)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # FastMCP takes host/port in constructor, not run()
    mcp.settings.host = args.host
    mcp.settings.port = args.port

    logger.info(f"Starting OhSINT MCP server on {args.host}:{args.port}")

    # MCP 1.26+ validates Host headers, blocking requests from IPs.
    # When binding to 0.0.0.0 (e.g., Hyper-V), we need to allow all hosts.
    if args.host == "0.0.0.0":
        import uvicorn
        from starlette.middleware.trustedhost import TrustedHostMiddleware

        # Get the ASGI app that FastMCP builds for SSE transport
        app = mcp.sse_app()

        # Wrap it to allow any Host header
        from starlette.applications import Starlette
        from starlette.routing import Mount
        wrapper = Starlette(
            routes=[Mount("/", app=app)],
            middleware=[
                (TrustedHostMiddleware, {"allowed_hosts": ["*"]}),
            ],
        )

        uvicorn.run(wrapper, host=args.host, port=args.port)
    else:
        mcp.run(transport="sse")


if __name__ == "__main__":
    main()
