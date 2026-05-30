"""MCP server for OSINT Orchestrator — exposes all tools to Claude Desktop/Code."""

from __future__ import annotations

import asyncio
import ipaddress
import json as _json
import logging
import os
import sys
import time as _time
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

# ---------------------------------------------------------------------------
# Audit log (MCP08)
# ---------------------------------------------------------------------------
AUDIT_LOG_PATH = DEFAULT_RESULTS_DIR / "audit.jsonl"


def _audit_log(
    tool_name: str,
    target: str,
    authorization_confirmed: bool,
    success: bool,
    execution_time: float,
    error: str = "",
    estimated_cost: float = 0.0,
    fcra_purpose: str = "",
) -> None:
    """Append a JSON-lines audit record (MCP08)."""
    record = {
        "timestamp": datetime.now().isoformat(),
        "tool_name": tool_name,
        "target": target,
        "initiator": "mcp_client",
        "authorization_confirmed": authorization_confirmed,
        "success": success,
        "execution_time_seconds": round(execution_time, 2),
    }
    if error:
        record["error"] = error[:500]
    if estimated_cost > 0:
        record["estimated_cost_usd"] = round(estimated_cost, 4)
    if fcra_purpose:
        record["fcra_purpose"] = fcra_purpose
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(_json.dumps(record) + "\n")
    except OSError as exc:
        logger.warning("Audit log write failed: %s", exc)


async def _run_tool_audited(
    tool_name: str,
    target: str,
    authorization_confirmed: bool,
    **kwargs: Any,
) -> str:
    """Run a tool with authorization check, FCRA check, and audit logging.

    Passive tools skip the authorization gate automatically.
    Active tools require authorization_confirmed=True.
    FCRA-gated tools require fcra_purpose kwarg.
    """
    _require_auth(authorization_confirmed, tool_name=tool_name)

    # FCRA check
    tool = _get_orchestrator().get_tool(tool_name)
    fcra_purpose = kwargs.pop("fcra_purpose", "")
    if tool and getattr(tool, "requires_fcra", False) and not fcra_purpose:
        raise ValueError(
            f"{tool_name} requires FCRA permissible purpose documentation. "
            "This tool accesses commercial identity resolution services governed by the "
            "Fair Credit Reporting Act. Pass fcra_purpose=<engagement-id>."
        )

    estimated_cost = getattr(tool, "estimated_cost_per_query", 0.0) if tool else 0.0

    start = _time.time()
    try:
        result = await asyncio.to_thread(
            _get_orchestrator().run_tool_resolved, tool_name, target, **kwargs
        )
        elapsed = _time.time() - start
        _audit_log(
            tool_name, target, authorization_confirmed,
            success=not result.errors, execution_time=elapsed,
            error=result.errors[0] if result.errors else "",
            estimated_cost=estimated_cost, fcra_purpose=fcra_purpose,
        )
        return _format_result(result)
    except Exception as exc:
        _audit_log(
            tool_name, target, authorization_confirmed,
            success=False, execution_time=_time.time() - start, error=str(exc),
            estimated_cost=estimated_cost, fcra_purpose=fcra_purpose,
        )
        raise


# ---------------------------------------------------------------------------
# DNS rebinding allowlist (LLM06 / MCP05)
# ---------------------------------------------------------------------------
_DEFAULT_ALLOWED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_allowed_host(host: str, allowed_networks: list) -> bool:
    """Check if a Host header value is from an allowed private network."""
    hostname = host.split(":")[0].strip()
    if hostname == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(hostname)
        return any(addr in net for net in allowed_networks)
    except ValueError:
        return False

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


def _require_auth(authorization_confirmed: bool, tool_name: str = "") -> None:
    """Raise if authorization not confirmed for active tools.

    Passive tools (querying public sources) skip the authorization gate.
    Active tools (interacting with target infrastructure) require explicit auth.
    """
    if tool_name:
        tool = _get_orchestrator().get_tool(tool_name)
        if tool and tool.is_passive:
            return  # passive tools don't need authorization
    if not authorization_confirmed:
        raise ValueError(
            "Authorization not confirmed. Active reconnaissance tools require "
            "WRITTEN AUTHORIZATION from the target owner before execution."
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
    start = _time.time()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
    output_dir = DEFAULT_RESULTS_DIR / safe_target / timestamp

    try:
        orchestrator = Orchestrator(config=_get_config(), timeout=timeout, verbose=True)
        report = await asyncio.to_thread(
            orchestrator.run_profile, target, profile, output_dir
        )
        save_report(report, output_dir, output_format)
        logger.info("Full recon complete: %d findings for %s", len(report.findings), target)
        _audit_log("full_recon", target, authorization_confirmed, True, _time.time() - start)
        return report.to_markdown()
    except Exception as exc:
        _audit_log("full_recon", target, authorization_confirmed, False, _time.time() - start, str(exc))
        raise


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
    return await _run_tool_audited(
        "theharvester", domain, authorization_confirmed,
        sources=sources, limit=limit,
    )


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
    return await _run_tool_audited(
        "spiderfoot", target, authorization_confirmed,
        use_case=use_case, output_format=output_format,
    )


@mcp.tool()
async def osint_recon_ng(
    target: str,
    modules: str = "passive",
    authorization_confirmed: bool = False,
) -> str:
    """Run recon-ng modules against a target.

    modules options: passive, active_set.
    """
    return await _run_tool_audited(
        "recon_ng", target, authorization_confirmed, modules=modules,
    )


@mcp.tool()
async def osint_metagoofil(
    domain: str,
    filetypes: str = "pdf,doc,xls,ppt,docx,xlsx,pptx",
    max_results: int = 100,
    authorization_confirmed: bool = False,
) -> str:
    """Harvest and analyze document metadata from a domain."""
    return await _run_tool_audited(
        "metagoofil", domain, authorization_confirmed,
        filetypes=filetypes, max_results=max_results,
    )


@mcp.tool()
async def osint_shodan(
    query: str,
    mode: str = "search",
    authorization_confirmed: bool = False,
) -> str:
    """Search Shodan for internet-connected devices and services.

    mode options: search, host, domain.
    """
    return await _run_tool_audited(
        "shodan", query, authorization_confirmed, mode=mode,
    )


@mcp.tool()
async def osint_exiftool(
    directory: str,
    filter_fields: str = "Author|Creator|Email|Producer|Template|Software",
    authorization_confirmed: bool = False,
) -> str:
    """Extract metadata from downloaded files in a directory."""
    return await _run_tool_audited(
        "exiftool", directory, authorization_confirmed,
        filter_fields=filter_fields,
    )


@mcp.tool()
async def osint_github_dorks(
    target: str,
    dork_file: str = "",
    authorization_confirmed: bool = False,
) -> str:
    """Scan GitHub repos/orgs for sensitive information leaks."""
    kwargs: dict[str, Any] = {}
    if dork_file:
        kwargs["dork_file"] = dork_file
    return await _run_tool_audited(
        "github_dorks", target, authorization_confirmed, **kwargs,
    )


@mcp.tool()
async def osint_google_dorks(
    domain: str,
    dork_category: str = "all",
    authorization_confirmed: bool = False,
) -> str:
    """Run Google dork queries against a target domain.

    Categories: all, ghdb_passive, filetype_dorks, login_dorks, sensitive_dorks, directories.
    """
    return await _run_tool_audited(
        "dork_cli", domain, authorization_confirmed,
        dork_category=dork_category,
    )


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
    return await _run_tool_audited(
        "brave_search", target, authorization_confirmed,
        queries=queries, count=count,
    )


@mcp.tool()
async def osint_xray(
    target: str,
    mode: str = "full",
    authorization_confirmed: bool = False,
) -> str:
    """Run XRay network recon against a target."""
    return await _run_tool_audited(
        "xray", target, authorization_confirmed, mode=mode,
    )


@mcp.tool()
async def osint_datasploit(
    target: str,
    target_type: str = "domain",
    authorization_confirmed: bool = False,
) -> str:
    """Run DataSploit OSINT visualizer. target_type: domain, email, ip, person."""
    return await _run_tool_audited(
        "datasploit", target, authorization_confirmed, target_type=target_type,
    )


# ---------------------------------------------------------------------------
# Passive infrastructure tools
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_subfinder(
    domain: str,
    all_sources: bool = True,
    authorization_confirmed: bool = False,
) -> str:
    """Fast passive subdomain enumeration via 40+ APIs (crt.sh, SecurityTrails, VirusTotal, etc.).

    Zero target interaction — queries public data sources only.
    """
    return await _run_tool_audited(
        "subfinder", domain, authorization_confirmed,
        all_sources=all_sources,
    )


@mcp.tool()
async def osint_crtsh(
    domain: str,
    wildcard: bool = True,
    authorization_confirmed: bool = False,
) -> str:
    """Search Certificate Transparency logs for subdomains and certificates.

    Queries crt.sh for all SSL/TLS certificates ever issued for the domain.
    Discovers subdomains, wildcard patterns, certificate timelines, and issuers.
    """
    return await _run_tool_audited(
        "crtsh", domain, authorization_confirmed,
        wildcard=wildcard,
    )


@mcp.tool()
async def osint_whois(
    target: str,
    authorization_confirmed: bool = False,
) -> str:
    """WHOIS domain registration lookup — registrant info, dates, name servers, registrar."""
    return await _run_tool_audited("whois", target, authorization_confirmed)


# ---------------------------------------------------------------------------
# Threat intel & breach data tools
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_virustotal(
    target: str,
    authorization_confirmed: bool = False,
) -> str:
    """Check domain or IP reputation via VirusTotal — malicious scores, DNS, categories, subdomains.

    Free tier: 4 requests/minute. Queries are spaced automatically.
    """
    return await _run_tool_audited("virustotal", target, authorization_confirmed)


@mcp.tool()
async def osint_h8mail(
    target: str,
    chase: bool = False,
    authorization_confirmed: bool = False,
) -> str:
    """Email breach hunting — checks HIBP, Snusbase, LeakLookup, Dehashed, IntelX.

    target: email address or domain to check for breaches.
    chase: follow related emails found in breach data.
    """
    return await _run_tool_audited(
        "h8mail", target, authorization_confirmed, chase=chase,
    )


@mcp.tool()
async def osint_waymore(
    domain: str,
    mode: str = "U",
    limit: int = 0,
    authorization_confirmed: bool = False,
) -> str:
    """Extract archived URLs from Wayback Machine, Common Crawl, AlienVault OTX, URLScan.

    Discovers forgotten endpoints, old configs, leaked files, and historical subdomains.
    mode: U (URLs only), R (responses), B (both).
    """
    kwargs: dict[str, Any] = {"mode": mode}
    if limit > 0:
        kwargs["limit"] = limit
    return await _run_tool_audited(
        "waymore", domain, authorization_confirmed, **kwargs,
    )


# ---------------------------------------------------------------------------
# Phone & Identity — Tier 1 (Open API)
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_numverify(
    phone: str,
    authorization_confirmed: bool = False,
) -> str:
    """Phone number validation — carrier, line type, location, country (NumVerify API, free tier)."""
    return await _run_tool_audited("numverify", phone, authorization_confirmed)


@mcp.tool()
async def osint_twilio_lookup(
    phone: str,
    authorization_confirmed: bool = False,
) -> str:
    """Phone carrier, CNAM (caller ID name), line type intelligence (Twilio API, ~$0.005/call)."""
    return await _run_tool_audited("twilio_lookup", phone, authorization_confirmed)


@mcp.tool()
async def osint_censys(
    target: str,
    authorization_confirmed: bool = False,
) -> str:
    """Internet device and certificate search — hosts, services, TLS certs (Censys API, free tier)."""
    return await _run_tool_audited("censys", target, authorization_confirmed)


# ---------------------------------------------------------------------------
# Phone & Identity — Tier 2 (Threat Intel)
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_intelx(
    target: str,
    max_results: int = 100,
    authorization_confirmed: bool = False,
) -> str:
    """Search leaked data and dark web — breaches, paste sites, darknet dumps (Intelligence X, free tier)."""
    return await _run_tool_audited(
        "intelx", target, authorization_confirmed, max_results=max_results,
    )


@mcp.tool()
async def osint_hudson_rock(
    target: str,
    authorization_confirmed: bool = False,
) -> str:
    """Infostealer credential lookup — Raccoon, Redline, Vidar compromised machine data (Hudson Rock, free)."""
    return await _run_tool_audited("hudson_rock", target, authorization_confirmed)


# ---------------------------------------------------------------------------
# Phone & Identity — Tier 3 (Consumer/Commercial)
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_consumer_identity_links(
    target: str,
    authorization_confirmed: bool = False,
) -> str:
    """Generate lookup URLs for manual investigation on consumer identity portals (Spokeo, BeenVerified, etc.)."""
    return await _run_tool_audited("consumer_identity_reference", target, authorization_confirmed)


@mcp.tool()
async def osint_whitepages_pro(
    phone: str,
    fcra_purpose: str = "",
    authorization_confirmed: bool = False,
) -> str:
    """Reverse phone/identity lookup — owner, address, carrier (Whitepages Pro, FCRA-gated)."""
    return await _run_tool_audited(
        "whitepages_pro", phone, authorization_confirmed, fcra_purpose=fcra_purpose,
    )


@mcp.tool()
async def osint_phone_recon(
    phone: str,
    authorization_confirmed: bool = False,
) -> str:
    """Run the phone number recon pipeline — cheapest tools first.

    Pipeline: NumVerify → Twilio → IntelX → Hudson Rock → consumer identity URLs.
    """
    _require_auth(authorization_confirmed, tool_name="numverify")
    start = _time.time()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = phone.replace("+", "").replace(" ", "")
    output_dir = DEFAULT_RESULTS_DIR / safe_target / timestamp

    try:
        orchestrator = Orchestrator(config=_get_config(), timeout=300, verbose=True)
        report = await asyncio.to_thread(
            orchestrator.run_profile, phone, "phone", output_dir,
        )
        save_report(report, output_dir, "all")
        _audit_log("phone_recon", phone, authorization_confirmed, True, _time.time() - start)
        return report.to_markdown()
    except Exception as exc:
        _audit_log("phone_recon", phone, authorization_confirmed, False, _time.time() - start, str(exc))
        raise


# ---------------------------------------------------------------------------
# Expanded identity OSINT
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_maigret(
    usernames: str,
    authorization_confirmed: bool = False,
) -> str:
    """Search for usernames across 3,000+ sites with profile data extraction.

    usernames: Comma-separated list. Better false-positive filtering than Sherlock.
    Extracts profile data (names, bios, links) not just presence detection.
    """
    username_list = [u.strip() for u in usernames.split(",") if u.strip()]
    return await _run_tool_audited(
        "maigret", usernames, authorization_confirmed,
        usernames=username_list,
    )


@mcp.tool()
async def osint_holehe(
    email: str,
    only_used: bool = True,
    authorization_confirmed: bool = False,
) -> str:
    """Check which platforms an email is registered on via password reset endpoints.

    Checks 120+ platforms. Different approach than username search —
    tells you WHERE an email is registered (Twitter, Instagram, Spotify, etc.).
    """
    return await _run_tool_audited(
        "holehe", email, authorization_confirmed,
        only_used=only_used,
    )


# --- Previously missing tool endpoints ---


@mcp.tool()
async def osint_snitch(
    target: str,
    authorization_confirmed: bool = False,
) -> str:
    """Run Snitch information gathering via dorks against a target."""
    return await _run_tool_audited("snitch", target, authorization_confirmed)


@mcp.tool()
async def osint_vcsmap(
    target: str,
    mode: str = "full",
    authorization_confirmed: bool = False,
) -> str:
    """Scan public version control systems for sensitive info about a target."""
    return await _run_tool_audited(
        "vcsmap", target, authorization_confirmed, mode=mode,
    )


@mcp.tool()
async def osint_creepy(
    target: str,
    mode: str = "social",
    authorization_confirmed: bool = False,
) -> str:
    """Geolocation OSINT from social media profiles."""
    return await _run_tool_audited(
        "creepy", target, authorization_confirmed, mode=mode,
    )


@mcp.tool()
async def osint_goodork(
    target: str,
    query: str = "",
    pages: int = 3,
    authorization_confirmed: bool = False,
) -> str:
    """Run GooDork Google dorking from CLI against a target."""
    kwargs: dict[str, Any] = {"pages": pages}
    if query:
        kwargs["query"] = query
    return await _run_tool_audited(
        "goodork", target, authorization_confirmed, **kwargs,
    )


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
    lines = ["| Tool | Type | Installed | Description |", "|------|------|-----------|-------------|"]
    for t in _get_orchestrator().all_tools():
        status = "Yes" if t.is_installed() else "No"
        recon_type = "passive" if t.is_passive else "active"
        lines.append(f"| {t.name} | {recon_type} | {status} | {t.description} |")
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
# LinkedIn / People Recon tools
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_crosslinked(
    company_name: str,
    domain: str = "",
    email_format: str = "",
    authorization_confirmed: bool = False,
) -> str:
    """LinkedIn employee enumeration via search engine scraping (passive).

    Scrapes Google/Bing for LinkedIn profiles matching the company name.
    Generates formatted emails based on discovered names.
    No LinkedIn account needed — fully passive.
    """
    kwargs: dict[str, Any] = {}
    if domain:
        kwargs["domain"] = domain
    if email_format:
        kwargs["email_format"] = email_format
    return await _run_tool_audited(
        "crosslinked", company_name, authorization_confirmed, **kwargs,
    )


@mcp.tool()
async def osint_inspy(
    company_name: str,
    mode: str = "both",
    domain: str = "",
    email_format: str = "",
    authorization_confirmed: bool = False,
) -> str:
    """LinkedIn employee and tech stack enumeration via InSpy.

    mode options:
    - empspy: Employee enumeration by title/department
    - techspy: Technology stack fingerprinting from job listings
    - both: Run EmpSpy + TechSpy together
    """
    kwargs: dict[str, Any] = {"mode": mode}
    if domain:
        kwargs["domain"] = domain
    if email_format:
        kwargs["email_format"] = email_format
    return await _run_tool_audited(
        "inspy", company_name, authorization_confirmed, **kwargs,
    )


@mcp.tool()
async def osint_linkedin2username(
    company: str,
    domain: str = "",
    depth: int = 5,
    sleep: int = 3,
    keywords: str = "",
    authorization_confirmed: bool = False,
) -> str:
    """Authenticated LinkedIn employee scraping via Selenium.

    Generates multiple username format files (jsmith, john.smith, etc.).
    Requires LinkedIn credentials in api_keys.yaml.
    WARNING: LinkedIn may rate-limit or ban accounts that scrape aggressively.
    """
    return await _run_tool_audited(
        "linkedin2username", company, authorization_confirmed,
        domain=domain, depth=depth, sleep=sleep, keywords=keywords,
    )


@mcp.tool()
async def osint_sherlock(
    usernames: str,
    nsfw: bool = False,
    authorization_confirmed: bool = False,
) -> str:
    """Search for usernames across 400+ social media sites.

    usernames: Comma-separated list of usernames to search.
    Batch mode — all usernames checked in a single invocation.
    """
    username_list = [u.strip() for u in usernames.split(",") if u.strip()]
    return await _run_tool_audited(
        "sherlock", usernames, authorization_confirmed,
        usernames=username_list, nsfw=nsfw,
    )


@mcp.tool()
async def osint_people_recon(
    company_name: str,
    domain: str = "",
    profile: str = "passive",
    authorization_confirmed: bool = False,
) -> str:
    """Run the full people reconnaissance pipeline.

    Pipeline order:
    1. CrossLinked + InSpy (passive, parallel)
    2. linkedin2username (active only, if credentials configured)
    3. Deduplicate person names across tools
    4. Generate username variations
    5. Sherlock batch search on all discovered usernames
    6. theHarvester validates discovered emails

    profile options: passive (1,3-5), active (1-6), full (all tools).
    """
    _require_auth(authorization_confirmed)
    start = _time.time()
    profile_map = {"passive": "people", "active": "people", "full": "people"}
    scan_profile = profile_map.get(profile, "people")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = company_name.replace("/", "_").replace(":", "_").replace(" ", "_")
    output_dir = DEFAULT_RESULTS_DIR / safe_target / timestamp

    try:
        orchestrator = Orchestrator(config=_get_config(), timeout=600, verbose=True)
        report = await asyncio.to_thread(
            orchestrator.run_profile, company_name, scan_profile, output_dir,
        )
        save_report(report, output_dir, "all")
        _audit_log("people_recon", company_name, authorization_confirmed, True, _time.time() - start)
        return report.to_markdown()
    except Exception as exc:
        _audit_log("people_recon", company_name, authorization_confirmed, False, _time.time() - start, str(exc))
        raise


# ---------------------------------------------------------------------------
# Subdomain takeover detection
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_subdomain_takeover(
    domains: str,
    re_scan_path: str = "",
    authorization_confirmed: bool = False,
    per_domain: bool = False,
    max_subdomains: int = 5000,
) -> str:
    """Detect subdomain takeover vulnerabilities for one or more domains.

    Pipeline: enumerate subdomains (subfinder + crt.sh) → resolve CNAMEs (dnsx) →
    filter by provider patterns → fingerprint (subzy + nuclei) → cross-validate.

    Detection only — does not claim resources or interact with provider accounts.

    Args:
        domains: comma-separated domain list (e.g. "hilton.com,hilton.io")
        re_scan_path: optional path to previous report.json to skip enumeration
        per_domain: if True, return findings grouped per domain
        max_subdomains: cap on total subdomains to process
    """
    _require_auth(authorization_confirmed)
    start = _time.time()

    domain_list = [d.strip().lower() for d in domains.split(",") if d.strip()]
    if not domain_list:
        raise ValueError("No domains provided. Pass comma-separated domain list.")

    try:
        from src.pipelines.takeover import TakeoverPipeline

        pipeline = TakeoverPipeline(
            config=_get_config(),
            timeout=DEFAULT_TIMEOUT,
            verbose=True,
        )

        re_path = Path(re_scan_path) if re_scan_path else None

        report = await asyncio.to_thread(
            pipeline.run, domain_list, re_path, max_subdomains,
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = DEFAULT_RESULTS_DIR / f"takeover_{timestamp}"
        save_report(report, output_dir, "all")

        _audit_log(
            "subdomain_takeover", domains, authorization_confirmed,
            True, _time.time() - start,
        )
        return report.to_markdown()
    except Exception as exc:
        _audit_log(
            "subdomain_takeover", domains, authorization_confirmed,
            False, _time.time() - start, str(exc),
        )
        raise


@mcp.tool()
async def osint_dnsx_cname(
    domain: str,
    authorization_confirmed: bool = False,
) -> str:
    """Resolve DNS CNAME records for a domain to identify dangling records."""
    return await _run_tool_audited("dnsx_cname", domain, authorization_confirmed)


@mcp.tool()
async def osint_subzy(
    domain: str,
    authorization_confirmed: bool = False,
) -> str:
    """Check subdomains for takeover vulnerabilities via provider fingerprints."""
    return await _run_tool_audited("subzy", domain, authorization_confirmed)


@mcp.tool()
async def osint_nuclei_takeovers(
    domain: str,
    authorization_confirmed: bool = False,
) -> str:
    """Run nuclei takeover templates against a domain for fingerprint validation."""
    return await _run_tool_audited("nuclei_takeovers", domain, authorization_confirmed)


# ---------------------------------------------------------------------------
# Pipeline A — Historical URL Harvesting
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_url_harvest(
    domains: str,
    authorization_confirmed: bool = False,
    max_urls: int = 500000,
) -> str:
    """Harvest historical URLs from Wayback Machine, Common Crawl, OTX, URLScan.

    Collects URLs, deduplicates, runs pattern matching (redirects, secrets, S3 buckets),
    extracts JS URLs for downstream analysis, and mines robots.txt history.

    Args:
        domains: comma-separated domain list
        max_urls: cap on total URLs to process
    """
    _require_auth(authorization_confirmed)
    start = _time.time()
    domain_list = [d.strip().lower() for d in domains.split(",") if d.strip()]
    try:
        from src.pipelines.url_harvest import UrlHarvestPipeline
        pipeline = UrlHarvestPipeline(config=_get_config(), timeout=DEFAULT_TIMEOUT, verbose=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = DEFAULT_RESULTS_DIR / f"url_harvest_{timestamp}"
        report = await asyncio.to_thread(pipeline.run, domain_list, max_urls, output_dir)
        save_report(report, output_dir, "all")
        _audit_log("url_harvest", domains, authorization_confirmed, True, _time.time() - start)
        return report.to_markdown()
    except Exception as exc:
        _audit_log("url_harvest", domains, authorization_confirmed, False, _time.time() - start, str(exc))
        raise


@mcp.tool()
async def osint_gau(domain: str, authorization_confirmed: bool = False) -> str:
    """Fetch known URLs from Wayback Machine, Common Crawl, OTX, URLScan."""
    return await _run_tool_audited("gau", domain, authorization_confirmed)


@mcp.tool()
async def osint_waybackurls(domain: str, authorization_confirmed: bool = False) -> str:
    """Fetch all URLs from the Wayback Machine for a domain."""
    return await _run_tool_audited("waybackurls", domain, authorization_confirmed)


# ---------------------------------------------------------------------------
# Pipeline B — Secret Surface Discovery
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_secret_surface(
    domains: str,
    authorization_confirmed: bool = False,
) -> str:
    """Discover leaked secrets across GitHub, Docker Hub, and Postman.

    Searches public repos, container images, and API workspaces. Verifies secrets
    with TruffleHog --only-verified. Never stores raw secrets.

    Args:
        domains: comma-separated domain/org list
    """
    _require_auth(authorization_confirmed)
    start = _time.time()
    domain_list = [d.strip().lower() for d in domains.split(",") if d.strip()]
    try:
        from src.pipelines.secret_surface import SecretSurfacePipeline
        pipeline = SecretSurfacePipeline(config=_get_config(), timeout=DEFAULT_TIMEOUT, verbose=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = DEFAULT_RESULTS_DIR / f"secret_surface_{timestamp}"
        report = await asyncio.to_thread(pipeline.run, domain_list)
        save_report(report, output_dir, "all")
        _audit_log("secret_surface", domains, authorization_confirmed, True, _time.time() - start)
        return report.to_markdown()
    except Exception as exc:
        _audit_log("secret_surface", domains, authorization_confirmed, False, _time.time() - start, str(exc))
        raise


@mcp.tool()
async def osint_github_code_search(domain: str, authorization_confirmed: bool = False) -> str:
    """Search GitHub for leaked secrets and sensitive files in public repos."""
    return await _run_tool_audited("github_code_search", domain, authorization_confirmed)


@mcp.tool()
async def osint_trufflehog_github(org: str, authorization_confirmed: bool = False) -> str:
    """Scan a GitHub org for verified leaked secrets with TruffleHog."""
    return await _run_tool_audited("trufflehog_github", org, authorization_confirmed)


@mcp.tool()
async def osint_docker_hub_search(org: str, authorization_confirmed: bool = False) -> str:
    """Search Docker Hub for an org's public container images."""
    return await _run_tool_audited("docker_hub_search", org, authorization_confirmed)


@mcp.tool()
async def osint_gitleaks(target: str, authorization_confirmed: bool = False) -> str:
    """Run Gitleaks regex-based secret scanner against a target."""
    return await _run_tool_audited("gitleaks", target, authorization_confirmed)


# ---------------------------------------------------------------------------
# Pipeline C — JavaScript File Analysis
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_js_analysis(
    domains: str,
    js_urls_file: str = "",
    authorization_confirmed: bool = False,
) -> str:
    """Analyze JavaScript files for endpoints, secrets, and source maps.

    Collects JS URLs, downloads and beautifies files, runs LinkFinder + SecretFinder,
    TruffleHog filesystem scan, and checks for Swagger/OpenAPI docs.

    Args:
        domains: comma-separated domain list
        js_urls_file: optional path to js_urls.txt from url_harvest pipeline
    """
    _require_auth(authorization_confirmed)
    start = _time.time()
    domain_list = [d.strip().lower() for d in domains.split(",") if d.strip()]
    try:
        from src.pipelines.js_analysis import JsAnalysisPipeline
        pipeline = JsAnalysisPipeline(config=_get_config(), timeout=DEFAULT_TIMEOUT, verbose=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = DEFAULT_RESULTS_DIR / f"js_analysis_{timestamp}"
        report = await asyncio.to_thread(
            pipeline.run, domain_list, js_urls_file or None, output_dir,
        )
        save_report(report, output_dir, "all")
        _audit_log("js_analysis", domains, authorization_confirmed, True, _time.time() - start)
        return report.to_markdown()
    except Exception as exc:
        _audit_log("js_analysis", domains, authorization_confirmed, False, _time.time() - start, str(exc))
        raise


@mcp.tool()
async def osint_linkfinder(target: str, authorization_confirmed: bool = False) -> str:
    """Extract endpoints and API paths from a JavaScript file."""
    return await _run_tool_audited("linkfinder", target, authorization_confirmed)


# ---------------------------------------------------------------------------
# ProjectDiscovery — Passive
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_katana(target: str, authorization_confirmed: bool = False) -> str:
    """Crawl a target for JS files, endpoints, forms, and tech stack."""
    return await _run_tool_audited("katana", target, authorization_confirmed)


@mcp.tool()
async def osint_uncover(target: str, engines: str = "shodan,censys", authorization_confirmed: bool = False) -> str:
    """Search Shodan, Censys, Fofa, Hunter, ZoomEye, Netlas in one query."""
    return await _run_tool_audited("uncover", target, authorization_confirmed, engines=engines)


@mcp.tool()
async def osint_tlsx(target: str, authorization_confirmed: bool = False) -> str:
    """Grab TLS certificate data — SANs, ciphers, JARM hash, expiry."""
    return await _run_tool_audited("tlsx", target, authorization_confirmed)


@mcp.tool()
async def osint_asnmap(target: str, authorization_confirmed: bool = False) -> str:
    """Map org name, domain, or IP to ASN numbers and CIDR ranges."""
    return await _run_tool_audited("asnmap", target, authorization_confirmed)


@mcp.tool()
async def osint_cdncheck(target: str, authorization_confirmed: bool = False) -> str:
    """Detect CDN, WAF, and cloud providers for an IP or domain."""
    return await _run_tool_audited("cdncheck", target, authorization_confirmed)


@mcp.tool()
async def osint_urlfinder(domain: str, authorization_confirmed: bool = False) -> str:
    """Passively gather URLs from web pages for a domain."""
    return await _run_tool_audited("urlfinder", domain, authorization_confirmed)


@mcp.tool()
async def osint_cvemap(target: str, severity: str = "critical,high", authorization_confirmed: bool = False) -> str:
    """Look up CVEs with EPSS scores, KEV status, and exploit references."""
    return await _run_tool_audited("cvemap", target, authorization_confirmed, severity=severity)


@mcp.tool()
async def osint_alterx(domain: str, authorization_confirmed: bool = False) -> str:
    """Generate subdomain permutation wordlists via DSL patterns."""
    return await _run_tool_audited("alterx", domain, authorization_confirmed)


# ---------------------------------------------------------------------------
# ProjectDiscovery — Active (require authorization)
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_httpx(target: str, authorization_confirmed: bool = False) -> str:
    """Probe hosts for HTTP status, titles, tech stack, and headers. Requires authorization."""
    return await _run_tool_audited("httpx", target, authorization_confirmed)


@mcp.tool()
async def osint_naabu(target: str, top_ports: str = "100", authorization_confirmed: bool = False) -> str:
    """Fast port scan — SYN/CONNECT modes. Requires authorization."""
    return await _run_tool_audited("naabu", target, authorization_confirmed, top_ports=top_ports)


@mcp.tool()
async def osint_shuffledns(domain: str, authorization_confirmed: bool = False) -> str:
    """DNS brute-force with wildcard filtering. Requires authorization."""
    return await _run_tool_audited("shuffledns", domain, authorization_confirmed)


@mcp.tool()
async def osint_interactsh(target: str = "generate", authorization_confirmed: bool = False) -> str:
    """Generate OOB interaction URLs for blind vulnerability testing. Requires authorization."""
    return await _run_tool_audited("interactsh", target, authorization_confirmed)


# ---------------------------------------------------------------------------
# Full Passive Pipeline
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_passive_full(
    domains: str,
    authorization_confirmed: bool = False,
    skip_takeover: bool = False,
) -> str:
    """Run full passive OSINT: takeover + URL harvest + secret surface + JS analysis.

    Chains all passive pipelines with cross-pipeline data flow.
    Estimated runtime: 30-90 minutes depending on target size.

    Args:
        domains: comma-separated domain list
        skip_takeover: skip subdomain takeover pipeline
    """
    _require_auth(authorization_confirmed)
    start = _time.time()
    domain_list = [d.strip().lower() for d in domains.split(",") if d.strip()]
    try:
        from src.pipelines.passive_full import PassiveFullPipeline
        pipeline = PassiveFullPipeline(config=_get_config(), timeout=DEFAULT_TIMEOUT, verbose=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = DEFAULT_RESULTS_DIR / f"passive_full_{timestamp}"
        report = await asyncio.to_thread(
            pipeline.run, domain_list, output_dir, skip_takeover,
        )
        save_report(report, output_dir, "all")
        _audit_log("passive_full", domains, authorization_confirmed, True, _time.time() - start)
        return report.to_markdown()
    except Exception as exc:
        _audit_log("passive_full", domains, authorization_confirmed, False, _time.time() - start, str(exc))
        raise


# ---------------------------------------------------------------------------
# Active reconnaissance (auth-gated funnel)
# ---------------------------------------------------------------------------
@mcp.tool()
async def osint_active_recon(
    domains: str,
    authorization_confirmed: bool = False,
    top_ports: str = "100",
    nuclei_severity: str = "high,critical",
    brute: bool = False,
    crawl_depth: int = 2,
) -> str:
    """ACTIVE recon funnel: subfinder/crtsh → naabu → httpx → katana → nuclei.

    Touches the target directly at every stage. REQUIRES authorization_confirmed=True
    (written authorization from the target owner). Each stage narrows to confirmed-live
    before the next, more expensive/noisier stage runs. Recon only — does not exploit.

    Args:
        domains: comma-separated domain list
        top_ports: naabu top-ports preset (100/1000/full)
        nuclei_severity: nuclei severity filter (e.g. "high,critical")
        brute: add active DNS brute-force (shuffledns); slow + loud, off by default
        crawl_depth: katana crawl depth
    """
    _require_auth(authorization_confirmed)  # active pipeline — auth mandatory
    start = _time.time()
    domain_list = [d.strip().lower() for d in domains.split(",") if d.strip()]
    if not domain_list:
        raise ValueError("No domains provided. Pass comma-separated domain list.")
    try:
        from src.pipelines.active_recon import ActiveReconPipeline

        pipeline = ActiveReconPipeline(config=_get_config(), timeout=DEFAULT_TIMEOUT, verbose=True)
        report = await asyncio.to_thread(
            pipeline.run, domain_list, True, top_ports, nuclei_severity, brute, crawl_depth,
        )
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = DEFAULT_RESULTS_DIR / f"active_recon_{timestamp}"
        save_report(report, output_dir, "all")
        _audit_log("active_recon", domains, authorization_confirmed, True, _time.time() - start)
        return report.to_markdown()
    except Exception as exc:
        _audit_log("active_recon", domains, authorization_confirmed, False, _time.time() - start, str(exc))
        raise


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
        ohsint-mcp                              # binds to 127.0.0.1:8055
        ohsint-mcp --host 0.0.0.0               # binds to all interfaces (Hyper-V)
        ohsint-mcp --host 0.0.0.0 --token SECRET # with bearer auth
    """
    import argparse

    parser = argparse.ArgumentParser(description="OhSINT MCP Server")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (default: 127.0.0.1, use 0.0.0.0 for Hyper-V)")
    parser.add_argument("--port", type=int, default=8055, help="Port (default: 8055)")
    parser.add_argument("--token", default=None,
                        help="Bearer token for auth (or set OHSINT_MCP_TOKEN env var)")
    parser.add_argument("--allowed-hosts", default=None,
                        help="Comma-separated extra allowed hosts/CIDRs for DNS rebinding check")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Resolve bearer token: CLI flag > config file > env var
    token = args.token or _get_config().get_mcp_token()

    # FastMCP takes host/port in constructor, not run()
    mcp.settings.host = args.host
    mcp.settings.port = args.port

    logger.info("Starting OhSINT MCP server on %s:%d", args.host, args.port)

    if token:
        logger.info("Bearer token authentication ENABLED")
    else:
        logger.warning(
            "No bearer token configured — MCP server is UNAUTHENTICATED. "
            "Set --token, OHSINT_MCP_TOKEN, or mcp_server.bearer_token in api_keys.yaml"
        )

    # --- DNS rebinding protection (MCP05 / LLM06) ---
    # MCP 1.26+ validates Host headers. When binding to any non-localhost
    # address (0.0.0.0 or a specific private IP like a Hyper-V NAT address),
    # the default validator rejects the Host header. We install a private-network
    # allowlist so RFC1918 IPs are accepted while public IPs are still blocked.
    if args.host not in ("127.0.0.1", "localhost", ""):
        from mcp.server.transport_security import TransportSecurityMiddleware

        allowed_networks = list(_DEFAULT_ALLOWED_NETWORKS)
        # Always allow the exact bound host (covers specific-IP binds)
        try:
            allowed_networks.append(ipaddress.ip_network(args.host, strict=False))
        except ValueError:
            pass
        if args.allowed_hosts:
            for entry in args.allowed_hosts.split(","):
                entry = entry.strip()
                try:
                    allowed_networks.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    # Treat as a literal hostname
                    pass

        async def _validate_private_only(self, request, is_post=False):
            """Allow requests only from private/RFC1918 networks (LLM06)."""
            if is_post:
                content_type = request.headers.get("content-type")
                if content_type and not content_type.lower().startswith("application/json"):
                    from starlette.responses import Response
                    return Response("Invalid Content-Type", status_code=400)
            host = request.headers.get("host", "")
            if _is_allowed_host(host, allowed_networks):
                return None
            logger.warning("Blocked Host header: %s", host)
            from starlette.responses import Response
            return Response("Host not allowed", status_code=403)

        TransportSecurityMiddleware.validate_request = _validate_private_only
        logger.info("DNS rebinding: allowing private networks only")

    # --- Bearer token auth middleware (MCP07) ---
    if token:
        import uvicorn

        app = mcp.sse_app()

        async def _auth_wrapper(scope, receive, send):
            """ASGI middleware that validates Bearer token on all HTTP requests.

            Only checks HTTP scope types. MCP SSE transport is HTTP-only,
            so non-HTTP ASGI types (e.g., lifespan) are passed through
            without authentication. If MCP adds WebSocket transport in
            the future, this middleware must be extended.
            """
            if scope["type"] == "http":
                headers = dict(scope.get("headers", []))
                auth_header = headers.get(b"authorization", b"").decode()
                if not auth_header.startswith("Bearer ") or auth_header[7:] != token:
                    from starlette.responses import PlainTextResponse
                    response = PlainTextResponse("Unauthorized", status_code=401)
                    await response(scope, receive, send)
                    return
            await app(scope, receive, send)

        uvicorn.run(_auth_wrapper, host=args.host, port=args.port)
    else:
        mcp.run(transport="sse")


if __name__ == "__main__":
    main()
