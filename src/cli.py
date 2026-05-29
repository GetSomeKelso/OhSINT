"""Main CLI entry point for OSINT Orchestrator."""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

# Force UTF-8 on Windows to avoid cp1252 encoding errors with Rich
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

import logging

import click
from rich.console import Console
from rich.table import Table

from src.config import Config, DEFAULT_RESULTS_DIR, DEFAULT_TIMEOUT
from src.orchestrator import Orchestrator
from src.report import save_report

console = Console()

AUTHORIZATION_BANNER = """
[bold red]╔══════════════════════════════════════════════════════════════╗
║  LEGAL NOTICE — AUTHORIZATION REQUIRED                       ║
║                                                              ║
║  You must have WRITTEN AUTHORIZATION from the target owner   ║
║  before running any reconnaissance scan.                     ║
║                                                              ║
║  Unauthorized scanning is illegal and unethical.             ║
╚══════════════════════════════════════════════════════════════╝[/bold red]
"""


def require_authorization(ctx: click.Context, tool_name: str = "") -> None:
    """Gate active recon behind authorization confirmation.

    Passive tools (querying public sources) run without authorization.
    Active tools (interacting with target infrastructure) require --authorization
    or interactive confirmation.
    """
    # Check if the tool is passive — if so, skip the gate
    if tool_name:
        config = ctx.obj.get("config") or Config()
        orchestrator = Orchestrator(config=config)
        t = orchestrator.get_tool(tool_name)
        if t and t.is_passive:
            return

    auth = ctx.params.get("authorization") or ctx.obj.get("authorization")
    if not auth:
        console.print(AUTHORIZATION_BANNER)
        console.print(
            "[yellow]Pass --authorization to confirm you have written permission, "
            "or answer the prompt below.[/yellow]\n"
        )
        confirmed = click.confirm(
            "Do you have written authorization to scan this target?",
            default=False,
        )
        if not confirmed:
            console.print("[red]Scan aborted. Authorization is required.[/red]")
            sys.exit(1)
        ctx.obj["authorization"] = True


FCRA_BANNER = """
[bold red]╔══════════════════════════════════════════════════════════════╗
║  FCRA PERMISSIBLE PURPOSE REQUIRED                           ║
║                                                              ║
║  This tool accesses commercial identity resolution services  ║
║  governed by the Fair Credit Reporting Act.                  ║
║                                                              ║
║  Re-run with: --fcra-permissible-purpose <engagement-id>     ║
╚══════════════════════════════════════════════════════════════╝[/bold red]
"""


def require_fcra(ctx: click.Context, tool_name: str = "") -> None:
    """Gate FCRA-regulated tools behind permissible purpose documentation."""
    if tool_name:
        config = ctx.obj.get("config") or Config()
        orchestrator = Orchestrator(config=config)
        t = orchestrator.get_tool(tool_name)
        if t and not getattr(t, "requires_fcra", False):
            return  # tool doesn't need FCRA
    fcra_purpose = ctx.obj.get("fcra_purpose")
    if not fcra_purpose:
        console.print(FCRA_BANNER)
        sys.exit(1)


@click.group()
@click.option(
    "--authorization",
    is_flag=True,
    default=False,
    help="Confirm written authorization exists for this scan.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Output directory (default: ./results/<target>/<timestamp>/).",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["json", "md", "html", "all"]),
    default="all",
    help="Report format.",
)
@click.option(
    "--timeout",
    type=int,
    default=DEFAULT_TIMEOUT,
    help=f"Per-tool timeout in seconds (default: {DEFAULT_TIMEOUT}).",
)
@click.option(
    "--parallel/--no-parallel",
    "-P",
    default=True,
    help="Run tools in parallel where safe.",
)
@click.option("--verbose", "-v", is_flag=True, default=False, help="Verbose output.")
@click.option("--dry-run", is_flag=True, default=False, help="Show what would execute without running.")
@click.option(
    "--fcra-permissible-purpose",
    type=str,
    default=None,
    help="Engagement ID for FCRA permissible purpose (required for commercial identity tools).",
)
@click.option(
    "--confirm-costs",
    is_flag=True,
    default=False,
    help="Confirm acceptance of per-query API costs for paid tools (e.g., Twilio).",
)
@click.pass_context
def cli(ctx, authorization, output, output_format, timeout, parallel, verbose, dry_run,
        fcra_permissible_purpose, confirm_costs):
    """OhSINT — Unified OSINT Reconnaissance Orchestrator."""
    ctx.ensure_object(dict)
    ctx.obj["authorization"] = authorization
    ctx.obj["output"] = output
    ctx.obj["output_format"] = output_format
    ctx.obj["timeout"] = timeout
    ctx.obj["parallel"] = parallel
    ctx.obj["verbose"] = verbose
    ctx.obj["dry_run"] = dry_run
    ctx.obj["fcra_purpose"] = fcra_permissible_purpose
    ctx.obj["confirm_costs"] = confirm_costs
    ctx.obj["config"] = Config()

    # Configure logging
    log_level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@cli.command()
@click.option("--target", "-t", required=True, help="Target (domain, IP, email, person name, org).")
@click.option(
    "--profile",
    "-p",
    type=click.Choice(["standard", "passive", "infrastructure", "threat-intel", "phone", "identity", "commercial_identity", "active", "full", "metadata", "social", "people"]),
    default="standard",
    help="Scan profile.",
)
@click.pass_context
def full_recon(ctx, target, profile):
    """Run all tools in a scan profile against a target.

    Passive-only profiles (passive, metadata, social) run without authorization.
    Profiles containing active tools (active, full) require --authorization.
    """
    # Only require auth if the profile includes active tools
    if profile in ("active", "full"):
        require_authorization(ctx)
    # FCRA-gated profiles require both authorization and FCRA purpose
    if profile == "commercial_identity":
        require_authorization(ctx)
        require_fcra(ctx)
    output_dir = _resolve_output_dir(ctx, target)

    orchestrator = Orchestrator(
        config=ctx.obj["config"],
        timeout=ctx.obj["timeout"],
        parallel=ctx.obj["parallel"],
        verbose=ctx.obj["verbose"],
    )

    if ctx.obj.get("dry_run"):
        _dry_run_profile(orchestrator, target, profile)
        return

    console.print(f"[bold green]Starting {profile} recon against {target}[/bold green]")
    console.print(f"Results -> {output_dir}\n")
    report = orchestrator.run_profile(target, profile, output_dir)

    save_report(report, output_dir, ctx.obj["output_format"])
    console.print(f"\n[green]Reports saved to {output_dir}[/green]")
    _print_summary(report)


@cli.command()
@click.option("--target", "-t", required=True, help="Target.")
@click.argument("tool_name")
@click.pass_context
def tool(ctx, target, tool_name):
    """Run a single OSINT tool by name."""
    require_authorization(ctx, tool_name=tool_name)
    require_fcra(ctx, tool_name=tool_name)

    if ctx.obj.get("dry_run"):
        orchestrator = Orchestrator(config=ctx.obj["config"])
        t = orchestrator.get_tool(tool_name)
        if t is None:
            console.print(f"[red]Unknown tool: {tool_name}[/red]")
            return
        cmd = t.build_command(target)
        console.print(f"[yellow][DRY RUN][/yellow] Would execute: {' '.join(cmd)}")
        console.print(f"  Installed: {t.is_installed()}")
        return

    output_dir = _resolve_output_dir(ctx, target)

    orchestrator = Orchestrator(
        config=ctx.obj["config"],
        timeout=ctx.obj["timeout"],
        verbose=ctx.obj["verbose"],
    )
    result = orchestrator.run_tool_resolved(tool_name, target)
    if result.errors:
        for err in result.errors:
            console.print(f"[red]Error: {err}[/red]")
    else:
        console.print(f"[green]{tool_name} completed in {result.execution_time_seconds:.1f}s[/green]")
        if ctx.obj["verbose"]:
            console.print(result.raw_output)


@cli.command("list-tools")
@click.pass_context
def list_tools(ctx):
    """Show all available tools and their installation status."""
    orchestrator = Orchestrator(config=ctx.obj["config"])
    table = Table(title="OSINT Tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Type", style="dim")
    table.add_column("Installed", style="green")
    table.add_column("Binary", style="dim")
    table.add_column("Description")

    for t in orchestrator.all_tools():
        installed = "✓" if t.is_installed() else "✗"
        recon_type = "[green]passive[/green]" if t.is_passive else "[yellow]active[/yellow]"
        style = "" if t.is_installed() else "red"
        table.add_row(t.name, recon_type, installed, t.binary_name, t.description, style=style)

    console.print(table)


@cli.command("install-check")
@click.pass_context
def install_check(ctx):
    """Verify all tools are installed and API keys configured."""
    config: Config = ctx.obj["config"]
    orchestrator = Orchestrator(config=config)

    console.print("[bold]Checking tool installation...[/bold]\n")
    all_ok = True

    # Check binaries
    for t in orchestrator.all_tools():
        if t.is_installed():
            console.print(f"  [green]✓[/green] {t.name} ({t.binary_name})")
        else:
            console.print(f"  [red]✗[/red] {t.name} — install with: {t.install_cmd}")
            all_ok = False

    # Check API keys
    console.print("\n[bold]Checking API keys...[/bold]\n")
    if not config.api_keys_file_exists():
        console.print(
            "  [yellow]⚠ No api_keys.yaml found. "
            "Copy configs/api_keys.yaml.example → configs/api_keys.yaml[/yellow]"
        )
        all_ok = False
    else:
        for t in orchestrator.all_tools():
            missing = t.check_api_keys()
            if missing:
                console.print(f"  [yellow]⚠[/yellow] {t.name} missing keys: {', '.join(missing)}")
                all_ok = False

    # Check wordlists / data sources (optional — warn, don't fail)
    console.print("\n[bold]Checking wordlists...[/bold]\n")
    for item in config.get_paths_status():
        if item["exists"]:
            console.print(f"  [green]✓[/green] {item['name']}: {item['path']}")
        else:
            console.print(
                f"  [yellow]⚠[/yellow] {item['name']}: {item['path']} not found\n"
                f"       → install: {item['install']}"
            )

    if all_ok:
        console.print("\n[bold green]All checks passed.[/bold green]")
    else:
        console.print("\n[yellow]Some checks failed — see above.[/yellow]")


@cli.command("api-keys")
@click.pass_context
def api_keys(ctx):
    """Show API key configuration status."""
    config: Config = ctx.obj["config"]
    if not config.api_keys_file_exists():
        console.print(
            "[yellow]No api_keys.yaml found. "
            "Copy configs/api_keys.yaml.example → configs/api_keys.yaml[/yellow]"
        )
        return

    keys = config.get_all_api_keys()
    table = Table(title="API Keys")
    table.add_column("Tool", style="cyan")
    table.add_column("Key", style="dim")
    table.add_column("Status")

    for tool_name, tool_keys in sorted(keys.items()):
        if isinstance(tool_keys, dict):
            for key_name, value in sorted(tool_keys.items()):
                status = "[green]Set[/green]" if value else "[red]Empty[/red]"
                table.add_row(tool_name, key_name, status)
        else:
            status = "[green]Set[/green]" if tool_keys else "[red]Empty[/red]"
            table.add_row(tool_name, "api_key", status)

    console.print(table)


@cli.command()
@click.option("--target", "-t", multiple=True, help="Target domain(s). Repeat for multiple.")
@click.option("--targets-file", type=click.Path(exists=True), default=None,
              help="File with one domain per line.")
@click.option("--scope-file", type=click.Path(exists=True), default=None,
              help="HackerOne/Bugcrowd scope file — parses assets, prompts for selection.")
@click.option("--re-scan", type=click.Path(exists=True), default=None,
              help="Previous report.json — skip enumeration, re-run fingerprinting only.")
@click.option("--max-subdomains", type=int, default=5000,
              help="Cap on total subdomains to process (default: 5000).")
@click.option("--per-domain", is_flag=True, default=False,
              help="Generate separate per-domain reports in addition to combined.")
@click.option("--dns-bruteforce", is_flag=True, default=False,
              help="Add optional n0kovo DNS brute-force (dnsx). Slow (30-90 min); needs the wordlist.")
@click.pass_context
def takeover(ctx, target, targets_file, scope_file, re_scan, max_subdomains, per_domain, dns_bruteforce):
    """Detect subdomain takeover vulnerabilities.

    Enumerates subdomains, resolves CNAMEs, filters by provider patterns,
    fingerprints dangling records. Detection only — does not claim resources.

    Provide targets via -t flags, --targets-file, or --scope-file.
    """
    from src.pipelines.takeover import TakeoverPipeline

    # Resolve target list: scope-file > targets-file > -t flags
    domains = _resolve_takeover_targets(ctx, target, targets_file, scope_file)
    if not domains:
        console.print("[red]No targets specified. Use -t, --targets-file, or --scope-file.[/red]")
        sys.exit(1)

    config: Config = ctx.obj["config"]
    pipeline = TakeoverPipeline(
        config=config,
        timeout=ctx.obj["timeout"],
        verbose=ctx.obj["verbose"],
    )

    # Dry run
    if ctx.obj.get("dry_run"):
        console.print(f"[yellow][DRY RUN][/yellow] Subdomain takeover pipeline")
        console.print(f"  Targets: {', '.join(domains)}\n")
        table = Table(title="Pipeline stages")
        table.add_column("Tool", style="cyan")
        table.add_column("Installed")
        table.add_column("Command preview")
        for info in pipeline.dry_run(domains):
            installed = "[green]Yes[/green]" if info["installed"] else "[red]No[/red]"
            table.add_row(info["name"], installed, info["command"])
        console.print(table)
        return

    console.print(f"[bold green]Starting subdomain takeover detection[/bold green]")
    console.print(f"  Targets: {', '.join(domains)}")

    re_scan_path = Path(re_scan) if re_scan else None
    output_dir = _resolve_output_dir(ctx, "takeover_" + "_".join(domains[:3]))

    report = pipeline.run(
        targets=domains,
        re_scan_path=re_scan_path,
        max_subdomains=max_subdomains,
        dns_bruteforce=dns_bruteforce,
    )

    save_report(report, output_dir, ctx.obj["output_format"])
    console.print(f"\n[green]Reports saved to {output_dir}[/green]")

    # Per-domain reports
    if per_domain and len(domains) > 1:
        for domain in domains:
            domain_findings = [
                f for f in report.findings
                if (f.raw_data or {}).get("parent_domain") == domain
            ]
            if domain_findings:
                from src.models import ReconReport
                domain_report = ReconReport(
                    target=domain,
                    scan_profile="subdomain_takeover",
                    start_time=report.start_time,
                    end_time=report.end_time,
                    authorization_confirmed=True,
                    tools_executed=report.tools_executed,
                    tools_failed=report.tools_failed,
                    findings=domain_findings,
                    summary={f.type.value: 1 for f in domain_findings},
                )
                domain_dir = _resolve_output_dir(ctx, domain)
                save_report(domain_report, domain_dir, ctx.obj["output_format"])
                console.print(f"  [dim]Per-domain report: {domain_dir}[/dim]")

    _print_takeover_summary(report)


def _resolve_takeover_targets(ctx, target_flags, targets_file, scope_file) -> list[str]:
    """Resolve target domains from the various input options."""
    if scope_file:
        from src.pipelines.scope_parser import parse_scope_file, extract_domains_from_scope
        assets = parse_scope_file(Path(scope_file))
        domain_assets = extract_domains_from_scope(assets, include_ineligible=True)

        if not domain_assets:
            console.print("[yellow]No domain/wildcard assets found in scope file.[/yellow]")
            return []

        # Present interactive selection
        table = Table(title="Parsed scope assets")
        table.add_column("", width=3)
        table.add_column("Domain", style="cyan")
        table.add_column("Type", style="dim")
        table.add_column("Severity")
        table.add_column("Eligibility")

        for asset in domain_assets:
            check = "[green]✓[/green]" if asset["eligible"] else "[red]✗[/red]"
            elig = "[green]Eligible[/green]" if asset["eligible"] else "[red]Ineligible[/red]"
            table.add_row(check, asset["domain"], asset["asset_type"], asset["severity"], elig)

        console.print(table)
        console.print()

        # Default to eligible domains
        eligible = [a["domain"] for a in domain_assets if a["eligible"]]
        ineligible = [a["domain"] for a in domain_assets if not a["eligible"]]

        if ineligible:
            console.print(f"  [dim]{len(ineligible)} ineligible domain(s) excluded by default[/dim]")

        if not eligible:
            console.print("[yellow]No eligible domains found.[/yellow]")
            include_all = click.confirm("Include ineligible domains anyway?", default=False)
            if include_all:
                return [a["domain"] for a in domain_assets]
            return []

        console.print(f"  [green]{len(eligible)} eligible domain(s) selected[/green]")
        proceed = click.confirm(f"Run takeover scan on these {len(eligible)} domains?", default=True)
        if not proceed:
            return []
        return eligible

    if targets_file:
        from src.pipelines.scope_parser import parse_targets_file
        return parse_targets_file(Path(targets_file))

    if target_flags:
        return [t.lower().strip() for t in target_flags if t.strip()]

    return []


def _print_takeover_summary(report) -> None:
    """Print a takeover-specific summary with severity coloring."""
    console.print(f"\n[bold]Takeover Scan Summary[/bold]")
    console.print(f"  Tools executed: {len(report.tools_executed)}")
    console.print(f"  Tools failed:   {len(report.tools_failed)}")
    console.print(f"  Total findings: {len(report.findings)}")

    confirmed = [f for f in report.findings if "confirmed" in f.tags]
    unconfirmed = [f for f in report.findings if "unconfirmed" in f.tags]
    cname_only = [f for f in report.findings if "cname-only" in f.tags]

    if confirmed:
        console.print(f"\n  [bold red]CONFIRMED TAKEOVERS ({len(confirmed)}):[/bold red]")
        for f in confirmed:
            rd = f.raw_data or {}
            console.print(
                f"    [red]●[/red] {f.value} → {rd.get('cname_target', '?')} "
                f"({rd.get('provider_name', '?')}) [{rd.get('severity', '?')}]"
            )
    if unconfirmed:
        console.print(f"\n  [yellow]UNCONFIRMED ({len(unconfirmed)}):[/yellow]")
        for f in unconfirmed:
            rd = f.raw_data or {}
            console.print(
                f"    [yellow]○[/yellow] {f.value} → {rd.get('cname_target', '?')} "
                f"({rd.get('provider_name', '?')})"
            )
    if cname_only:
        console.print(f"\n  [dim]CNAME-ONLY ({len(cname_only)}):[/dim]")
        for f in cname_only:
            rd = f.raw_data or {}
            console.print(
                f"    [dim]·[/dim] {f.value} → {rd.get('cname_target', '?')} "
                f"({rd.get('provider_name', '?')})"
            )

    if not report.findings:
        console.print("\n  [green]No takeover candidates found — target appears safe.[/green]")


@cli.command("url-harvest")
@click.option("--target", "-t", multiple=True, help="Target domain(s).")
@click.option("--targets-file", type=click.Path(exists=True), default=None)
@click.option("--scope-file", type=click.Path(exists=True), default=None)
@click.option("--max-urls", type=int, default=500000)
@click.pass_context
def url_harvest(ctx, target, targets_file, scope_file, max_urls):
    """Harvest historical URLs from Wayback Machine, Common Crawl, OTX, URLScan."""
    from src.pipelines.url_harvest import UrlHarvestPipeline

    domains = _resolve_takeover_targets(ctx, target, targets_file, scope_file)
    if not domains:
        console.print("[red]No targets specified.[/red]")
        sys.exit(1)

    config: Config = ctx.obj["config"]
    pipeline = UrlHarvestPipeline(config=config, timeout=ctx.obj["timeout"], verbose=ctx.obj["verbose"])

    if ctx.obj.get("dry_run"):
        console.print(f"[yellow][DRY RUN][/yellow] URL Harvest Pipeline")
        console.print(f"  Targets: {', '.join(domains)}\n")
        table = Table(title="Pipeline stages")
        table.add_column("Tool", style="cyan")
        table.add_column("Installed")
        table.add_column("Command preview")
        for info in pipeline.dry_run(domains):
            installed = "[green]Yes[/green]" if info["installed"] else "[red]No[/red]"
            table.add_row(info["name"], installed, info["command"])
        console.print(table)
        return

    output_dir = _resolve_output_dir(ctx, "url_harvest_" + "_".join(domains[:3]))
    console.print(f"[bold green]Starting URL harvest[/bold green]")
    console.print(f"  Targets: {', '.join(domains)}")
    report = pipeline.run(targets=domains, max_urls=max_urls, output_dir=output_dir)
    save_report(report, output_dir, ctx.obj["output_format"])
    console.print(f"\n[green]Reports saved to {output_dir}[/green]")
    _print_summary(report)


@cli.command("secret-surface")
@click.option("--target", "-t", multiple=True, help="Target domain(s) or org name(s).")
@click.option("--targets-file", type=click.Path(exists=True), default=None)
@click.option("--scope-file", type=click.Path(exists=True), default=None)
@click.pass_context
def secret_surface(ctx, target, targets_file, scope_file):
    """Discover leaked secrets across GitHub, Docker Hub, and Postman."""
    from src.pipelines.secret_surface import SecretSurfacePipeline

    domains = _resolve_takeover_targets(ctx, target, targets_file, scope_file)
    if not domains:
        console.print("[red]No targets specified.[/red]")
        sys.exit(1)

    config: Config = ctx.obj["config"]
    pipeline = SecretSurfacePipeline(config=config, timeout=ctx.obj["timeout"], verbose=ctx.obj["verbose"])

    if ctx.obj.get("dry_run"):
        console.print(f"[yellow][DRY RUN][/yellow] Secret Surface Pipeline")
        console.print(f"  Targets: {', '.join(domains)}\n")
        table = Table(title="Pipeline stages")
        table.add_column("Tool", style="cyan")
        table.add_column("Installed")
        table.add_column("Command preview")
        for info in pipeline.dry_run(domains):
            installed = "[green]Yes[/green]" if info["installed"] else "[red]No[/red]"
            table.add_row(info["name"], installed, info["command"])
        console.print(table)
        return

    output_dir = _resolve_output_dir(ctx, "secret_surface_" + "_".join(domains[:3]))
    console.print(f"[bold green]Starting secret surface discovery[/bold green]")
    console.print(f"  Targets: {', '.join(domains)}")
    report = pipeline.run(targets=domains)
    save_report(report, output_dir, ctx.obj["output_format"])
    console.print(f"\n[green]Reports saved to {output_dir}[/green]")
    _print_summary(report)


@cli.command("js-analysis")
@click.option("--target", "-t", multiple=True, help="Target domain(s).")
@click.option("--targets-file", type=click.Path(exists=True), default=None)
@click.option("--scope-file", type=click.Path(exists=True), default=None)
@click.option("--js-urls-file", type=click.Path(exists=True), default=None,
              help="JS URL list from url-harvest pipeline (js_urls.txt).")
@click.pass_context
def js_analysis(ctx, target, targets_file, scope_file, js_urls_file):
    """Analyze JavaScript files for endpoints, secrets, and source maps."""
    from src.pipelines.js_analysis import JsAnalysisPipeline

    domains = _resolve_takeover_targets(ctx, target, targets_file, scope_file)
    if not domains:
        console.print("[red]No targets specified.[/red]")
        sys.exit(1)

    config: Config = ctx.obj["config"]
    pipeline = JsAnalysisPipeline(config=config, timeout=ctx.obj["timeout"], verbose=ctx.obj["verbose"])

    if ctx.obj.get("dry_run"):
        console.print(f"[yellow][DRY RUN][/yellow] JS Analysis Pipeline")
        console.print(f"  Targets: {', '.join(domains)}\n")
        table = Table(title="Pipeline stages")
        table.add_column("Tool", style="cyan")
        table.add_column("Installed")
        table.add_column("Command preview")
        for info in pipeline.dry_run(domains):
            installed = "[green]Yes[/green]" if info["installed"] else "[red]No[/red]"
            table.add_row(info["name"], installed, info["command"])
        console.print(table)
        return

    output_dir = _resolve_output_dir(ctx, "js_analysis_" + "_".join(domains[:3]))
    console.print(f"[bold green]Starting JS analysis[/bold green]")
    console.print(f"  Targets: {', '.join(domains)}")
    report = pipeline.run(targets=domains, js_urls_file=js_urls_file, output_dir=output_dir)
    save_report(report, output_dir, ctx.obj["output_format"])
    console.print(f"\n[green]Reports saved to {output_dir}[/green]")
    _print_summary(report)


@cli.command("passive-full")
@click.option("--target", "-t", multiple=True, help="Target domain(s).")
@click.option("--targets-file", type=click.Path(exists=True), default=None)
@click.option("--scope-file", type=click.Path(exists=True), default=None)
@click.option("--skip-takeover", is_flag=True, default=False, help="Skip subdomain takeover pipeline.")
@click.pass_context
def passive_full(ctx, target, targets_file, scope_file, skip_takeover):
    """Run full passive OSINT: takeover + URL harvest + secret surface + JS analysis."""
    from src.pipelines.passive_full import PassiveFullPipeline

    domains = _resolve_takeover_targets(ctx, target, targets_file, scope_file)
    if not domains:
        console.print("[red]No targets specified.[/red]")
        sys.exit(1)

    config: Config = ctx.obj["config"]
    pipeline = PassiveFullPipeline(config=config, timeout=ctx.obj["timeout"], verbose=ctx.obj["verbose"])

    if ctx.obj.get("dry_run"):
        console.print(f"[yellow][DRY RUN][/yellow] Full Passive Pipeline")
        console.print(f"  Targets: {', '.join(domains)}\n")
        table = Table(title="All pipeline stages")
        table.add_column("Tool", style="cyan")
        table.add_column("Installed")
        table.add_column("Command preview")
        for info in pipeline.dry_run(domains):
            installed = "[green]Yes[/green]" if info["installed"] else "[red]No[/red]"
            table.add_row(info["name"], installed, info["command"])
        console.print(table)
        return

    output_dir = _resolve_output_dir(ctx, "passive_full_" + "_".join(domains[:3]))
    console.print(f"[bold green]Starting full passive OSINT scan[/bold green]")
    console.print(f"  Targets: {', '.join(domains)}")
    report = pipeline.run(targets=domains, output_dir=output_dir, skip_takeover=skip_takeover)
    save_report(report, output_dir, ctx.obj["output_format"])
    console.print(f"\n[green]Reports saved to {output_dir}[/green]")
    _print_summary(report)


@cli.command("opsec-check")
@click.pass_context
def opsec_check(ctx):
    """Verify OPSEC configuration — UA rotation, proxy egress, session isolation."""
    config: Config = ctx.obj["config"]
    opsec = config.get_opsec_config()

    console.print("[bold]OPSEC Configuration Check[/bold]\n")

    # Request hygiene
    hygiene = opsec.get("request_hygiene", {})
    ua_count = len(hygiene.get("user_agents", []))
    rotate = hygiene.get("rotate_user_agent", False)
    console.print(f"  {'[green]✓[/green]' if rotate else '[yellow]✗[/yellow]'} "
                  f"User-Agent rotation: {'enabled' if rotate else 'disabled'} ({ua_count} agents)")

    rate_limits = hygiene.get("rate_limits", {})
    default_rpm = rate_limits.get("default_rpm", "not set")
    per_host = rate_limits.get("per_host", {})
    console.print(f"  [green]✓[/green] Rate limits: {default_rpm} rpm default, {len(per_host)} host overrides")

    cookies = hygiene.get("cookies_disabled", False)
    console.print(f"  {'[green]✓[/green]' if cookies else '[yellow]✗[/yellow]'} "
                  f"Cookies: {'disabled' if cookies else 'enabled'}")

    # Egress
    egress = opsec.get("egress", {})
    enabled = egress.get("enabled", False)
    if enabled:
        ptype = egress.get("proxy_type", "?")
        phost = egress.get("proxy_host", "?")
        pport = egress.get("proxy_port", "?")
        console.print(f"  [green]✓[/green] Egress proxy: {ptype}://{phost}:{pport}")

        # Test proxy connectivity
        try:
            import httpx
            # Direct IP
            direct_resp = httpx.get("https://api.ipify.org", timeout=10)
            direct_ip = direct_resp.text.strip()

            # Proxied IP
            proxy_url = f"{ptype}://{phost}:{pport}"
            proxied_resp = httpx.get("https://api.ipify.org", timeout=15, proxy=proxy_url)
            proxied_ip = proxied_resp.text.strip()

            if direct_ip != proxied_ip:
                console.print(f"    [green]✓[/green] Proxy working: {direct_ip} → {proxied_ip}")
            else:
                console.print(f"    [red]✗[/red] Proxy NOT working: same IP ({direct_ip})")
        except Exception as e:
            console.print(f"    [red]✗[/red] Proxy test failed: {e}")

        if ptype == "tor":
            import shutil
            if shutil.which("tor"):
                console.print(f"    [green]✓[/green] Tor binary found")
            else:
                console.print(f"    [red]✗[/red] Tor binary not found")
    else:
        console.print(f"  [yellow]✗[/yellow] Egress proxy: disabled (enable in configs/opsec.yaml)")

    # Session isolation
    session = opsec.get("session", {})
    random_suffix = session.get("random_suffix", False)
    auto_archive = session.get("auto_archive", False)
    console.print(f"  {'[green]✓[/green]' if random_suffix else '[yellow]✗[/yellow]'} "
                  f"Session isolation: random suffix {'enabled' if random_suffix else 'disabled'}")
    console.print(f"  {'[green]✓[/green]' if auto_archive else '[dim]-[/dim]'} "
                  f"Auto-archive: {'enabled' if auto_archive else 'disabled'}")

    if not opsec:
        console.print("\n[yellow]No configs/opsec.yaml found — using defaults[/yellow]")


def _resolve_output_dir(ctx: click.Context, target: str) -> Path:
    if ctx.obj["output"]:
        return Path(ctx.obj["output"])
    config: Config = ctx.obj["config"]
    opsec = config.get_opsec_config()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")

    # Module 3: Session isolation — random suffix
    if opsec.get("session", {}).get("random_suffix", False):
        import secrets as _secrets
        suffix = _secrets.token_hex(4)
        return DEFAULT_RESULTS_DIR / f"{safe_target}_{timestamp}_{suffix}"

    return DEFAULT_RESULTS_DIR / safe_target / timestamp


def _print_summary(report) -> None:
    console.print(f"\n[bold]Scan Summary[/bold]")
    console.print(f"  Tools executed: {len(report.tools_executed)}")
    console.print(f"  Tools failed:   {len(report.tools_failed)}")
    console.print(f"  Total findings: {len(report.findings)}")
    if report.summary:
        for intel_type, count in sorted(report.summary.items()):
            console.print(f"    {intel_type}: {count}")


def _dry_run_profile(orchestrator, target: str, profile: str) -> None:
    """Show what a profile scan would execute without running anything."""
    config = orchestrator.config
    profile_data = config.get_profile(profile)
    if not profile_data:
        console.print(f"[red]Unknown profile: {profile}[/red]")
        return

    console.print(f"[yellow][DRY RUN][/yellow] Profile: {profile}")
    console.print(f"  {profile_data.get('description', '')}\n")

    table = Table(title=f"Tools that would execute against {target}")
    table.add_column("Tool", style="cyan")
    table.add_column("Installed")
    table.add_column("Command")

    for entry in profile_data.get("tools", []):
        if isinstance(entry, str):
            tool_name = entry
            kwargs = {}
        elif isinstance(entry, dict):
            tool_name = list(entry.keys())[0]
            kwargs = entry[tool_name] if isinstance(entry[tool_name], dict) else {}
        else:
            continue

        t = orchestrator.get_tool(tool_name)
        if t:
            installed = "[green]Yes[/green]" if t.is_installed() else "[red]No[/red]"
            try:
                cmd = " ".join(t.build_command(target, **kwargs))
            except Exception:
                cmd = "(command build failed)"
            table.add_row(tool_name, installed, cmd)
        else:
            table.add_row(tool_name, "[red]Not registered[/red]", "-")

    console.print(table)


if __name__ == "__main__":
    cli()
