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


def require_authorization(ctx: click.Context) -> None:
    """Gate every scan behind authorization confirmation."""
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
@click.pass_context
def cli(ctx, authorization, output, output_format, timeout, parallel, verbose, dry_run):
    """OhSINT — Unified OSINT Reconnaissance Orchestrator."""
    ctx.ensure_object(dict)
    ctx.obj["authorization"] = authorization
    ctx.obj["output"] = output
    ctx.obj["output_format"] = output_format
    ctx.obj["timeout"] = timeout
    ctx.obj["parallel"] = parallel
    ctx.obj["verbose"] = verbose
    ctx.obj["dry_run"] = dry_run
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
    type=click.Choice(["passive", "active", "full", "metadata", "social"]),
    default="passive",
    help="Scan profile.",
)
@click.pass_context
def full_recon(ctx, target, profile):
    """Run all tools in a scan profile against a target."""
    require_authorization(ctx)
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
    require_authorization(ctx)

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
    result = orchestrator.run_tool(tool_name, target)
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
    table.add_column("Installed", style="green")
    table.add_column("Binary", style="dim")
    table.add_column("Description")

    for t in orchestrator.all_tools():
        installed = "✓" if t.is_installed() else "✗"
        style = "" if t.is_installed() else "red"
        table.add_row(t.name, installed, t.binary_name, t.description, style=style)

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


def _resolve_output_dir(ctx: click.Context, target: str) -> Path:
    if ctx.obj["output"]:
        return Path(ctx.obj["output"])
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
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
