"""Historical URL harvesting pipeline.

Chains: gau + waybackurls + waymore (parallel) → merge/deduplicate →
gf pattern matching → JS URL extraction → robots.txt history.

All passive — queries public archives only.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from rich.console import Console

from src.config import Config, DEFAULT_TIMEOUT
from src.models import IntelFinding, IntelType, ReconReport, ToolResult
from src.tools._url_classify import is_js_url

console = Console()
logger = logging.getLogger("ohsint.pipeline.url_harvest")

# gf patterns to run (in order)
_GF_PATTERNS = ["redirect", "aws-keys", "s3-buckets", "secrets", "interestingparams"]


class UrlHarvestPipeline:
    """Multi-stage historical URL harvesting and pattern analysis."""

    def __init__(
        self,
        config: Optional[Config] = None,
        timeout: int = DEFAULT_TIMEOUT,
        verbose: bool = False,
    ):
        self.config = config or Config()
        self.timeout = timeout
        self.verbose = verbose
        self._pipeline_config = self.config.get_pipeline_config("url_harvest")

    def run(
        self,
        targets: list[str],
        max_urls: int | None = None,
        output_dir: Path | None = None,
    ) -> ReconReport:
        """Run the full URL harvesting pipeline."""
        start_time = datetime.now(timezone.utc)
        tools_executed: list[str] = []
        tools_failed: list[str] = []
        all_findings: list[IntelFinding] = []
        temp_files: list[str] = []

        max_urls = max_urls or self._pipeline_config.get("gau_max_urls", 500000)

        try:
            # Stage 1: Collect URLs from all sources
            console.print(f"[cyan]Stage 1:[/cyan] Collecting URLs for {len(targets)} domain(s)...")
            all_urls, js_urls, enum_executed, enum_failed, enum_findings = self._enumerate_urls(targets)
            tools_executed.extend(enum_executed)
            tools_failed.extend(enum_failed)
            all_findings.extend(enum_findings)

            if len(all_urls) > max_urls:
                console.print(
                    f"  [yellow]⚠[/yellow] Truncating {len(all_urls)} URLs to {max_urls}"
                )
                all_urls = set(sorted(all_urls)[:max_urls])

            console.print(f"  [green]✓[/green] {len(all_urls)} unique URLs, {len(js_urls)} JS files")

            if not all_urls:
                console.print("[yellow]No URLs found — nothing to analyze.[/yellow]")
                return self._build_report(targets, start_time, tools_executed, tools_failed, all_findings)

            # Stage 2: Write URL list for gf
            url_file = self._write_temp_file(sorted(all_urls), "urls")
            temp_files.append(url_file)

            # Stage 3: Pattern matching with gf
            console.print(f"[cyan]Stage 3:[/cyan] Running gf pattern matching ({len(_GF_PATTERNS)} patterns)...")
            gf_findings, gf_executed, gf_failed = self._run_gf_patterns(targets[0], url_file)
            tools_executed.extend(gf_executed)
            tools_failed.extend(gf_failed)
            all_findings.extend(gf_findings)
            console.print(f"  [green]✓[/green] {len(gf_findings)} pattern matches found")

            # Stage 4: Extract JS URLs for Pipeline C
            console.print(f"[cyan]Stage 4:[/cyan] Extracting JS URLs...")
            js_urls_file = None
            if output_dir and js_urls:
                output_dir.mkdir(parents=True, exist_ok=True)
                js_urls_file = str(output_dir / "js_urls.txt")
                with open(js_urls_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(sorted(js_urls)) + "\n")
                console.print(f"  [green]✓[/green] {len(js_urls)} JS URLs written to {js_urls_file}")
            else:
                console.print(f"  [dim]  {len(js_urls)} JS URLs found (no output dir for file)[/dim]")

            # Stage 5: robots.txt history
            console.print("[cyan]Stage 5:[/cyan] Fetching robots.txt history from Wayback...")
            robots_findings = self._robots_txt_history(targets)
            all_findings.extend(robots_findings)
            console.print(f"  [green]✓[/green] {len(robots_findings)} historical robots.txt paths found")

            # Also write full URL list to output dir
            if output_dir:
                all_urls_file = str(output_dir / "all_urls.txt")
                with open(all_urls_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(sorted(all_urls)) + "\n")

            report = self._build_report(targets, start_time, tools_executed, tools_failed, all_findings)
            # Stash js_urls_file path for Pipeline C
            if js_urls_file:
                report.resolved_target = report.resolved_target or {}
                report.resolved_target["js_urls_file"] = js_urls_file
            return report

        finally:
            for f in temp_files:
                try:
                    os.unlink(f)
                except OSError:
                    pass

    def dry_run(self, targets: list[str]) -> list[dict]:
        """Show what would be executed without running."""
        from src.tools.gau import Gau
        from src.tools.waybackurls import Waybackurls
        from src.tools.waymore import Waymore
        from src.tools.gf_patterns import GfPatterns

        tools_info = []
        for cls in [Gau, Waybackurls, Waymore, GfPatterns]:
            tool = cls(config=self.config)
            cmd = tool.build_command(targets[0]) if targets else []
            tools_info.append({
                "name": tool.name,
                "installed": tool.is_installed(),
                "command": " ".join(cmd) if cmd else "(API-based)",
            })
        return tools_info

    # ── Stage implementations ─────────────────────────────────────────

    def _enumerate_urls(
        self, targets: list[str]
    ) -> tuple[set[str], set[str], list[str], list[str], list[IntelFinding]]:
        """Stage 1: Run gau + waybackurls + waymore in parallel per domain."""
        from src.tools.gau import Gau
        from src.tools.waybackurls import Waybackurls
        from src.tools.waymore import Waymore

        gau = Gau(config=self.config)
        wb = Waybackurls(config=self.config)
        wm = Waymore(config=self.config)

        all_urls: set[str] = set()
        js_urls: set[str] = set()
        executed: list[str] = []
        failed: list[str] = []
        findings: list[IntelFinding] = []

        tasks = []
        for domain in targets:
            tasks.append(("gau", gau, domain))
            tasks.append(("waybackurls", wb, domain))
            tasks.append(("waymore", wm, domain))

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = {
                pool.submit(tool.run, domain, timeout=self.timeout): (name, domain)
                for name, tool, domain in tasks
            }
            for future in concurrent.futures.as_completed(futures):
                name, domain = futures[future]
                result = future.result()
                if result.errors:
                    if name not in failed:
                        failed.append(name)
                    console.print(f"  [red]✗[/red] {name} ({domain}): {result.errors[0]}")
                else:
                    if name not in executed:
                        executed.append(name)
                    urls = result.structured_data.get("urls", [])
                    if not urls:
                        # waymore doesn't have "urls" key — compute from total_urls
                        urls = []
                    all_urls.update(urls)
                    js = result.structured_data.get("js_urls", [])
                    js_urls.update(js)

                    # Extract findings
                    for fd in result.structured_data.get("findings", []):
                        try:
                            findings.append(IntelFinding(**fd))
                        except Exception:
                            pass

                    url_count = result.structured_data.get("total_urls", len(urls))
                    console.print(
                        f"  [green]✓[/green] {name} ({domain}): {url_count} URLs "
                        f"({result.execution_time_seconds:.1f}s)"
                    )

        # Also extract JS URLs from the full set
        for url in all_urls:
            if is_js_url(url):
                js_urls.add(url)

        return all_urls, js_urls, executed, failed, findings

    def _run_gf_patterns(
        self, target: str, url_file: str
    ) -> tuple[list[IntelFinding], list[str], list[str]]:
        """Stage 3: Run gf pattern matching against URL list."""
        from src.tools.gf_patterns import GfPatterns

        gf = GfPatterns(config=self.config)
        findings: list[IntelFinding] = []
        executed: list[str] = []
        failed: list[str] = []

        for pattern in _GF_PATTERNS:
            result = gf.run(target, timeout=60, input_file=url_file, pattern=pattern)
            if result.errors:
                if "gf_patterns" not in failed:
                    failed.append("gf_patterns")
                console.print(f"    [red]✗[/red] gf:{pattern}: {result.errors[0]}")
            else:
                if "gf_patterns" not in executed:
                    executed.append("gf_patterns")
                matches = result.structured_data.get("total_matches", 0)
                console.print(f"    [green]✓[/green] gf:{pattern}: {matches} matches")
                for fd in result.structured_data.get("findings", []):
                    try:
                        findings.append(IntelFinding(**fd))
                    except Exception:
                        pass

        return findings, executed, failed

    def _robots_txt_history(self, targets: list[str]) -> list[IntelFinding]:
        """Stage 5: Fetch robots.txt history from Wayback CDX API."""
        findings: list[IntelFinding] = []
        max_snapshots = self._pipeline_config.get("robots_max_snapshots", 200)

        for domain in targets:
            try:
                from src.http_client import OhSINTHTTPClient
                with OhSINTHTTPClient(self.config, timeout=30) as client:
                    resp = client.get(
                        "https://web.archive.org/cdx/search/cdx",
                        params={
                            "url": f"{domain}/robots.txt",
                            "output": "json",
                            "fl": "timestamp,statuscode,original",
                            "limit": max_snapshots,
                        },
                    )
                    if resp.status_code != 200:
                        continue
                    data = resp.json()
            except Exception as e:
                logger.warning("robots.txt history fetch failed for %s: %s", domain, e)
                continue

            # First row is headers, rest are data
            if len(data) < 2:
                continue

            # Collect all unique disallow paths across snapshots
            disallow_paths: set[str] = set()
            for row in data[1:]:
                timestamp = row[0] if len(row) > 0 else ""
                status = row[1] if len(row) > 1 else ""
                if status != "200":
                    continue

                # Fetch the actual robots.txt content from Wayback
                try:
                    wb_url = f"https://web.archive.org/web/{timestamp}id_/{domain}/robots.txt"
                    resp2 = client.get(wb_url, follow_redirects=True)
                    if resp2.status_code == 200:
                        for rline in resp2.text.splitlines():
                            rline = rline.strip()
                            if rline.lower().startswith("disallow:"):
                                path = rline.split(":", 1)[1].strip()
                                if path and path != "/":
                                    disallow_paths.add(path)
                except Exception:
                    continue

                # Limit fetches to avoid hammering Wayback
                if len(disallow_paths) > 500:
                    break

            if disallow_paths:
                findings.append(IntelFinding(
                    type=IntelType.SENSITIVE_FILE,
                    value=f"{domain}/robots.txt ({len(disallow_paths)} historical paths)",
                    source_tool="wayback_cdx",
                    confidence=0.5,
                    tags=["robots.txt", "historical", "wordlist"],
                    raw_data={
                        "domain": domain,
                        "disallow_paths": sorted(disallow_paths),
                        "total_paths": len(disallow_paths),
                        "source": "wayback_cdx_robots",
                    },
                ))

        return findings

    # ── Utilities ─────────────────────────────────────────────────────

    def _write_temp_file(self, lines: list[str], prefix: str) -> str:
        fd, path = tempfile.mkstemp(prefix=f"ohsint_{prefix}_", suffix=".txt")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except Exception:
            os.close(fd)
            raise
        return path

    def _build_report(
        self,
        targets: list[str],
        start_time: datetime,
        executed: list[str],
        failed: list[str],
        findings: list[IntelFinding],
    ) -> ReconReport:
        summary: dict[str, int] = {}
        for f in findings:
            summary[f.type.value] = summary.get(f.type.value, 0) + 1

        return ReconReport(
            target=", ".join(targets),
            scan_profile="url_harvest",
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            authorization_confirmed=True,
            tools_executed=executed,
            tools_failed=failed,
            findings=findings,
            summary=summary,
        )
