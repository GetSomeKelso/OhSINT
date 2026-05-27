"""Full passive OSINT pipeline — chains all pipeline modules.

Execution order:
  Phase 1 (parallel): takeover + url_harvest + secret_surface
  Phase 2 (sequential): js_analysis (depends on url_harvest's js_urls.txt)

Merges all reports into a single deduplicated ReconReport.
"""

from __future__ import annotations

import concurrent.futures
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console

from src.config import Config, DEFAULT_TIMEOUT
from src.models import IntelFinding, ReconReport

console = Console()
logger = logging.getLogger("ohsint.pipeline.passive_full")


class PassiveFullPipeline:
    """Meta-pipeline chaining takeover → url_harvest → secret_surface → js_analysis."""

    def __init__(
        self,
        config: Optional[Config] = None,
        timeout: int = DEFAULT_TIMEOUT,
        verbose: bool = False,
    ):
        self.config = config or Config()
        self.timeout = timeout
        self.verbose = verbose

    def run(
        self,
        targets: list[str],
        output_dir: Path | None = None,
        skip_takeover: bool = False,
    ) -> ReconReport:
        """Run all passive pipelines and merge results."""
        start_time = datetime.now(timezone.utc)

        from src.pipelines.takeover import TakeoverPipeline
        from src.pipelines.url_harvest import UrlHarvestPipeline
        from src.pipelines.secret_surface import SecretSurfacePipeline
        from src.pipelines.js_analysis import JsAnalysisPipeline

        reports: list[ReconReport] = []

        # Phase 1: Independent pipelines in parallel
        console.print("[bold cyan]Phase 1:[/bold cyan] Running independent pipelines in parallel...\n")

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = {}

            if not skip_takeover:
                tp = TakeoverPipeline(config=self.config, timeout=self.timeout, verbose=self.verbose)
                futures[pool.submit(tp.run, targets)] = "takeover"

            uh = UrlHarvestPipeline(config=self.config, timeout=self.timeout, verbose=self.verbose)
            uh_output = output_dir / "url_harvest" if output_dir else None
            futures[pool.submit(uh.run, targets, output_dir=uh_output)] = "url_harvest"

            ss = SecretSurfacePipeline(config=self.config, timeout=self.timeout, verbose=self.verbose)
            futures[pool.submit(ss.run, targets)] = "secret_surface"

            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    report = future.result()
                    reports.append(report)
                    console.print(
                        f"\n[green]✓[/green] {name} complete: "
                        f"{len(report.findings)} findings"
                    )
                except Exception as e:
                    logger.error("Pipeline %s failed: %s", name, e)
                    console.print(f"\n[red]✗[/red] {name} failed: {e}")

        # Phase 2: JS analysis depends on url_harvest output
        console.print("\n[bold cyan]Phase 2:[/bold cyan] Running JS analysis (depends on URL harvest)...\n")

        # Find js_urls_file from url_harvest report
        js_urls_file = None
        for r in reports:
            if r.scan_profile == "url_harvest" and r.resolved_target:
                js_urls_file = r.resolved_target.get("js_urls_file")
                break

        try:
            ja = JsAnalysisPipeline(config=self.config, timeout=self.timeout, verbose=self.verbose)
            ja_output = output_dir / "js_analysis" if output_dir else None
            js_report = ja.run(targets, js_urls_file=js_urls_file, output_dir=ja_output)
            reports.append(js_report)
            console.print(
                f"\n[green]✓[/green] js_analysis complete: "
                f"{len(js_report.findings)} findings"
            )
        except Exception as e:
            logger.error("JS analysis failed: %s", e)
            console.print(f"\n[red]✗[/red] js_analysis failed: {e}")

        # Merge all reports
        merged = self._merge_reports(reports, targets, start_time)
        console.print(
            f"\n[bold green]Full passive scan complete:[/bold green] "
            f"{len(merged.findings)} total findings across {len(merged.tools_executed)} tools"
        )
        return merged

    def dry_run(self, targets: list[str]) -> list[dict]:
        """Show all pipeline stages and tools."""
        from src.pipelines.takeover import TakeoverPipeline
        from src.pipelines.url_harvest import UrlHarvestPipeline
        from src.pipelines.secret_surface import SecretSurfacePipeline
        from src.pipelines.js_analysis import JsAnalysisPipeline

        all_info = []
        for pipeline_cls, label in [
            (TakeoverPipeline, "[takeover]"),
            (UrlHarvestPipeline, "[url_harvest]"),
            (SecretSurfacePipeline, "[secret_surface]"),
            (JsAnalysisPipeline, "[js_analysis]"),
        ]:
            p = pipeline_cls(config=self.config)
            for info in p.dry_run(targets):
                info["name"] = f"{label} {info['name']}"
                all_info.append(info)

        return all_info

    def _merge_reports(
        self,
        reports: list[ReconReport],
        targets: list[str],
        start_time: datetime,
    ) -> ReconReport:
        """Merge multiple pipeline reports into a single deduplicated report."""
        all_findings: list[IntelFinding] = []
        all_executed: list[str] = []
        all_failed: list[str] = []

        for r in reports:
            all_findings.extend(r.findings)
            for t in r.tools_executed:
                if t not in all_executed:
                    all_executed.append(t)
            for t in r.tools_failed:
                if t not in all_failed:
                    all_failed.append(t)

        summary: dict[str, int] = {}
        for f in all_findings:
            summary[f.type.value] = summary.get(f.type.value, 0) + 1

        merged = ReconReport(
            target=", ".join(targets),
            scan_profile="osint_passive_full",
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            authorization_confirmed=True,
            tools_executed=all_executed,
            tools_failed=all_failed,
            findings=all_findings,
            summary=summary,
        )
        return merged.deduplicate()
