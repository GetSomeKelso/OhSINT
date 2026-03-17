"""Core orchestration engine for OSINT Orchestrator."""

from __future__ import annotations

import concurrent.futures
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console

from src.config import Config, DEFAULT_TIMEOUT
from src.models import IntelFinding, ReconReport, ToolResult
from src.tools.base import BaseTool

console = Console()


class Orchestrator:
    """Runs OSINT tools individually or as scan profiles."""

    def __init__(
        self,
        config: Optional[Config] = None,
        timeout: int = DEFAULT_TIMEOUT,
        parallel: bool = True,
        verbose: bool = False,
    ):
        self.config = config or Config()
        self.timeout = timeout
        self.parallel = parallel
        self.verbose = verbose
        # Import tools to trigger registration, then snapshot the registry
        import src.tools  # noqa: F401
        from src.registry import _TOOL_REGISTRY
        self._tools: Dict[str, BaseTool] = {
            name: cls(config=self.config) for name, cls in _TOOL_REGISTRY.items()
        }

    def all_tools(self) -> List[BaseTool]:
        return list(self._tools.values())

    def get_tool(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def run_tool(self, name: str, target: str, **kwargs) -> ToolResult:
        """Run a single tool by name."""
        tool = self.get_tool(name)
        if tool is None:
            return ToolResult(
                tool_name=name,
                target=target,
                raw_output="",
                errors=[f"Unknown tool: {name}. Use 'list-tools' to see available tools."],
            )
        if self.verbose:
            console.print(f"  [dim]Running {name}...[/dim]")
        return tool.run(target, timeout=self.timeout, **kwargs)

    def run_profile(
        self,
        target: str,
        profile_name: str,
        output_dir: Path,
    ) -> ReconReport:
        """Run all tools in a scan profile."""
        profile = self.config.get_profile(profile_name)
        if profile is None:
            return ReconReport(
                target=target,
                scan_profile=profile_name,
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow(),
                authorization_confirmed=True,
                tools_failed=["profile_not_found"],
            )

        tool_configs = profile.get("tools", [])
        tool_names = []
        tool_kwargs: Dict[str, dict] = {}
        for entry in tool_configs:
            if isinstance(entry, str):
                tool_names.append(entry)
                tool_kwargs[entry] = {}
            elif isinstance(entry, dict):
                for tname, tconf in entry.items():
                    tool_names.append(tname)
                    tool_kwargs[tname] = tconf if isinstance(tconf, dict) else {}

        start_time = datetime.utcnow()
        results: List[ToolResult] = []
        executed: List[str] = []
        failed: List[str] = []

        # Determine which tools can run in parallel vs sequential
        sequential_tools = {"spiderfoot", "recon_ng"}
        parallel_batch = [n for n in tool_names if n not in sequential_tools and n in self._tools]
        sequential_batch = [n for n in tool_names if n in sequential_tools and n in self._tools]
        skipped = [n for n in tool_names if n not in self._tools]

        # Run parallel batch
        if self.parallel and len(parallel_batch) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                futures = {
                    pool.submit(
                        self._run_single, name, target, tool_kwargs.get(name, {})
                    ): name
                    for name in parallel_batch
                }
                for future in concurrent.futures.as_completed(futures):
                    name = futures[future]
                    result = future.result()
                    results.append(result)
                    if result.errors:
                        failed.append(name)
                    else:
                        executed.append(name)
        else:
            for name in parallel_batch:
                result = self._run_single(name, target, tool_kwargs.get(name, {}))
                results.append(result)
                if result.errors:
                    failed.append(name)
                else:
                    executed.append(name)

        # Run sequential batch
        for name in sequential_batch:
            result = self._run_single(name, target, tool_kwargs.get(name, {}))
            results.append(result)
            if result.errors:
                failed.append(name)
            else:
                executed.append(name)

        for name in skipped:
            failed.append(name)

        # Build report
        all_findings: List[IntelFinding] = []
        for r in results:
            all_findings.extend(self._extract_findings(r))

        report = ReconReport(
            target=target,
            scan_profile=profile_name,
            start_time=start_time,
            end_time=datetime.utcnow(),
            authorization_confirmed=True,
            tools_executed=executed,
            tools_failed=failed,
            findings=all_findings,
        )
        return report.deduplicate()

    def _run_single(self, name: str, target: str, kwargs: dict) -> ToolResult:
        """Run a single tool with logging."""
        console.print(f"  [cyan]▶[/cyan] {name}")
        result = self.run_tool(name, target, **kwargs)
        if result.errors:
            console.print(f"  [red]✗[/red] {name}: {result.errors[0]}")
        else:
            console.print(
                f"  [green]✓[/green] {name} ({result.execution_time_seconds:.1f}s)"
            )
        return result

    def _extract_findings(self, result: ToolResult) -> List[IntelFinding]:
        """Extract IntelFindings from a ToolResult's structured_data."""
        findings = []
        for finding_data in result.structured_data.get("findings", []):
            try:
                findings.append(IntelFinding(**finding_data))
            except Exception:
                pass  # Skip malformed findings
        return findings
