"""Core orchestration engine for OSINT Orchestrator."""

from __future__ import annotations

import concurrent.futures
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console

from src.config import Config, DEFAULT_TIMEOUT
from src.models import IntelFinding, ReconReport, ToolResult
from src.target import ResolvedTarget, TargetResolver
from src.tools.base import BaseTool

console = Console()
logger = logging.getLogger("ohsint.orchestrator")


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
        self.resolver = TargetResolver()
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
        """Run a single tool by name (target already resolved)."""
        tool = self.get_tool(name)
        if tool is None:
            logger.warning("Unknown tool requested: %s", name)
            return ToolResult(
                tool_name=name,
                target=target,
                raw_output="",
                errors=[f"Unknown tool: {name}. Use 'list-tools' to see available tools."],
            )
        if self.verbose:
            console.print(f"  [dim]Running {name}...[/dim]")
        logger.info("Running tool %s against %s", name, target)
        return tool.run(target, timeout=self.timeout, **kwargs)

    def run_tool_resolved(self, name: str, raw_target: str, **kwargs) -> ToolResult:
        """Resolve the target for a specific tool, then run it."""
        tool = self.get_tool(name)
        if tool is not None and tool.accepted_target_types:
            resolved = self.resolver.resolve(raw_target)
            effective = resolved.get_for(tool.accepted_target_types)
            logger.info(
                "Resolved %r → %r for tool %s (wants %s)",
                raw_target, effective, name,
                [t.value for t in tool.accepted_target_types],
            )
        else:
            effective = raw_target
        return self.run_tool(name, effective, **kwargs)

    def run_profile(
        self,
        target: str,
        profile_name: str,
        output_dir: Path,
    ) -> ReconReport:
        """Run all tools in a scan profile, resolving the target for each tool."""
        profile = self.config.get_profile(profile_name)
        if profile is None:
            logger.error("Profile not found: %s", profile_name)
            return ReconReport(
                target=target,
                scan_profile=profile_name,
                start_time=datetime.now(timezone.utc),
                end_time=datetime.now(timezone.utc),
                authorization_confirmed=True,
                tools_failed=["profile_not_found"],
            )

        # Resolve the target once for all tools
        resolved = self.resolver.resolve(target)
        if self.verbose:
            console.print(f"  [dim]Target resolved: {target!r} → detected as {resolved.detected_type.value} ({resolved.confidence:.0%})[/dim]")
            if resolved.domain:
                console.print(f"  [dim]  domain: {resolved.domain}[/dim]")
            if resolved.github_handle:
                console.print(f"  [dim]  github: {resolved.github_handle}[/dim]")
            if resolved.org_name:
                console.print(f"  [dim]  org:    {resolved.org_name}[/dim]")
            if resolved.person_name:
                console.print(f"  [dim]  person: {resolved.person_name}[/dim]")

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

        start_time = datetime.now(timezone.utc)
        results: List[ToolResult] = []
        executed: List[str] = []
        failed: List[str] = []

        # Determine which tools can run in parallel vs sequential
        # Heavy tools and tools requiring credentials run sequentially
        sequential_tools = {"spiderfoot", "recon_ng", "linkedin2username"}
        # Sherlock runs AFTER people-discovery tools (CrossLinked, InSpy, linkedin2username)
        # to consume their discovered names as input
        post_pipeline_tools = {"sherlock"}
        parallel_batch = [
            n for n in tool_names
            if n not in sequential_tools and n not in post_pipeline_tools and n in self._tools
        ]
        sequential_batch = [n for n in tool_names if n in sequential_tools and n in self._tools]
        post_batch = [n for n in tool_names if n in post_pipeline_tools and n in self._tools]
        skipped = [n for n in tool_names if n not in self._tools]

        logger.info(
            "Profile %s: %d parallel, %d sequential, %d skipped",
            profile_name, len(parallel_batch), len(sequential_batch), len(skipped),
        )

        # Run parallel batch
        if self.parallel and len(parallel_batch) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                futures = {
                    pool.submit(
                        self._run_single, name, resolved, tool_kwargs.get(name, {})
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
                result = self._run_single(name, resolved, tool_kwargs.get(name, {}))
                results.append(result)
                if result.errors:
                    failed.append(name)
                else:
                    executed.append(name)

        # Run sequential batch
        for name in sequential_batch:
            result = self._run_single(name, resolved, tool_kwargs.get(name, {}))
            results.append(result)
            if result.errors:
                failed.append(name)
            else:
                executed.append(name)

        # Run post-pipeline tools (e.g., Sherlock consumes discovered people)
        if post_batch:
            # Collect person names and usernames from prior results
            discovered_usernames = set()
            for r in results:
                for person in r.structured_data.get("people", []):
                    # Generate username variants from person names
                    parts = person.lower().split()
                    if len(parts) >= 2:
                        first, last = parts[0], parts[-1]
                        discovered_usernames.add(f"{first[0]}{last}")      # jsmith
                        discovered_usernames.add(f"{first}.{last}")        # john.smith
                        discovered_usernames.add(f"{first}{last[0]}")      # johns
                for username in r.structured_data.get("usernames", []):
                    discovered_usernames.add(username)

            if discovered_usernames:
                for name in post_batch:
                    kwargs = dict(tool_kwargs.get(name, {}))
                    kwargs["usernames"] = sorted(discovered_usernames)
                    result = self._run_single(name, resolved, kwargs)
                    results.append(result)
                    if result.errors:
                        failed.append(name)
                    else:
                        executed.append(name)
            else:
                logger.info("No usernames discovered — skipping post-pipeline tools: %s", post_batch)
                for name in post_batch:
                    # Run with the raw target as fallback
                    result = self._run_single(name, resolved, tool_kwargs.get(name, {}))
                    results.append(result)
                    if result.errors:
                        failed.append(name)
                    else:
                        executed.append(name)

        for name in skipped:
            logger.warning("Tool %s not registered, skipping", name)
            failed.append(name)

        # Build report
        all_findings: List[IntelFinding] = []
        for r in results:
            all_findings.extend(self._extract_findings(r))

        report = ReconReport(
            target=target,
            resolved_target=resolved.summary_dict(),
            scan_profile=profile_name,
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            authorization_confirmed=True,
            tools_executed=executed,
            tools_failed=failed,
            findings=all_findings,
        )
        return report.deduplicate()

    def _run_single(
        self, name: str, resolved: ResolvedTarget, kwargs: dict
    ) -> ToolResult:
        """Pick the right target variant for a tool and run it."""
        tool = self.get_tool(name)
        if tool is not None and tool.accepted_target_types:
            effective_target = resolved.get_for(tool.accepted_target_types)
        else:
            effective_target = resolved.raw

        console.print(f"  [cyan]▶[/cyan] {name} → [dim]{effective_target}[/dim]")
        result = self.run_tool(name, effective_target, **kwargs)
        if result.errors:
            logger.warning("Tool %s failed: %s", name, result.errors[0])
            console.print(f"  [red]✗[/red] {name}: {result.errors[0]}")
        else:
            logger.info("Tool %s completed in %.1fs", name, result.execution_time_seconds)
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
            except Exception as exc:
                logger.debug(
                    "Skipping malformed finding from %s: %s (data: %s)",
                    result.tool_name, exc, finding_data,
                )
        return findings
