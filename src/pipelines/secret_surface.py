"""Secret surface discovery pipeline.

Chains: GitHub Code Search + Docker Hub Search + Postman Search (parallel) →
TruffleHog verification (parallel) → Gitleaks secondary scan → cross-validate.

All passive. Never stores full secrets. Never authenticates with found credentials.
"""

from __future__ import annotations

import concurrent.futures
import logging
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console

from src.config import Config, DEFAULT_TIMEOUT
from src.models import IntelFinding, IntelType, ReconReport, ToolResult

console = Console()
logger = logging.getLogger("ohsint.pipeline.secret_surface")


class SecretSurfacePipeline:
    """Multi-stage secret surface discovery pipeline."""

    def __init__(
        self,
        config: Optional[Config] = None,
        timeout: int = DEFAULT_TIMEOUT,
        verbose: bool = False,
    ):
        self.config = config or Config()
        self.timeout = timeout
        self.verbose = verbose
        self._pipeline_config = self.config.get_pipeline_config("secret_surface")

    def run(self, targets: list[str]) -> ReconReport:
        """Run the full secret surface discovery pipeline."""
        start_time = datetime.now(timezone.utc)
        tools_executed: list[str] = []
        tools_failed: list[str] = []
        all_findings: list[IntelFinding] = []

        # Stages 1-3: Discovery (parallel)
        console.print(f"[cyan]Stage 1-3:[/cyan] Searching GitHub, Docker Hub, Postman for {len(targets)} target(s)...")
        repos, images, workspaces, disc_findings, disc_exec, disc_fail = self._discover(targets)
        tools_executed.extend(disc_exec)
        tools_failed.extend(disc_fail)
        all_findings.extend(disc_findings)

        console.print(
            f"  [green]✓[/green] {len(repos)} repos, {len(images)} Docker images, "
            f"{len(workspaces)} Postman workspaces"
        )

        # Stage 4: TruffleHog verification (parallel)
        if repos or images or workspaces:
            console.print(f"[cyan]Stage 4:[/cyan] Running TruffleHog verification...")
            th_findings, th_exec, th_fail = self._trufflehog_scan(targets, repos, images, workspaces)
            tools_executed.extend(th_exec)
            tools_failed.extend(th_fail)

            verified = sum(1 for f in th_findings if (f.raw_data or {}).get("verified"))
            console.print(f"  [green]✓[/green] {len(th_findings)} secrets found, {verified} verified")
        else:
            console.print("  [dim]No targets for TruffleHog — skipping[/dim]")
            th_findings = []

        # Stage 5: Gitleaks secondary scan
        if repos:
            console.print(f"[cyan]Stage 5:[/cyan] Running Gitleaks on {len(repos)} repos...")
            gl_findings, gl_exec, gl_fail = self._gitleaks_scan(targets, repos)
            tools_executed.extend(gl_exec)
            tools_failed.extend(gl_fail)
            console.print(f"  [green]✓[/green] {len(gl_findings)} Gitleaks findings")
        else:
            gl_findings = []

        # Stage 6: Cross-validate
        console.print("[cyan]Stage 6:[/cyan] Cross-validating findings...")
        validated = self._cross_validate(th_findings, gl_findings)
        all_findings.extend(validated)

        confirmed = sum(1 for f in validated if "verified" in f.tags)
        console.print(f"  [green]✓[/green] {len(validated)} total secret findings, {confirmed} verified")

        return self._build_report(targets, start_time, tools_executed, tools_failed, all_findings)

    def dry_run(self, targets: list[str]) -> list[dict]:
        """Show what would be executed."""
        from src.tools.github_code_search import GithubCodeSearch
        from src.tools.docker_hub_search import DockerHubSearch
        from src.tools.postman_workspace_search import PostmanWorkspaceSearch
        from src.tools.trufflehog_github import TrufflehogGithub
        from src.tools.trufflehog_docker import TrufflehogDocker
        from src.tools.trufflehog_postman import TrufflehogPostman
        from src.tools.gitleaks import Gitleaks

        tools_info = []
        for cls in [GithubCodeSearch, DockerHubSearch, PostmanWorkspaceSearch,
                    TrufflehogGithub, TrufflehogDocker, TrufflehogPostman, Gitleaks]:
            tool = cls(config=self.config)
            cmd = tool.build_command(targets[0]) if targets else []
            tools_info.append({
                "name": tool.name,
                "installed": tool.is_installed(),
                "command": " ".join(cmd) if cmd else "(API-based)",
            })
        return tools_info

    # ── Stage implementations ─────────────────────────────────────────

    def _discover(
        self, targets: list[str]
    ) -> tuple[list[str], list[dict], list[dict], list[IntelFinding], list[str], list[str]]:
        """Stages 1-3: Search GitHub, Docker Hub, Postman in parallel."""
        from src.tools.github_code_search import GithubCodeSearch
        from src.tools.docker_hub_search import DockerHubSearch
        from src.tools.postman_workspace_search import PostmanWorkspaceSearch

        gh = GithubCodeSearch(config=self.config)
        dh = DockerHubSearch(config=self.config)
        pm = PostmanWorkspaceSearch(config=self.config)

        repos: list[str] = []
        images: list[dict] = []
        workspaces: list[dict] = []
        findings: list[IntelFinding] = []
        executed: list[str] = []
        failed: list[str] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = {}
            for domain in targets:
                futures[pool.submit(gh.run, domain, timeout=self.timeout)] = ("github_code_search", domain)
                futures[pool.submit(dh.run, domain, timeout=60)] = ("docker_hub_search", domain)
                futures[pool.submit(pm.run, domain, timeout=60)] = ("postman_workspace_search", domain)

            for future in concurrent.futures.as_completed(futures):
                name, domain = futures[future]
                result = future.result()

                if result.errors:
                    # Don't count "not configured" as a failure — it's expected
                    if any("not configured" in e.lower() for e in result.errors):
                        console.print(f"  [dim]  {name}: skipped (not configured)[/dim]")
                    else:
                        if name not in failed:
                            failed.append(name)
                        console.print(f"  [red]✗[/red] {name} ({domain}): {result.errors[0]}")
                else:
                    if name not in executed:
                        executed.append(name)

                    if name == "github_code_search":
                        repos.extend(result.structured_data.get("repos_found", []))
                    elif name == "docker_hub_search":
                        images.extend(result.structured_data.get("images", []))
                    elif name == "postman_workspace_search":
                        workspaces.extend(result.structured_data.get("workspaces", []))

                    for fd in result.structured_data.get("findings", []):
                        try:
                            findings.append(IntelFinding(**fd))
                        except Exception:
                            pass

        return repos, images, workspaces, findings, executed, failed

    def _trufflehog_scan(
        self,
        targets: list[str],
        repos: list[str],
        images: list[dict],
        workspaces: list[dict],
    ) -> tuple[list[IntelFinding], list[str], list[str]]:
        """Stage 4: Run TruffleHog against discovered assets."""
        from src.tools.trufflehog_github import TrufflehogGithub
        from src.tools.trufflehog_docker import TrufflehogDocker
        from src.tools.trufflehog_postman import TrufflehogPostman

        findings: list[IntelFinding] = []
        executed: list[str] = []
        failed: list[str] = []
        max_images = self._pipeline_config.get("docker_max_images", 20)
        th_timeout = self._pipeline_config.get("trufflehog_timeout", 600)

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = {}

            # GitHub org scan
            if targets:
                th_gh = TrufflehogGithub(config=self.config)
                for target in targets[:3]:  # Limit to 3 orgs
                    org = target.split(".")[0] if "." in target else target
                    futures[pool.submit(th_gh.run, org, timeout=th_timeout)] = "trufflehog_github"

            # Docker image scans
            if images:
                th_docker = TrufflehogDocker(config=self.config)
                for img in images[:max_images]:
                    img_name = img.get("repo_name", "")
                    if img_name:
                        futures[pool.submit(
                            th_docker.run, img_name, timeout=th_timeout, image=img_name
                        )] = "trufflehog_docker"

            # Postman workspace scans
            if workspaces:
                th_pm = TrufflehogPostman(config=self.config)
                for ws in workspaces[:10]:
                    ws_id = ws.get("id", "")
                    if ws_id:
                        futures[pool.submit(
                            th_pm.run, ws_id, timeout=th_timeout, workspace=ws_id
                        )] = "trufflehog_postman"

            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                result = future.result()

                if result.errors:
                    if any("not configured" in e.lower() or "not installed" in e.lower() for e in result.errors):
                        pass  # Skip silently
                    elif name not in failed:
                        failed.append(name)
                else:
                    if name not in executed:
                        executed.append(name)

                for fd in result.structured_data.get("findings", []):
                    try:
                        findings.append(IntelFinding(**fd))
                    except Exception:
                        pass

        return findings, executed, failed

    def _gitleaks_scan(
        self, targets: list[str], repos: list[str]
    ) -> tuple[list[IntelFinding], list[str], list[str]]:
        """Stage 5: Run Gitleaks as secondary validation."""
        from src.tools.gitleaks import Gitleaks

        gl = Gitleaks(config=self.config)
        findings: list[IntelFinding] = []
        executed: list[str] = []
        failed: list[str] = []

        if not gl.is_installed():
            return findings, executed, ["gitleaks"]

        # Gitleaks needs cloned repos — for now, run against org if possible
        for target in targets[:3]:
            org = target.split(".")[0] if "." in target else target
            result = gl.run(org, timeout=self.timeout, source=org)
            if result.errors:
                if "gitleaks" not in failed:
                    failed.append("gitleaks")
            else:
                if "gitleaks" not in executed:
                    executed.append("gitleaks")
                for fd in result.structured_data.get("findings", []):
                    try:
                        findings.append(IntelFinding(**fd))
                    except Exception:
                        pass

        return findings, executed, failed

    def _cross_validate(
        self,
        trufflehog_findings: list[IntelFinding],
        gitleaks_findings: list[IntelFinding],
    ) -> list[IntelFinding]:
        """Stage 6: Cross-validate TruffleHog and Gitleaks findings."""
        # Build lookup of TruffleHog-verified secrets by redacted preview
        th_verified: set[str] = set()
        th_all: set[str] = set()
        for f in trufflehog_findings:
            key = (f.raw_data or {}).get("raw_secret_redacted", "")
            if key:
                th_all.add(key)
                if (f.raw_data or {}).get("verified"):
                    th_verified.add(key)

        gl_keys: set[str] = set()
        for f in gitleaks_findings:
            key = (f.raw_data or {}).get("raw_secret_redacted", "")
            if key:
                gl_keys.add(key)

        # Assign final confidence
        validated: list[IntelFinding] = []

        for f in trufflehog_findings:
            key = (f.raw_data or {}).get("raw_secret_redacted", "")
            if key in gl_keys and key in th_verified:
                # Both tools + verified
                validated.append(f.model_copy(update={
                    "confidence": 0.95,
                    "tags": list(set(f.tags + ["cross-validated"])),
                }))
            elif key in th_verified:
                # TruffleHog verified only
                validated.append(f.model_copy(update={"confidence": 0.85}))
            else:
                # Unverified
                validated.append(f.model_copy(update={"confidence": 0.5}))

        # Add Gitleaks-only findings (not in TruffleHog results)
        for f in gitleaks_findings:
            key = (f.raw_data or {}).get("raw_secret_redacted", "")
            if key and key not in th_all:
                validated.append(f.model_copy(update={
                    "confidence": 0.4,
                    "tags": list(set(f.tags + ["gitleaks-only"])),
                }))

        return validated

    # ── Utilities ─────────────────────────────────────────────────────

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
            scan_profile="secret_surface",
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            authorization_confirmed=True,
            tools_executed=executed,
            tools_failed=failed,
            findings=findings,
            summary=summary,
        )
