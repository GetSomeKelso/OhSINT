"""JavaScript file analysis pipeline.

Chains: subjs + getjs (JS URL collection) → download → beautify →
source map check → LinkFinder + SecretFinder → TruffleHog filesystem →
Swagger/OpenAPI discovery.

All passive — downloads publicly accessible files only.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import logging
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from rich.console import Console

from src.config import Config, DEFAULT_TIMEOUT
from src.models import IntelFinding, IntelType, ReconReport, ToolResult

console = Console()
logger = logging.getLogger("ohsint.pipeline.js_analysis")


class JsAnalysisPipeline:
    """Multi-stage JavaScript file analysis pipeline."""

    def __init__(
        self,
        config: Optional[Config] = None,
        timeout: int = DEFAULT_TIMEOUT,
        verbose: bool = False,
    ):
        self.config = config or Config()
        self.timeout = timeout
        self.verbose = verbose
        self._pipeline_config = self.config.get_pipeline_config("js_analysis")

    def run(
        self,
        targets: list[str],
        js_urls_file: str | None = None,
        output_dir: Path | None = None,
    ) -> ReconReport:
        """Run the full JS analysis pipeline."""
        start_time = datetime.now(timezone.utc)
        tools_executed: list[str] = []
        tools_failed: list[str] = []
        all_findings: list[IntelFinding] = []

        # Create temp working directory for JS files
        work_dir = tempfile.mkdtemp(prefix="ohsint_js_")

        try:
            # Stage 1: Collect JS URLs
            console.print(f"[cyan]Stage 1:[/cyan] Collecting JS URLs for {len(targets)} target(s)...")
            js_urls, coll_exec, coll_fail = self._collect_js_urls(targets, js_urls_file)
            tools_executed.extend(coll_exec)
            tools_failed.extend(coll_fail)
            console.print(f"  [green]✓[/green] {len(js_urls)} unique JS URLs")

            if not js_urls:
                console.print("[yellow]No JS URLs found — nothing to analyze.[/yellow]")
                return self._build_report(targets, start_time, tools_executed, tools_failed, all_findings)

            # Stage 2: Download JS files
            max_files = self._pipeline_config.get("js_max_files", 500)
            max_size = self._pipeline_config.get("js_max_file_size_mb", 5)
            console.print(f"[cyan]Stage 2:[/cyan] Downloading JS files (max {max_files}, ≤{max_size}MB each)...")
            js_dir, downloaded = self._download_js(js_urls, Path(work_dir) / "js_files", max_files, max_size)
            console.print(f"  [green]✓[/green] {downloaded} files downloaded to {js_dir}")

            if downloaded == 0:
                console.print("[yellow]No JS files downloaded — nothing to analyze.[/yellow]")
                return self._build_report(targets, start_time, tools_executed, tools_failed, all_findings)

            # Stage 3: Beautify
            console.print("[cyan]Stage 3:[/cyan] Beautifying JS files...")
            beautified = self._beautify(js_dir)
            console.print(f"  [green]✓[/green] {beautified} files beautified")

            # Stage 4: Source map check
            disable_sourcemaps = self._pipeline_config.get("disable_sourcemap_recovery", False)
            if not disable_sourcemaps:
                console.print("[cyan]Stage 4:[/cyan] Checking for source maps...")
                sm_findings = self._check_sourcemaps(js_urls)
                all_findings.extend(sm_findings)
                console.print(f"  [green]✓[/green] {len(sm_findings)} source maps found")
            else:
                console.print("[cyan]Stage 4:[/cyan] Source map recovery disabled")

            # Stage 5: LinkFinder + SecretFinder
            console.print("[cyan]Stage 5:[/cyan] Analyzing JS files for endpoints and secrets...")
            analysis_findings, analysis_exec, analysis_fail = self._analyze_content(js_dir)
            tools_executed.extend(analysis_exec)
            tools_failed.extend(analysis_fail)
            all_findings.extend(analysis_findings)
            endpoints = sum(1 for f in analysis_findings if f.type == IntelType.JS_ENDPOINT)
            secrets = sum(1 for f in analysis_findings if f.type == IntelType.LEAKED_SECRET)
            console.print(f"  [green]✓[/green] {endpoints} endpoints, {secrets} secrets")

            # Stage 6: TruffleHog filesystem scan
            console.print("[cyan]Stage 6:[/cyan] Running TruffleHog on JS directory...")
            th_findings = self._trufflehog_filesystem(js_dir)
            all_findings.extend(th_findings)
            console.print(f"  [green]✓[/green] {len(th_findings)} TruffleHog findings")

            # Stage 7: Swagger/OpenAPI discovery
            console.print("[cyan]Stage 7:[/cyan] Checking for exposed API documentation...")
            swagger_findings = self._swagger_discovery(targets)
            all_findings.extend(swagger_findings)
            console.print(f"  [green]✓[/green] {len(swagger_findings)} API docs found")

            # Copy results to output dir if specified
            if output_dir:
                output_dir.mkdir(parents=True, exist_ok=True)
                dest_js = output_dir / "js_files"
                if js_dir.exists():
                    shutil.copytree(js_dir, dest_js, dirs_exist_ok=True)

            return self._build_report(targets, start_time, tools_executed, tools_failed, all_findings)

        finally:
            # Cleanup temp directory
            try:
                shutil.rmtree(work_dir)
            except OSError:
                pass

    def dry_run(self, targets: list[str]) -> list[dict]:
        from src.tools.subjs import Subjs
        from src.tools.getjs import GetJs
        from src.tools.linkfinder_tool import LinkFinderTool
        from src.tools.secretfinder_tool import SecretFinderTool

        tools_info = []
        for cls in [Subjs, GetJs, LinkFinderTool, SecretFinderTool]:
            tool = cls(config=self.config)
            cmd = tool.build_command(targets[0]) if targets else []
            tools_info.append({
                "name": tool.name,
                "installed": tool.is_installed(),
                "command": " ".join(cmd) if cmd else "(internal)",
            })
        # Add js-beautify and trufflehog
        tools_info.append({
            "name": "js-beautify",
            "installed": shutil.which("js-beautify") is not None,
            "command": "js-beautify -r -f <file>",
        })
        tools_info.append({
            "name": "trufflehog (filesystem)",
            "installed": shutil.which("trufflehog") is not None,
            "command": "trufflehog filesystem <dir> --json --only-verified",
        })
        # Stage 7 API-doc path source (SecLists, resolved via configs/paths.yaml)
        seclists = self.config.get_path("seclists")
        api_file = os.path.join(seclists, "Discovery", "Web-Content", "api", "api-endpoints.txt")
        tools_info.append({
            "name": "SecLists api-endpoints (Stage 7 paths)",
            "installed": os.path.isfile(api_file),
            "command": f"probe https://<host>/<path> for paths in {api_file}",
        })
        return tools_info

    # ── Stage implementations ─────────────────────────────────────────

    def _collect_js_urls(
        self, targets: list[str], prev_js_file: str | None
    ) -> tuple[set[str], list[str], list[str]]:
        """Stage 1: Collect JS URLs from subjs, getjs, and previous pipeline output."""
        from src.tools.subjs import Subjs
        from src.tools.getjs import GetJs

        sj = Subjs(config=self.config)
        gj = GetJs(config=self.config)
        js_urls: set[str] = set()
        executed: list[str] = []
        failed: list[str] = []

        # Load from previous pipeline output
        if prev_js_file and os.path.exists(prev_js_file):
            with open(prev_js_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and line.startswith("http"):
                        js_urls.add(line)
            console.print(f"  [dim]  Loaded {len(js_urls)} JS URLs from Pipeline A[/dim]")

        # Run subjs + getjs in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = {}
            for target in targets:
                futures[pool.submit(sj.run, target, timeout=self.timeout)] = ("subjs", target)
                futures[pool.submit(gj.run, target, timeout=self.timeout)] = ("getjs", target)

            for future in concurrent.futures.as_completed(futures):
                name, target = futures[future]
                result = future.result()
                if result.errors:
                    if name not in failed:
                        failed.append(name)
                else:
                    if name not in executed:
                        executed.append(name)
                    urls = result.structured_data.get("js_urls", [])
                    js_urls.update(urls)

        return js_urls, executed, failed

    def _download_js(
        self, js_urls: set[str], js_dir: Path, max_files: int, max_size_mb: int
    ) -> tuple[Path, int]:
        """Stage 2: Download JS files."""
        js_dir.mkdir(parents=True, exist_ok=True)
        downloaded = 0
        max_bytes = max_size_mb * 1024 * 1024

        sorted_urls = sorted(js_urls)[:max_files]

        try:
            from src.http_client import OhSINTHTTPClient
            with OhSINTHTTPClient(self.config, timeout=15) as client:
                for url in sorted_urls:
                    try:
                        # Use HEAD first to check size
                        head = client.head(url, follow_redirects=True)
                        content_length = int(head.headers.get("content-length", 0))
                        if content_length > max_bytes:
                            logger.info("Skipping oversized JS: %s (%d bytes)", url, content_length)
                            continue

                        resp = client.get(url, follow_redirects=True)
                        if resp.status_code != 200:
                            continue
                        if len(resp.content) > max_bytes:
                            continue

                        # Name file by URL hash
                        filename = hashlib.md5(url.encode()).hexdigest() + ".js"
                        (js_dir / filename).write_bytes(resp.content)
                        downloaded += 1

                    except Exception:
                        continue
        except Exception as e:
            logger.warning("JS download error: %s", e)

        return js_dir, downloaded

    def _beautify(self, js_dir: Path) -> int:
        """Stage 3: Run js-beautify on downloaded files."""
        if not shutil.which("js-beautify"):
            logger.warning("js-beautify not installed — skipping beautification")
            return 0

        beautified = 0
        for js_file in js_dir.glob("*.js"):
            if "_beautified" in js_file.name:
                continue
            out_file = js_file.with_name(js_file.stem + "_beautified.js")
            try:
                subprocess.run(
                    ["js-beautify", "-f", str(js_file), "-o", str(out_file)],
                    capture_output=True, timeout=30, shell=False,
                )
                beautified += 1
            except Exception:
                continue

        return beautified

    def _check_sourcemaps(self, js_urls: set[str]) -> list[IntelFinding]:
        """Stage 4: Check for .map source map files."""
        findings = []
        try:
            with OhSINTHTTPClient(self.config, timeout=10) as client:
                for url in sorted(js_urls)[:200]:  # Limit checks
                    map_url = url + ".map"
                    try:
                        resp = client.head(map_url)
                        if resp.status_code == 200:
                            findings.append(IntelFinding(
                                type=IntelType.SENSITIVE_FILE,
                                value=map_url,
                                source_tool="sourcemap_check",
                                confidence=0.9,
                                tags=["sourcemap", "javascript", "sensitive"],
                                raw_data={"original_js": url, "map_url": map_url},
                            ))
                    except Exception:
                        continue
        except Exception:
            pass

        return findings

    def _analyze_content(
        self, js_dir: Path
    ) -> tuple[list[IntelFinding], list[str], list[str]]:
        """Stage 5: Run LinkFinder + SecretFinder on JS files."""
        from src.tools.linkfinder_tool import LinkFinderTool
        from src.tools.secretfinder_tool import SecretFinderTool

        lf = LinkFinderTool(config=self.config)
        sf = SecretFinderTool(config=self.config)
        findings: list[IntelFinding] = []
        executed: list[str] = []
        failed: list[str] = []

        # Prefer beautified files, fall back to original
        js_files = list(js_dir.glob("*_beautified.js"))
        if not js_files:
            js_files = list(js_dir.glob("*.js"))

        for js_file in js_files[:100]:  # Cap analysis
            # LinkFinder
            if lf.is_installed():
                result = lf.run(str(js_file), timeout=30, input_file=str(js_file))
                if not result.errors:
                    if "linkfinder" not in executed:
                        executed.append("linkfinder")
                    for fd in result.structured_data.get("findings", []):
                        try:
                            findings.append(IntelFinding(**fd))
                        except Exception:
                            pass
                elif "linkfinder" not in failed:
                    failed.append("linkfinder")

            # SecretFinder
            if sf.is_installed():
                result = sf.run(str(js_file), timeout=30, input_file=str(js_file))
                if not result.errors:
                    if "secretfinder" not in executed:
                        executed.append("secretfinder")
                    for fd in result.structured_data.get("findings", []):
                        try:
                            findings.append(IntelFinding(**fd))
                        except Exception:
                            pass
                elif "secretfinder" not in failed:
                    failed.append("secretfinder")

        return findings, executed, failed

    def _trufflehog_filesystem(self, js_dir: Path) -> list[IntelFinding]:
        """Stage 6: Run TruffleHog filesystem mode on JS directory."""
        if not shutil.which("trufflehog"):
            return []

        from src.tools.trufflehog_github import _parse_trufflehog_json

        try:
            proc = subprocess.run(
                ["trufflehog", "filesystem", str(js_dir),
                 "--json", "--only-verified", "--no-update"],
                capture_output=True, text=True, timeout=300, shell=False,
            )
            finding_dicts = _parse_trufflehog_json(proc.stdout, "trufflehog_filesystem", "javascript")
            return [IntelFinding(**fd) for fd in finding_dicts]
        except Exception as e:
            logger.warning("TruffleHog filesystem scan failed: %s", e)
            return []

    def _load_api_doc_paths(self) -> list[str]:
        """Build the API-doc path list: hardcoded fallback ∪ SecLists sources.

        Sources (when present): SecLists ``Discovery/Web-Content/swagger.txt`` and
        ``api/api-endpoints.txt`` (resolved via configs/paths.yaml). Falls back to
        the hardcoded ``swagger_common_paths`` when SecLists is not installed.
        Still passive — these paths are probed on hosts already known to be live.
        """
        hardcoded = self._pipeline_config.get("swagger_common_paths", [
            "/swagger.json", "/api-docs", "/openapi.json",
            "/v2/api-docs", "/v3/api-docs",
        ])
        paths: list[str] = list(hardcoded)

        if self._pipeline_config.get("seclists_api_paths", True):
            seclists = self.config.get_path("seclists")
            sources = [
                os.path.join(seclists, "Discovery", "Web-Content", "swagger.txt"),
                os.path.join(seclists, "Discovery", "Web-Content", "api", "api-endpoints.txt"),
            ]
            found_any = False
            for src in sources:
                if not os.path.isfile(src):
                    continue
                found_any = True
                try:
                    with open(src, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            p = line.strip()
                            if not p or p.startswith("#"):
                                continue
                            if not p.startswith("/"):
                                p = "/" + p
                            paths.append(p)
                except OSError as e:
                    logger.warning("Could not read SecLists path file %s: %s", src, e)
            if not found_any:
                logger.warning(
                    "SecLists API path files not found under %s — using hardcoded fallback. "
                    "Install: git clone https://github.com/danielmiessler/SecLists /opt/SecLists",
                    seclists,
                )
                console.print(
                    f"  [yellow]⚠ SecLists not found at {seclists} — using "
                    f"{len(hardcoded)} hardcoded API-doc paths[/yellow]"
                )

        # Dedup preserving order (hardcoded high-signal paths first), then cap
        seen: set[str] = set()
        deduped: list[str] = []
        for p in paths:
            if p not in seen:
                seen.add(p)
                deduped.append(p)

        cap = int(self._pipeline_config.get("seclists_api_max_paths", 1000))
        if cap > 0 and len(deduped) > cap:
            deduped = deduped[:cap]
        return deduped

    def _swagger_discovery(self, targets: list[str]) -> list[IntelFinding]:
        """Stage 7: Check for exposed Swagger/OpenAPI documentation."""
        from src.http_client import OhSINTHTTPClient

        common_paths = self._load_api_doc_paths()
        findings = []

        try:
            with OhSINTHTTPClient(self.config, timeout=10) as client:
                for target in targets:
                    host = target if target.startswith("http") else f"https://{target}"
                    for path in common_paths:
                        url = f"{host}{path}"
                        try:
                            resp = client.get(url)
                            if resp.status_code == 200:
                                text = resp.text[:500]
                                if any(kw in text.lower() for kw in ['"swagger"', '"openapi"', '"paths"', '"info"']):
                                    findings.append(IntelFinding(
                                        type=IntelType.EXPOSED_API_DOC,
                                        value=url,
                                        source_tool="swagger_discovery",
                                        confidence=0.9,
                                        tags=["swagger", "openapi", "exposed"],
                                        raw_data={
                                            "url": url,
                                            "snippet": text[:200],
                                        },
                                    ))
                        except Exception:
                            continue
        except Exception:
            pass

        return findings

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
            scan_profile="js_analysis",
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            authorization_confirmed=True,
            tools_executed=executed,
            tools_failed=failed,
            findings=findings,
            summary=summary,
        )
