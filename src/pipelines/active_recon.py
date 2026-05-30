"""Active reconnaissance pipeline — the narrowing funnel.

Chains: subfinder + crt.sh seed → (optional shuffledns brute) → naabu port scan
→ httpx HTTP probe → katana crawl → nuclei template scan.

Each stage NARROWS to confirmed-live before spending the next (more expensive,
noisier) stage on it:
  - naabu only scans resolved subdomains
  - httpx only probes hosts:ports naabu found open
  - katana only crawls services httpx confirmed live
  - nuclei only fires at the crawled live surface

ACTIVE — every stage touches the target. Requires explicit authorization.
Detection/recon only; does not exploit.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console

from src.config import Config, DEFAULT_TIMEOUT
from src.models import IntelFinding, IntelType, ReconReport, ToolResult

console = Console()
logger = logging.getLogger("ohsint.pipeline.active_recon")


class AuthorizationError(RuntimeError):
    """Raised when the active pipeline is invoked without confirmed authorization."""


class ActiveReconPipeline:
    """Multi-stage active reconnaissance pipeline (auth-gated)."""

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
        authorization_confirmed: bool = False,
        top_ports: str = "100",
        nuclei_severity: str = "high,critical",
        brute: bool = False,
        crawl_depth: int = 2,
        max_hosts: int = 2000,
    ) -> ReconReport:
        """Run the active recon funnel against one or more domains.

        Raises AuthorizationError unless authorization_confirmed is True — this
        pipeline sends traffic directly to the target.
        """
        if not authorization_confirmed:
            raise AuthorizationError(
                "Active reconnaissance requires WRITTEN AUTHORIZATION from the "
                "target owner. Refusing to run: every stage touches the target."
            )

        start_time = datetime.now(timezone.utc)
        executed: list[str] = []
        failed: list[str] = []
        findings: list[IntelFinding] = []
        temp_files: list[str] = []

        try:
            # Stage 1: passive subdomain seed (subfinder + crt.sh)
            console.print(f"[cyan]Stage 1:[/cyan] Seeding subdomains for {len(targets)} target(s)...")
            subs, seed_exec, seed_fail = self._seed(targets)
            executed.extend(seed_exec)
            failed.extend(seed_fail)
            console.print(f"  [green]✓[/green] {len(subs)} seed subdomains")

            # Stage 1b: optional active DNS brute-force (shuffledns)
            if brute:
                console.print("[cyan]Stage 1b:[/cyan] Active DNS brute-force (shuffledns)...")
                bsubs, bexec, bfail = self._brute(targets, subs)
                executed.extend(bexec)
                failed.extend(bfail)
                if bsubs:
                    before = len(subs)
                    subs |= bsubs
                    console.print(f"  [green]✓[/green] +{len(subs) - before} subdomains ({len(subs)} total)")

            if not subs:
                # No subs — fall back to bare targets so the funnel still runs
                subs = set(targets)

            if len(subs) > max_hosts:
                console.print(f"  [yellow]⚠[/yellow] Truncating {len(subs)} → {max_hosts} hosts")
                subs = set(sorted(subs)[:max_hosts])

            sub_file = self._write_temp(sorted(subs), "arecon_subs")
            temp_files.append(sub_file)

            # Stage 2: port scan (naabu) — only the resolved subdomains
            console.print(f"[cyan]Stage 2:[/cyan] Port scan (naabu, top-{top_ports}) on {len(subs)} hosts...")
            host_ports, naabu_findings, naabu_ok = self._port_scan(targets[0], sub_file, top_ports)
            findings.extend(naabu_findings)
            executed.append("naabu") if naabu_ok else failed.append("naabu")
            console.print(f"  [green]✓[/green] {len(host_ports)} open host:port pairs")

            # Probe targets: host:port pairs if naabu found any, else the subs themselves
            probe_lines = host_ports if host_ports else sorted(subs)
            probe_file = self._write_temp(probe_lines, "arecon_probe")
            temp_files.append(probe_file)

            # Stage 3: HTTP probe (httpx) — only open ports
            console.print(f"[cyan]Stage 3:[/cyan] HTTP probe (httpx) on {len(probe_lines)} candidates...")
            live_urls, httpx_findings, httpx_ok = self._http_probe(targets[0], probe_file)
            findings.extend(httpx_findings)
            executed.append("httpx") if httpx_ok else failed.append("httpx")
            console.print(f"  [green]✓[/green] {len(live_urls)} live HTTP services")

            if not live_urls:
                console.print("[yellow]No live HTTP services — stopping before crawl/scan.[/yellow]")
                return self._build_report(targets, start_time, executed, failed, findings)

            # Stage 4: crawl (katana) — only confirmed-live services
            console.print(f"[cyan]Stage 4:[/cyan] Crawl (katana, depth {crawl_depth}) on {len(live_urls)} services...")
            crawl_findings, crawl_exec, crawl_fail = self._crawl(live_urls, crawl_depth)
            findings.extend(crawl_findings)
            executed.extend(crawl_exec)
            failed.extend(crawl_fail)
            js = sum(1 for f in crawl_findings if f.type == IntelType.SENSITIVE_FILE)
            eps = sum(1 for f in crawl_findings if f.type == IntelType.JS_ENDPOINT)
            console.print(f"  [green]✓[/green] {eps} endpoints, {js} JS files")

            # Stage 5: nuclei template scan — only the live surface
            live_file = self._write_temp(sorted(live_urls), "arecon_live")
            temp_files.append(live_file)
            console.print(f"[cyan]Stage 5:[/cyan] nuclei scan ({nuclei_severity}) on {len(live_urls)} services...")
            nuclei_findings, nuclei_ok = self._vuln_scan(targets[0], live_file, nuclei_severity)
            findings.extend(nuclei_findings)
            executed.append("nuclei_scan") if nuclei_ok else failed.append("nuclei_scan")
            console.print(f"  [green]✓[/green] {len(nuclei_findings)} nuclei findings")

            return self._build_report(targets, start_time, executed, failed, findings)

        finally:
            for f in temp_files:
                try:
                    os.unlink(f)
                except OSError:
                    pass

    def dry_run(self, targets: list[str]) -> list[dict]:
        """Show the funnel stages without running anything."""
        from src.tools.subfinder import Subfinder
        from src.tools.crtsh import CrtSh
        from src.tools.naabu_tool import NaabuTool
        from src.tools.httpx_tool import HttpxTool
        from src.tools.katana_tool import KatanaTool
        from src.tools.nuclei_scan import NucleiScan
        from src.tools.shuffledns_tool import ShufflednsTool

        info = []
        ordered = [Subfinder, CrtSh, NaabuTool, HttpxTool, KatanaTool, NucleiScan]
        for cls in ordered:
            tool = cls(config=self.config)
            cmd = tool.build_command(targets[0]) if targets else []
            info.append({
                "name": tool.name,
                "installed": tool.is_installed(),
                "command": " ".join(cmd) if cmd else "(API-based)",
            })
        # shuffledns is opt-in (--brute), so flag it optional
        sd = ShufflednsTool(config=self.config)
        info.append({
            "name": "shuffledns (--brute)",
            "installed": sd.is_installed(),
            "optional": True,
            "command": " ".join(sd.build_command(targets[0])) if targets else "(opt-in)",
        })
        return info

    # ── Stage implementations ─────────────────────────────────────────

    def _seed(self, targets: list[str]) -> tuple[set[str], list[str], list[str]]:
        from src.tools.subfinder import Subfinder
        from src.tools.crtsh import CrtSh

        subfinder = Subfinder(config=self.config)
        crtsh = CrtSh(config=self.config)
        subs: set[str] = set()
        executed: list[str] = []
        failed: list[str] = []

        tasks = []
        for d in targets:
            tasks.append(("subfinder", subfinder, d))
            tasks.append(("crtsh", crtsh, d))

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(t.run, d, timeout=self.timeout): (n, d) for n, t, d in tasks}
            for fut in concurrent.futures.as_completed(futures):
                name, _ = futures[fut]
                result = fut.result()
                if result.errors:
                    if name not in failed:
                        failed.append(name)
                else:
                    if name not in executed:
                        executed.append(name)
                    subs.update(result.structured_data.get("subdomains", []))
        return subs, executed, failed

    def _brute(self, targets: list[str], existing: set[str]) -> tuple[set[str], list[str], list[str]]:
        from src.tools.shuffledns_tool import ShufflednsTool

        sd = ShufflednsTool(config=self.config)
        if not sd.is_installed():
            console.print("  [yellow]⚠ shuffledns not installed — skipping brute[/yellow]")
            return set(), [], ["shuffledns"]

        wordlist = self.config.get_path("n0kovo_subdomains")
        wl_file = os.path.join(wordlist, "n0kovo_subdomains_huge.txt") if wordlist else ""
        new_subs: set[str] = set()
        executed: list[str] = []
        failed: list[str] = []
        for d in targets:
            result = sd.run(d, timeout=max(self.timeout, 1800),
                            wordlist=wl_file if os.path.isfile(wl_file) else None)
            if result.errors:
                if "shuffledns" not in failed:
                    failed.append("shuffledns")
            else:
                if "shuffledns" not in executed:
                    executed.append("shuffledns")
                for s in result.structured_data.get("subdomains", []):
                    if s not in existing:
                        new_subs.add(s)
        return new_subs, executed, failed

    def _port_scan(self, target: str, sub_file: str, top_ports: str) -> tuple[list[str], list[IntelFinding], bool]:
        from src.tools.naabu_tool import NaabuTool

        naabu = NaabuTool(config=self.config)
        if not naabu.is_installed():
            return [], [], False
        result = naabu.run(target, timeout=self.timeout, input_file=sub_file, top_ports=top_ports)
        host_ports = [f"{p['host']}:{p['port']}" for p in result.structured_data.get("open_ports", [])]
        findings = self._to_findings(result)
        return host_ports, findings, not result.errors

    def _http_probe(self, target: str, probe_file: str) -> tuple[set[str], list[IntelFinding], bool]:
        from src.tools.httpx_tool import HttpxTool

        httpx_tool = HttpxTool(config=self.config)
        if not httpx_tool.is_installed():
            return set(), [], False
        result = httpx_tool.run(target, timeout=self.timeout, input_file=probe_file)
        live = {h["url"] for h in result.structured_data.get("hosts", []) if h.get("url")}
        findings = self._to_findings(result)
        return live, findings, not result.errors

    def _crawl(self, live_urls: set[str], depth: int) -> tuple[list[IntelFinding], list[str], list[str]]:
        from src.tools.katana_tool import KatanaTool

        katana = KatanaTool(config=self.config)
        findings: list[IntelFinding] = []
        executed: list[str] = []
        failed: list[str] = []
        if not katana.is_installed():
            return findings, executed, ["katana"]

        # Cap crawl breadth to keep runtime sane; one katana run per live URL
        for url in sorted(live_urls)[:100]:
            result = katana.run(url, timeout=self.timeout, depth=depth)
            if result.errors:
                if "katana" not in failed:
                    failed.append("katana")
            else:
                if "katana" not in executed:
                    executed.append("katana")
                findings.extend(self._to_findings(result))
        return findings, executed, failed

    def _vuln_scan(self, target: str, live_file: str, severity: str) -> tuple[list[IntelFinding], bool]:
        from src.tools.nuclei_scan import NucleiScan

        nuclei = NucleiScan(config=self.config)
        if not nuclei.is_installed():
            return [], False
        result = nuclei.run(target, timeout=max(self.timeout, 1200),
                            input_file=live_file, severity=severity)
        return self._to_findings(result), not result.errors

    # ── Utilities ─────────────────────────────────────────────────────

    def _to_findings(self, result: ToolResult) -> list[IntelFinding]:
        out: list[IntelFinding] = []
        for fd in result.structured_data.get("findings", []):
            try:
                out.append(IntelFinding(**fd))
            except Exception:
                pass
        return out

    def _write_temp(self, lines: list[str], prefix: str) -> str:
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
            scan_profile="active_recon",
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            authorization_confirmed=True,
            tools_executed=executed,
            tools_failed=failed,
            findings=findings,
            summary=summary,
        )
