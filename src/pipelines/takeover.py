"""Subdomain takeover detection pipeline.

Chains: subfinder + crt.sh → dnsx CNAME resolution → provider filtering →
subzy + nuclei fingerprinting → cross-validation.

Detection only — does not claim resources or interact with provider accounts.
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
from src.report import load_report

console = Console()
logger = logging.getLogger("ohsint.pipeline.takeover")


class TakeoverPipeline:
    """Multi-stage subdomain takeover detection pipeline."""

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
        re_scan_path: Optional[Path] = None,
        max_subdomains: int = 5000,
        dns_bruteforce: bool = False,
    ) -> ReconReport:
        """Run the full takeover detection pipeline against one or more domains."""
        start_time = datetime.now(timezone.utc)
        tools_executed: list[str] = []
        tools_failed: list[str] = []
        temp_files: list[str] = []

        try:
            # Stage 1: Enumerate subdomains
            if re_scan_path:
                console.print("[cyan]Stage 1:[/cyan] Loading subdomains from previous scan...")
                subdomains, parent_map = self._load_previous_subdomains(re_scan_path)
                console.print(f"  [green]✓[/green] Loaded {len(subdomains)} subdomains from previous report")
            else:
                console.print(f"[cyan]Stage 1:[/cyan] Enumerating subdomains for {len(targets)} domain(s)...")
                subdomains, parent_map, enum_executed, enum_failed = self._enumerate(targets)
                tools_executed.extend(enum_executed)
                tools_failed.extend(enum_failed)

                if len(subdomains) > max_subdomains:
                    console.print(
                        f"  [yellow]⚠[/yellow] Truncating {len(subdomains)} subdomains "
                        f"to {max_subdomains} (use --max-subdomains to increase)"
                    )
                    subdomains = sorted(subdomains)[:max_subdomains]

                console.print(f"  [green]✓[/green] {len(subdomains)} unique subdomains found")

            # Stage 1b: Optional n0kovo DNS brute-force (off by default)
            if dns_bruteforce and not re_scan_path:
                bf_subs, bf_exec, bf_fail = self._dns_bruteforce(targets, subdomains, parent_map)
                tools_executed.extend(bf_exec)
                tools_failed.extend(bf_fail)
                if bf_subs:
                    before = len(subdomains)
                    subdomains |= bf_subs  # merge + dedup (set union)
                    console.print(
                        f"  [green]✓[/green] DNS brute-force added {len(subdomains) - before} "
                        f"new subdomains ({len(subdomains)} total)"
                    )
                    if len(subdomains) > max_subdomains:
                        console.print(
                            f"  [yellow]⚠[/yellow] Truncating {len(subdomains)} subdomains "
                            f"to {max_subdomains}"
                        )
                        subdomains = set(sorted(subdomains)[:max_subdomains])

            if not subdomains:
                console.print("[yellow]No subdomains found — nothing to check.[/yellow]")
                return self._empty_report(targets, start_time, tools_executed, tools_failed)

            # Write subdomains to temp file
            sub_file = self._write_temp_file(sorted(subdomains), "subs")
            temp_files.append(sub_file)

            # Stage 2: Resolve CNAMEs
            console.print(f"[cyan]Stage 2:[/cyan] Resolving CNAMEs for {len(subdomains)} subdomains...")
            cname_map, dnsx_result = self._resolve_cnames(targets[0], sub_file)
            if dnsx_result.errors:
                tools_failed.append("dnsx_cname")
            else:
                tools_executed.append("dnsx_cname")
            console.print(f"  [green]✓[/green] {len(cname_map)} subdomains have CNAME records")

            # Stage 3: Filter by provider patterns
            console.print("[cyan]Stage 3:[/cyan] Filtering CNAMEs against takeover provider patterns...")
            candidates = self._filter_by_providers(cname_map, parent_map)
            console.print(f"  [green]✓[/green] {len(candidates)} candidates match known providers")

            if not candidates:
                console.print("[green]No dangling CNAME candidates found — target appears safe.[/green]")
                return self._build_report(
                    targets, start_time, tools_executed, tools_failed,
                    findings=[], cname_map=cname_map,
                )

            # Write candidates to temp file
            candidate_subs = [c["subdomain"] for c in candidates]
            cand_file = self._write_temp_file(candidate_subs, "candidates")
            temp_files.append(cand_file)

            # Stage 4: Fingerprint with subzy + nuclei (parallel)
            console.print(f"[cyan]Stage 4:[/cyan] Fingerprinting {len(candidates)} candidates...")
            subzy_result, nuclei_result = self._fingerprint(targets[0], cand_file)

            if subzy_result.errors:
                tools_failed.append("subzy")
                console.print(f"  [red]✗[/red] subzy: {subzy_result.errors[0]}")
            else:
                tools_executed.append("subzy")
                console.print(f"  [green]✓[/green] subzy ({subzy_result.execution_time_seconds:.1f}s)")

            if nuclei_result.errors:
                tools_failed.append("nuclei_takeovers")
                console.print(f"  [red]✗[/red] nuclei: {nuclei_result.errors[0]}")
            else:
                tools_executed.append("nuclei_takeovers")
                console.print(f"  [green]✓[/green] nuclei ({nuclei_result.execution_time_seconds:.1f}s)")

            # Stage 5: Cross-validate
            console.print("[cyan]Stage 5:[/cyan] Cross-validating findings...")
            findings = self._cross_validate(candidates, subzy_result, nuclei_result, parent_map)

            confirmed = sum(1 for f in findings if "confirmed" in f.tags)
            unconfirmed = sum(1 for f in findings if "unconfirmed" in f.tags)
            cname_only = sum(1 for f in findings if "cname-only" in f.tags)
            console.print(
                f"  [green]✓[/green] {confirmed} confirmed, "
                f"{unconfirmed} unconfirmed, {cname_only} CNAME-only"
            )

            # Diff against previous scan if re-scanning
            diff = None
            if re_scan_path:
                diff = self._diff_results(re_scan_path, findings)

            report = self._build_report(
                targets, start_time, tools_executed, tools_failed,
                findings=findings, cname_map=cname_map, diff=diff,
            )
            return report

        finally:
            for f in temp_files:
                try:
                    os.unlink(f)
                except OSError:
                    pass

    def dry_run(self, targets: list[str]) -> list[dict]:
        """Show what would be executed without running anything."""
        from src.tools.dnsx_cname import DnsxCname
        from src.tools.nuclei_takeovers import NucleiTakeovers
        from src.tools.subzy import SubzyTool
        from src.tools.subfinder import Subfinder
        from src.tools.crtsh import CrtSh

        tools_info = []
        for cls in [Subfinder, CrtSh, DnsxCname, SubzyTool, NucleiTakeovers]:
            tool = cls(config=self.config)
            cmd = tool.build_command(targets[0]) if targets else []
            tools_info.append({
                "name": tool.name,
                "installed": tool.is_installed(),
                "command": " ".join(cmd) if cmd else "(API-based)",
            })

        # Optional n0kovo DNS brute-force (only runs with --dns-bruteforce)
        bf_cfg = (self.config.get_profile("subdomain_takeover") or {}).get(
            "optional_dns_bruteforce", {}
        )
        wl = self.config.resolve_path_tokens(bf_cfg.get("wordlist", ""))
        conc = bf_cfg.get("concurrency", 100)
        dom = targets[0] if targets else "<domain>"
        tools_info.append({
            "name": "dnsx (n0kovo brute-force, --dns-bruteforce)",
            "installed": bool(wl) and os.path.isfile(wl),
            "optional": True,  # only runs with --dns-bruteforce
            "command": f"dnsx -d {dom} -w {wl or '<wordlist>'} -t {conc} -silent",
        })
        return tools_info

    # ── Stage implementations ─────────────────────────────────────────

    def _enumerate(
        self, targets: list[str]
    ) -> tuple[set[str], dict[str, str], list[str], list[str]]:
        """Stage 1: Enumerate subdomains for all targets via subfinder + crt.sh."""
        from src.tools.subfinder import Subfinder
        from src.tools.crtsh import CrtSh

        subfinder = Subfinder(config=self.config)
        crtsh = CrtSh(config=self.config)
        all_subdomains: set[str] = set()
        parent_map: dict[str, str] = {}
        executed: list[str] = []
        failed: list[str] = []

        tasks = []
        for domain in targets:
            tasks.append(("subfinder", subfinder, domain))
            tasks.append(("crtsh", crtsh, domain))

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = {
                pool.submit(self._run_enum_tool, tool, domain): (name, domain)
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
                    subs = result.structured_data.get("subdomains", [])
                    for sub in subs:
                        all_subdomains.add(sub)
                        if sub not in parent_map:
                            parent_map[sub] = domain
                    console.print(
                        f"  [green]✓[/green] {name} ({domain}): {len(subs)} subdomains "
                        f"({result.execution_time_seconds:.1f}s)"
                    )

        return all_subdomains, parent_map, executed, failed

    def _run_enum_tool(self, tool, domain: str) -> ToolResult:
        return tool.run(domain, timeout=self.timeout)

    def _dns_bruteforce(
        self, targets: list[str], existing: set[str], parent_map: dict[str, str]
    ) -> tuple[set[str], list[str], list[str]]:
        """Stage 1b: optional passive DNS brute-force via dnsx + n0kovo wordlist.

        Resolves <word>.<domain> candidates and merges live hits into the
        subdomain set. Off by default; enabled via `ohsint takeover --dns-bruteforce`.
        Honors configs/paths.yaml for the wordlist location.
        """
        import shutil
        import subprocess

        new_subs: set[str] = set()
        executed: list[str] = []
        failed: list[str] = []

        bf_cfg = (self.config.get_profile("subdomain_takeover") or {}).get(
            "optional_dns_bruteforce", {}
        )
        wordlist = self.config.resolve_path_tokens(bf_cfg.get("wordlist", ""))
        concurrency = int(bf_cfg.get("concurrency", 100))

        if not shutil.which("dnsx"):
            console.print("  [yellow]⚠ dnsx not installed — skipping DNS brute-force[/yellow]")
            failed.append("dnsx_bruteforce")
            return new_subs, executed, failed

        if not wordlist or not os.path.isfile(wordlist):
            console.print(
                f"  [yellow]⚠ Wordlist not found: {wordlist or '(unset)'} — skipping DNS "
                f"brute-force. Install: git clone https://github.com/n0kovo/n0kovo_subdomains[/yellow]"
            )
            failed.append("dnsx_bruteforce")
            return new_subs, executed, failed

        console.print(
            "[cyan]Stage 1b:[/cyan] DNS brute-force via dnsx (n0kovo wordlist, ~30-90 min)..."
        )
        for domain in targets:
            cmd = [
                "dnsx", "-d", domain, "-w", wordlist,
                "-t", str(concurrency), "-silent",
            ]
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=max(self.timeout, 3600), shell=False,
                )
                for line in proc.stdout.splitlines():
                    host = line.strip().lower().rstrip(".")
                    if host == domain or host.endswith("." + domain):
                        if host not in existing:
                            new_subs.add(host)
                            parent_map.setdefault(host, domain)
                if "dnsx_bruteforce" not in executed:
                    executed.append("dnsx_bruteforce")
            except Exception as e:
                logger.warning("dnsx brute-force failed for %s: %s", domain, e)
                if "dnsx_bruteforce" not in failed:
                    failed.append("dnsx_bruteforce")

        return new_subs, executed, failed

    def _resolve_cnames(self, target: str, subdomain_file: str) -> tuple[dict, ToolResult]:
        """Stage 2: Resolve CNAMEs via dnsx."""
        from src.tools.dnsx_cname import DnsxCname

        dnsx = DnsxCname(config=self.config)
        result = dnsx.run(target, timeout=self.timeout, input_file=subdomain_file)
        cname_map = result.structured_data.get("cname_map", {})
        return cname_map, result

    def _filter_by_providers(
        self, cname_map: dict[str, list[str]], parent_map: dict[str, str]
    ) -> list[dict]:
        """Stage 3: Filter CNAMEs matching known takeover provider patterns."""
        providers = self.config.get_takeover_providers()
        if not providers:
            logger.warning("No takeover providers configured — check configs/takeover_providers.yaml")
            return []

        candidates = []
        for subdomain, cnames in cname_map.items():
            for cname in cnames:
                for provider in providers:
                    pattern = provider.get("pattern", "")
                    if pattern and pattern in cname:
                        candidates.append({
                            "subdomain": subdomain,
                            "cname_target": cname,
                            "provider": provider,
                            "parent_domain": parent_map.get(subdomain, ""),
                        })
                        break

        return candidates

    def _fingerprint(
        self, target: str, candidates_file: str
    ) -> tuple[ToolResult, ToolResult]:
        """Stage 4: Run subzy + nuclei in parallel against candidates."""
        from src.tools.subzy import SubzyTool
        from src.tools.nuclei_takeovers import NucleiTakeovers

        subzy = SubzyTool(config=self.config)
        nuclei = NucleiTakeovers(config=self.config)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f_subzy = pool.submit(
                subzy.run, target, timeout=self.timeout, input_file=candidates_file
            )
            f_nuclei = pool.submit(
                nuclei.run, target, timeout=self.timeout, input_file=candidates_file
            )
            subzy_result = f_subzy.result()
            nuclei_result = f_nuclei.result()

        return subzy_result, nuclei_result

    def _cross_validate(
        self,
        candidates: list[dict],
        subzy_result: ToolResult,
        nuclei_result: ToolResult,
        parent_map: dict[str, str],
    ) -> list[IntelFinding]:
        """Stage 5: Cross-validate subzy and nuclei findings, assign confidence."""
        subzy_hits: set[str] = set()
        for finding in subzy_result.structured_data.get("findings", []):
            value = finding.get("value", "").strip().lower()
            if value:
                subzy_hits.add(value)

        nuclei_hits: set[str] = set()
        for finding in nuclei_result.structured_data.get("findings", []):
            value = finding.get("value", "").strip().lower()
            if value:
                nuclei_hits.add(value)

        findings: list[IntelFinding] = []
        for candidate in candidates:
            subdomain = candidate["subdomain"]
            cname_target = candidate["cname_target"]
            provider = candidate["provider"]
            parent_domain = candidate.get("parent_domain", parent_map.get(subdomain, ""))

            in_subzy = subdomain in subzy_hits
            in_nuclei = subdomain in nuclei_hits
            tools_confirmed = []
            if in_subzy:
                tools_confirmed.append("subzy")
            if in_nuclei:
                tools_confirmed.append("nuclei")

            if in_subzy and in_nuclei:
                confidence = 0.95
                status_tag = "confirmed"
            elif in_subzy or in_nuclei:
                confidence = 0.65
                status_tag = "unconfirmed"
            else:
                confidence = 0.3
                status_tag = "cname-only"

            provider_tag = provider.get("name", "unknown").lower().replace(" ", "-")

            findings.append(IntelFinding(
                type=IntelType.SUBDOMAIN_TAKEOVER,
                value=subdomain,
                source_tool=",".join(tools_confirmed) if tools_confirmed else "dnsx_cname",
                confidence=confidence,
                tags=["takeover", status_tag, provider_tag],
                raw_data={
                    "cname_target": cname_target,
                    "provider_name": provider.get("name", "unknown"),
                    "fingerprint_match": ", ".join(provider.get("fingerprints", [])),
                    "takeover_tools_confirmed": tools_confirmed,
                    "poc_approach": provider.get("poc", ""),
                    "severity": provider.get("severity", "medium"),
                    "parent_domain": parent_domain,
                },
            ))

        return findings

    # ── Re-scan helpers ───────────────────────────────────────────────

    def _load_previous_subdomains(
        self, report_path: Path
    ) -> tuple[set[str], dict[str, str]]:
        """Load subdomains from a previous report for re-scanning."""
        report = load_report(report_path)
        subdomains: set[str] = set()
        parent_map: dict[str, str] = {}

        for finding in report.findings:
            if finding.type in (IntelType.SUBDOMAIN, IntelType.SUBDOMAIN_TAKEOVER):
                sub = finding.value.strip().lower()
                subdomains.add(sub)
                parent = (finding.raw_data or {}).get("parent_domain", "")
                if parent:
                    parent_map[sub] = parent

        return subdomains, parent_map

    def _diff_results(
        self, previous_path: Path, current_findings: list[IntelFinding]
    ) -> dict:
        """Compare current findings against previous report."""
        previous = load_report(previous_path)
        prev_takeovers = {
            f.value.strip().lower()
            for f in previous.findings
            if f.type == IntelType.SUBDOMAIN_TAKEOVER
        }
        curr_takeovers = {f.value.strip().lower() for f in current_findings}

        return {
            "new": sorted(curr_takeovers - prev_takeovers),
            "resolved": sorted(prev_takeovers - curr_takeovers),
            "unchanged": sorted(curr_takeovers & prev_takeovers),
        }

    # ── Utility helpers ───────────────────────────────────────────────

    def _write_temp_file(self, lines: list[str], prefix: str) -> str:
        """Write lines to a temp file, return path. Caller must clean up."""
        fd, path = tempfile.mkstemp(prefix=f"ohsint_{prefix}_", suffix=".txt")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except Exception:
            os.close(fd)
            raise
        return path

    def _empty_report(
        self,
        targets: list[str],
        start_time: datetime,
        executed: list[str],
        failed: list[str],
    ) -> ReconReport:
        return ReconReport(
            target=", ".join(targets),
            scan_profile="subdomain_takeover",
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            authorization_confirmed=True,
            tools_executed=executed,
            tools_failed=failed,
            findings=[],
            summary={},
        )

    def _build_report(
        self,
        targets: list[str],
        start_time: datetime,
        executed: list[str],
        failed: list[str],
        findings: list[IntelFinding],
        cname_map: dict | None = None,
        diff: dict | None = None,
    ) -> ReconReport:
        summary: dict[str, int] = {}
        for f in findings:
            summary[f.type.value] = summary.get(f.type.value, 0) + 1

        report = ReconReport(
            target=", ".join(targets),
            scan_profile="subdomain_takeover",
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            authorization_confirmed=True,
            tools_executed=executed,
            tools_failed=failed,
            findings=findings,
            summary=summary,
        )
        return report
