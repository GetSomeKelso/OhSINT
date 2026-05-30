"""SOCMINT — individual subject profiling from a username / email / name seed.

Distinct from the company-scoped people_recon (which starts from a company and
finds employees). This starts from a SINGLE individual identifier and builds a
profile by pivoting across public sources.

Chain (seed-type routed):
  email    → holehe (platform registration) + h8mail (breach) + derive username
  username → sherlock + maigret (cross-platform enumeration)
  name     → derive username candidates → sherlock + maigret
  then     → correlate, dedupe, profile report

CONSENT GATE: this profiles an individual. It is passive (public data, no target
traffic) so it does not use the active --authorization gate — but it DOES require
an explicit consent attestation that profiling this person is authorized
(engagement scope or your own accounts). Refuses to run otherwise.

Never scrapes facial images (prohibited). Public-profile enumeration only.
"""

from __future__ import annotations

import concurrent.futures
import logging
import re
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console

from src.config import Config, DEFAULT_TIMEOUT
from src.models import IntelFinding, IntelType, ReconReport, ToolResult

console = Console()
logger = logging.getLogger("ohsint.pipeline.socmint")


class ConsentError(RuntimeError):
    """Raised when SOCMINT is invoked without confirmed consent to profile a person."""


def classify_seed(seed: str) -> str:
    """Classify a seed identifier as 'email', 'name', or 'username'."""
    s = seed.strip()
    if "@" in s and "." in s.split("@", 1)[-1]:
        return "email"
    if " " in s:
        return "name"
    return "username"


def derive_usernames(seed: str, seed_type: str) -> list[str]:
    """Derive candidate usernames from an email or name seed."""
    if seed_type == "username":
        return [seed.strip()]
    if seed_type == "email":
        local = seed.split("@", 1)[0].strip()
        return [local] if local else []
    # name → first.last permutations
    parts = [p for p in re.split(r"\s+", seed.strip().lower()) if p]
    if not parts:
        return []
    if len(parts) == 1:
        return parts
    first, last = parts[0], parts[-1]
    return list(dict.fromkeys([
        f"{first}{last}",
        f"{first}.{last}",
        f"{first}_{last}",
        f"{first[0]}{last}",
        f"{first}{last[0]}",
    ]))


class SocmintPipeline:
    """Individual SOCMINT profiling pipeline (consent-gated)."""

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
        seed: str,
        consent_confirmed: bool = False,
        max_usernames: int = 5,
        breach_check: bool = True,
    ) -> ReconReport:
        """Profile an individual from a username / email / name seed.

        Raises ConsentError unless consent_confirmed is True — profiling an
        individual requires explicit attestation of authorization.
        """
        if not consent_confirmed:
            raise ConsentError(
                "SOCMINT profiles an individual. Confirm you are authorized to "
                "profile this subject (engagement scope or your own accounts) "
                "before running. Refusing without consent attestation."
            )

        start_time = datetime.now(timezone.utc)
        executed: list[str] = []
        failed: list[str] = []
        findings: list[IntelFinding] = []

        seed_type = classify_seed(seed)
        console.print(f"[bold green]SOCMINT profile[/bold green] — seed: {seed} ([cyan]{seed_type}[/cyan])")

        # Stage 1: email-specific pivots (holehe + h8mail)
        if seed_type == "email":
            console.print("[cyan]Stage 1:[/cyan] Email pivots (holehe platform check + breach)...")
            email_findings, e_exec, e_fail = self._email_pivot(seed, breach_check)
            findings.extend(email_findings)
            executed.extend(e_exec)
            failed.extend(e_fail)
            console.print(f"  [green]✓[/green] {len(email_findings)} email-derived findings")

        # Stage 2: derive usernames + cross-platform enumeration
        usernames = derive_usernames(seed, seed_type)[:max_usernames]
        if usernames:
            console.print(f"[cyan]Stage 2:[/cyan] Username enumeration (sherlock + maigret) on {usernames}...")
            uname_findings, u_exec, u_fail = self._username_enum(usernames)
            findings.extend(uname_findings)
            executed.extend(u_exec)
            failed.extend(u_fail)
            profiles = sum(1 for f in uname_findings if f.type == IntelType.SOCIAL_PROFILE)
            console.print(f"  [green]✓[/green] {profiles} social profiles across platforms")
        else:
            console.print("[yellow]No usernames could be derived from seed.[/yellow]")

        # Stage 3: correlate recovery emails surfaced by holehe → flag for follow-up
        recovery = self._extract_recovery_identifiers(findings)
        if recovery:
            console.print(f"  [dim]  {len(recovery)} recovery identifier(s) surfaced for manual follow-up[/dim]")

        return self._build_report(seed, seed_type, start_time, executed, failed, findings)

    def dry_run(self, targets: list[str]) -> list[dict]:
        """Show which tools would run. Seed type determines the chain."""
        from src.tools.sherlock_tool import SherlockTool
        from src.tools.maigret_tool import MaigretTool
        from src.tools.holehe_tool import HoleheTool

        seed = targets[0] if targets else "user"
        seed_type = classify_seed(seed)
        info = []
        for cls in [SherlockTool, MaigretTool]:
            tool = cls(config=self.config)
            info.append({
                "name": tool.name,
                "installed": tool.is_installed(),
                "command": " ".join(tool.build_command(seed)),
            })
        # holehe only fires for email seeds — mark optional otherwise
        holehe = HoleheTool(config=self.config)
        info.append({
            "name": "holehe",
            "installed": holehe.is_installed(),
            "optional": seed_type != "email",
            "command": " ".join(holehe.build_command(seed if seed_type == "email" else "user@example.com")),
        })
        # h8mail breach check — optional (email-only, degrades without keys)
        try:
            from src.tools.h8mail import H8mail
            h8 = H8mail(config=self.config)
            info.append({
                "name": "h8mail (breach)",
                "installed": h8.is_installed(),
                "optional": True,
                "command": "h8mail -t <email>",
            })
        except Exception:
            pass
        return info

    # ── Stage implementations ─────────────────────────────────────────

    def _email_pivot(self, email: str, breach_check: bool) -> tuple[list[IntelFinding], list[str], list[str]]:
        from src.tools.holehe_tool import HoleheTool

        findings: list[IntelFinding] = []
        executed: list[str] = []
        failed: list[str] = []

        holehe = HoleheTool(config=self.config)
        if holehe.is_installed():
            result = holehe.run(email, timeout=self.timeout)
            if result.errors:
                failed.append("holehe")
            else:
                executed.append("holehe")
                findings.extend(self._to_findings(result))
        else:
            failed.append("holehe")

        if breach_check:
            try:
                from src.tools.h8mail import H8mail
                h8 = H8mail(config=self.config)
                if h8.is_installed():
                    result = h8.run(email, timeout=self.timeout)
                    if result.errors:
                        failed.append("h8mail")
                    else:
                        executed.append("h8mail")
                        findings.extend(self._to_findings(result))
            except Exception as e:
                logger.info("h8mail breach check skipped: %s", e)

        return findings, executed, failed

    def _username_enum(self, usernames: list[str]) -> tuple[list[IntelFinding], list[str], list[str]]:
        from src.tools.sherlock_tool import SherlockTool
        from src.tools.maigret_tool import MaigretTool

        sherlock = SherlockTool(config=self.config)
        maigret = MaigretTool(config=self.config)
        findings: list[IntelFinding] = []
        executed: list[str] = []
        failed: list[str] = []

        joined = ",".join(usernames)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = {}
            if sherlock.is_installed():
                futures[pool.submit(sherlock.run, joined, timeout=self.timeout, usernames=usernames)] = "sherlock"
            else:
                failed.append("sherlock")
            if maigret.is_installed():
                futures[pool.submit(maigret.run, joined, timeout=self.timeout, usernames=usernames)] = "maigret"
            else:
                failed.append("maigret")

            for fut in concurrent.futures.as_completed(futures):
                name = futures[fut]
                try:
                    result = fut.result()
                    if result.errors:
                        failed.append(name)
                    else:
                        executed.append(name)
                        findings.extend(self._to_findings(result))
                except Exception as e:
                    logger.warning("%s failed: %s", name, e)
                    failed.append(name)

        return findings, executed, failed

    def _extract_recovery_identifiers(self, findings: list[IntelFinding]) -> list[str]:
        recovery = []
        for f in findings:
            rd = f.raw_data or {}
            if rd.get("recovery_email"):
                recovery.append(rd["recovery_email"])
            if rd.get("phone"):
                recovery.append(rd["phone"])
        return sorted(set(recovery))

    # ── Utilities ─────────────────────────────────────────────────────

    def _to_findings(self, result: ToolResult) -> list[IntelFinding]:
        out: list[IntelFinding] = []
        for fd in result.structured_data.get("findings", []):
            try:
                out.append(IntelFinding(**fd))
            except Exception:
                pass
        return out

    def _build_report(
        self,
        seed: str,
        seed_type: str,
        start_time: datetime,
        executed: list[str],
        failed: list[str],
        findings: list[IntelFinding],
    ) -> ReconReport:
        # dedupe before summarising
        seen: dict[str, IntelFinding] = {}
        for f in findings:
            key = f"{f.type.value}:{f.value.lower().strip()}"
            if key in seen:
                seen[key] = seen[key].merge_with(f)
            else:
                seen[key] = f
        deduped = list(seen.values())

        summary: dict[str, int] = {}
        for f in deduped:
            summary[f.type.value] = summary.get(f.type.value, 0) + 1

        report = ReconReport(
            target=seed,
            resolved_target={"seed_type": seed_type},
            scan_profile="socmint",
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            authorization_confirmed=True,
            tools_executed=executed,
            tools_failed=failed,
            findings=deduped,
            summary=summary,
        )
        return report
