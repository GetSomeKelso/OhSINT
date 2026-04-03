"""Holehe — email-to-platform registration check via password reset endpoints."""

from __future__ import annotations

import csv
import glob
import os
import re
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class HoleheTool(BaseTool):
    name = "holehe"
    description = "Email-to-platform mapping — checks 120+ sites for email registration via password reset"
    binary_name = "holehe"
    install_cmd = "pip install holehe"
    accepted_target_types = (TargetType.EMAIL,)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name, target, "--no-color", "--no-clear"]

        # CSV output (holehe auto-names the file)
        if kwargs.get("csv", True):
            cmd.append("-C")

        # Only show sites where email is registered
        if kwargs.get("only_used", False):
            cmd.append("--only-used")

        # Skip password recovery modules (adobe, mail.ru, etc.)
        if kwargs.get("no_password_recovery", False):
            cmd.append("-NP")

        timeout = kwargs.get("timeout")
        if timeout:
            cmd.extend(["-T", str(timeout)])

        self._target_email = target
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        registered = []
        not_registered = []
        rate_limited = []
        errors = []
        findings = []

        email = getattr(self, "_target_email", target)

        # Parse stdout — format:
        # [+] twitter.com
        # [+] instagram.com s]****@g]****.com / +1*****678
        # [-] github.com
        # [x] discord.com
        # [!] some-site.com
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("[+]"):
                # Registered — may include recovery info after the domain
                content = line[3:].strip()
                parts = content.split(None, 1)
                domain = parts[0] if parts else content
                extra = parts[1] if len(parts) > 1 else ""

                entry = {"domain": domain}
                if extra:
                    # Parse recovery email and phone
                    recovery_match = re.search(r'(\S+@\S+)', extra)
                    phone_match = re.search(r'(\+[\d*]+)', extra)
                    if recovery_match:
                        entry["recovery_email"] = recovery_match.group(1)
                    if phone_match:
                        entry["phone"] = phone_match.group(1)

                registered.append(entry)
            elif line.startswith("[-]"):
                domain = line[3:].strip().split()[0] if line[3:].strip() else ""
                if domain:
                    not_registered.append(domain)
            elif line.startswith("[x]"):
                domain = line[3:].strip().split()[0] if line[3:].strip() else ""
                if domain:
                    rate_limited.append(domain)
            elif line.startswith("[!]"):
                domain = line[3:].strip().split()[0] if line[3:].strip() else ""
                if domain:
                    errors.append(domain)

        # Also try CSV parsing as fallback/supplement
        # Holehe auto-names: holehe_{timestamp}_{email}_results.csv
        csv_files = glob.glob(f"holehe_*_{email.replace('@', '_at_')}_results.csv") + \
                    glob.glob(f"holehe_*_results.csv")
        for csv_file in csv_files[:1]:  # Take first match
            try:
                with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        exists = row.get("exists", "").lower()
                        domain = row.get("domain", "")
                        if exists == "true" and domain:
                            if not any(r["domain"] == domain for r in registered):
                                entry = {"domain": domain, "method": row.get("method", "")}
                                recovery = row.get("emailrecovery")
                                phone = row.get("phoneNumber")
                                if recovery and recovery != "None":
                                    entry["recovery_email"] = recovery
                                if phone and phone != "None":
                                    entry["phone"] = phone
                                registered.append(entry)
            except (OSError, csv.Error):
                pass

        # Build findings
        for reg in registered:
            domain = reg["domain"]
            tags = ["holehe", "registered"]
            value = f"{email} registered on {domain}"

            raw_data = {"email": email, "domain": domain}
            if reg.get("recovery_email"):
                raw_data["recovery_email"] = reg["recovery_email"]
                value += f" (recovery: {reg['recovery_email']})"
            if reg.get("phone"):
                raw_data["phone"] = reg["phone"]

            findings.append({
                "type": IntelType.SOCIAL_PROFILE,
                "value": value,
                "source_tool": self.name,
                "confidence": 0.9,
                "tags": tags,
                "raw_data": raw_data,
            })

        # Summary email finding
        if registered:
            findings.append({
                "type": IntelType.EMAIL,
                "value": f"{email} — registered on {len(registered)} platforms",
                "source_tool": self.name,
                "confidence": 0.95,
                "tags": ["holehe", "email-footprint"],
                "raw_data": {"total_registered": len(registered), "total_checked": len(registered) + len(not_registered) + len(rate_limited)},
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "email": email,
                "registered": registered,
                "total_registered": len(registered),
                "total_not_registered": len(not_registered),
                "total_rate_limited": len(rate_limited),
                "total_errors": len(errors),
                "findings": findings,
            },
        )
