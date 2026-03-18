"""theHarvester — emails, subdomains, IPs, people names from search engines."""

from __future__ import annotations

import json
import re
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class TheHarvester(BaseTool):
    name = "theharvester"
    description = "Harvest emails, subdomains, IPs from search engines"
    binary_name = "theHarvester"
    install_cmd = "pip install theHarvester"
    accepted_target_types = (TargetType.DOMAIN,)
    requires_api_keys = (
        "theharvester.bing_api",
        "theharvester.github_token",
        "theharvester.hunter_api",
    )

    def build_command(self, target: str, **kwargs) -> List[str]:
        sources = kwargs.get("sources", "all")
        limit = kwargs.get("limit", 500)
        cmd = [
            self.binary_name,
            "-d", target,
            "-b", sources,
            "-l", str(limit),
        ]
        # Request JSON output if supported
        output_file = kwargs.get("output_file")
        if output_file:
            cmd.extend(["-f", output_file])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        emails = set()
        subdomains = set()
        ips = set()
        people = set()

        # theHarvester outputs sections like:
        # [*] Emails found: ...
        # [*] Hosts found: ...
        # [*] IPs found: ...
        current_section = None
        for line in raw_output.splitlines():
            line_stripped = line.strip()
            lower = line_stripped.lower()

            if "emails found" in lower or "emails:" in lower:
                current_section = "emails"
                continue
            elif "hosts found" in lower or "hosts:" in lower:
                current_section = "hosts"
                continue
            elif "ips found" in lower or "ips:" in lower:
                current_section = "ips"
                continue
            elif "people found" in lower or "people:" in lower or "linkedin" in lower:
                current_section = "people"
                continue
            elif line_stripped.startswith("[*]") or line_stripped.startswith("---"):
                if not any(k in lower for k in ("email", "host", "ip", "people")):
                    current_section = None
                continue

            if not line_stripped or line_stripped.startswith("["):
                continue

            if current_section == "emails":
                email = self._extract_email(line_stripped)
                if email:
                    emails.add(email)
            elif current_section == "hosts":
                parts = line_stripped.split(":")
                host = parts[0].strip()
                if "." in host:
                    subdomains.add(host)
                if len(parts) > 1:
                    ip = parts[-1].strip()
                    if self._is_ip(ip):
                        ips.add(ip)
            elif current_section == "ips":
                ip = line_stripped.split()[0] if line_stripped.split() else ""
                if self._is_ip(ip):
                    ips.add(ip)
            elif current_section == "people":
                if line_stripped and not line_stripped.startswith("["):
                    people.add(line_stripped)

        # Also try regex extraction as fallback
        for email in re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', raw_output):
            emails.add(email.lower())

        findings = []
        for email in sorted(emails):
            findings.append({
                "type": IntelType.EMAIL,
                "value": email,
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["harvested"],
            })
        for sub in sorted(subdomains):
            findings.append({
                "type": IntelType.SUBDOMAIN,
                "value": sub,
                "source_tool": self.name,
                "confidence": 0.7,
                "tags": ["harvested"],
            })
        for ip in sorted(ips):
            findings.append({
                "type": IntelType.IP_ADDRESS,
                "value": ip,
                "source_tool": self.name,
                "confidence": 0.7,
                "tags": ["harvested"],
            })
        for person in sorted(people):
            findings.append({
                "type": IntelType.PERSON,
                "value": person,
                "source_tool": self.name,
                "confidence": 0.5,
                "tags": ["linkedin"],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "emails": sorted(emails),
                "subdomains": sorted(subdomains),
                "ips": sorted(ips),
                "people": sorted(people),
                "findings": findings,
            },
        )

    @staticmethod
    def _extract_email(text: str) -> str | None:
        match = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', text)
        return match.group(0).lower() if match else None

    @staticmethod
    def _is_ip(text: str) -> bool:
        parts = text.split(".")
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
