"""DataSploit — OSINT visualizer (Shodan, Censys, Clearbit, etc.)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

# DataSploit is cloned to /opt/tools/datasploit in Docker
DATASPLOIT_DIR = Path("/opt/tools/datasploit")


@register_tool
class DataSploit(BaseTool):
    name = "datasploit"
    description = "OSINT visualizer — aggregates Shodan, Censys, Clearbit"
    binary_name = "python3"
    install_cmd = "git clone https://github.com/upgoingstar/datasploit.git /opt/tools/datasploit"
    accepted_target_types = (TargetType.DOMAIN, TargetType.IP, TargetType.EMAIL, TargetType.PERSON_NAME)
    requires_api_keys = ("shodan.api_key",)

    def is_installed(self) -> bool:
        """Check if the datasploit directory exists."""
        return DATASPLOIT_DIR.exists() and (DATASPLOIT_DIR / "datasploit.py").exists()

    def build_command(self, target: str, **kwargs) -> List[str]:
        target_type = kwargs.get("target_type", "domain")
        script = str(DATASPLOIT_DIR / "datasploit.py")

        cmd = ["python3", script, "-t", target]
        if target_type == "email":
            cmd.extend(["--email"])
        elif target_type == "ip":
            cmd.extend(["--ip"])
        elif target_type == "person":
            cmd.extend(["--person"])
        # domain is the default

        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = []

        # DataSploit outputs structured sections with headers
        # Try JSON blocks first
        json_blocks = re.findall(r'\{[^{}]+\}', raw_output, re.DOTALL)
        for block in json_blocks:
            try:
                data = json.loads(block)
                findings.extend(self._extract_from_dict(data))
            except json.JSONDecodeError:
                continue

        # Parse line-by-line for common patterns
        emails = set()
        ips = set()
        subdomains = set()

        for line in raw_output.splitlines():
            stripped = line.strip()

            # Emails
            for email in re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', stripped):
                emails.add(email.lower())

            # IPs
            for ip in re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', stripped):
                ips.add(ip)

            # Subdomains
            for sub in re.findall(r'([\w.-]+\.' + re.escape(target) + r')\b', stripped):
                subdomains.add(sub.lower())

        for email in sorted(emails):
            findings.append({
                "type": IntelType.EMAIL,
                "value": email,
                "source_tool": self.name,
                "confidence": 0.6,
                "tags": ["datasploit"],
            })
        for ip in sorted(ips):
            findings.append({
                "type": IntelType.IP_ADDRESS,
                "value": ip,
                "source_tool": self.name,
                "confidence": 0.6,
                "tags": ["datasploit"],
            })
        for sub in sorted(subdomains):
            findings.append({
                "type": IntelType.SUBDOMAIN,
                "value": sub,
                "source_tool": self.name,
                "confidence": 0.6,
                "tags": ["datasploit"],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "emails": sorted(emails),
                "ips": sorted(ips),
                "subdomains": sorted(subdomains),
                "findings": findings,
            },
        )

    def _extract_from_dict(self, data: dict) -> list:
        findings = []
        for key, value in data.items():
            if not isinstance(value, str):
                continue
            key_lower = key.lower()
            if "email" in key_lower:
                findings.append({
                    "type": IntelType.EMAIL,
                    "value": value,
                    "source_tool": self.name,
                    "confidence": 0.7,
                    "tags": ["datasploit"],
                })
            elif "ip" in key_lower:
                findings.append({
                    "type": IntelType.IP_ADDRESS,
                    "value": value,
                    "source_tool": self.name,
                    "confidence": 0.7,
                    "tags": ["datasploit"],
                })
            elif "host" in key_lower or "domain" in key_lower:
                findings.append({
                    "type": IntelType.SUBDOMAIN,
                    "value": value,
                    "source_tool": self.name,
                    "confidence": 0.6,
                    "tags": ["datasploit"],
                })
        return findings
