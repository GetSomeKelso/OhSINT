"""WHOIS — domain registration and ownership lookup."""

from __future__ import annotations

import re
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class WhoisTool(BaseTool):
    name = "whois"
    description = "WHOIS/RDAP domain registration lookup — registrant, dates, name servers"
    binary_name = "whois"
    install_cmd = "sudo apt install whois"
    accepted_target_types = (TargetType.DOMAIN, TargetType.IP)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["whois", target]

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        fields: dict[str, str] = {}
        name_servers = set()
        emails = set()
        findings = []

        # Parse key-value WHOIS fields
        for line in raw_output.splitlines():
            line = line.strip()
            if not line or line.startswith("%") or line.startswith("#"):
                continue

            # Standard "Key: Value" format
            match = re.match(r'^([A-Za-z][A-Za-z /\-_]+):\s*(.+)$', line)
            if not match:
                continue

            key = match.group(1).strip().lower()
            value = match.group(2).strip()

            if not value:
                continue

            # Registrant / org info
            if "registrant" in key or "org" in key:
                fields.setdefault(key, value)
            elif "registrar" in key:
                fields.setdefault(key, value)
            elif "creation" in key or "created" in key:
                fields["created"] = value
            elif "expir" in key:
                fields["expires"] = value
            elif "updated" in key:
                fields["updated"] = value
            elif "name server" in key or "nserver" in key:
                name_servers.add(value.lower().rstrip("."))
            elif "status" in key:
                fields.setdefault("status", value)
            elif "dnssec" in key:
                fields["dnssec"] = value

            # Extract emails
            for email in re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', value):
                emails.add(email.lower())

        # Build the WHOIS record finding
        whois_data = dict(fields)
        whois_data["name_servers"] = sorted(name_servers)
        whois_data["emails"] = sorted(emails)

        findings.append({
            "type": IntelType.WHOIS_RECORD,
            "value": target,
            "source_tool": self.name,
            "confidence": 1.0,
            "tags": ["whois", "registration"],
            "raw_data": whois_data,
        })

        # Add name servers as DNS records
        for ns in sorted(name_servers):
            findings.append({
                "type": IntelType.DNS_RECORD,
                "value": f"NS: {ns}",
                "source_tool": self.name,
                "confidence": 1.0,
                "tags": ["whois", "nameserver"],
            })

        # Add discovered emails
        for email in sorted(emails):
            findings.append({
                "type": IntelType.EMAIL,
                "value": email,
                "source_tool": self.name,
                "confidence": 0.9,
                "tags": ["whois", "registrant"],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "registrar": fields.get("registrar", ""),
                "created": fields.get("created", ""),
                "expires": fields.get("expires", ""),
                "updated": fields.get("updated", ""),
                "status": fields.get("status", ""),
                "dnssec": fields.get("dnssec", ""),
                "name_servers": sorted(name_servers),
                "emails": sorted(emails),
                "registrant": {
                    k: v for k, v in fields.items()
                    if "registrant" in k or "org" in k
                },
                "findings": findings,
            },
        )
