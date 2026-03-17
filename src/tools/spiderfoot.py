"""SpiderFoot — multi-source OSINT automation (200+ modules)."""

from __future__ import annotations

import csv
import io
import json
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.tools.base import BaseTool

# Map SpiderFoot event types to our IntelType
_SF_TYPE_MAP = {
    "EMAILADDR": IntelType.EMAIL,
    "EMAIL_ADDRESS": IntelType.EMAIL,
    "INTERNET_NAME": IntelType.SUBDOMAIN,
    "IP_ADDRESS": IntelType.IP_ADDRESS,
    "IPV6_ADDRESS": IntelType.IP_ADDRESS,
    "HUMAN_NAME": IntelType.PERSON,
    "SOCIAL_MEDIA": IntelType.SOCIAL_PROFILE,
    "GEOINFO": IntelType.GEOLOCATION,
    "VULNERABILITY": IntelType.VULNERABILITY,
    "WEBSERVER_TECHNOLOGY": IntelType.TECHNOLOGY,
    "SOFTWARE_USED": IntelType.TECHNOLOGY,
    "TCP_PORT_OPEN": IntelType.PORT_SERVICE,
    "DNS_TEXT": IntelType.DNS_RECORD,
    "DNS_SPF": IntelType.DNS_RECORD,
    "BGP_AS_OWNER": IntelType.ASN,
    "LEAKSITE_CONTENT": IntelType.CREDENTIAL,
}


@register_tool
class SpiderFoot(BaseTool):
    name = "spiderfoot"
    description = "Multi-source OSINT automation (200+ modules)"
    binary_name = "spiderfoot"
    install_cmd = "pip install spiderfoot"
    requires_api_keys = [
        "spiderfoot.virustotal",
        "spiderfoot.censys_id",
    ]

    def build_command(self, target: str, **kwargs) -> List[str]:
        use_case = kwargs.get("use_case", "all")
        output_format = kwargs.get("output_format", "json")

        cmd = [
            "spiderfoot",
            "-s", target,
            "-u", use_case,
        ]

        # Map output format to SpiderFoot flags
        if output_format == "json":
            cmd.extend(["-o", "json"])
        elif output_format == "csv":
            cmd.extend(["-o", "csv"])
        else:
            cmd.extend(["-o", "tab"])

        # Quiet mode to reduce noise
        cmd.append("-q")

        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = []
        structured = {"events": [], "findings": []}

        # Try JSON parsing first
        try:
            events = json.loads(raw_output)
            if isinstance(events, list):
                structured["events"] = events
                findings = self._parse_events(events)
        except (json.JSONDecodeError, TypeError):
            pass

        # Fallback: try CSV/tab-separated parsing
        if not findings and raw_output.strip():
            findings = self._parse_tabular(raw_output)

        structured["findings"] = findings

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data=structured,
        )

    def _parse_events(self, events: list) -> list:
        findings = []
        seen = set()
        for event in events:
            if not isinstance(event, dict):
                continue
            event_type = event.get("type", "")
            data = event.get("data", "")
            if not data or not event_type:
                continue

            intel_type = _SF_TYPE_MAP.get(event_type)
            if intel_type is None:
                continue

            key = f"{intel_type}:{data}"
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "type": intel_type,
                "value": str(data),
                "source_tool": self.name,
                "confidence": 0.7,
                "tags": [f"sf:{event_type.lower()}"],
            })
        return findings

    def _parse_tabular(self, raw_output: str) -> list:
        """Parse tab-separated or CSV SpiderFoot output."""
        findings = []
        seen = set()

        for line in raw_output.splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                parts = line.split(",", 3)
            if len(parts) < 3:
                continue

            # SpiderFoot tab output: Updated, Type, Module, Source, Data
            event_type = parts[1].strip() if len(parts) > 1 else ""
            data = parts[-1].strip() if parts else ""

            intel_type = _SF_TYPE_MAP.get(event_type)
            if intel_type is None:
                continue

            key = f"{intel_type}:{data}"
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "type": intel_type,
                "value": data,
                "source_tool": self.name,
                "confidence": 0.6,
                "tags": [f"sf:{event_type.lower()}"],
            })
        return findings
