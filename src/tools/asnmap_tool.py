"""asnmap — map organizations, domains, and IPs to ASN and CIDR ranges."""

from __future__ import annotations

import json
import re
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class AsnmapTool(BaseTool):
    name = "asnmap"
    description = "ASN mapper — resolves org names, domains, or IPs to ASN numbers and CIDR ranges"
    binary_name = "asnmap"
    install_cmd = "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    accepted_target_types = (TargetType.DOMAIN, TargetType.ORG_NAME, TargetType.IP)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name]

        # Auto-detect input type
        input_type = kwargs.get("input_type")
        if input_type == "asn" or target.upper().startswith("AS"):
            cmd.extend(["-a", target])
        elif input_type == "ip" or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target):
            cmd.extend(["-i", target])
        elif input_type == "org" or (not "." in target and not target[0].isdigit()):
            cmd.extend(["-org", target])
        else:
            cmd.extend(["-d", target])

        cmd.extend(["-json", "-silent"])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        asn_records = []
        cidr_ranges = set()
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                # Plain text: might be a CIDR range directly
                if "/" in line and re.match(r'^\d', line):
                    cidr_ranges.add(line)
                continue

            as_number = data.get("as_number", data.get("asn", ""))
            as_name = data.get("as_name", data.get("as_org", ""))
            as_country = data.get("as_country", data.get("country", ""))
            as_range = data.get("as_range", data.get("cidr", ""))

            if as_range:
                if isinstance(as_range, list):
                    for r in as_range:
                        cidr_ranges.add(r)
                else:
                    cidr_ranges.add(as_range)

            record = {
                "as_number": str(as_number),
                "as_name": as_name,
                "as_country": as_country,
                "as_range": as_range,
            }
            asn_records.append(record)

            if as_number:
                findings.append({
                    "type": IntelType.ASN,
                    "value": f"AS{as_number} ({as_name})" if as_name else f"AS{as_number}",
                    "source_tool": self.name,
                    "confidence": 0.95,
                    "tags": ["asnmap", as_country] if as_country else ["asnmap"],
                    "raw_data": record,
                })

        for cidr in sorted(cidr_ranges):
            findings.append({
                "type": IntelType.IP_ADDRESS,
                "value": cidr,
                "source_tool": self.name,
                "confidence": 0.9,
                "tags": ["asnmap", "cidr-range"],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "asn_records": asn_records,
                "cidr_ranges": sorted(cidr_ranges),
                "total_ranges": len(cidr_ranges),
                "findings": findings,
            },
        )
