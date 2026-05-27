"""dnsx — fast DNS resolution with CNAME extraction for takeover detection."""

from __future__ import annotations

import json
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class DnsxCname(BaseTool):
    name = "dnsx_cname"
    description = "DNS CNAME resolution — identifies dangling CNAMEs pointing at third-party providers"
    binary_name = "dnsx"
    install_cmd = "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    accepted_target_types = (TargetType.DOMAIN,)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name]

        input_file = kwargs.get("input_file")
        if input_file:
            cmd.extend(["-l", str(input_file)])
        else:
            cmd.extend(["-d", target])

        cmd.extend(["-cname", "-resp", "-json", "-silent"])

        retry = kwargs.get("retry", 2)
        cmd.extend(["-retry", str(retry)])

        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        cname_map: dict[str, list[str]] = {}
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            host = data.get("host", "").strip().lower()
            cnames = data.get("cname", [])
            if not host or not cnames:
                continue

            if isinstance(cnames, str):
                cnames = [cnames]

            cleaned = [c.strip().lower().rstrip(".") for c in cnames if c.strip()]
            if cleaned:
                cname_map[host] = cleaned

            for cname in cleaned:
                findings.append({
                    "type": IntelType.DNS_RECORD,
                    "value": f"CNAME: {host} → {cname}",
                    "source_tool": self.name,
                    "confidence": 1.0,
                    "tags": ["dnsx", "cname"],
                    "raw_data": {"host": host, "cname": cname},
                })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "cname_map": cname_map,
                "total_resolved": len(cname_map),
                "findings": findings,
            },
        )
