"""shuffledns — massDNS wrapper for subdomain brute-force with wildcard filtering."""

from __future__ import annotations

import json
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class ShufflednsTool(BaseTool):
    name = "shuffledns"
    description = "DNS brute-force — massDNS wrapper with wildcard filtering for subdomain enumeration"
    binary_name = "shuffledns"
    install_cmd = "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    accepted_target_types = (TargetType.DOMAIN,)
    requires_api_keys = ()
    is_passive = False  # Active — mass DNS resolution

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name, "-d", target]

        wordlist = kwargs.get("wordlist")
        if wordlist:
            cmd.extend(["-w", str(wordlist)])

        # Subdomain list mode (verify existing subdomains instead of brute-force)
        input_file = kwargs.get("input_file")
        if input_file:
            cmd.extend(["-list", str(input_file)])

        resolvers = kwargs.get("resolvers")
        if resolvers:
            cmd.extend(["-r", str(resolvers)])

        cmd.extend(["-json", "-silent"])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        subdomains = set()
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                host = data.get("hostname", data.get("host", "")).strip().lower()
            except (json.JSONDecodeError, ValueError):
                # Plain text: one subdomain per line
                host = line.lower()

            if host and "." in host:
                subdomains.add(host)
                findings.append({
                    "type": IntelType.SUBDOMAIN,
                    "value": host,
                    "source_tool": self.name,
                    "confidence": 0.95,
                    "tags": ["shuffledns", "dns-brute"],
                })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "subdomains": sorted(subdomains),
                "total_found": len(subdomains),
                "findings": findings,
            },
        )
