"""Subfinder — fast passive subdomain enumeration via 40+ APIs."""

from __future__ import annotations

import json
import re
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class Subfinder(BaseTool):
    name = "subfinder"
    description = "Fast passive subdomain enumeration via 40+ APIs (crt.sh, SecurityTrails, VirusTotal, etc.)"
    binary_name = "subfinder"
    install_cmd = "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    accepted_target_types = (TargetType.DOMAIN,)
    requires_api_keys = ()  # works without keys but better with them

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name, "-d", target, "-silent", "-json"]

        # Use all sources for maximum coverage
        if kwargs.get("all_sources", True):
            cmd.append("-all")

        # Optional: limit to specific sources
        sources = kwargs.get("sources")
        if sources:
            cmd.extend(["-s", sources])

        # Optional: exclude sources
        exclude = kwargs.get("exclude_sources")
        if exclude:
            cmd.extend(["-es", exclude])

        # Timeout per source
        source_timeout = kwargs.get("source_timeout")
        if source_timeout:
            cmd.extend(["-timeout", str(source_timeout)])

        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        subdomains = set()
        sources_map: dict[str, list[str]] = {}  # subdomain -> list of sources
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            # JSON output format: {"host":"sub.example.com","source":"crtsh",...}
            try:
                data = json.loads(line)
                host = data.get("host", "").strip().lower()
                source = data.get("source", "unknown")
                if host and "." in host:
                    subdomains.add(host)
                    sources_map.setdefault(host, []).append(source)
                continue
            except (json.JSONDecodeError, ValueError):
                pass

            # Fallback: plain text output (one subdomain per line)
            if "." in line and not line.startswith("["):
                host = line.lower().strip()
                # Basic sanity check — should look like a domain
                if re.match(r'^[a-z0-9][\w.-]*\.[a-z]{2,}$', host):
                    subdomains.add(host)

        # Build findings
        for sub in sorted(subdomains):
            sources = sources_map.get(sub, [])
            # Higher confidence when found by multiple sources
            confidence = min(0.5 + 0.1 * len(sources), 0.95)
            findings.append({
                "type": IntelType.SUBDOMAIN,
                "value": sub,
                "source_tool": self.name,
                "confidence": confidence,
                "tags": ["subfinder"] + sources[:5],
                "raw_data": {"sources": sources},
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "subdomains": sorted(subdomains),
                "total_found": len(subdomains),
                "sources_used": list({s for sources in sources_map.values() for s in sources}),
                "findings": findings,
            },
        )
