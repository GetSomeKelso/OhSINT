"""uncover — multi-engine search across Shodan, Censys, Fofa, Hunter, ZoomEye, Netlas."""

from __future__ import annotations

import json
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class UncoverTool(BaseTool):
    name = "uncover"
    description = "Multi-engine search — queries Shodan, Censys, Fofa, Hunter, ZoomEye, Netlas in one shot"
    binary_name = "uncover"
    install_cmd = "go install github.com/projectdiscovery/uncover/cmd/uncover@latest"
    accepted_target_types = (TargetType.DOMAIN, TargetType.ORG_NAME, TargetType.IP)
    requires_api_keys = ()  # works with any configured engine keys

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name, "-q", target]

        engines = kwargs.get("engines", "shodan,censys")
        cmd.extend(["-e", engines])

        limit = kwargs.get("limit", 100)
        cmd.extend(["-limit", str(limit)])

        cmd.extend(["-json", "-silent"])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        hosts = []
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            host = data.get("host", data.get("ip", ""))
            ip = data.get("ip", "")
            port = data.get("port", 0)
            engine = data.get("engine", data.get("source", "unknown"))

            if host:
                hosts.append({"host": host, "ip": ip, "port": port, "engine": engine})

            if ip:
                findings.append({
                    "type": IntelType.IP_ADDRESS,
                    "value": f"{ip}:{port}" if port else ip,
                    "source_tool": self.name,
                    "confidence": 0.8,
                    "tags": ["uncover", engine],
                    "raw_data": {"host": host, "ip": ip, "port": port, "engine": engine},
                })

            if port:
                findings.append({
                    "type": IntelType.PORT_SERVICE,
                    "value": f"{host or ip}:{port}",
                    "source_tool": self.name,
                    "confidence": 0.8,
                    "tags": ["uncover", engine],
                    "raw_data": {"host": host, "port": port},
                })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "hosts": hosts,
                "total_hosts": len(hosts),
                "findings": findings,
            },
        )
