"""httpx — fast HTTP probing with tech detection, status codes, and header analysis."""

from __future__ import annotations

import json
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class HttpxTool(BaseTool):
    name = "httpx"
    description = "HTTP prober — discovers live hosts, tech stack, status codes, titles, headers"
    binary_name = "httpx"
    install_cmd = "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    accepted_target_types = (TargetType.DOMAIN, TargetType.IP, TargetType.URL)
    requires_api_keys = ()
    is_passive = False  # Active — sends HTTP requests directly to target

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name]

        input_file = kwargs.get("input_file")
        if input_file:
            cmd.extend(["-l", str(input_file)])
        else:
            cmd.extend(["-u", target])

        # Probes
        cmd.extend(["-sc", "-title", "-server", "-td"])

        if kwargs.get("follow_redirects", True):
            cmd.append("-fr")

        # Rate limiting
        rate = kwargs.get("rate_limit", 50)
        cmd.extend(["-rl", str(rate)])

        threads = kwargs.get("threads", 25)
        cmd.extend(["-threads", str(threads)])

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

            url = data.get("url", "")
            status = data.get("status_code", data.get("status-code", 0))
            title = data.get("title", "")
            server = data.get("webserver", data.get("server", ""))
            tech = data.get("tech", data.get("technologies", []))
            content_length = data.get("content_length", data.get("content-length", 0))
            host = data.get("host", data.get("input", ""))

            host_info = {
                "url": url,
                "status_code": status,
                "title": title,
                "server": server,
                "tech": tech,
                "content_length": content_length,
            }
            hosts.append(host_info)

            # Live host finding
            if url:
                findings.append({
                    "type": IntelType.IP_ADDRESS,
                    "value": url,
                    "source_tool": self.name,
                    "confidence": 1.0,
                    "tags": ["httpx", "live-host", f"status:{status}"],
                    "raw_data": host_info,
                })

            # Tech detection findings
            if isinstance(tech, list):
                for t in tech:
                    if isinstance(t, str) and t:
                        findings.append({
                            "type": IntelType.TECHNOLOGY,
                            "value": f"{t} ({host or url})",
                            "source_tool": self.name,
                            "confidence": 0.85,
                            "tags": ["httpx", "tech-detect"],
                        })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "hosts": hosts,
                "total_live": len(hosts),
                "findings": findings,
            },
        )
