"""naabu — fast port scanner with SYN/CONNECT modes."""

from __future__ import annotations

import json
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class NaabuTool(BaseTool):
    name = "naabu"
    description = "Fast port scanner — SYN/CONNECT scanning with top-ports presets"
    binary_name = "naabu"
    install_cmd = "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    accepted_target_types = (TargetType.DOMAIN, TargetType.IP, TargetType.CIDR)
    requires_api_keys = ()
    is_passive = False  # Active — sends packets to target

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name]

        input_file = kwargs.get("input_file")
        if input_file:
            cmd.extend(["-l", str(input_file)])
        else:
            cmd.extend(["-host", target])

        # Port specification
        ports = kwargs.get("ports")
        if ports:
            cmd.extend(["-p", ports])
        else:
            top = kwargs.get("top_ports", "100")
            cmd.extend(["-top-ports", str(top)])

        # Scan type
        scan_type = kwargs.get("scan_type", "c")  # c=connect, s=syn
        cmd.extend(["-s", scan_type])

        # Rate
        rate = kwargs.get("rate", 1000)
        cmd.extend(["-rate", str(rate)])

        cmd.extend(["-json", "-silent"])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        open_ports = []
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                # Plain text: "host:port"
                if ":" in line:
                    parts = line.rsplit(":", 1)
                    if len(parts) == 2 and parts[1].isdigit():
                        data = {"host": parts[0], "port": int(parts[1])}
                    else:
                        continue
                else:
                    continue

            host = data.get("host", data.get("ip", ""))
            ip = data.get("ip", host)
            port = data.get("port", 0)

            if host and port:
                open_ports.append({"host": host, "ip": ip, "port": port})
                findings.append({
                    "type": IntelType.PORT_SERVICE,
                    "value": f"{host}:{port}",
                    "source_tool": self.name,
                    "confidence": 1.0,
                    "tags": ["naabu", "open-port"],
                    "raw_data": {"host": host, "ip": ip, "port": port},
                })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "open_ports": open_ports,
                "total_open": len(open_ports),
                "findings": findings,
            },
        )
