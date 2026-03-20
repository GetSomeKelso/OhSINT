"""XRay — network recon, mapping, OSINT from public networks."""

from __future__ import annotations

import json
import re
from typing import List

from pathlib import Path

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

_XRAY_SEARCH_PATHS = [
    Path.home() / "Tools" / "osint-deps" / "xray",
    Path("/opt/tools/xray"),
]


def _find_xray_dir() -> Path | None:
    for p in _XRAY_SEARCH_PATHS:
        if p.exists() and (p / "cmd" / "xray").is_dir():
            return p
        # Also check for pre-built binary in the dir
        if p.exists() and (p / "xray").exists():
            return p
    return None


@register_tool
class XRay(BaseTool):
    name = "xray"
    description = "Network recon and OSINT from public networks (archived, legacy)"
    binary_name = "xray"
    install_cmd = "git clone https://github.com/evilsocket/xray.git ~/Tools/osint-deps/xray && cd ~/Tools/osint-deps/xray && go build -o xray ./cmd/xray/ && sudo cp xray /usr/local/bin/"
    accepted_target_types = (TargetType.DOMAIN, TargetType.IP, TargetType.CIDR)
    requires_api_keys = ("shodan.api_key",)

    def is_installed(self) -> bool:
        import shutil
        if shutil.which(self.binary_name):
            return True
        src_dir = _find_xray_dir()
        if src_dir and (src_dir / "xray").exists():
            return True
        return False

    def build_command(self, target: str, **kwargs) -> List[str]:
        mode = kwargs.get("mode", "full")
        cmd = ["xray", "-target", target, "-shodan-key"]

        api_key = self.config.get_api_key("shodan", "api_key") or ""
        cmd.append(api_key)

        if mode == "full":
            cmd.append("-run-all")

        # JSON output
        output_file = kwargs.get("output_file")
        if output_file:
            cmd.extend(["-out", output_file])

        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = []
        hosts = set()
        ports = set()
        banners = []

        # Try JSON parsing first
        try:
            data = json.loads(raw_output)
            if isinstance(data, dict):
                return self._parse_json(data, target)
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        findings.extend(self._parse_host_entry(item))
                return ToolResult(
                    tool_name=self.name,
                    target=target,
                    raw_output=raw_output,
                    structured_data={"findings": findings},
                )
        except (json.JSONDecodeError, TypeError):
            pass

        # Fallback: parse text output
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            # IP:port patterns
            ip_port = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)', line)
            if ip_port:
                ip = ip_port.group(1)
                port = ip_port.group(2)
                hosts.add(ip)
                ports.add((ip, port))

            # Hostname patterns
            host_match = re.search(r'([\w.-]+\.\w{2,})', line)
            if host_match and not host_match.group(1)[0].isdigit():
                hostname = host_match.group(1)
                if hostname not in ("github.com", "golang.org"):
                    findings.append({
                        "type": IntelType.SUBDOMAIN,
                        "value": hostname,
                        "source_tool": self.name,
                        "confidence": 0.6,
                        "tags": ["xray"],
                    })

            # Banner/service info
            if "banner" in line.lower() or "service" in line.lower():
                banners.append(line)

        for ip in sorted(hosts):
            findings.append({
                "type": IntelType.IP_ADDRESS,
                "value": ip,
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["xray"],
            })

        for ip, port in sorted(ports):
            findings.append({
                "type": IntelType.PORT_SERVICE,
                "value": f"{ip}:{port}",
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["xray"],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "hosts": sorted(hosts),
                "ports": [{"ip": i, "port": p} for i, p in sorted(ports)],
                "banners": banners,
                "findings": findings,
            },
        )

    def _parse_json(self, data: dict, target: str) -> ToolResult:
        findings = []
        for host_data in data.get("hosts", []):
            findings.extend(self._parse_host_entry(host_data))
        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=json.dumps(data, indent=2),
            structured_data={"findings": findings, **data},
        )

    def _parse_host_entry(self, entry: dict) -> list:
        findings = []
        ip = entry.get("ip", entry.get("address", ""))
        if ip:
            findings.append({
                "type": IntelType.IP_ADDRESS,
                "value": ip,
                "source_tool": self.name,
                "confidence": 0.85,
                "tags": ["xray"],
            })
        for hostname in entry.get("hostnames", []):
            findings.append({
                "type": IntelType.SUBDOMAIN,
                "value": hostname,
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["xray"],
            })
        for port_info in entry.get("ports", []):
            port = port_info if isinstance(port_info, (str, int)) else port_info.get("port", "")
            findings.append({
                "type": IntelType.PORT_SERVICE,
                "value": f"{ip}:{port}",
                "source_tool": self.name,
                "confidence": 0.85,
                "tags": ["xray"],
            })
        return findings
