"""recon-ng — modular recon framework (Metasploit-style)."""

from __future__ import annotations

import json
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import List, Optional

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.tools.base import BaseTool


# Default module sets for different scan modes
MODULE_SETS = {
    "passive": [
        "recon/domains-hosts/hackertarget",
        "recon/domains-hosts/threatcrowd",
        "recon/domains-contacts/whois_pocs",
        "recon/hosts-hosts/resolve",
        "recon/netblocks-hosts/shodan_net",
    ],
    "active_set": [
        "recon/domains-hosts/hackertarget",
        "recon/domains-hosts/threatcrowd",
        "recon/domains-hosts/brute_hosts",
        "recon/domains-contacts/whois_pocs",
        "recon/hosts-hosts/resolve",
        "recon/hosts-ports/shodan_ip",
        "recon/netblocks-hosts/shodan_net",
        "discovery/info_disclosure/interesting_files",
    ],
}


@register_tool
class ReconNg(BaseTool):
    name = "recon_ng"
    description = "Modular recon framework (Metasploit-style)"
    binary_name = "recon-ng"
    install_cmd = "pip install recon-ng"
    requires_api_keys = (
        "recon_ng.shodan_api",
        "recon_ng.bing_api",
    )

    def build_command(self, target: str, **kwargs) -> List[str]:
        workspace = kwargs.get("workspace", f"ohsint_{target.replace('.', '_')}")
        modules = kwargs.get("modules", "passive")
        rc_file = kwargs.get("rc_file")

        if rc_file is None:
            rc_file = self._generate_rc(target, workspace, modules)

        return ["recon-ng", "-r", rc_file]

    def _generate_rc(
        self, target: str, workspace: str, modules_key: str
    ) -> str:
        """Generate a recon-ng resource script (.rc)."""
        modules = MODULE_SETS.get(modules_key, MODULE_SETS["passive"])

        lines = [
            f"workspaces create {workspace}",
            f"db insert domains {target}",
        ]

        # Add API keys from config
        api_keys = {
            "shodan_api": self.config.get_api_key("recon_ng", "shodan_api"),
            "bing_api": self.config.get_api_key("recon_ng", "bing_api"),
            "github_api": self.config.get_api_key("recon_ng", "github_api"),
            "virustotal_api": self.config.get_api_key("recon_ng", "virustotal_api"),
        }
        for key_name, key_value in api_keys.items():
            if key_value:
                lines.append(f"keys add {key_name} {key_value}")

        for module in modules:
            lines.extend([
                f"modules load {module}",
                f"options set SOURCE {target}",
                "run",
                "back",
            ])

        lines.append("exit")

        rc_path = Path(tempfile.mktemp(suffix=".rc", prefix="recon_ng_"))
        rc_path.write_text("\n".join(lines))
        return str(rc_path)

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        """Parse recon-ng output and optionally the workspace database."""
        findings = []
        hosts = set()
        contacts = set()
        ports = set()

        # Parse stdout for common patterns
        for line in raw_output.splitlines():
            line = line.strip()

            # Host discoveries: [*] host.example.com (1.2.3.4)
            host_match = re.search(
                r'\[.\]\s+([\w.-]+\.\w+)\s+\(?([\d.]+)\)?', line
            )
            if host_match:
                hostname = host_match.group(1)
                ip = host_match.group(2)
                hosts.add((hostname, ip))
                continue

            # Email/contact: typically in POC table
            email_match = re.search(r'([\w.+-]+@[\w-]+\.[\w.-]+)', line)
            if email_match and "[" not in line[:5]:
                contacts.add(email_match.group(1).lower())

            # Port info
            port_match = re.search(r'(\d{1,5})/(tcp|udp)\s+(\S+)', line)
            if port_match:
                ports.add(
                    (port_match.group(1), port_match.group(2), port_match.group(3))
                )

        # Build findings
        for hostname, ip in hosts:
            findings.append({
                "type": IntelType.SUBDOMAIN,
                "value": hostname,
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["recon-ng"],
            })
            findings.append({
                "type": IntelType.IP_ADDRESS,
                "value": ip,
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["recon-ng"],
            })

        for email in sorted(contacts):
            findings.append({
                "type": IntelType.EMAIL,
                "value": email,
                "source_tool": self.name,
                "confidence": 0.7,
                "tags": ["recon-ng", "whois"],
            })

        for port, proto, service in sorted(ports):
            findings.append({
                "type": IntelType.PORT_SERVICE,
                "value": f"{port}/{proto} ({service})",
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["recon-ng"],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "hosts": [{"hostname": h, "ip": i} for h, i in sorted(hosts)],
                "contacts": sorted(contacts),
                "ports": [
                    {"port": p, "proto": pr, "service": s}
                    for p, pr, s in sorted(ports)
                ],
                "findings": findings,
            },
        )
