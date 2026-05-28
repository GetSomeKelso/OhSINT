"""tlsx — fast TLS data collection: certs, ciphers, SANs, JARM fingerprints."""

from __future__ import annotations

import json
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class TlsxTool(BaseTool):
    name = "tlsx"
    description = "TLS certificate grabber — SANs, ciphers, JARM hash, cert chain, expiry dates"
    binary_name = "tlsx"
    install_cmd = "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
    accepted_target_types = (TargetType.DOMAIN, TargetType.IP)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name]

        input_file = kwargs.get("input_file")
        if input_file:
            cmd.extend(["-l", str(input_file)])
        else:
            cmd.extend(["-u", target])

        cmd.extend(["-san", "-cn", "-so", "-json", "-silent"])

        if kwargs.get("jarm", True):
            cmd.append("-jarm")

        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        certs = []
        subdomains = set()
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            host = data.get("host", "")
            subject_cn = data.get("subject_cn", "")
            sans = data.get("subject_an", [])
            issuer = data.get("issuer_cn", data.get("issuer_org", ""))
            not_before = data.get("not_before", "")
            not_after = data.get("not_after", "")
            tls_version = data.get("tls_version", "")
            cipher = data.get("cipher", "")
            jarm = data.get("jarm_hash", data.get("jarm", ""))

            cert_info = {
                "host": host,
                "subject_cn": subject_cn,
                "sans": sans,
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
                "tls_version": tls_version,
                "cipher": cipher,
                "jarm": jarm,
            }
            certs.append(cert_info)

            # Extract subdomains from SANs
            if isinstance(sans, list):
                for san in sans:
                    san = san.strip().lower()
                    if san and "." in san and not san.startswith("*"):
                        subdomains.add(san)

            # Certificate finding
            findings.append({
                "type": IntelType.CERTIFICATE,
                "value": subject_cn or host,
                "source_tool": self.name,
                "confidence": 1.0,
                "tags": ["tlsx", "tls", tls_version] if tls_version else ["tlsx", "tls"],
                "raw_data": cert_info,
            })

        # Subdomain findings from SANs
        for sub in sorted(subdomains):
            findings.append({
                "type": IntelType.SUBDOMAIN,
                "value": sub,
                "source_tool": self.name,
                "confidence": 0.95,
                "tags": ["tlsx", "san", "certificate"],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "certificates": certs,
                "subdomains": sorted(subdomains),
                "total_certs": len(certs),
                "findings": findings,
            },
        )
