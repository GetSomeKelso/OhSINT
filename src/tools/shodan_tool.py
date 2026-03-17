"""Shodan — internet-connected device search engine (Python API)."""

from __future__ import annotations

import json
from typing import List, Optional

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.tools.base import BaseTool


@register_tool
class ShodanTool(BaseTool):
    name = "shodan"
    description = "Search Shodan for internet-connected devices and services"
    binary_name = "shodan"
    install_cmd = "pip install shodan"
    requires_api_keys = ["shodan.api_key"]

    def build_command(self, target: str, **kwargs) -> List[str]:
        mode = kwargs.get("mode", "search")
        api_key = self.config.get_api_key("shodan", "api_key")

        if mode == "host":
            return ["shodan", "host", target]
        elif mode == "domain":
            return ["shodan", "domain", target]
        else:
            # Default: search mode
            cmd = ["shodan", "search", "--fields", "ip_str,port,org,hostnames,os", target]
            return cmd

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        """Override run to use the Python API when available, CLI as fallback."""
        mode = kwargs.get("mode", "search")
        api_key = self.config.get_api_key("shodan", "api_key")

        if api_key:
            try:
                return self._run_api(target, mode, api_key)
            except ImportError:
                pass  # Fall back to CLI

        return super().run(target, timeout=timeout, **kwargs)

    def _run_api(self, target: str, mode: str, api_key: str) -> ToolResult:
        """Use the Shodan Python library directly."""
        import time
        import shodan

        start = time.time()
        api = shodan.Shodan(api_key)
        findings = []
        raw_data = {}

        try:
            if mode == "host":
                host = api.host(target)
                raw_data = host
                findings = self._parse_host(host)
            elif mode == "domain":
                domain_info = api.dns.domain_info(target)
                raw_data = domain_info
                findings = self._parse_domain(domain_info, target)
            else:
                results = api.search(target)
                raw_data = {
                    "total": results.get("total", 0),
                    "matches": results.get("matches", [])[:50],
                }
                findings = self._parse_search(results)
        except shodan.APIError as e:
            elapsed = time.time() - start
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                errors=[f"Shodan API error: {e}"],
                execution_time_seconds=elapsed,
            )

        elapsed = time.time() - start
        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=json.dumps(raw_data, default=str, indent=2),
            structured_data={"findings": findings, **raw_data},
            execution_time_seconds=elapsed,
        )

    def _parse_host(self, host: dict) -> list:
        findings = []
        ip = host.get("ip_str", "")
        if ip:
            findings.append({
                "type": IntelType.IP_ADDRESS,
                "value": ip,
                "source_tool": self.name,
                "confidence": 0.95,
                "tags": ["shodan"],
            })

        for hostname in host.get("hostnames", []):
            findings.append({
                "type": IntelType.SUBDOMAIN,
                "value": hostname,
                "source_tool": self.name,
                "confidence": 0.9,
                "tags": ["shodan"],
            })

        for service in host.get("data", []):
            port = service.get("port", "")
            transport = service.get("transport", "tcp")
            product = service.get("product", "unknown")
            findings.append({
                "type": IntelType.PORT_SERVICE,
                "value": f"{port}/{transport} ({product})",
                "source_tool": self.name,
                "confidence": 0.9,
                "tags": ["shodan"],
            })

            # Extract technologies
            if product and product != "unknown":
                version = service.get("version", "")
                tech = f"{product} {version}".strip()
                findings.append({
                    "type": IntelType.TECHNOLOGY,
                    "value": tech,
                    "source_tool": self.name,
                    "confidence": 0.85,
                    "tags": ["shodan"],
                })

            # Check for vulns
            for vuln in service.get("vulns", []):
                findings.append({
                    "type": IntelType.VULNERABILITY,
                    "value": vuln,
                    "source_tool": self.name,
                    "confidence": 0.7,
                    "tags": ["shodan", "cve"],
                })

        org = host.get("org", "")
        asn = host.get("asn", "")
        if asn:
            findings.append({
                "type": IntelType.ASN,
                "value": f"{asn} ({org})" if org else asn,
                "source_tool": self.name,
                "confidence": 0.9,
                "tags": ["shodan"],
            })

        return findings

    def _parse_domain(self, domain_info: dict, target: str) -> list:
        findings = []
        for record in domain_info.get("data", []):
            rtype = record.get("type", "")
            value = record.get("value", "")
            subdomain = record.get("subdomain", "")
            if subdomain:
                fqdn = f"{subdomain}.{target}" if subdomain != target else target
                findings.append({
                    "type": IntelType.SUBDOMAIN,
                    "value": fqdn,
                    "source_tool": self.name,
                    "confidence": 0.9,
                    "tags": ["shodan", f"dns:{rtype}"],
                })
            if value:
                findings.append({
                    "type": IntelType.DNS_RECORD,
                    "value": f"{rtype}: {value}",
                    "source_tool": self.name,
                    "confidence": 0.9,
                    "tags": ["shodan"],
                })
        return findings

    def _parse_search(self, results: dict) -> list:
        findings = []
        seen_ips = set()
        for match in results.get("matches", []):
            ip = match.get("ip_str", "")
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                hostnames = match.get("hostnames", [])
                findings.append({
                    "type": IntelType.IP_ADDRESS,
                    "value": ip,
                    "source_tool": self.name,
                    "confidence": 0.9,
                    "tags": ["shodan"] + hostnames[:3],
                })

            port = match.get("port", "")
            transport = match.get("transport", "tcp")
            if port:
                findings.append({
                    "type": IntelType.PORT_SERVICE,
                    "value": f"{ip}:{port}/{transport}",
                    "source_tool": self.name,
                    "confidence": 0.9,
                    "tags": ["shodan"],
                })

            org = match.get("org", "")
            asn = match.get("asn", "")
            if asn and asn not in {f.get("value", "").split()[0] for f in findings if f.get("type") == IntelType.ASN}:
                findings.append({
                    "type": IntelType.ASN,
                    "value": f"{asn} ({org})" if org else asn,
                    "source_tool": self.name,
                    "confidence": 0.85,
                    "tags": ["shodan"],
                })

        return findings

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        """Parse CLI output as fallback."""
        findings = []
        for line in raw_output.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                ip = parts[0].strip()
                port = parts[1].strip() if len(parts) > 1 else ""
                if ip:
                    findings.append({
                        "type": IntelType.IP_ADDRESS,
                        "value": ip,
                        "source_tool": self.name,
                        "confidence": 0.9,
                        "tags": ["shodan"],
                    })
                if port:
                    findings.append({
                        "type": IntelType.PORT_SERVICE,
                        "value": f"{ip}:{port}",
                        "source_tool": self.name,
                        "confidence": 0.9,
                        "tags": ["shodan"],
                    })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={"findings": findings},
        )
