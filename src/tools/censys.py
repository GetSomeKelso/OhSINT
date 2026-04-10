"""Censys — internet device and certificate search via API v2."""

from __future__ import annotations

import re
from typing import List

import httpx

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

CENSYS_API_BASE = "https://search.censys.io/api/v2"


@register_tool
class CensysTool(BaseTool):
    name = "censys"
    description = "Internet device and certificate search — hosts, services, TLS certs (Censys API)"
    binary_name = "censys"
    install_cmd = "pip install httpx  # API-based. Set censys.api_id and censys.api_secret in api_keys.yaml"
    accepted_target_types = (TargetType.DOMAIN, TargetType.IP, TargetType.PHONE)
    requires_api_keys = ("censys.api_id", "censys.api_secret")

    def is_installed(self) -> bool:
        try:
            import httpx  # noqa: F401
            return True
        except ImportError:
            return False

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["censys", "--target", target]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        import time as _time

        api_id = self.config.get_api_key("censys", "api_id")
        api_secret = self.config.get_api_key("censys", "api_secret")
        if not api_id or not api_secret:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={}, execution_time_seconds=0.0,
                errors=["Censys API credentials not configured. Set censys.api_id and censys.api_secret in api_keys.yaml"],
            )

        start = _time.time()
        findings = []
        errors = []
        raw_parts = []
        auth = (api_id, api_secret)

        # Detect target type and build query
        is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target))
        is_phone = bool(re.match(r'^\+?\d[\d\s.()-]{6,18}\d$', target))

        if is_phone:
            # Search for SIP/VoIP infrastructure associated with the phone
            digits = re.sub(r'\D', '', target)
            query = f'services.sip.invite.to.uri:"{digits}" OR services.service_name: SIP'
        elif is_ip:
            query = target
        else:
            query = target

        try:
            with httpx.Client(timeout=timeout, auth=auth) as client:
                if is_ip:
                    # Direct host lookup
                    resp = client.get(f"{CENSYS_API_BASE}/hosts/{target}")
                    resp.raise_for_status()
                    data = resp.json()
                    result_data = data.get("result", {})

                    # Parse services
                    services = result_data.get("services", [])
                    for svc in services:
                        port = svc.get("port", "")
                        service_name = svc.get("service_name", "unknown")
                        transport = svc.get("transport_protocol", "")
                        banner = svc.get("banner", "")[:200]

                        findings.append({
                            "type": IntelType.PORT_SERVICE,
                            "value": f"{target}:{port}/{transport} — {service_name}",
                            "source_tool": self.name,
                            "confidence": 0.95,
                            "tags": ["censys", "service", service_name.lower()],
                            "raw_data": {"port": port, "service": service_name, "transport": transport},
                        })
                        raw_parts.append(f"  {port}/{transport} {service_name}")

                    # ASN info
                    autonomous_system = result_data.get("autonomous_system", {})
                    asn = autonomous_system.get("asn")
                    if asn:
                        findings.append({
                            "type": IntelType.ASN,
                            "value": f"AS{asn} ({autonomous_system.get('name', '')}) — {autonomous_system.get('country_code', '')}",
                            "source_tool": self.name,
                            "confidence": 0.95,
                            "tags": ["censys", "asn"],
                        })

                else:
                    # Search query (domains, phones, general)
                    resp = client.get(
                        f"{CENSYS_API_BASE}/hosts/search",
                        params={"q": query, "per_page": 25},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    hits = data.get("result", {}).get("hits", [])

                    raw_parts.append(f"Search: {query} ({len(hits)} hosts)")
                    for hit in hits:
                        ip = hit.get("ip", "")
                        services = hit.get("services", [])
                        for svc in services:
                            port = svc.get("port", "")
                            service_name = svc.get("service_name", "unknown")
                            findings.append({
                                "type": IntelType.PORT_SERVICE,
                                "value": f"{ip}:{port} — {service_name}",
                                "source_tool": self.name,
                                "confidence": 0.9,
                                "tags": ["censys", "service"],
                                "raw_data": {"ip": ip, "port": port, "service": service_name},
                            })

                        if ip:
                            findings.append({
                                "type": IntelType.IP_ADDRESS,
                                "value": ip,
                                "source_tool": self.name,
                                "confidence": 0.9,
                                "tags": ["censys"],
                            })

        except httpx.HTTPStatusError as e:
            errors.append(f"Censys API error: HTTP {e.response.status_code}")
        except Exception as e:
            errors.append(f"Censys error: {e}")

        elapsed = _time.time() - start
        return ToolResult(
            tool_name=self.name, target=target,
            raw_output="\n".join(raw_parts),
            structured_data={"findings": findings, "query": query},
            errors=errors, execution_time_seconds=elapsed,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        return ToolResult(tool_name=self.name, target=target, raw_output=raw_output, structured_data={})
