"""VirusTotal — domain/IP threat reputation via API v3."""

from __future__ import annotations

import re
import time as _time
from typing import List

import httpx

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

VT_API_BASE = "https://www.virustotal.com/api/v3"

# Free tier: 4 req/min — space requests 15s apart
VT_REQUEST_DELAY = 15


@register_tool
class VirusTotalTool(BaseTool):
    name = "virustotal"
    description = "Domain/IP threat reputation — malicious scores, DNS, categories, subdomains (VirusTotal API)"
    binary_name = "virustotal"  # API-based, no binary
    install_cmd = "pip install httpx  # API-based. Set virustotal.api_key in api_keys.yaml"
    accepted_target_types = (TargetType.DOMAIN, TargetType.IP)
    requires_api_keys = ("virustotal.api_key",)

    def is_installed(self) -> bool:
        try:
            import httpx  # noqa: F401
            return True
        except ImportError:
            return False

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["virustotal", "--target", target]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        """Query VirusTotal API v3 for domain or IP reputation."""
        api_key = self.config.get_api_key("virustotal", "api_key")
        if not api_key:
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={},
                errors=["VirusTotal API key not configured. Set virustotal.api_key in api_keys.yaml"],
                execution_time_seconds=0.0,
            )

        start = _time.time()
        headers = {"x-apikey": api_key, "Accept": "application/json"}
        findings = []
        errors = []
        raw_parts = []
        reputation_data = {}

        # Detect target type
        is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target))
        endpoint = "ip_addresses" if is_ip else "domains"

        with httpx.Client(timeout=timeout) as client:
            # 1. Main lookup — domain or IP
            try:
                resp = client.get(f"{VT_API_BASE}/{endpoint}/{target}", headers=headers)
                resp.raise_for_status()
                data = resp.json().get("data", {})
                attrs = data.get("attributes", {})

                # Analysis stats
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected

                reputation_data = {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total_engines": total,
                    "reputation_score": attrs.get("reputation", 0),
                }

                raw_parts.append(f"Analysis: {malicious} malicious, {suspicious} suspicious, {harmless} harmless / {total} engines")
                raw_parts.append(f"Reputation score: {attrs.get('reputation', 'N/A')}")

                # Reputation finding
                risk = "clean"
                confidence = 0.9
                if malicious > 0:
                    risk = "malicious"
                elif suspicious > 0:
                    risk = "suspicious"
                    confidence = 0.7

                findings.append({
                    "type": IntelType.REPUTATION,
                    "value": f"{target}: {malicious}/{total} malicious ({risk})",
                    "source_tool": self.name,
                    "confidence": confidence,
                    "tags": ["virustotal", risk],
                    "raw_data": reputation_data,
                })

                # Categories
                categories = attrs.get("categories", {})
                if categories:
                    raw_parts.append(f"Categories: {', '.join(categories.values())}")

                # DNS records (domain only)
                dns_records = attrs.get("last_dns_records", [])
                for rec in dns_records:
                    rec_type = rec.get("type", "")
                    rec_value = rec.get("value", "")
                    if rec_type and rec_value:
                        findings.append({
                            "type": IntelType.DNS_RECORD,
                            "value": f"{rec_type}: {rec_value}",
                            "source_tool": self.name,
                            "confidence": 0.95,
                            "tags": ["virustotal", "dns"],
                            "raw_data": rec,
                        })

                # ASN info (IP only)
                if is_ip:
                    asn = attrs.get("asn")
                    as_owner = attrs.get("as_owner", "")
                    country = attrs.get("country", "")
                    network = attrs.get("network", "")
                    if asn:
                        findings.append({
                            "type": IntelType.ASN,
                            "value": f"AS{asn} ({as_owner}) — {country} — {network}",
                            "source_tool": self.name,
                            "confidence": 0.95,
                            "tags": ["virustotal", "asn"],
                            "raw_data": {"asn": asn, "as_owner": as_owner, "country": country, "network": network},
                        })
                        raw_parts.append(f"ASN: AS{asn} {as_owner} ({country})")

            except httpx.HTTPStatusError as e:
                errors.append(f"VT lookup failed: HTTP {e.response.status_code}")
            except Exception as e:
                errors.append(f"VT lookup error: {e}")

            # 2. Subdomains (domain only, skip for IPs)
            if not is_ip and not errors:
                _time.sleep(VT_REQUEST_DELAY)
                try:
                    resp = client.get(
                        f"{VT_API_BASE}/domains/{target}/subdomains",
                        headers=headers,
                        params={"limit": 40},
                    )
                    resp.raise_for_status()
                    sub_data = resp.json().get("data", [])
                    subdomains = []
                    for item in sub_data:
                        sub_id = item.get("id", "")
                        if sub_id:
                            subdomains.append(sub_id)
                            findings.append({
                                "type": IntelType.SUBDOMAIN,
                                "value": sub_id,
                                "source_tool": self.name,
                                "confidence": 0.9,
                                "tags": ["virustotal", "subdomain"],
                            })
                    if subdomains:
                        raw_parts.append(f"Subdomains: {len(subdomains)} found")
                except httpx.HTTPStatusError:
                    pass  # subdomains endpoint may not be available on free tier
                except Exception:
                    pass

        elapsed = _time.time() - start

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output="\n".join(raw_parts),
            structured_data={
                "reputation": reputation_data,
                "categories": categories if not is_ip else {},
                "dns_records": [r for r in dns_records] if not is_ip else [],
                "findings": findings,
            },
            errors=errors,
            execution_time_seconds=elapsed,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={},
        )
