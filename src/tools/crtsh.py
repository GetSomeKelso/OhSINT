"""crt.sh — Certificate Transparency log search (API-based)."""

from __future__ import annotations

import json
import re
from typing import List

import httpx

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

CRTSH_API_URL = "https://crt.sh"


@register_tool
class CrtSh(BaseTool):
    name = "crtsh"
    description = "Certificate Transparency log search — discovers subdomains and certificates from public CT logs"
    binary_name = "crtsh"  # API-based, no binary
    install_cmd = "pip install httpx  # API-based, no binary needed"
    accepted_target_types = (TargetType.DOMAIN,)
    requires_api_keys = ()

    def is_installed(self) -> bool:
        """API-based — installed if httpx is available."""
        try:
            import httpx  # noqa: F401
            return True
        except ImportError:
            return False

    def build_command(self, target: str, **kwargs) -> List[str]:
        """Not used — this tool uses the API directly."""
        return ["crtsh", "--domain", target]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        """Query crt.sh API for Certificate Transparency data."""
        import time as _time

        start = _time.time()
        wildcard = kwargs.get("wildcard", True)
        deduplicate = kwargs.get("deduplicate", True)

        # Build query — %.domain.com for wildcard subdomain discovery
        query = f"%.{target}" if wildcard else target

        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    CRTSH_API_URL,
                    params={"q": query, "output": "json"},
                )
                response.raise_for_status()
                entries = response.json()
        except httpx.HTTPStatusError as e:
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={},
                errors=[f"crt.sh API error: {e.response.status_code}"],
                execution_time_seconds=_time.time() - start,
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={},
                errors=[f"crt.sh query failed: {e}"],
                execution_time_seconds=_time.time() - start,
            )

        elapsed = _time.time() - start

        # Parse entries — each has: issuer_ca_id, issuer_name, common_name,
        # name_value, id, entry_timestamp, not_before, not_after, serial_number
        subdomains = set()
        certificates = []
        issuers = set()

        for entry in entries:
            # name_value can contain multiple names separated by newlines
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                # Skip wildcards and empty
                if not name or name.startswith("*"):
                    # Extract the base domain from wildcard
                    if name.startswith("*."):
                        subdomains.add(name[2:])
                    continue
                if "." in name:
                    subdomains.add(name)

            common_name = entry.get("common_name", "").strip().lower()
            if common_name and "." in common_name and not common_name.startswith("*"):
                subdomains.add(common_name)

            issuer = entry.get("issuer_name", "")
            if issuer:
                issuers.add(issuer)

            certificates.append({
                "id": entry.get("id"),
                "common_name": common_name,
                "name_value": name_value,
                "issuer": issuer,
                "not_before": entry.get("not_before", ""),
                "not_after": entry.get("not_after", ""),
                "serial_number": entry.get("serial_number", ""),
            })

        # Deduplicate certificates by id if requested
        if deduplicate:
            seen_ids = set()
            unique_certs = []
            for cert in certificates:
                cert_id = cert.get("id")
                if cert_id not in seen_ids:
                    seen_ids.add(cert_id)
                    unique_certs.append(cert)
            certificates = unique_certs

        # Build findings
        findings = []
        for sub in sorted(subdomains):
            findings.append({
                "type": IntelType.SUBDOMAIN,
                "value": sub,
                "source_tool": self.name,
                "confidence": 0.9,  # CT logs are authoritative
                "tags": ["crtsh", "certificate-transparency"],
            })

        for cert in certificates[:100]:  # Cap to avoid huge output
            findings.append({
                "type": IntelType.CERTIFICATE,
                "value": cert.get("common_name", "unknown"),
                "source_tool": self.name,
                "confidence": 1.0,
                "tags": ["crtsh", "certificate"],
                "raw_data": cert,
            })

        raw_lines = [f"crt.sh query: {query}", f"Entries: {len(entries)}"]
        raw_lines.append(f"Unique subdomains: {len(subdomains)}")
        raw_lines.append(f"Certificates: {len(certificates)}")

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output="\n".join(raw_lines),
            structured_data={
                "subdomains": sorted(subdomains),
                "total_subdomains": len(subdomains),
                "total_certificates": len(certificates),
                "issuers": sorted(issuers),
                "certificates": certificates[:50],  # Cap for structured data
                "findings": findings,
            },
            execution_time_seconds=elapsed,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        """Not used — run() handles everything directly."""
        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={},
        )
