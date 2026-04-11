"""Whitepages Pro — reverse phone and identity lookup (FCRA-gated)."""

from __future__ import annotations

import re
from typing import List

import httpx

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

WHITEPAGES_PRO_API = "https://proapi.whitepages.com/3.0"


@register_tool
class WhitepagesProTool(BaseTool):
    name = "whitepages_pro"
    description = "Reverse phone/identity lookup — owner, address, carrier (Whitepages Pro API, FCRA-gated)"
    binary_name = "whitepages_pro"
    install_cmd = "pip install httpx  # API-based. Requires Whitepages Pro subscription + FCRA permissible purpose"
    accepted_target_types = (TargetType.PHONE, TargetType.PERSON_NAME)
    requires_api_keys = ("whitepages_pro.api_key",)
    requires_fcra = True
    estimated_cost_per_query = 0.10

    def is_installed(self) -> bool:
        try:
            import httpx  # noqa: F401
            return bool(self.config.get_api_key("whitepages_pro", "api_key"))
        except ImportError:
            return False

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["whitepages_pro", "--target", target]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        import time as _time

        # Defense-in-depth: FCRA check at tool level (also enforced by CLI/MCP gates)
        if not kwargs.get("fcra_purpose"):
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={}, execution_time_seconds=0.0,
                errors=[
                    "FCRA permissible purpose required. This tool accesses commercial "
                    "identity resolution services governed by the Fair Credit Reporting Act."
                ],
            )

        api_key = self.config.get_api_key("whitepages_pro", "api_key")
        if not api_key:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={}, execution_time_seconds=0.0,
                errors=["Whitepages Pro API key not configured. Requires subscription at https://pro.whitepages.com"],
            )

        phone = re.sub(r'[\s()-]', '', target)
        start = _time.time()
        findings = []
        errors = []

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(
                    f"{WHITEPAGES_PRO_API}/phone",
                    params={"phone": phone},
                    headers={"Api-Key": api_key},
                )
                resp.raise_for_status()
                data = resp.json()

            # Parse phone owner info
            belongs_to = data.get("belongs_to", [])
            for owner in belongs_to:
                name = owner.get("name", "")
                age_range = owner.get("age_range", "")
                owner_type = owner.get("type", "")

                if name:
                    findings.append({
                        "type": IntelType.PERSON,
                        "value": f"{name} ({owner_type}, {age_range})" if age_range else name,
                        "source_tool": self.name,
                        "confidence": 0.9,
                        "tags": ["whitepages-pro", "phone-owner"],
                        "raw_data": owner,
                    })

            # Parse carrier/line type
            line_type = data.get("line_type", "")
            carrier = data.get("carrier", "")
            if carrier or line_type:
                findings.append({
                    "type": IntelType.PHONE_INFO,
                    "value": f"{phone}: {carrier} ({line_type})",
                    "source_tool": self.name,
                    "confidence": 0.95,
                    "tags": ["whitepages-pro", "carrier"],
                })

            # Parse associated addresses
            current_addresses = data.get("current_addresses", [])
            for addr in current_addresses:
                street = addr.get("street_line_1", "")
                city = addr.get("city", "")
                state = addr.get("state_code", "")
                zip_code = addr.get("postal_code", "")
                if street:
                    findings.append({
                        "type": IntelType.GEOLOCATION,
                        "value": f"{street}, {city}, {state} {zip_code}".strip(", "),
                        "source_tool": self.name,
                        "confidence": 0.85,
                        "tags": ["whitepages-pro", "address"],
                    })

        except httpx.HTTPStatusError as e:
            errors.append(f"Whitepages Pro API error: HTTP {e.response.status_code}")
        except Exception as e:
            errors.append(f"Whitepages Pro error: {e}")

        elapsed = _time.time() - start
        return ToolResult(
            tool_name=self.name, target=target, raw_output="",
            structured_data={"findings": findings, "estimated_cost_usd": self.estimated_cost_per_query},
            errors=errors, execution_time_seconds=elapsed,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        return ToolResult(tool_name=self.name, target=target, raw_output=raw_output, structured_data={})
