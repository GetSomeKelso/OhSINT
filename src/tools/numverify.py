"""NumVerify — phone number validation and carrier lookup via API."""

from __future__ import annotations

import re
from typing import List

import httpx

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

NUMVERIFY_API_URL = "http://apilayer.net/api/validate"


@register_tool
class NumVerifyTool(BaseTool):
    name = "numverify"
    description = "Phone number validation — carrier, line type, location, country (NumVerify API)"
    binary_name = "numverify"
    install_cmd = "pip install httpx  # API-based. Set numverify.api_key in api_keys.yaml"
    accepted_target_types = (TargetType.PHONE,)
    requires_api_keys = ("numverify.api_key",)

    def is_installed(self) -> bool:
        try:
            import httpx  # noqa: F401
            return True
        except ImportError:
            return False

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["numverify", "--number", target]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        import time as _time

        api_key = self.config.get_api_key("numverify", "api_key")
        if not api_key:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={}, execution_time_seconds=0.0,
                errors=["NumVerify API key not configured. Set numverify.api_key in api_keys.yaml"],
            )

        # Normalize phone number — strip spaces, dashes, parens
        phone = re.sub(r'[\s()-]', '', target)

        start = _time.time()
        findings = []
        errors = []

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(NUMVERIFY_API_URL, params={
                    "access_key": api_key,
                    "number": phone,
                    "format": "1",
                })
                resp.raise_for_status()
                data = resp.json()

            if not data.get("valid", False):
                errors.append(f"Phone number {phone} is not valid according to NumVerify")
            else:
                carrier = data.get("carrier", "unknown")
                line_type = data.get("line_type", "unknown")
                country = data.get("country_name", "unknown")
                location = data.get("location", "")

                findings.append({
                    "type": IntelType.PHONE_INFO,
                    "value": f"{phone}: {carrier} ({line_type}) — {country}",
                    "source_tool": self.name,
                    "confidence": 0.9,
                    "tags": ["numverify", "carrier", line_type],
                    "raw_data": {
                        "valid": data.get("valid"),
                        "number": data.get("number"),
                        "local_format": data.get("local_format"),
                        "international_format": data.get("international_format"),
                        "country_prefix": data.get("country_prefix"),
                        "country_code": data.get("country_code"),
                        "country_name": country,
                        "location": location,
                        "carrier": carrier,
                        "line_type": line_type,
                    },
                })

        except httpx.HTTPStatusError as e:
            errors.append(f"NumVerify API error: HTTP {e.response.status_code}")
        except Exception as e:
            errors.append(f"NumVerify error: {e}")

        elapsed = _time.time() - start
        return ToolResult(
            tool_name=self.name, target=target,
            raw_output=str(data) if 'data' in dir() else "",
            structured_data={"findings": findings},
            errors=errors, execution_time_seconds=elapsed,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        return ToolResult(tool_name=self.name, target=target, raw_output=raw_output, structured_data={})
