"""Twilio Lookup — carrier, CNAM, line type intelligence via Twilio API v2."""

from __future__ import annotations

import base64
import re
from typing import List

import httpx

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

TWILIO_LOOKUP_URL = "https://lookups.twilio.com/v2/PhoneNumbers"


@register_tool
class TwilioLookupTool(BaseTool):
    name = "twilio_lookup"
    description = "Phone carrier, CNAM (caller ID name), line type intelligence (Twilio Lookup API, ~$0.005/call)"
    binary_name = "twilio_lookup"
    install_cmd = "pip install httpx  # API-based. Set twilio.account_sid and twilio.auth_token in api_keys.yaml"
    accepted_target_types = (TargetType.PHONE,)
    requires_api_keys = ("twilio.account_sid", "twilio.auth_token")
    estimated_cost_per_query = 0.005

    def is_installed(self) -> bool:
        try:
            import httpx  # noqa: F401
            return True
        except ImportError:
            return False

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["twilio_lookup", "--number", target]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        import time as _time

        account_sid = self.config.get_api_key("twilio", "account_sid")
        auth_token = self.config.get_api_key("twilio", "auth_token")
        if not account_sid or not auth_token:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={}, execution_time_seconds=0.0,
                errors=["Twilio credentials not configured. Set twilio.account_sid and twilio.auth_token in api_keys.yaml"],
            )

        phone = re.sub(r'[\s()-]', '', target)
        if not phone.startswith("+"):
            phone = f"+{phone}"

        start = _time.time()
        findings = []
        errors = []
        raw_data = {}

        try:
            auth = (account_sid, auth_token)
            with httpx.Client(timeout=timeout, auth=auth) as client:
                resp = client.get(
                    f"{TWILIO_LOOKUP_URL}/{phone}",
                    params={"Fields": "caller_name,line_type_intelligence"},
                )
                resp.raise_for_status()
                data = resp.json()
                raw_data = data

            # Caller name (CNAM)
            caller_name_data = data.get("caller_name") or {}
            caller_name = caller_name_data.get("caller_name", "")
            caller_type = caller_name_data.get("caller_type", "")

            # Line type intelligence
            line_type_data = data.get("line_type_intelligence") or {}
            line_type = line_type_data.get("type", "unknown")
            carrier = line_type_data.get("carrier_name", "unknown")
            mobile_country_code = line_type_data.get("mobile_country_code", "")
            mobile_network_code = line_type_data.get("mobile_network_code", "")

            phone_info = {
                "phone": phone,
                "carrier": carrier,
                "line_type": line_type,
                "caller_name": caller_name,
                "caller_type": caller_type,
                "country_code": data.get("country_code", ""),
                "national_format": data.get("national_format", ""),
            }

            findings.append({
                "type": IntelType.PHONE_INFO,
                "value": f"{phone}: {carrier} ({line_type})",
                "source_tool": self.name,
                "confidence": 0.95,
                "tags": ["twilio", "carrier", line_type],
                "raw_data": phone_info,
            })

            if caller_name:
                findings.append({
                    "type": IntelType.PERSON,
                    "value": caller_name,
                    "source_tool": self.name,
                    "confidence": 0.7,
                    "tags": ["twilio", "cnam", caller_type],
                    "raw_data": {"phone": phone, "caller_type": caller_type},
                })

        except httpx.HTTPStatusError as e:
            errors.append(f"Twilio Lookup error: HTTP {e.response.status_code}")
        except Exception as e:
            errors.append(f"Twilio Lookup error: {e}")

        elapsed = _time.time() - start
        return ToolResult(
            tool_name=self.name, target=target,
            raw_output=str(raw_data),
            structured_data={"findings": findings, "estimated_cost_usd": self.estimated_cost_per_query},
            errors=errors, execution_time_seconds=elapsed,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        return ToolResult(tool_name=self.name, target=target, raw_output=raw_output, structured_data={})
