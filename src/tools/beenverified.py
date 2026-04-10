"""BeenVerified — identity resolution via business API (FCRA-gated)."""

from __future__ import annotations

from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class BeenVerifiedTool(BaseTool):
    name = "beenverified"
    description = "Identity resolution — phone/email/name lookup (BeenVerified Business API, FCRA-gated)"
    binary_name = "beenverified"
    install_cmd = "pip install httpx  # API-based. Requires BeenVerified business API subscription + FCRA permissible purpose"
    accepted_target_types = (TargetType.PHONE, TargetType.EMAIL, TargetType.PERSON_NAME)
    requires_api_keys = ("beenverified.api_key",)
    requires_fcra = True
    estimated_cost_per_query = 0.15

    def is_installed(self) -> bool:
        try:
            import httpx  # noqa: F401
            return bool(self.config.get_api_key("beenverified", "api_key"))
        except ImportError:
            return False

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["beenverified", "--target", target]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        import time as _time
        import httpx

        api_key = self.config.get_api_key("beenverified", "api_key")
        if not api_key:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"findings": []}, execution_time_seconds=0.0,
                errors=[
                    "BeenVerified Business API key not configured. "
                    "Requires business subscription at https://www.beenverified.com/business/"
                ],
            )

        start = _time.time()
        findings = []
        errors = []

        api_base = self.config.get_api_key("beenverified", "api_endpoint") or "https://api.beenverified.com/v2"
        headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(
                    f"{api_base}/search",
                    headers=headers,
                    params={"query": target},
                )
                resp.raise_for_status()
                data = resp.json()

                results = data.get("results", [])
                for person in results:
                    name = person.get("name", "")
                    if name:
                        findings.append({
                            "type": IntelType.PERSON,
                            "value": name,
                            "source_tool": self.name,
                            "confidence": 0.85,
                            "tags": ["beenverified", "identity"],
                            "raw_data": person,
                        })

        except httpx.HTTPStatusError as e:
            errors.append(f"BeenVerified API error: HTTP {e.response.status_code}")
        except Exception as e:
            errors.append(f"BeenVerified error: {e}")

        elapsed = _time.time() - start
        return ToolResult(
            tool_name=self.name, target=target, raw_output="",
            structured_data={"findings": findings, "estimated_cost_usd": self.estimated_cost_per_query},
            errors=errors, execution_time_seconds=elapsed,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        return ToolResult(tool_name=self.name, target=target, raw_output=raw_output, structured_data={})
