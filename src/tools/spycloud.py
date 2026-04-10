"""SpyCloud — enterprise botnet log and recaptured credential search (gated)."""

from __future__ import annotations

from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class SpyCloudTool(BaseTool):
    name = "spycloud"
    description = "Enterprise botnet log and recaptured credential search (SpyCloud — requires enterprise account)"
    binary_name = "spycloud"
    install_cmd = "pip install httpx  # API-based. Requires SpyCloud enterprise account and API key"
    accepted_target_types = (TargetType.PHONE, TargetType.EMAIL, TargetType.DOMAIN)
    requires_api_keys = ("spycloud.api_key",)

    def is_installed(self) -> bool:
        try:
            import httpx  # noqa: F401
            return True
        except ImportError:
            return False

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["spycloud", "--target", target]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        # Check if SpyCloud is explicitly enabled
        enabled = self.config.get_api_key("spycloud", "enabled")
        if not enabled or str(enabled).lower() not in ("true", "1", "yes"):
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"findings": []}, execution_time_seconds=0.0,
                errors=[
                    "SpyCloud requires an enterprise account with security firm verification. "
                    "Set spycloud.enabled: true and spycloud.api_key in api_keys.yaml when you have access. "
                    "Contact SpyCloud at https://spycloud.com for enterprise pricing."
                ],
            )

        import time as _time
        import httpx

        api_key = self.config.get_api_key("spycloud", "api_key")
        if not api_key:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={}, execution_time_seconds=0.0,
                errors=["SpyCloud API key not configured. Set spycloud.api_key in api_keys.yaml"],
            )

        start = _time.time()
        findings = []
        errors = []

        # SpyCloud enterprise API endpoint — varies by contract
        api_base = self.config.get_api_key("spycloud", "api_endpoint") or "https://api.spycloud.io/enterprise-v2"
        headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(
                    f"{api_base}/breach/data/emails/{target}",
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()

                results = data.get("results", [])
                for record in results:
                    source = record.get("source_id", "")
                    severity = record.get("severity", 0)
                    findings.append({
                        "type": IntelType.CREDENTIAL,
                        "value": f"{target} — SpyCloud breach record (severity: {severity})",
                        "source_tool": self.name,
                        "confidence": 0.9,
                        "tags": ["spycloud", "botnet", "recaptured"],
                        "raw_data": {"source_id": source, "severity": severity},
                    })

        except httpx.HTTPStatusError as e:
            errors.append(f"SpyCloud API error: HTTP {e.response.status_code}")
        except Exception as e:
            errors.append(f"SpyCloud error: {e}")

        elapsed = _time.time() - start
        return ToolResult(
            tool_name=self.name, target=target, raw_output="",
            structured_data={"findings": findings},
            errors=errors, execution_time_seconds=elapsed,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        return ToolResult(tool_name=self.name, target=target, raw_output=raw_output, structured_data={})
