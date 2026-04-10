"""TransUnion SmartMove identity/background reports (~$25-45/report, FCRA-gated)."""

from __future__ import annotations

from typing import List

from src.models import ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class SmartMoveTool(BaseTool):
    name = "smartmove"
    description = "TransUnion SmartMove identity/background reports (~$25-45/report, FCRA-gated)"
    binary_name = "smartmove"
    install_cmd = "Contact vendor: https://www.mysmartmove.com"
    accepted_target_types = (TargetType.PHONE, TargetType.EMAIL, TargetType.PERSON_NAME)
    requires_api_keys = ("smartmove.api_key",)
    requires_fcra = True
    estimated_cost_per_query = 25.0

    def is_installed(self) -> bool:
        return bool(self.config.get_api_key("smartmove", "api_key"))

    def build_command(self, target: str, **kwargs) -> List[str]:
        return []

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        if not self.is_installed():
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"findings": []}, execution_time_seconds=0.0,
                errors=[
                    f"{self.name} is a placeholder for a commercial identity resolution service. "
                    f"This tool requires a contract with the vendor and FCRA permissible purpose. "
                    f"Contact: https://www.mysmartmove.com"
                ],
            )
        # If API key is configured, the user has negotiated access.
        # Implementation depends on their specific contract/endpoint.
        api_key = self.config.get_api_key("smartmove", "api_key")
        endpoint = self.config.get_api_key("smartmove", "api_endpoint") or ""
        return ToolResult(
            tool_name=self.name, target=target, raw_output="",
            structured_data={"findings": []}, execution_time_seconds=0.0,
            errors=[
                f"{self.name} API key is configured but no vendor-specific endpoint is implemented. "
                f"Set smartmove.api_endpoint in api_keys.yaml to your contract-specific URL."
            ],
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        return ToolResult(tool_name=self.name, target=target, raw_output=raw_output, structured_data={})
