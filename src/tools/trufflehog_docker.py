"""TruffleHog Docker mode — scan public Docker Hub images for leaked secrets."""

from __future__ import annotations

from typing import List

from src.models import ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool
from src.tools.trufflehog_github import _parse_trufflehog_json


@register_tool
class TrufflehogDocker(BaseTool):
    name = "trufflehog_docker"
    description = "TruffleHog Docker scanner — finds verified leaked secrets in public Docker images"
    binary_name = "trufflehog"
    install_cmd = "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin"
    accepted_target_types = (TargetType.DOMAIN, TargetType.ORG_NAME)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        image = kwargs.get("image", target)
        return [
            self.binary_name, "docker",
            "--image", image,
            "--json",
            "--only-verified",
            "--no-update",
        ]

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = _parse_trufflehog_json(raw_output, self.name, "docker_hub")
        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "total_secrets": len(findings),
                "findings": findings,
            },
        )
