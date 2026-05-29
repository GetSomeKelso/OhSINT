"""TruffleHog Postman mode — scan public Postman workspaces for leaked secrets."""

from __future__ import annotations

import os
import subprocess
import time as _time
from typing import List

from src.models import ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool
from src.tools.trufflehog_github import _parse_trufflehog_json


@register_tool
class TrufflehogPostman(BaseTool):
    name = "trufflehog_postman"
    description = "TruffleHog Postman scanner — finds verified leaked secrets in public workspaces"
    binary_name = "trufflehog"
    install_cmd = "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin"
    accepted_target_types = (TargetType.ORG_NAME,)
    requires_api_keys = ("postman.api_key",)

    def build_command(self, target: str, **kwargs) -> List[str]:
        workspace = kwargs.get("workspace", target)
        return [
            self.binary_name, "postman",
            "--workspace", workspace,
            "--json",
            "--only-verified",
            "--no-update",
        ]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        """Override to inject POSTMAN_TOKEN env var."""
        postman_key = self.config.get_api_key("postman", "api_key")
        if not postman_key:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"findings": []},
                errors=["Postman API key not configured — skipping Postman scan"],
            )

        if not self.is_installed():
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"findings": []},
                errors=[f"{self.name} not installed. Install with: {self.install_cmd}"],
            )

        cmd = self.build_command(target, **kwargs)
        env = self._build_proxy_env() or os.environ.copy()
        env["POSTMAN_TOKEN"] = postman_key

        start = _time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, shell=False, env=env,
            )
            elapsed = _time.time() - start
            result = self.parse_output(proc.stdout, target)
            result.execution_time_seconds = elapsed
            if proc.returncode != 0 and proc.stderr:
                result.errors.append(proc.stderr.strip()[:500])
            return result
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"findings": []},
                errors=[f"TruffleHog Postman timed out after {timeout}s"],
                execution_time_seconds=_time.time() - start,
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"findings": []},
                errors=[f"TruffleHog Postman error: {e}"],
                execution_time_seconds=_time.time() - start,
            )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = _parse_trufflehog_json(raw_output, self.name, "postman")
        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "total_secrets": len(findings),
                "findings": findings,
            },
        )
