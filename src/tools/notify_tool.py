"""notify — stream tool output to Slack, Discord, Telegram, and email."""

from __future__ import annotations

import subprocess
import time as _time
from typing import List

from src.models import ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class NotifyTool(BaseTool):
    name = "notify"
    description = "Alert streaming — sends findings to Slack, Discord, Telegram, or email"
    binary_name = "notify"
    install_cmd = "go install github.com/projectdiscovery/notify/cmd/notify@latest"
    accepted_target_types = ()  # Not a scanning tool — utility
    requires_api_keys = ()  # Configured via ~/.config/notify/provider-config.yaml

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name, "-silent"]
        provider = kwargs.get("provider")
        if provider:
            cmd.extend(["-provider", provider])
        return cmd

    def run(self, target: str, timeout: int = 30, **kwargs) -> ToolResult:
        """Override run() to pipe message through stdin to notify."""
        if not self.is_installed():
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"findings": []},
                errors=[f"{self.name} not installed. Install with: {self.install_cmd}"],
            )

        message = kwargs.get("message", target)
        cmd = self.build_command(target, **kwargs)
        start = _time.time()

        try:
            proc = subprocess.run(
                cmd, input=message, capture_output=True, text=True,
                timeout=timeout, shell=False,
                env=self._build_proxy_env(),
            )
            elapsed = _time.time() - start

            errors = []
            if proc.returncode != 0 and proc.stderr:
                errors.append(proc.stderr.strip()[:500])

            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output=proc.stdout,
                structured_data={
                    "message_sent": not bool(errors),
                    "findings": [],
                },
                errors=errors,
                execution_time_seconds=elapsed,
            )

        except Exception as e:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"findings": []},
                errors=[f"notify error: {e}"],
                execution_time_seconds=_time.time() - start,
            )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        return ToolResult(
            tool_name=self.name, target=target, raw_output=raw_output,
            structured_data={"findings": []},
        )
