"""alterx — smart subdomain wordlist generator using DSL patterns."""

from __future__ import annotations

import subprocess
import time as _time
from typing import List

from src.models import ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class AlterxTool(BaseTool):
    name = "alterx"
    description = "Subdomain wordlist generator — creates permutation-based subdomain lists via DSL"
    binary_name = "alterx"
    install_cmd = "go install github.com/projectdiscovery/alterx/cmd/alterx@latest"
    accepted_target_types = (TargetType.DOMAIN,)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        return [self.binary_name, "-silent"]

    def run(self, target: str, timeout: int = 120, **kwargs) -> ToolResult:
        """Override run() to pipe subdomain list through stdin."""
        if not self.is_installed():
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"wordlist": [], "findings": []},
                errors=[f"{self.name} not installed. Install with: {self.install_cmd}"],
            )

        input_file = kwargs.get("input_file")
        cmd = self.build_command(target, **kwargs)
        start = _time.time()

        try:
            if input_file:
                with open(input_file, "r", encoding="utf-8") as f:
                    proc = subprocess.run(
                        cmd, stdin=f, capture_output=True, text=True,
                        timeout=timeout, shell=False,
                        env=self._build_proxy_env(),
                    )
            else:
                proc = subprocess.run(
                    cmd, input=target + "\n", capture_output=True, text=True,
                    timeout=timeout, shell=False,
                    env=self._build_proxy_env(),
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
                structured_data={"wordlist": [], "findings": []},
                errors=[f"alterx timed out after {timeout}s"],
                execution_time_seconds=_time.time() - start,
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"wordlist": [], "findings": []},
                errors=[f"alterx error: {e}"],
                execution_time_seconds=_time.time() - start,
            )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        wordlist = set()
        for line in raw_output.splitlines():
            line = line.strip()
            if line and "." in line:
                wordlist.add(line.lower())

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "wordlist": sorted(wordlist),
                "total_permutations": len(wordlist),
                "findings": [],  # Wordlists are intermediate data, not findings
            },
        )
