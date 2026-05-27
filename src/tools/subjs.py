"""subjs — crawl hosts to discover JavaScript file URLs."""

from __future__ import annotations

import subprocess
import time as _time
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class Subjs(BaseTool):
    name = "subjs"
    description = "JavaScript URL discovery — crawls hosts and extracts linked JS file URLs"
    binary_name = "subjs"
    install_cmd = "go install github.com/lc/subjs@latest"
    accepted_target_types = (TargetType.DOMAIN, TargetType.URL)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name]
        ua = kwargs.get("user_agent", "Mozilla/5.0")
        cmd.extend(["-ua", ua])
        return cmd

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        """Override run() to pipe host list through stdin."""
        if not self.is_installed():
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"js_urls": [], "findings": []},
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
                    )
            else:
                # Single target via stdin
                proc = subprocess.run(
                    cmd, input=target + "\n", capture_output=True, text=True,
                    timeout=timeout, shell=False,
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
                structured_data={"js_urls": [], "findings": []},
                errors=[f"subjs timed out after {timeout}s"],
                execution_time_seconds=_time.time() - start,
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"js_urls": [], "findings": []},
                errors=[f"subjs error: {e}"],
                execution_time_seconds=_time.time() - start,
            )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        js_urls = set()
        for line in raw_output.splitlines():
            line = line.strip()
            if line and line.startswith("http"):
                js_urls.add(line)

        findings = [{
            "type": IntelType.SENSITIVE_FILE,
            "value": url,
            "source_tool": self.name,
            "confidence": 0.5,
            "tags": ["subjs", "javascript"],
        } for url in sorted(js_urls)]

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "js_urls": sorted(js_urls),
                "total_js_urls": len(js_urls),
                "findings": findings,
            },
        )
