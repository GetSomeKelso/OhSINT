"""getJS — JavaScript URL collector, handles SPAs and dynamic loading."""

from __future__ import annotations

from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class GetJs(BaseTool):
    name = "getjs"
    description = "JavaScript URL collector — extracts JS file URLs including SPA bundles"
    binary_name = "getjs"
    install_cmd = "npm install -g getjs"
    accepted_target_types = (TargetType.DOMAIN, TargetType.URL)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        url = target if target.startswith("http") else f"https://{target}"
        cmd = [self.binary_name, "--url", url, "--complete"]
        return cmd

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
            "tags": ["getjs", "javascript"],
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
