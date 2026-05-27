"""LinkFinder — extract endpoints and paths from JavaScript files."""

from __future__ import annotations

import re
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class LinkFinderTool(BaseTool):
    name = "linkfinder"
    description = "JavaScript endpoint extractor — discovers API paths and URLs in JS files"
    binary_name = "linkfinder"
    install_cmd = "pip install linkfinder"
    accepted_target_types = (TargetType.URL,)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        input_file = kwargs.get("input_file", target)
        return [self.binary_name, "-i", input_file, "-o", "cli"]

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        endpoints = set()
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Filter noise: skip very short paths, numeric-only, single chars
            if len(line) < 3:
                continue
            if re.match(r'^/?\d+$', line):
                continue
            if re.match(r'^[a-zA-Z]$', line):
                continue
            # Skip common false positives
            if line in ("/", "#", ".", ".."):
                continue

            endpoints.add(line)

            # Higher confidence for absolute paths
            confidence = 0.7 if line.startswith("/") or line.startswith("http") else 0.4

            findings.append({
                "type": IntelType.JS_ENDPOINT,
                "value": line,
                "source_tool": self.name,
                "confidence": confidence,
                "tags": ["linkfinder", "js-endpoint"],
                "raw_data": {
                    "js_source": target,
                    "endpoint": line,
                },
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "endpoints": sorted(endpoints),
                "total_endpoints": len(endpoints),
                "findings": findings,
            },
        )
