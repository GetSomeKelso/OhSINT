"""cdncheck — detect CDN, WAF, and cloud providers for given IPs/domains."""

from __future__ import annotations

import json
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class CdncheckTool(BaseTool):
    name = "cdncheck"
    description = "CDN/WAF/cloud detection — identifies Cloudflare, Akamai, AWS, Azure, etc. for IPs"
    binary_name = "cdncheck"
    install_cmd = "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
    accepted_target_types = (TargetType.DOMAIN, TargetType.IP)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name]

        input_file = kwargs.get("input_file")
        if input_file:
            cmd.extend(["-l", str(input_file)])
        else:
            cmd.extend(["-i", target])

        cmd.extend(["-resp", "-json", "-silent"])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        detections = []
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            host = data.get("input", data.get("host", ""))
            cdn = data.get("cdn", False)
            cdn_name = data.get("cdn_name", "")
            waf = data.get("waf", False)
            waf_name = data.get("waf_name", "")
            cloud = data.get("cloud", False)
            cloud_name = data.get("cloud_name", "")

            detection = {
                "host": host,
                "cdn": cdn,
                "cdn_name": cdn_name,
                "waf": waf,
                "waf_name": waf_name,
                "cloud": cloud,
                "cloud_name": cloud_name,
            }
            detections.append(detection)

            tags = ["cdncheck"]
            techs = []
            if cdn and cdn_name:
                techs.append(f"CDN: {cdn_name}")
                tags.append(cdn_name.lower())
            if waf and waf_name:
                techs.append(f"WAF: {waf_name}")
                tags.append(waf_name.lower())
            if cloud and cloud_name:
                techs.append(f"Cloud: {cloud_name}")
                tags.append(cloud_name.lower())

            if techs:
                findings.append({
                    "type": IntelType.TECHNOLOGY,
                    "value": f"{host}: {', '.join(techs)}",
                    "source_tool": self.name,
                    "confidence": 0.9,
                    "tags": tags,
                    "raw_data": detection,
                })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "detections": detections,
                "total_detections": len(detections),
                "findings": findings,
            },
        )
