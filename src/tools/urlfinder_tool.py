"""urlfinder — passive URL gathering from web pages."""

from __future__ import annotations

from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool
from src.tools._url_classify import classify_url, extract_subdomain, is_js_url


@register_tool
class UrlfinderTool(BaseTool):
    name = "urlfinder"
    description = "Passive URL discovery — gathers URLs from web pages without active crawling"
    binary_name = "urlfinder"
    install_cmd = "go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
    accepted_target_types = (TargetType.DOMAIN,)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name, "-d", target, "-silent"]
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        urls = set()
        js_urls = set()
        subdomains = set()
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line or not line.startswith("http"):
                continue

            urls.add(line)

            sub = extract_subdomain(line, target)
            if sub:
                subdomains.add(sub)

            if is_js_url(line):
                js_urls.add(line)

            finding = classify_url(line, source_tool=self.name)
            if finding:
                findings.append(finding)

        for sub in sorted(subdomains):
            findings.append({
                "type": IntelType.SUBDOMAIN,
                "value": sub,
                "source_tool": self.name,
                "confidence": 0.75,
                "tags": ["urlfinder", "subdomain"],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "urls": sorted(urls),
                "js_urls": sorted(js_urls),
                "total_urls": len(urls),
                "subdomains": sorted(subdomains),
                "findings": findings,
            },
        )
