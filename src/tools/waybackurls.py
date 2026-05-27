"""waybackurls — fetch all URLs known to Wayback Machine for a domain."""

from __future__ import annotations

from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool
from src.tools._url_classify import classify_url, extract_subdomain, is_js_url


@register_tool
class Waybackurls(BaseTool):
    name = "waybackurls"
    description = "Fetch all URLs from the Wayback Machine for a domain"
    binary_name = "waybackurls"
    install_cmd = "go install github.com/tomnomnom/waybackurls@latest"
    accepted_target_types = (TargetType.DOMAIN,)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name]

        # Include subdomains by default
        if kwargs.get("no_subs", False):
            cmd.append("-no-subs")

        # waybackurls takes domain via stdin or as arg depending on version
        cmd.append(target)

        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        urls = set()
        subdomains = set()
        js_urls = set()
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
                "tags": ["waybackurls", "archived", "subdomain"],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "urls": sorted(urls),
                "total_urls": len(urls),
                "subdomains": sorted(subdomains),
                "js_urls": sorted(js_urls),
                "findings": findings,
            },
        )
