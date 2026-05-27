"""gau — fetch known URLs from Wayback Machine, Common Crawl, OTX, and URLScan."""

from __future__ import annotations

from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool
from src.tools._url_classify import classify_url, extract_subdomain, is_js_url


@register_tool
class Gau(BaseTool):
    name = "gau"
    description = "Fetch known URLs from Wayback Machine, Common Crawl, AlienVault OTX, and URLScan"
    binary_name = "gau"
    install_cmd = "go install github.com/lc/gau/v2/cmd/gau@latest"
    accepted_target_types = (TargetType.DOMAIN,)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name]

        if kwargs.get("subs", True):
            cmd.append("--subs")

        threads = kwargs.get("threads", 5)
        cmd.extend(["--threads", str(threads)])

        providers = kwargs.get("providers")
        if providers:
            cmd.extend(["--providers", providers])

        blacklist = kwargs.get("blacklist")
        if blacklist:
            cmd.extend(["--blacklist", blacklist])

        # gau takes domain as positional argument
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

        # Add subdomain findings
        for sub in sorted(subdomains):
            findings.append({
                "type": IntelType.SUBDOMAIN,
                "value": sub,
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["gau", "archived", "subdomain"],
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
