"""katana — next-generation web crawler with JS extraction and tech detection."""

from __future__ import annotations

import json
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool
from src.tools._url_classify import is_js_url


@register_tool
class KatanaTool(BaseTool):
    name = "katana"
    description = "Web crawler — extracts JS files, API endpoints, forms, and tech stack from pages"
    binary_name = "katana"
    install_cmd = "CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest"
    accepted_target_types = (TargetType.DOMAIN, TargetType.URL)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        url = target if target.startswith("http") else f"https://{target}"
        cmd = [self.binary_name, "-u", url]

        # JS crawling + tech detection
        if kwargs.get("js_crawl", True):
            cmd.append("-jc")
        if kwargs.get("tech_detect", True):
            cmd.append("-td")

        # Depth and rate
        depth = kwargs.get("depth", 3)
        cmd.extend(["-d", str(depth)])
        rate = kwargs.get("rate_limit", 50)
        cmd.extend(["-rl", str(rate)])

        # Scope
        scope = kwargs.get("scope", "rdn")
        cmd.extend(["-fs", scope])

        # Headless mode
        if kwargs.get("headless", False):
            cmd.append("-hl")
            cmd.append("-no-sandbox")

        # Known files (robots.txt, sitemap)
        if kwargs.get("known_files", True):
            cmd.extend(["-kf", "robotstxt,sitemapxml"])

        # Output
        cmd.extend(["-jsonl", "-silent"])

        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        urls = set()
        js_urls = set()
        endpoints = set()
        technologies = set()
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                # Plain text fallback — one URL per line
                if line.startswith("http"):
                    urls.add(line)
                    if is_js_url(line):
                        js_urls.add(line)
                continue

            endpoint = data.get("request", {}).get("endpoint", data.get("endpoint", ""))
            if not endpoint:
                endpoint = data.get("url", "")
            if endpoint:
                urls.add(endpoint)

            # JS file detection
            if is_js_url(endpoint):
                js_urls.add(endpoint)

            # Technology detection
            techs = data.get("tech", data.get("technologies", []))
            if isinstance(techs, list):
                for tech in techs:
                    if isinstance(tech, str) and tech:
                        technologies.add(tech)

            # Endpoint extraction from JS parsing
            source = data.get("source", "")
            tag = data.get("tag", "")
            if tag in ("js", "script") and endpoint:
                endpoints.add(endpoint)

        # Build findings
        for js in sorted(js_urls):
            findings.append({
                "type": IntelType.SENSITIVE_FILE,
                "value": js,
                "source_tool": self.name,
                "confidence": 0.7,
                "tags": ["katana", "javascript"],
            })

        for ep in sorted(endpoints):
            if len(ep) > 3 and not ep.isdigit():
                findings.append({
                    "type": IntelType.JS_ENDPOINT,
                    "value": ep,
                    "source_tool": self.name,
                    "confidence": 0.6,
                    "tags": ["katana", "endpoint"],
                })

        for tech in sorted(technologies):
            findings.append({
                "type": IntelType.TECHNOLOGY,
                "value": tech,
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["katana", "tech-detect"],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "urls": sorted(urls),
                "js_urls": sorted(js_urls),
                "endpoints": sorted(endpoints),
                "technologies": sorted(technologies),
                "total_urls": len(urls),
                "findings": findings,
            },
        )
