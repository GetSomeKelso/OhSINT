"""waymore — web archive URL extraction from Wayback Machine, Common Crawl, and more."""

from __future__ import annotations

from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool
from src.tools._url_classify import (
    classify_url,
    extract_subdomain,
    SENSITIVE_EXTENSIONS,
    DOCUMENT_EXTENSIONS,
    TECH_PATTERNS,
)


@register_tool
class Waymore(BaseTool):
    name = "waymore"
    description = "Web archive URL extraction — Wayback Machine, Common Crawl, AlienVault OTX, URLScan"
    binary_name = "waymore"
    install_cmd = "pip install waymore"
    accepted_target_types = (TargetType.DOMAIN,)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        mode = kwargs.get("mode", "U")  # U=URLs only, R=responses, B=both
        cmd = [self.binary_name, "-i", target, "-mode", mode]

        # Limit results
        limit = kwargs.get("limit")
        if limit:
            cmd.extend(["-l", str(limit)])

        # Filter by response code
        filter_codes = kwargs.get("filter_codes")
        if filter_codes:
            cmd.extend(["-fc", filter_codes])

        # Date range
        from_date = kwargs.get("from_date")
        if from_date:
            cmd.extend(["-from", from_date])
        to_date = kwargs.get("to_date")
        if to_date:
            cmd.extend(["-to", to_date])

        # Verbose for more diagnostic info
        if kwargs.get("verbose", False):
            cmd.append("-v")

        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        urls = set()
        subdomains = set()
        findings = []
        sensitive_files = []
        documents = []
        tech_indicators = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Skip diagnostic/info lines
            if line.startswith("[") or line.startswith("waymore") or "INFO" in line:
                continue
            # Must look like a URL
            if not line.startswith("http"):
                continue

            urls.add(line)

            # Extract subdomain
            sub = extract_subdomain(line, target)
            if sub:
                subdomains.add(sub)

            # Classify URL into finding categories
            finding = classify_url(line, source_tool=self.name)
            if finding:
                findings.append(finding)
                ftype = finding["type"]
                if ftype == IntelType.SENSITIVE_FILE:
                    sensitive_files.append(line)
                elif ftype == IntelType.DOCUMENT:
                    documents.append(line)
                elif ftype == IntelType.TECHNOLOGY:
                    tech_indicators.append({"url": line, "tech": finding["tags"][-1]})

        # Add subdomain findings
        for sub in sorted(subdomains):
            findings.append({
                "type": IntelType.SUBDOMAIN,
                "value": sub,
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["waymore", "archived", "subdomain"],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "total_urls": len(urls),
                "subdomains": sorted(subdomains),
                "sensitive_files": sensitive_files[:50],
                "documents": documents[:50],
                "tech_indicators": tech_indicators[:50],
                "findings": findings,
            },
        )
