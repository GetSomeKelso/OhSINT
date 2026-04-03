"""waymore — web archive URL extraction from Wayback Machine, Common Crawl, and more."""

from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

# File extensions that indicate sensitive/interesting content
_SENSITIVE_EXTENSIONS = frozenset({
    ".env", ".bak", ".sql", ".log", ".conf", ".config", ".cfg",
    ".ini", ".yml", ".yaml", ".json", ".xml", ".key", ".pem",
    ".crt", ".p12", ".pfx", ".old", ".backup", ".dump", ".tar",
    ".gz", ".zip", ".rar",
})

_DOCUMENT_EXTENSIONS = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp", ".csv", ".rtf",
})

_TECH_PATTERNS = [
    (r'/api/', "api-endpoint"),
    (r'/v[12]/api', "api-endpoint"),
    (r'/graphql', "graphql"),
    (r'/swagger', "swagger"),
    (r'/wp-', "wordpress"),
    (r'/wp-admin', "wordpress-admin"),
    (r'/wp-content/plugins', "wordpress-plugin"),
    (r'/administrator', "admin-panel"),
    (r'/phpmyadmin', "phpmyadmin"),
    (r'\.php\?', "php"),
    (r'\.asp', "asp"),
    (r'\.jsp', "jsp"),
    (r'/cgi-bin/', "cgi"),
]


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
            try:
                parsed = urlparse(line)
                hostname = parsed.hostname
                if hostname and hostname.endswith(f".{target}"):
                    subdomains.add(hostname)
            except Exception:
                continue

            lower = line.lower()
            path = parsed.path.lower() if parsed else lower

            # Categorize URL
            categorized = False

            # Check sensitive files
            for ext in _SENSITIVE_EXTENSIONS:
                if path.endswith(ext) or ext + "?" in path:
                    sensitive_files.append(line)
                    findings.append({
                        "type": IntelType.SENSITIVE_FILE,
                        "value": line,
                        "source_tool": self.name,
                        "confidence": 0.7,
                        "tags": ["waymore", "archived", f"ext:{ext}"],
                    })
                    categorized = True
                    break

            # Check documents
            if not categorized:
                for ext in _DOCUMENT_EXTENSIONS:
                    if path.endswith(ext):
                        documents.append(line)
                        findings.append({
                            "type": IntelType.DOCUMENT,
                            "value": line,
                            "source_tool": self.name,
                            "confidence": 0.7,
                            "tags": ["waymore", "archived", "document"],
                        })
                        categorized = True
                        break

            # Check technology indicators
            if not categorized:
                for pattern, tag in _TECH_PATTERNS:
                    if re.search(pattern, lower):
                        tech_indicators.append({"url": line, "tech": tag})
                        findings.append({
                            "type": IntelType.TECHNOLOGY,
                            "value": f"{tag}: {line}",
                            "source_tool": self.name,
                            "confidence": 0.6,
                            "tags": ["waymore", "archived", tag],
                        })
                        categorized = True
                        break

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
