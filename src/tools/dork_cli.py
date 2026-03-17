"""dork-cli — command-line Google dork tool with rate limiting."""

from __future__ import annotations

import re
import time
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.tools.base import BaseTool
from src.config import DEFAULT_DORK_DELAY

# Built-in dork categories from GHDB and Google-Dorks repos
DORK_CATEGORIES = {
    "ghdb_passive": [
        'intitle:"index of"',
        'inurl:"/admin/"',
        'filetype:sql "insert into"',
        'filetype:log inurl:password',
        'intitle:"Apache Status"',
        'inurl:wp-config.bak',
        'intitle:"phpMyAdmin"',
        'filetype:env DB_PASSWORD',
        'inurl:".git" intitle:"index of"',
        'filetype:xml inurl:sitemap',
    ],
    "filetype_dorks": [
        "filetype:pdf",
        "filetype:doc",
        "filetype:docx",
        "filetype:xls",
        "filetype:xlsx",
        "filetype:ppt",
        "filetype:pptx",
        "filetype:csv",
        "filetype:txt",
        "filetype:xml",
        "filetype:conf",
        "filetype:cfg",
        "filetype:log",
        "filetype:bak",
        "filetype:sql",
    ],
    "login_dorks": [
        'inurl:login',
        'inurl:signin',
        'intitle:"login"',
        'inurl:admin',
        'inurl:portal',
        'intitle:"Sign In"',
        'inurl:auth',
    ],
    "sensitive_dorks": [
        'filetype:env "DB_PASSWORD"',
        'filetype:yml "password"',
        'filetype:json "api_key"',
        'intitle:"index of" ".env"',
        'intitle:"index of" "credentials"',
        'filetype:log "password"',
        'inurl:".git/config"',
        'filetype:bak inurl:"wp-config"',
        'inurl:"/server-status"',
        'intitle:"Dashboard" inurl:grafana',
    ],
    "directories": [
        'intitle:"index of" "parent directory"',
        'intitle:"index of" inurl:backup',
        'intitle:"index of" inurl:upload',
        'intitle:"index of" inurl:tmp',
        'intitle:"index of" inurl:private',
    ],
}


@register_tool
class DorkCli(BaseTool):
    name = "dork_cli"
    description = "Google dork queries with built-in dork library and rate limiting"
    binary_name = "dork"
    install_cmd = "pip install dork-cli"
    requires_api_keys = []

    def build_command(self, target: str, **kwargs) -> List[str]:
        query = kwargs.get("query", f"site:{target}")
        pages = kwargs.get("pages", 2)
        return ["dork", "-q", query, "-p", str(pages)]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        """Run dork queries from a category or custom list with rate limiting."""
        dork_category = kwargs.pop("dorks", kwargs.pop("dork_category", "all"))
        custom_dorks = kwargs.pop("custom_dorks", None)
        delay = kwargs.pop("delay", DEFAULT_DORK_DELAY)

        # Resolve dork list
        if custom_dorks:
            dorks = custom_dorks
        elif dork_category == "all":
            dorks = []
            for cat_dorks in DORK_CATEGORIES.values():
                dorks.extend(cat_dorks)
        elif dork_category in DORK_CATEGORIES:
            dorks = DORK_CATEGORIES[dork_category]
        else:
            dorks = [f"site:{target}"]

        all_raw = []
        all_findings = []
        errors = []
        total_time = 0.0

        for dork in dorks:
            query = f"{dork} site:{target}" if "site:" not in dork else f"{dork} {target}"
            result = super().run(target, timeout=timeout, query=query, **kwargs)
            all_raw.append(f"--- Dork: {dork} ---\n{result.raw_output}")
            all_findings.extend(result.structured_data.get("findings", []))
            errors.extend(result.errors)
            total_time += result.execution_time_seconds

            # Rate limit between queries
            time.sleep(delay)

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output="\n".join(all_raw),
            structured_data={
                "dork_category": dork_category,
                "dorks_executed": len(dorks),
                "findings": all_findings,
            },
            errors=errors,
            execution_time_seconds=total_time,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = []
        urls = set()

        for line in raw_output.splitlines():
            line = line.strip()
            if not line or line.startswith("---"):
                continue

            url_match = re.search(r'https?://[^\s<>"]+', line)
            if url_match:
                url = url_match.group(0).rstrip(".,;)")
                if url not in urls:
                    urls.add(url)
                    intel_type, tags = self._categorize_result(url, line)
                    findings.append({
                        "type": intel_type,
                        "value": url,
                        "source_tool": self.name,
                        "confidence": 0.5,
                        "tags": ["google-dork"] + tags,
                    })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={"urls": sorted(urls), "findings": findings},
        )

    @staticmethod
    def _categorize_result(url: str, context: str) -> tuple:
        lower = url.lower()
        ctx = context.lower()
        if any(ext in lower for ext in (".pdf", ".doc", ".xls", ".ppt", ".csv")):
            return IntelType.DOCUMENT, ["filetype"]
        elif any(kw in lower for kw in ("login", "signin", "admin", "auth")):
            return IntelType.SENSITIVE_FILE, ["login-page"]
        elif any(kw in lower for kw in (".env", ".git", "config", "backup", ".bak")):
            return IntelType.SENSITIVE_FILE, ["exposure"]
        elif "index of" in ctx:
            return IntelType.SENSITIVE_FILE, ["directory-listing"]
        else:
            return IntelType.SUBDOMAIN, ["dorked"]
