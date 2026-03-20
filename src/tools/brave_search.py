"""Brave Search — web search API for OSINT reconnaissance."""

from __future__ import annotations

import json
import re
import time
from typing import List, Optional

import httpx

from src.config import DEFAULT_DORK_DELAY
from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

# Brave Search API endpoint
BRAVE_API_URL = "https://api.search.brave.com/res/v1/web/search"

# Built-in OSINT dork queries to run against a domain
OSINT_QUERIES = {
    "subdomains": "site:{domain}",
    "documents": 'site:{domain} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:ppt OR filetype:docx OR filetype:xlsx',
    "login_pages": 'site:{domain} inurl:login OR inurl:signin OR inurl:admin OR inurl:auth',
    "exposed_files": 'site:{domain} filetype:env OR filetype:log OR filetype:sql OR filetype:bak OR filetype:conf',
    "directory_listings": 'site:{domain} intitle:"index of"',
    "config_exposure": 'site:{domain} inurl:.git OR inurl:wp-config OR inurl:config OR inurl:.env',
    "error_pages": 'site:{domain} intitle:"error" OR intitle:"exception" OR intitle:"traceback"',
    "api_endpoints": 'site:{domain} inurl:api OR inurl:v1 OR inurl:v2 OR inurl:graphql',
}


@register_tool
class BraveSearch(BaseTool):
    name = "brave_search"
    description = "Web search via Brave Search API — replaces Google dorking"
    binary_name = "brave_search"  # Not a binary — API-based tool
    install_cmd = "pip install httpx  # API-based, no binary needed. Set brave.api_key in api_keys.yaml"
    accepted_target_types = (TargetType.DOMAIN, TargetType.IP, TargetType.EMAIL, TargetType.PERSON_NAME)
    requires_api_keys = ("brave.api_key",)

    def is_installed(self) -> bool:
        """Brave Search is API-based — installed if httpx is available."""
        try:
            import httpx  # noqa: F401
            return True
        except ImportError:
            return False

    def build_command(self, target: str, **kwargs) -> List[str]:
        """Not used — this tool uses the API directly, not subprocess."""
        return ["brave_search", "--query", f"site:{target}"]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        """Query Brave Search API with OSINT-focused queries."""
        import time as _time

        api_key = self.config.get_api_key("brave", "api_key")
        if not api_key:
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={},
                errors=["Brave Search API key not configured. Set brave.api_key in api_keys.yaml"],
                execution_time_seconds=0.0,
            )

        # Determine which queries to run
        query_set = kwargs.get("queries", "all")
        custom_queries = kwargs.get("custom_queries", None)
        delay = kwargs.get("delay", DEFAULT_DORK_DELAY)
        count = kwargs.get("count", 20)  # results per query

        if custom_queries:
            queries = {f"custom_{i}": q for i, q in enumerate(custom_queries)}
        elif query_set == "all":
            queries = dict(OSINT_QUERIES)
        elif query_set in OSINT_QUERIES:
            queries = {query_set: OSINT_QUERIES[query_set]}
        else:
            queries = {"search": f"site:{target}"}

        all_findings = []
        all_raw = []
        errors = []
        start = _time.time()

        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "X-Subscription-Token": api_key,
        }

        with httpx.Client(timeout=timeout) as client:
            for category, query_template in queries.items():
                query = query_template.format(domain=target)
                try:
                    response = client.get(
                        BRAVE_API_URL,
                        headers=headers,
                        params={"q": query, "count": count},
                    )
                    response.raise_for_status()
                    data = response.json()

                    results = data.get("web", {}).get("results", [])
                    all_raw.append(f"--- Query: {query} ({len(results)} results) ---")

                    for result in results:
                        url = result.get("url", "")
                        title = result.get("title", "")
                        description = result.get("description", "")
                        finding = self._categorize_result(
                            url, title, description, category, target
                        )
                        if finding:
                            all_findings.append(finding)
                            all_raw.append(f"  {url} — {title}")

                except httpx.HTTPStatusError as e:
                    errors.append(f"Brave API error for '{query}': {e.response.status_code}")
                except Exception as e:
                    errors.append(f"Error querying '{query}': {e}")

                # Rate limit between queries
                _time.sleep(delay)

        elapsed = _time.time() - start

        # Deduplicate findings by URL
        seen_urls = set()
        unique_findings = []
        for f in all_findings:
            if f["value"] not in seen_urls:
                seen_urls.add(f["value"])
                unique_findings.append(f)

        # Extract subdomains from all URLs
        subdomains = set()
        for f in unique_findings:
            sub_match = re.search(
                r'https?://([\w.-]+\.' + re.escape(target) + r')', f["value"]
            )
            if sub_match:
                subdomains.add(sub_match.group(1).lower())

        # Add subdomain findings
        for sub in sorted(subdomains):
            if not any(f["value"] == sub and f["type"] == IntelType.SUBDOMAIN for f in unique_findings):
                unique_findings.append({
                    "type": IntelType.SUBDOMAIN,
                    "value": sub,
                    "source_tool": self.name,
                    "confidence": 0.7,
                    "tags": ["brave-search", "subdomain-enum"],
                })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output="\n".join(all_raw),
            structured_data={
                "queries_executed": len(queries),
                "total_results": len(unique_findings),
                "subdomains": sorted(subdomains),
                "findings": unique_findings,
            },
            errors=errors,
            execution_time_seconds=elapsed,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        """Not used — run() handles everything directly."""
        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={},
        )

    def _categorize_result(
        self, url: str, title: str, description: str, category: str, target: str
    ) -> Optional[dict]:
        """Categorize a search result into an IntelFinding."""
        if not url:
            return None

        lower_url = url.lower()
        lower_title = title.lower()
        context = f"{lower_url} {lower_title} {description.lower()}"

        # Determine intel type based on query category and content
        if category == "documents":
            return {
                "type": IntelType.DOCUMENT,
                "value": url,
                "source_tool": self.name,
                "confidence": 0.7,
                "tags": ["brave-search", "document"],
                "raw_data": {"title": title, "description": description},
            }
        elif category == "login_pages":
            return {
                "type": IntelType.SENSITIVE_FILE,
                "value": url,
                "source_tool": self.name,
                "confidence": 0.6,
                "tags": ["brave-search", "login-page"],
                "raw_data": {"title": title, "description": description},
            }
        elif category in ("exposed_files", "config_exposure"):
            return {
                "type": IntelType.SENSITIVE_FILE,
                "value": url,
                "source_tool": self.name,
                "confidence": 0.7,
                "tags": ["brave-search", "exposure"],
                "raw_data": {"title": title, "description": description},
            }
        elif category == "directory_listings":
            return {
                "type": IntelType.SENSITIVE_FILE,
                "value": url,
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["brave-search", "directory-listing"],
                "raw_data": {"title": title, "description": description},
            }
        elif category == "error_pages":
            return {
                "type": IntelType.TECHNOLOGY,
                "value": url,
                "source_tool": self.name,
                "confidence": 0.5,
                "tags": ["brave-search", "error-page", "info-disclosure"],
                "raw_data": {"title": title, "description": description},
            }
        elif category == "api_endpoints":
            return {
                "type": IntelType.TECHNOLOGY,
                "value": url,
                "source_tool": self.name,
                "confidence": 0.6,
                "tags": ["brave-search", "api-endpoint"],
                "raw_data": {"title": title, "description": description},
            }
        else:
            # Default: subdomains / general
            intel_type = IntelType.SUBDOMAIN
            tags = ["brave-search"]
            if any(ext in lower_url for ext in (".pdf", ".doc", ".xls", ".csv")):
                intel_type = IntelType.DOCUMENT
                tags.append("document")
            elif any(kw in lower_url for kw in (".env", ".git", "config", "backup")):
                intel_type = IntelType.SENSITIVE_FILE
                tags.append("exposure")

            return {
                "type": intel_type,
                "value": url,
                "source_tool": self.name,
                "confidence": 0.5,
                "tags": tags,
                "raw_data": {"title": title, "description": description},
            }
