"""GitHub Code Search — API-based secret-focused code search across public repos."""

from __future__ import annotations

import time as _time
from typing import List

import httpx

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

GITHUB_API_URL = "https://api.github.com/search/code"

# Secret-focused search queries — {target} is replaced with org/domain
_SEARCH_QUERIES = [
    'org:{target} filename:.env',
    'org:{target} "api_key"',
    'org:{target} "secret_key"',
    'org:{target} "aws_access_key_id"',
    'org:{target} "AWS_SECRET_ACCESS_KEY"',
    'org:{target} extension:pem "PRIVATE KEY"',
    'org:{target} "password" filename:config',
    '"{domain}" "api_key" NOT org:{target}',
    '"{domain}" "secret" filename:.env NOT org:{target}',
]


@register_tool
class GithubCodeSearch(BaseTool):
    name = "github_code_search"
    description = "GitHub Code Search API — finds secrets, credentials, and sensitive files in public repos"
    binary_name = "github_code_search"
    install_cmd = "pip install httpx  # API-based, no binary needed"
    accepted_target_types = (TargetType.DOMAIN, TargetType.ORG_NAME, TargetType.GITHUB_HANDLE)
    requires_api_keys = ("github_dorks.github_token",)

    def is_installed(self) -> bool:
        try:
            import httpx  # noqa: F401
            return True
        except ImportError:
            return False

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["github_code_search", "--target", target]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        start = _time.time()
        token = self.config.get_api_key("github_dorks", "github_token")
        if not token:
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={"findings": []},
                errors=["GitHub token not configured. Set github_dorks.github_token in api_keys.yaml"],
            )

        delay = kwargs.get("delay", 3)
        domain = kwargs.get("domain", target)
        org = kwargs.get("org", target.split(".")[0] if "." in target else target)

        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3.text-match+json",
        }

        findings = []
        errors = []
        repos_found: set[str] = set()
        raw_lines = []

        try:
            from src.http_client import OhSINTHTTPClient
            client = OhSINTHTTPClient(self.config, timeout=30)
            for query_template in _SEARCH_QUERIES:
                query = query_template.replace("{target}", org).replace("{domain}", domain)
                raw_lines.append(f"Query: {query}")

                try:
                    resp = client.get(
                        GITHUB_API_URL,
                        params={"q": query, "per_page": 30},
                        headers=headers,
                    )

                    if resp.status_code == 403:
                        errors.append(f"Rate limited on query: {query}")
                        _time.sleep(delay * 2)
                        continue

                    if resp.status_code != 200:
                        errors.append(f"HTTP {resp.status_code} for query: {query}")
                        continue

                    data = resp.json()
                    items = data.get("items", [])
                    raw_lines.append(f"  Results: {len(items)}")

                    for item in items:
                        repo_url = item.get("repository", {}).get("html_url", "")
                        file_path = item.get("path", "")
                        html_url = item.get("html_url", "")
                        repo_name = item.get("repository", {}).get("full_name", "")

                        if repo_url:
                            repos_found.add(repo_url)

                        # Determine finding type
                        lower_path = file_path.lower()
                        if lower_path.endswith((".env", ".pem", ".key", ".p12")):
                            intel_type = IntelType.SENSITIVE_FILE
                            confidence = 0.8
                        elif any(kw in query.lower() for kw in ["api_key", "secret", "password", "aws"]):
                            intel_type = IntelType.CREDENTIAL
                            confidence = 0.6
                        else:
                            intel_type = IntelType.SENSITIVE_FILE
                            confidence = 0.5

                        findings.append({
                            "type": intel_type,
                            "value": f"{repo_name}/{file_path}",
                            "source_tool": self.name,
                            "confidence": confidence,
                            "tags": ["github", "code-search", query_template.split()[0]],
                            "raw_data": {
                                "repo_url": repo_url,
                                "file_path": file_path,
                                "html_url": html_url,
                                "query": query,
                            },
                        })

                except httpx.HTTPStatusError:
                    errors.append(f"HTTP error for query: {query}")
                except Exception as e:
                    errors.append(f"Error on query '{query}': {e}")

                _time.sleep(delay)

        except Exception as e:
            errors.append(f"GitHub Code Search failed: {e}")

        elapsed = _time.time() - start
        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output="\n".join(raw_lines),
            structured_data={
                "repos_found": sorted(repos_found),
                "total_repos": len(repos_found),
                "total_findings": len(findings),
                "findings": findings,
            },
            errors=errors,
            execution_time_seconds=elapsed,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        return ToolResult(tool_name=self.name, target=target, raw_output=raw_output, structured_data={})
