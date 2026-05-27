"""Docker Hub Search — discover public Docker images for an organization."""

from __future__ import annotations

import time as _time
from typing import List

import httpx

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

DOCKER_HUB_API = "https://hub.docker.com/v2"


@register_tool
class DockerHubSearch(BaseTool):
    name = "docker_hub_search"
    description = "Docker Hub public image discovery — finds org's published container images"
    binary_name = "docker_hub_search"
    install_cmd = "pip install httpx  # API-based, no binary needed"
    accepted_target_types = (TargetType.ORG_NAME, TargetType.DOMAIN)
    requires_api_keys = ()

    def is_installed(self) -> bool:
        try:
            import httpx  # noqa: F401
            return True
        except ImportError:
            return False

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["docker_hub_search", "--org", target]

    def run(self, target: str, timeout: int = 60, **kwargs) -> ToolResult:
        start = _time.time()
        org = target.split(".")[0] if "." in target else target
        max_images = kwargs.get("max_images", 20)
        findings = []
        images = []
        errors = []

        try:
            from src.http_client import OhSINTHTTPClient
            client = OhSINTHTTPClient(self.config, timeout=30)
            # Search for org's repositories
            resp = client.get(
                f"{DOCKER_HUB_API}/search/repositories",
                params={"query": org, "page_size": min(max_images, 100)},
            )
            if resp.status_code != 200:
                errors.append(f"Docker Hub API returned {resp.status_code}")
            else:
                data = resp.json()
                for result in data.get("results", []):
                    repo_name = result.get("repo_name", "")
                    description = result.get("short_description", "")
                    star_count = result.get("star_count", 0)
                    pull_count = result.get("pull_count", 0)
                    is_official = result.get("is_official", False)

                    images.append({
                        "repo_name": repo_name,
                        "description": description[:200],
                        "star_count": star_count,
                        "pull_count": pull_count,
                        "is_official": is_official,
                    })

                    findings.append({
                        "type": IntelType.TECHNOLOGY,
                        "value": f"Docker: {repo_name}",
                        "source_tool": self.name,
                        "confidence": 0.7,
                        "tags": ["docker-hub", "container-image"],
                        "raw_data": {
                            "repo_name": repo_name,
                            "pull_count": pull_count,
                        },
                    })

        except Exception as e:
            errors.append(f"Docker Hub search failed: {e}")

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=f"Found {len(images)} Docker Hub images for {org}",
            structured_data={
                "images": images[:max_images],
                "total_images": len(images),
                "findings": findings,
            },
            errors=errors,
            execution_time_seconds=_time.time() - start,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        return ToolResult(tool_name=self.name, target=target, raw_output=raw_output, structured_data={})
