"""Postman Workspace Search — discover public Postman workspaces for an organization."""

from __future__ import annotations

import time as _time
from typing import List

import httpx

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

POSTMAN_API_URL = "https://api.getpostman.com"


@register_tool
class PostmanWorkspaceSearch(BaseTool):
    name = "postman_workspace_search"
    description = "Postman public workspace discovery — finds org's published API workspaces"
    binary_name = "postman_workspace_search"
    install_cmd = "pip install httpx  # API-based, no binary needed"
    accepted_target_types = (TargetType.ORG_NAME, TargetType.DOMAIN)
    requires_api_keys = ("postman.api_key",)

    def is_installed(self) -> bool:
        try:
            import httpx  # noqa: F401
            return True
        except ImportError:
            return False

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["postman_workspace_search", "--org", target]

    def run(self, target: str, timeout: int = 60, **kwargs) -> ToolResult:
        start = _time.time()
        api_key = self.config.get_api_key("postman", "api_key")
        if not api_key:
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={"workspaces": [], "findings": []},
                errors=["Postman API key not configured — skipping workspace search"],
                execution_time_seconds=0.0,
            )

        org = target.split(".")[0] if "." in target else target
        workspaces = []
        findings = []
        errors = []

        try:
            headers = {"X-Api-Key": api_key}
            from src.http_client import OhSINTHTTPClient
            with OhSINTHTTPClient(self.config, timeout=30) as client:
                resp = client.get(
                    f"{POSTMAN_API_URL}/workspaces",
                    params={"type": "public"},
                    headers=headers,
                )
                if resp.status_code != 200:
                    errors.append(f"Postman API returned {resp.status_code}")
                else:
                    data = resp.json()
                    for ws in data.get("workspaces", []):
                        ws_name = ws.get("name", "")
                        ws_id = ws.get("id", "")
                        # Filter to workspaces matching the org name
                        if org.lower() in ws_name.lower():
                            workspaces.append({
                                "id": ws_id,
                                "name": ws_name,
                                "type": ws.get("type", "public"),
                            })
                            findings.append({
                                "type": IntelType.TECHNOLOGY,
                                "value": f"Postman Workspace: {ws_name}",
                                "source_tool": self.name,
                                "confidence": 0.6,
                                "tags": ["postman", "workspace", "public"],
                                "raw_data": {
                                    "workspace_id": ws_id,
                                    "workspace_name": ws_name,
                                },
                            })

        except Exception as e:
            errors.append(f"Postman workspace search failed: {e}")

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=f"Found {len(workspaces)} Postman workspaces for {org}",
            structured_data={
                "workspaces": workspaces,
                "total_workspaces": len(workspaces),
                "findings": findings,
            },
            errors=errors,
            execution_time_seconds=_time.time() - start,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        return ToolResult(tool_name=self.name, target=target, raw_output=raw_output, structured_data={})
