"""Intelligence X — leaked data and dark web search via API."""

from __future__ import annotations

import time as _time
from typing import List

import httpx

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

INTELX_API_BASE = "https://2.intelx.io"


@register_tool
class IntelXTool(BaseTool):
    name = "intelx"
    description = "Leaked data and dark web search — breaches, paste sites, darknet dumps (Intelligence X API)"
    binary_name = "intelx"
    install_cmd = "pip install httpx  # API-based. Set intelx.api_key in api_keys.yaml"
    accepted_target_types = (TargetType.PHONE, TargetType.EMAIL, TargetType.DOMAIN, TargetType.IP)
    requires_api_keys = ("intelx.api_key",)

    def is_installed(self) -> bool:
        try:
            import httpx  # noqa: F401
            return True
        except ImportError:
            return False

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["intelx", "--target", target]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        api_key = self.config.get_api_key("intelx", "api_key")
        if not api_key:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={}, execution_time_seconds=0.0,
                errors=["Intelligence X API key not configured. Set intelx.api_key in api_keys.yaml"],
            )

        max_results = kwargs.get("max_results", 100)
        start = _time.time()
        findings = []
        errors = []
        raw_parts = []
        headers = {"x-key": api_key, "Content-Type": "application/json"}

        try:
            with httpx.Client(timeout=timeout) as client:
                # Step 1: Submit search
                search_resp = client.post(
                    f"{INTELX_API_BASE}/intelligent/search",
                    headers=headers,
                    json={"term": target, "maxresults": max_results, "media": 0, "timeout": 5},
                )
                search_resp.raise_for_status()
                search_data = search_resp.json()
                search_id = search_data.get("id")

                if not search_id:
                    errors.append("IntelX search failed — no search ID returned")
                else:
                    # Step 2: Poll for results (free tier may be slow)
                    _time.sleep(3)
                    result_resp = client.get(
                        f"{INTELX_API_BASE}/intelligent/search/result",
                        headers=headers,
                        params={"id": search_id},
                    )
                    result_resp.raise_for_status()
                    result_data = result_resp.json()
                    records = result_data.get("records", [])

                    raw_parts.append(f"IntelX search for {target}: {len(records)} records")

                    for record in records:
                        name = record.get("name", "")
                        source = record.get("bucket", "")
                        media = record.get("media", 0)
                        date = record.get("date", "")
                        system_id = record.get("systemid", "")

                        # Classify by media type
                        # 0=all, 1=paste, 2=darknet, 3=document, etc.
                        tags = ["intelx"]
                        if media == 1:
                            tags.append("paste")
                        elif media == 2:
                            tags.append("darknet")
                        elif media == 3:
                            tags.append("document")

                        # Determine finding type
                        name_lower = (name or "").lower()
                        if any(kw in name_lower for kw in ("breach", "dump", "leak", "combo")):
                            intel_type = IntelType.BREACH
                            confidence = 0.85
                        elif any(kw in name_lower for kw in ("password", "credential", "hash")):
                            intel_type = IntelType.CREDENTIAL
                            confidence = 0.8
                        else:
                            intel_type = IntelType.SENSITIVE_FILE
                            confidence = 0.7

                        findings.append({
                            "type": intel_type,
                            "value": f"{name or system_id} ({source})",
                            "source_tool": self.name,
                            "confidence": confidence,
                            "tags": tags,
                            "raw_data": {
                                "name": name,
                                "source": source,
                                "date": date,
                                "media": media,
                                "system_id": system_id,
                            },
                        })

                    # Check for rate limiting
                    status = result_data.get("status", 0)
                    if status == 3:  # rate limited
                        errors.append("IntelX free tier rate limit reached. Upgrade for more queries.")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                errors.append("IntelX rate limit exceeded (429). Free tier allows ~10 searches/day.")
            else:
                errors.append(f"IntelX API error: HTTP {e.response.status_code}")
        except Exception as e:
            errors.append(f"IntelX error: {e}")

        elapsed = _time.time() - start
        return ToolResult(
            tool_name=self.name, target=target,
            raw_output="\n".join(raw_parts),
            structured_data={"total_records": len(findings), "findings": findings},
            errors=errors, execution_time_seconds=elapsed,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        return ToolResult(tool_name=self.name, target=target, raw_output=raw_output, structured_data={})
