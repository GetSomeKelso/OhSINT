"""Hudson Rock — infostealer credential lookup via free OSINT API."""

from __future__ import annotations

import re
from typing import List

import httpx

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

HUDSON_ROCK_API = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"


@register_tool
class HudsonRockTool(BaseTool):
    name = "hudson_rock"
    description = "Infostealer credential lookup — Raccoon, Redline, Vidar compromised machine data (Hudson Rock)"
    binary_name = "hudson_rock"
    install_cmd = "pip install httpx  # API-based, free basic tier. Optional: set hudson_rock.api_key for Pro"
    accepted_target_types = (TargetType.PHONE, TargetType.EMAIL, TargetType.DOMAIN)
    requires_api_keys = ()  # free basic tier works without key

    def is_installed(self) -> bool:
        try:
            import httpx  # noqa: F401
            return True
        except ImportError:
            return False

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["hudson_rock", "--target", target]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        import time as _time

        start = _time.time()
        findings = []
        errors = []
        raw_parts = []

        # Detect target type for endpoint selection
        is_email = bool(re.match(r'^[\w.+-]+@[\w-]+\.[\w.-]+$', target))
        is_domain = bool(re.match(r'^[a-z0-9][\w.-]*\.[a-z]{2,}$', target, re.IGNORECASE))

        if is_email:
            endpoint = f"{HUDSON_ROCK_API}/search-by-email"
            params = {"email": target}
        elif is_domain:
            endpoint = f"{HUDSON_ROCK_API}/search-by-domain"
            params = {"domain": target}
        else:
            # Assume phone or other identifier
            endpoint = f"{HUDSON_ROCK_API}/search-by-email"
            params = {"email": target}  # fallback

        headers = {"Accept": "application/json"}
        # Add Pro API key if configured
        api_key = self.config.get_api_key("hudson_rock", "api_key")
        if api_key:
            headers["api-key"] = api_key

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(endpoint, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()

            # Parse response — structure depends on endpoint
            stealers = data.get("stealers", [])
            if isinstance(data, list):
                stealers = data

            raw_parts.append(f"Hudson Rock: {len(stealers)} infostealer records for {target}")

            for stealer in stealers:
                computer_name = stealer.get("computer_name", "unknown")
                operating_system = stealer.get("operating_system", "")
                date_compromised = stealer.get("date_compromised", "")
                malware_path = stealer.get("malware_path", "")
                stealer_family = stealer.get("stealer", "unknown")

                findings.append({
                    "type": IntelType.INFOSTEALER,
                    "value": f"{target} — compromised machine: {computer_name} ({stealer_family})",
                    "source_tool": self.name,
                    "confidence": 0.9,
                    "tags": ["hudson-rock", "infostealer", stealer_family.lower()],
                    "raw_data": {
                        "computer_name": computer_name,
                        "operating_system": operating_system,
                        "date_compromised": date_compromised,
                        "malware_path": malware_path,
                        "stealer_family": stealer_family,
                    },
                })

                # Extract credentials if present
                top_logins = stealer.get("top_logins", [])
                for login in top_logins[:10]:
                    url = login.get("url", "")
                    username = login.get("username", "")
                    if url and username:
                        findings.append({
                            "type": IntelType.CREDENTIAL,
                            "value": f"{username} @ {url} (via {stealer_family})",
                            "source_tool": self.name,
                            "confidence": 0.85,
                            "tags": ["hudson-rock", "credential", "infostealer"],
                            "raw_data": {"url": url, "username": username, "stealer": stealer_family},
                        })

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                errors.append("Hudson Rock API access denied. Basic tier may have changed or Pro required.")
            elif e.response.status_code == 429:
                errors.append("Hudson Rock rate limit exceeded.")
            else:
                errors.append(f"Hudson Rock API error: HTTP {e.response.status_code}")
        except Exception as e:
            errors.append(f"Hudson Rock error: {e}")

        elapsed = _time.time() - start
        return ToolResult(
            tool_name=self.name, target=target,
            raw_output="\n".join(raw_parts),
            structured_data={"total_stealers": len(stealers) if 'stealers' in dir() else 0, "findings": findings},
            errors=errors, execution_time_seconds=elapsed,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        return ToolResult(tool_name=self.name, target=target, raw_output=raw_output, structured_data={})
