"""creepy — geolocation OSINT from social media."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

CREEPY_DIR = Path("/opt/tools/creepy")


@register_tool
class Creepy(BaseTool):
    name = "creepy"
    description = "Geolocation OSINT from social media profiles"
    binary_name = "python3"
    install_cmd = "git clone https://github.com/ilektrojohn/creepy.git /opt/tools/creepy"
    accepted_target_types = (TargetType.PERSON_NAME, TargetType.USERNAME)
    requires_api_keys = ()

    def is_installed(self) -> bool:
        return CREEPY_DIR.exists() and (CREEPY_DIR / "CreepyMain.py").exists()

    def build_command(self, target: str, **kwargs) -> List[str]:
        script = str(CREEPY_DIR / "CreepyMain.py")
        mode = kwargs.get("mode", "social")
        cmd = ["python3", script, "-t", target]
        if mode == "social":
            cmd.append("--social")
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = []
        locations = []
        social_profiles = []

        # Try JSON parsing
        try:
            data = json.loads(raw_output)
            if isinstance(data, dict):
                return self._parse_json(data, target)
        except (json.JSONDecodeError, TypeError):
            pass

        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # GPS coordinates: various formats
            # Decimal: 40.7128, -74.0060
            gps_match = re.search(
                r'(-?\d{1,3}\.\d{3,})\s*[,\s]\s*(-?\d{1,3}\.\d{3,})', stripped
            )
            if gps_match:
                lat = gps_match.group(1)
                lon = gps_match.group(2)
                locations.append({"latitude": lat, "longitude": lon, "context": stripped})
                findings.append({
                    "type": IntelType.GEOLOCATION,
                    "value": f"{lat}, {lon}",
                    "source_tool": self.name,
                    "confidence": 0.7,
                    "tags": ["creepy", "social-media"],
                })

            # Social profile URLs
            social_match = re.search(
                r'(https?://(?:twitter|x|facebook|instagram|linkedin|flickr)\.\w+/[^\s]+)',
                stripped,
            )
            if social_match:
                profile = social_match.group(1)
                social_profiles.append(profile)
                findings.append({
                    "type": IntelType.SOCIAL_PROFILE,
                    "value": profile,
                    "source_tool": self.name,
                    "confidence": 0.7,
                    "tags": ["creepy"],
                })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "locations": locations,
                "social_profiles": social_profiles,
                "findings": findings,
            },
        )

    def _parse_json(self, data: dict, target: str) -> ToolResult:
        findings = []
        locations = []

        for loc in data.get("locations", []):
            lat = loc.get("latitude", loc.get("lat", ""))
            lon = loc.get("longitude", loc.get("lon", loc.get("lng", "")))
            if lat and lon:
                locations.append({"latitude": str(lat), "longitude": str(lon)})
                findings.append({
                    "type": IntelType.GEOLOCATION,
                    "value": f"{lat}, {lon}",
                    "source_tool": self.name,
                    "confidence": 0.8,
                    "tags": ["creepy"],
                    "raw_data": loc,
                })

        for profile in data.get("profiles", []):
            url = profile.get("url", "")
            if url:
                findings.append({
                    "type": IntelType.SOCIAL_PROFILE,
                    "value": url,
                    "source_tool": self.name,
                    "confidence": 0.8,
                    "tags": ["creepy"],
                })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=json.dumps(data, indent=2),
            structured_data={
                "locations": locations,
                "findings": findings,
                **data,
            },
        )
