"""Sherlock — cross-platform username search across 400+ social media sites."""

from __future__ import annotations

import csv
import io
import os
import re
import tempfile
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class SherlockTool(BaseTool):
    name = "sherlock"
    description = "Username search across 400+ social media sites"
    binary_name = "sherlock"
    install_cmd = "pip install sherlock-project"
    accepted_target_types = (TargetType.USERNAME, TargetType.PERSON_NAME)

    def build_command(self, target: str, **kwargs) -> List[str]:
        # target can be a single username or comma-separated list
        usernames = kwargs.get("usernames", [])
        if not usernames:
            # Split on comma or space if multiple provided
            usernames = [u.strip() for u in re.split(r'[,\s]+', target) if u.strip()]

        output_dir = kwargs.get("output_dir", tempfile.gettempdir())
        self._output_dir = output_dir
        self._usernames = usernames

        cmd = [self.binary_name]
        cmd.extend(usernames)
        cmd.extend(["--folderoutput", output_dir, "--csv", "--print-found"])

        timeout = kwargs.get("request_timeout")
        if timeout:
            cmd.extend(["--timeout", str(timeout)])

        # Include NSFW sites for comprehensive recon
        if kwargs.get("nsfw", False):
            cmd.append("--nsfw")

        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        profiles = []
        usernames_found = set()
        findings = []

        output_dir = getattr(self, "_output_dir", tempfile.gettempdir())
        search_usernames = getattr(self, "_usernames", [target])

        # Parse CSV output files — one per username
        # CSV columns: username,name,url_main,url_user,exists,http_status,response_time_s
        for username in search_usernames:
            csv_file = os.path.join(output_dir, f"{username}.csv")
            if os.path.exists(csv_file):
                try:
                    with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            status = row.get("exists", "").strip()
                            if status == "Claimed":
                                site_name = row.get("name", "").strip()
                                url = row.get("url_user", "").strip()
                                if url:
                                    profiles.append({
                                        "username": username,
                                        "site": site_name,
                                        "url": url,
                                        "http_status": row.get("http_status", ""),
                                        "response_time": row.get("response_time_s", ""),
                                    })
                                    usernames_found.add(username)
                except Exception:
                    pass

        # Fallback: parse stdout for [+] lines
        # Format: [+] SiteName: https://url/username
        if not profiles:
            for line in raw_output.splitlines():
                line = line.strip()
                match = re.match(r'\[\+\]\s+(\S+):\s+(https?://\S+)', line)
                if match:
                    site_name = match.group(1)
                    url = match.group(2)
                    # Extract username from URL
                    username = url.rstrip("/").split("/")[-1]
                    profiles.append({
                        "username": username,
                        "site": site_name,
                        "url": url,
                    })
                    usernames_found.add(username)

        # Build findings
        for profile in profiles:
            findings.append({
                "type": IntelType.SOCIAL_PROFILE,
                "value": f"{profile['site']}: {profile['url']}",
                "source_tool": self.name,
                "confidence": 0.85,
                "tags": ["sherlock", profile.get("site", "").lower()],
                "raw_data": profile,
            })

        for username in sorted(usernames_found):
            findings.append({
                "type": IntelType.USERNAME,
                "value": username,
                "source_tool": self.name,
                "confidence": 0.9,
                "tags": ["sherlock", "confirmed"],
            })

        # Extract total count from stdout
        total_match = re.search(r'Search completed with (\d+) results', raw_output)
        total_found = int(total_match.group(1)) if total_match else len(profiles)

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "profiles": profiles,
                "usernames_searched": search_usernames,
                "usernames_found": sorted(usernames_found),
                "total_profiles_found": total_found,
                "findings": findings,
            },
        )
