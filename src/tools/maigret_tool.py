"""Maigret — username search across 3,000+ sites with false-positive filtering."""

from __future__ import annotations

import csv
import io
import json
import os
import re
import tempfile
import shutil
import stat
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class MaigretTool(BaseTool):
    name = "maigret"
    description = "Username search across 3,000+ sites with profile data extraction and false-positive filtering"
    binary_name = "maigret"
    install_cmd = "pip install maigret"
    accepted_target_types = (TargetType.USERNAME, TargetType.PERSON_NAME)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        # Accept comma-separated usernames
        usernames = kwargs.get("usernames", [])
        if not usernames:
            usernames = [u.strip() for u in re.split(r'[,\s]+', target) if u.strip()]

        # Secure output directory
        output_dir = kwargs.get("output_dir")
        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="ohsint_maigret_")
            os.chmod(output_dir, stat.S_IRWXU)
        self._output_dir = output_dir
        self._owns_output_dir = "output_dir" not in kwargs
        self._usernames = usernames

        cmd = [self.binary_name]
        cmd.extend(usernames)
        cmd.extend([
            "--folderoutput", output_dir,
            "--json", "ndjson",  # ndjson = one JSON object per line, found only
            "-C",               # also generate CSV
            "--no-color",
            "--print-not-found",
        ])

        timeout = kwargs.get("timeout")
        if timeout:
            cmd.extend(["--timeout", str(timeout)])

        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        profiles = []
        usernames_found = set()
        extracted_ids = {}  # username -> {field: value}
        findings = []

        output_dir = getattr(self, "_output_dir", "")
        search_usernames = getattr(self, "_usernames", [target])

        for username in search_usernames:
            # Try ndjson first — one JSON object per line, only claimed results
            ndjson_file = os.path.join(output_dir, f"report_{username}_ndjson.json")
            if os.path.exists(ndjson_file):
                try:
                    with open(ndjson_file, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                                site_name = entry.get("sitename", "")
                                url_user = entry.get("url_user", "")
                                http_status = entry.get("http_status", 0)

                                # Extract profile IDs (names, bios, etc.)
                                status_data = entry.get("status", {})
                                ids = status_data.get("ids", {})
                                tags = status_data.get("tags", [])

                                if url_user:
                                    profiles.append({
                                        "username": username,
                                        "site": site_name,
                                        "url": url_user,
                                        "http_status": http_status,
                                        "ids": ids,
                                        "tags": tags,
                                    })
                                    usernames_found.add(username)

                                    if ids:
                                        extracted_ids.setdefault(username, {}).update(ids)
                            except (json.JSONDecodeError, ValueError):
                                continue
                except OSError:
                    pass

            # Fallback: CSV
            if not any(p["username"] == username for p in profiles):
                csv_file = os.path.join(output_dir, f"report_{username}.csv")
                if os.path.exists(csv_file):
                    try:
                        with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
                            reader = csv.DictReader(f)
                            for row in reader:
                                if row.get("exists") == "Claimed":
                                    site_name = row.get("name", "")
                                    url = row.get("url_user", "")
                                    if url:
                                        profiles.append({
                                            "username": username,
                                            "site": site_name,
                                            "url": url,
                                            "http_status": row.get("http_status", ""),
                                        })
                                        usernames_found.add(username)
                    except OSError:
                        pass

        # Fallback: parse stdout
        if not profiles:
            for line in raw_output.splitlines():
                line = line.strip()
                match = re.match(r'\[\+\]\s+(\S+):\s+(https?://\S+)', line)
                if match:
                    site_name = match.group(1)
                    url = match.group(2)
                    username = url.rstrip("/").split("/")[-1]
                    profiles.append({
                        "username": username,
                        "site": site_name,
                        "url": url,
                    })
                    usernames_found.add(username)

        # Build findings
        for profile in profiles:
            tags = ["maigret"]
            if profile.get("tags"):
                tags.extend(profile["tags"][:3])
            findings.append({
                "type": IntelType.SOCIAL_PROFILE,
                "value": f"{profile['site']}: {profile['url']}",
                "source_tool": self.name,
                "confidence": 0.9,  # Maigret has better false-positive filtering than Sherlock
                "tags": tags,
                "raw_data": profile,
            })

        for username in sorted(usernames_found):
            findings.append({
                "type": IntelType.USERNAME,
                "value": username,
                "source_tool": self.name,
                "confidence": 0.95,
                "tags": ["maigret", "confirmed"],
            })

        # Add extracted identity data as PERSON findings
        for username, ids in extracted_ids.items():
            fullname = ids.get("fullname") or ids.get("name") or ids.get("FullName")
            if fullname:
                findings.append({
                    "type": IntelType.PERSON,
                    "value": fullname,
                    "source_tool": self.name,
                    "confidence": 0.8,
                    "tags": ["maigret", "profile-data"],
                    "raw_data": {"username": username, "ids": ids},
                })

        # Cleanup temp dir
        if getattr(self, "_owns_output_dir", False):
            tmp = getattr(self, "_output_dir", None)
            if tmp and os.path.isdir(tmp):
                try:
                    shutil.rmtree(tmp)
                except OSError:
                    pass

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "profiles": profiles,
                "usernames_searched": search_usernames,
                "usernames_found": sorted(usernames_found),
                "total_profiles_found": len(profiles),
                "extracted_ids": extracted_ids,
                "findings": findings,
            },
        )
