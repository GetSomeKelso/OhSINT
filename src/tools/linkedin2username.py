"""linkedin2username — authenticated LinkedIn employee scraping via Selenium."""

from __future__ import annotations

import logging
import os
import re
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

logger = logging.getLogger("ohsint.tools.linkedin2username")


@register_tool
class LinkedIn2Username(BaseTool):
    is_passive = False  # authenticates to LinkedIn via Selenium
    name = "linkedin2username"
    description = "Authenticated LinkedIn employee scraping — generates username format files"
    binary_name = "python3"
    install_cmd = (
        "git clone https://github.com/initstring/linkedin2username.git "
        "~/Tools/osint-deps/linkedin2username "
        "&& pip install -r ~/Tools/osint-deps/linkedin2username/requirements.txt"
    )
    accepted_target_types = (TargetType.ORG_NAME,)
    requires_api_keys = ("linkedin.email", "linkedin.password")

    _script_path = os.path.expanduser("~/Tools/osint-deps/linkedin2username/linkedin2username.py")

    def is_installed(self) -> bool:
        return os.path.isfile(self._script_path)

    def build_command(self, target: str, **kwargs) -> List[str]:
        domain = kwargs.get("domain", "")
        depth = kwargs.get("depth", 5)
        sleep = kwargs.get("sleep", 3)
        keywords = kwargs.get("keywords", "")
        output_dir = kwargs.get("output_dir", os.path.expanduser("~/Tools/osint-deps/li2u-output"))

        self._output_dir = output_dir
        self._company = target

        cmd = [
            "python3", self._script_path,
            "-c", target,
            "-d", str(depth),
            "-s", str(sleep),
            "-o", output_dir,
        ]
        if domain:
            cmd.extend(["-n", domain])
        if keywords:
            cmd.extend(["-k", keywords])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        people = set()
        emails = set()
        usernames = set()
        findings = []

        output_dir = getattr(self, "_output_dir", "")
        company = getattr(self, "_company", target)

        # linkedin2username generates 8 files per company:
        # {company}-rawnames.txt, {company}-metadata.txt, {company}-flast.txt,
        # {company}-f.last.txt, {company}-firstl.txt, {company}-first.last.txt,
        # {company}-first.txt, {company}-lastf.txt
        username_formats = {
            "flast": "first_initial_last",
            "f.last": "first_initial_dot_last",
            "firstl": "first_last_initial",
            "first.last": "first_dot_last",
            "first": "first_only",
            "lastf": "last_first_initial",
        }

        # Parse raw names
        rawnames_file = os.path.join(output_dir, f"{company}-rawnames.txt")
        if os.path.exists(rawnames_file):
            try:
                with open(rawnames_file, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        name = line.strip()
                        if name:
                            people.add(name)
            except Exception:
                pass

        # Parse metadata (name, title CSV)
        metadata_file = os.path.join(output_dir, f"{company}-metadata.txt")
        metadata = {}
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        parts = line.strip().split(",", 1)
                        if len(parts) >= 2:
                            name = parts[0].strip()
                            title = parts[1].strip()
                            if name:
                                people.add(name)
                                metadata[name] = title
            except Exception:
                pass

        # Parse username format files
        for fmt_suffix, fmt_tag in username_formats.items():
            fmt_file = os.path.join(output_dir, f"{company}-{fmt_suffix}.txt")
            if os.path.exists(fmt_file):
                try:
                    with open(fmt_file, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            username = line.strip()
                            if username:
                                # Check if it has @ (email) or is just a username
                                if "@" in username:
                                    emails.add(username.lower())
                                else:
                                    usernames.add(username)
                except Exception:
                    pass

        # Build findings
        for person in sorted(people):
            raw_data = {"title": metadata.get(person, "")} if person in metadata else None
            findings.append({
                "type": IntelType.PERSON,
                "value": person,
                "source_tool": self.name,
                "confidence": 0.9,
                "tags": ["linkedin", "authenticated"],
                "raw_data": raw_data,
            })

        for email in sorted(emails):
            findings.append({
                "type": IntelType.EMAIL,
                "value": email,
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["linkedin", "generated"],
            })

        for username in sorted(usernames):
            findings.append({
                "type": IntelType.USERNAME,
                "value": username,
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["linkedin", "generated"],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "people": sorted(people),
                "emails": sorted(emails),
                "usernames": sorted(usernames),
                "metadata": metadata,
                "findings": findings,
            },
        )
