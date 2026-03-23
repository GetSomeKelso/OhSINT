"""InSpy — LinkedIn employee enumeration (EmpSpy) and tech stack discovery (TechSpy)."""

from __future__ import annotations

import csv
import io
import json
import os
import re
import tempfile
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class InSpy(BaseTool):
    name = "inspy"
    description = "LinkedIn employee/tech stack enumeration (EmpSpy + TechSpy)"
    binary_name = "python3"
    install_cmd = (
        "git clone https://github.com/jobroche/InSpy.git ~/Tools/osint-deps/InSpy "
        "&& pip install -r ~/Tools/osint-deps/InSpy/requirements.txt"
    )
    accepted_target_types = (TargetType.ORG_NAME, TargetType.DOMAIN)
    requires_api_keys = ("hunter_io.api_key",)

    # Default paths — override via config if installed elsewhere
    _inspy_script = os.path.expanduser("~/Tools/osint-deps/InSpy/InSpy.py")
    _title_wordlist = os.path.expanduser("~/Tools/osint-deps/InSpy/wordlists/title-list-large.txt")
    _tech_wordlist = os.path.expanduser("~/Tools/osint-deps/InSpy/wordlists/tech-list-large.txt")

    def is_installed(self) -> bool:
        return os.path.isfile(self._inspy_script)

    def build_command(self, target: str, **kwargs) -> List[str]:
        mode = kwargs.get("mode", "empspy")
        domain = kwargs.get("domain", "")
        email_format = kwargs.get("email_format", "")

        # Output to JSON for easiest parsing
        self._output_file = os.path.join(tempfile.gettempdir(), f"inspy_{mode}_out.json")

        cmd = ["python3", self._inspy_script, target]

        if mode in ("empspy", "both"):
            cmd.extend(["--empspy", "--titles", self._title_wordlist])
            if domain and email_format:
                cmd.extend(["--domain", domain, "--email", email_format])
            elif domain:
                cmd.extend(["--domain", domain])

        if mode == "techspy":
            cmd = ["python3", self._inspy_script, target,
                   "--techspy", "--terms", self._tech_wordlist]

        cmd.extend(["--json", self._output_file])
        return cmd

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        """Run InSpy — handles 'both' mode by running empspy then techspy."""
        mode = kwargs.get("mode", "empspy")

        if mode == "both":
            # Run empspy first
            emp_kwargs = {**kwargs, "mode": "empspy"}
            emp_result = super().run(target, timeout=timeout, **emp_kwargs)

            # Then run techspy
            tech_kwargs = {**kwargs, "mode": "techspy"}
            tech_result = super().run(target, timeout=timeout, **tech_kwargs)

            # Merge results
            merged_findings = (
                emp_result.structured_data.get("findings", [])
                + tech_result.structured_data.get("findings", [])
            )
            merged_data = {
                "people": emp_result.structured_data.get("people", []),
                "emails": emp_result.structured_data.get("emails", []),
                "technologies": tech_result.structured_data.get("technologies", []),
                "findings": merged_findings,
            }
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output=emp_result.raw_output + "\n---\n" + tech_result.raw_output,
                structured_data=merged_data,
                errors=emp_result.errors + tech_result.errors,
                execution_time_seconds=emp_result.execution_time_seconds + tech_result.execution_time_seconds,
            )
        else:
            return super().run(target, timeout=timeout, **kwargs)

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        people = set()
        emails = set()
        technologies = set()
        findings = []

        # Try to parse JSON output file
        output_file = getattr(self, "_output_file", "")
        if output_file and os.path.exists(output_file):
            try:
                with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, dict):
                            name = entry.get("name", "").strip()
                            title = entry.get("title", "").strip()
                            email = entry.get("email", "").strip()
                            if name:
                                people.add(name)
                            if email:
                                emails.add(email.lower())
                elif isinstance(data, dict):
                    for name, info in data.items():
                        people.add(name.strip())
                        if isinstance(info, dict) and info.get("email"):
                            emails.add(info["email"].lower())
            except (json.JSONDecodeError, KeyError):
                pass

        # Fallback: parse stdout for employee names and tech stack
        for line in raw_output.splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            # Email extraction
            email_match = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', line)
            if email_match:
                emails.add(email_match.group(0).lower())
            # Technology mentions (TechSpy outputs matched tech terms)
            if any(kw in line.lower() for kw in ("technology", "tech", "stack", "software")):
                technologies.add(line)

        for person in sorted(people):
            findings.append({
                "type": IntelType.PERSON,
                "value": person,
                "source_tool": self.name,
                "confidence": 0.7,
                "tags": ["linkedin", "inspy"],
            })
        for email in sorted(emails):
            findings.append({
                "type": IntelType.EMAIL,
                "value": email,
                "source_tool": self.name,
                "confidence": 0.6,
                "tags": ["linkedin", "inspy"],
            })
        for tech in sorted(technologies):
            findings.append({
                "type": IntelType.TECHNOLOGY,
                "value": tech,
                "source_tool": self.name,
                "confidence": 0.5,
                "tags": ["techspy", "job_listing"],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "people": sorted(people),
                "emails": sorted(emails),
                "technologies": sorted(technologies),
                "findings": findings,
            },
        )
