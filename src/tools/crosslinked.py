"""CrossLinked — LinkedIn employee enumeration via search engine scraping."""

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
class CrossLinked(BaseTool):
    name = "crosslinked"
    description = "LinkedIn employee enumeration via search engine scraping (passive)"
    binary_name = "crosslinked"
    install_cmd = "pip install crosslinked"
    accepted_target_types = (TargetType.ORG_NAME, TargetType.DOMAIN)

    def build_command(self, target: str, **kwargs) -> List[str]:
        domain = kwargs.get("domain", "")
        email_format = kwargs.get("email_format", "{first}.{last}@" + domain if domain else "{first}.{last}")
        timeout = kwargs.get("search_timeout", 15)
        jitter = kwargs.get("jitter", 1)

        # CrossLinked writes output to files — use a temp dir
        self._output_base = kwargs.get("output_file", os.path.join(tempfile.gettempdir(), "crosslinked_out"))

        cmd = [
            self.binary_name,
            "-f", email_format,
            "-t", str(timeout),
            "-j", str(jitter),
            "-o", self._output_base,
            target,
        ]
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        people = set()
        emails = set()
        csv_records = []

        # Parse the CSV output file (names.csv format):
        # Datetime,Search,Name,Title,URL,rawText
        csv_path = getattr(self, "_output_base", "") + ".csv"
        if os.path.exists(csv_path):
            try:
                with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                    reader = csv.reader(f)
                    header = next(reader, None)
                    for row in reader:
                        if len(row) >= 5:
                            name = row[2].strip()
                            title = row[3].strip()
                            url = row[4].strip()
                            if name:
                                people.add(name)
                                csv_records.append({
                                    "name": name,
                                    "title": title,
                                    "url": url,
                                    "search_engine": row[1].strip() if len(row) > 1 else "",
                                })
            except Exception:
                pass

        # Parse the TXT output file (formatted emails, one per line)
        txt_path = getattr(self, "_output_base", "") + ".txt"
        if os.path.exists(txt_path):
            try:
                with open(txt_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line and "@" in line:
                            emails.add(line.lower())
                        elif line:
                            people.add(line)
            except Exception:
                pass

        # Also parse stdout for any names/emails printed during execution
        for line in raw_output.splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            email_match = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', line)
            if email_match:
                emails.add(email_match.group(0).lower())

        findings = []
        for person in sorted(people):
            findings.append({
                "type": IntelType.PERSON,
                "value": person,
                "source_tool": self.name,
                "confidence": 0.7,
                "tags": ["linkedin", "crosslinked"],
                "raw_data": next(
                    (r for r in csv_records if r["name"] == person), None
                ),
            })
        for email in sorted(emails):
            findings.append({
                "type": IntelType.EMAIL,
                "value": email,
                "source_tool": self.name,
                "confidence": 0.6,
                "tags": ["linkedin", "generated"],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "people": sorted(people),
                "emails": sorted(emails),
                "records": csv_records,
                "findings": findings,
            },
        )
