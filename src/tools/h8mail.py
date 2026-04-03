"""h8mail — email breach hunting and credential exposure lookup."""

from __future__ import annotations

import json
import os
import tempfile
import stat
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class H8mail(BaseTool):
    name = "h8mail"
    description = "Email breach hunting — checks HIBP, Snusbase, LeakLookup, Dehashed, IntelX"
    binary_name = "h8mail"
    install_cmd = "pip install h8mail"
    accepted_target_types = (TargetType.EMAIL, TargetType.DOMAIN)
    requires_api_keys = ()  # works without keys but better with them

    def build_command(self, target: str, **kwargs) -> List[str]:
        # Create a secure temp file for JSON output
        output_dir = tempfile.mkdtemp(prefix="ohsint_h8mail_")
        os.chmod(output_dir, stat.S_IRWXU)
        output_file = os.path.join(output_dir, "results.json")
        self._output_file = output_file
        self._output_dir = output_dir

        cmd = [self.binary_name, "-t", target, "-j", output_file]

        # Chase related emails found in breaches
        if kwargs.get("chase", False):
            cmd.append("--chase")

        # h8mail config file with API keys
        config_file = kwargs.get("config_file")
        if config_file:
            cmd.extend(["-c", config_file])

        # Loose mode — include partial matches
        if kwargs.get("loose", False):
            cmd.append("--loose")

        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = []
        breaches = []
        credentials = []
        emails_found = set()

        # Parse JSON output file
        output_file = getattr(self, "_output_file", None)
        json_data = None

        if output_file and os.path.exists(output_file):
            try:
                with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                    json_data = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass

        if json_data and "targets" in json_data:
            for entry in json_data["targets"]:
                email = entry.get("target", "")
                pwn_num = entry.get("pwn_num", 0)
                data_arrays = entry.get("data", [])

                if email:
                    emails_found.add(email)

                # Parse data arrays — each inner array is a source group
                # Format: "SOURCE_TYPE:value"
                for source_group in data_arrays:
                    if not isinstance(source_group, list):
                        continue
                    for item in source_group:
                        if not isinstance(item, str) or ":" not in item:
                            continue
                        # Split on first colon only — values may contain colons
                        source_type, _, value = item.partition(":")
                        source_type = source_type.strip()
                        value = value.strip()

                        if not value:
                            continue

                        if "HIBP" in source_type or "LEAK" in source_type or "BREACH" in source_type:
                            breaches.append({
                                "email": email,
                                "source": source_type,
                                "breach_name": value,
                            })
                            findings.append({
                                "type": IntelType.BREACH,
                                "value": f"{email} — {value}",
                                "source_tool": self.name,
                                "confidence": 0.9,
                                "tags": ["h8mail", "breach", source_type.lower()],
                                "raw_data": {"email": email, "source": source_type, "breach": value},
                            })
                        elif "PASSWORD" in source_type:
                            credentials.append({
                                "email": email,
                                "source": source_type,
                                "type": "password",
                            })
                            findings.append({
                                "type": IntelType.CREDENTIAL,
                                "value": f"{email} — credential exposed ({source_type})",
                                "source_tool": self.name,
                                "confidence": 0.95,
                                "tags": ["h8mail", "credential", "password"],
                                "raw_data": {"email": email, "source": source_type},
                            })
                        elif "HASH" in source_type:
                            credentials.append({
                                "email": email,
                                "source": source_type,
                                "type": "hash",
                            })
                            findings.append({
                                "type": IntelType.CREDENTIAL,
                                "value": f"{email} — hash exposed ({source_type})",
                                "source_tool": self.name,
                                "confidence": 0.9,
                                "tags": ["h8mail", "credential", "hash"],
                                "raw_data": {"email": email, "source": source_type},
                            })
                        elif "USERNAME" in source_type:
                            findings.append({
                                "type": IntelType.USERNAME,
                                "value": value,
                                "source_tool": self.name,
                                "confidence": 0.8,
                                "tags": ["h8mail", "username"],
                                "raw_data": {"email": email, "source": source_type},
                            })

                # Summary finding for the email
                if pwn_num > 0:
                    findings.append({
                        "type": IntelType.EMAIL,
                        "value": f"{email} — {pwn_num} breaches/exposures",
                        "source_tool": self.name,
                        "confidence": 0.9,
                        "tags": ["h8mail", "breached"],
                        "raw_data": {"pwn_num": pwn_num},
                    })

        # Fallback: parse stdout for breach mentions if no JSON
        if not findings and raw_output:
            for line in raw_output.splitlines():
                line = line.strip()
                # Look for [+] or breach-like patterns
                if "[HIBP]" in line or "breach" in line.lower():
                    findings.append({
                        "type": IntelType.BREACH,
                        "value": line[:200],
                        "source_tool": self.name,
                        "confidence": 0.6,
                        "tags": ["h8mail", "stdout-parse"],
                    })

        # Cleanup temp files
        output_dir = getattr(self, "_output_dir", None)
        if output_dir and os.path.isdir(output_dir):
            try:
                import shutil
                shutil.rmtree(output_dir)
            except OSError:
                pass

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "emails_checked": sorted(emails_found),
                "total_breaches": len(breaches),
                "total_credentials": len(credentials),
                "breaches": breaches,
                "findings": findings,
            },
        )
