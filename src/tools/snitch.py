"""snitch — information gathering via dorks."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.tools.base import BaseTool
from src.config import DEFAULT_DORK_DELAY

SNITCH_DIR = Path("/opt/tools/snitch")


@register_tool
class Snitch(BaseTool):
    name = "snitch"
    description = "Information gathering via dorks"
    binary_name = "python3"
    install_cmd = "git clone https://github.com/Smaash/snitch.git /opt/tools/snitch"
    requires_api_keys = []

    def is_installed(self) -> bool:
        return SNITCH_DIR.exists() and (SNITCH_DIR / "snitch.py").exists()

    def build_command(self, target: str, **kwargs) -> List[str]:
        script = str(SNITCH_DIR / "snitch.py")
        return ["python3", script, "-t", target]

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = []
        urls = set()
        emails = set()
        subdomains = set()

        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("["):
                continue

            # URLs
            url_match = re.search(r'https?://[^\s<>"]+', stripped)
            if url_match:
                url = url_match.group(0).rstrip(".,;)")
                urls.add(url)

            # Emails
            for email in re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', stripped):
                emails.add(email.lower())

            # Subdomains
            for sub in re.findall(
                r'([\w.-]+\.' + re.escape(target) + r')\b', stripped
            ):
                subdomains.add(sub.lower())

        for email in sorted(emails):
            findings.append({
                "type": IntelType.EMAIL,
                "value": email,
                "source_tool": self.name,
                "confidence": 0.5,
                "tags": ["snitch", "dork"],
            })
        for sub in sorted(subdomains):
            findings.append({
                "type": IntelType.SUBDOMAIN,
                "value": sub,
                "source_tool": self.name,
                "confidence": 0.5,
                "tags": ["snitch", "dork"],
            })
        for url in sorted(urls):
            lower = url.lower()
            if any(kw in lower for kw in (".env", "config", "admin", "login", ".git")):
                findings.append({
                    "type": IntelType.SENSITIVE_FILE,
                    "value": url,
                    "source_tool": self.name,
                    "confidence": 0.4,
                    "tags": ["snitch", "dork"],
                })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "urls": sorted(urls),
                "emails": sorted(emails),
                "subdomains": sorted(subdomains),
                "findings": findings,
            },
        )
