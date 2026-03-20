"""GooDork — Google dorking from CLI (Python script)."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool
from src.config import DEFAULT_DORK_DELAY

_GOODORK_SEARCH_PATHS = [
    Path.home() / "Tools" / "osint-deps" / "GooDork",
    Path("/opt/tools/GooDork"),
]


def _find_goodork_dir() -> Path | None:
    for p in _GOODORK_SEARCH_PATHS:
        if p.exists() and (p / "GooDork.py").exists():
            return p
    return None


@register_tool
class GooDork(BaseTool):
    name = "goodork"
    description = "Google dorking from the command line"
    binary_name = "GooDork"
    install_cmd = "git clone https://github.com/k3170makan/GooDork.git ~/Tools/osint-deps/GooDork && pip install beautifulsoup4"
    accepted_target_types = (TargetType.DOMAIN,)
    requires_api_keys = ()

    def is_installed(self) -> bool:
        import shutil
        if shutil.which(self.binary_name):
            return True
        return _find_goodork_dir() is not None

    def _get_executable(self) -> List[str]:
        import shutil
        if shutil.which(self.binary_name):
            return [self.binary_name]
        src_dir = _find_goodork_dir()
        if src_dir:
            return ["python3", str(src_dir / "GooDork.py")]
        return [self.binary_name]

    def build_command(self, target: str, **kwargs) -> List[str]:
        query = kwargs.get("query", f"site:{target}")
        pages = kwargs.get("pages", 3)
        return [*self._get_executable(), "-q", query, "-p", str(pages)]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        """Override to support multiple dork queries with rate limiting."""
        dorks = kwargs.pop("dorks", None)
        if not dorks:
            return super().run(target, timeout=timeout, **kwargs)

        # Run multiple dork queries with delay between each
        delay = kwargs.pop("delay", DEFAULT_DORK_DELAY)
        all_raw = []
        all_findings = []
        errors = []
        total_time = 0.0

        for dork in dorks:
            query = f"{dork} site:{target}" if "site:" not in dork else dork
            result = super().run(target, timeout=timeout, query=query, **kwargs)
            all_raw.append(f"--- Dork: {dork} ---\n{result.raw_output}")
            all_findings.extend(result.structured_data.get("findings", []))
            errors.extend(result.errors)
            total_time += result.execution_time_seconds
            time.sleep(delay)

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output="\n".join(all_raw),
            structured_data={"findings": all_findings},
            errors=errors,
            execution_time_seconds=total_time,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = []
        urls = set()

        for line in raw_output.splitlines():
            line = line.strip()
            if not line or line.startswith("---"):
                continue

            # Extract URLs from results
            url_match = re.search(r'https?://[^\s<>"]+', line)
            if url_match:
                url = url_match.group(0).rstrip(".,;)")
                if url not in urls:
                    urls.add(url)
                    # Categorize the finding
                    intel_type, tags = self._categorize_url(url)
                    findings.append({
                        "type": intel_type,
                        "value": url,
                        "source_tool": self.name,
                        "confidence": 0.5,
                        "tags": ["google-dork"] + tags,
                    })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "urls": sorted(urls),
                "findings": findings,
            },
        )

    @staticmethod
    def _categorize_url(url: str) -> tuple:
        """Categorize a dorked URL by likely content type."""
        lower = url.lower()
        if any(ext in lower for ext in (".pdf", ".doc", ".xls", ".ppt", ".csv")):
            return IntelType.DOCUMENT, ["filetype"]
        elif any(kw in lower for kw in ("login", "signin", "admin", "dashboard")):
            return IntelType.SENSITIVE_FILE, ["login-page"]
        elif any(kw in lower for kw in (".env", "config", "credential", "password")):
            return IntelType.SENSITIVE_FILE, ["config-exposure"]
        elif any(kw in lower for kw in ("wp-content", "wp-admin", "wordpress")):
            return IntelType.TECHNOLOGY, ["wordpress"]
        else:
            return IntelType.SUBDOMAIN, ["dorked"]
