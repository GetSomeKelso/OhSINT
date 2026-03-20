"""metagoofil — document metadata harvester (PDF/DOC/XLS)."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

# Possible locations for metagoofil installed from source
_METAGOOFIL_SEARCH_PATHS = [
    Path.home() / "Tools" / "osint-deps" / "metagoofil",
    Path("/opt/tools/metagoofil"),
]


def _find_metagoofil_dir() -> Path | None:
    """Return the first metagoofil source directory that exists."""
    for p in _METAGOOFIL_SEARCH_PATHS:
        if p.exists() and (p / "metagoofil.py").exists():
            return p
    return None


@register_tool
class Metagoofil(BaseTool):
    name = "metagoofil"
    description = "Harvest document metadata from a domain (PDF/DOC/XLS)"
    binary_name = "metagoofil"
    install_cmd = "git clone https://github.com/opsdisk/metagoofil.git ~/Tools/osint-deps/metagoofil && pip install -r ~/Tools/osint-deps/metagoofil/requirements.txt"
    accepted_target_types = (TargetType.DOMAIN,)
    requires_api_keys = ()

    def is_installed(self) -> bool:
        """Check PATH first, then known source directories."""
        import shutil
        if shutil.which(self.binary_name):
            return True
        return _find_metagoofil_dir() is not None

    def _get_executable(self) -> List[str]:
        """Return the command prefix for metagoofil."""
        import shutil
        if shutil.which(self.binary_name):
            return [self.binary_name]
        src_dir = _find_metagoofil_dir()
        if src_dir:
            return ["python3", str(src_dir / "metagoofil.py")]
        return [self.binary_name]  # will fail with a clear error

    def build_command(self, target: str, **kwargs) -> List[str]:
        filetypes = kwargs.get("filetypes", "pdf,doc,xls,ppt,docx,xlsx,pptx")
        max_results = kwargs.get("max_results", 100)
        output_dir = kwargs.get(
            "output_dir", tempfile.mkdtemp(prefix="metagoofil_")
        )

        # Store output_dir so exiftool can find downloads later
        self._last_output_dir = output_dir

        return [
            *self._get_executable(),
            "-d", target,
            "-t", filetypes,
            "-l", str(max_results),
            "-o", output_dir,
            "-n", "0",  # no limit on downloads
        ]

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = []
        users = set()
        emails = set()
        software = set()
        documents = []

        # Parse metagoofil output sections
        current_section = None
        for line in raw_output.splitlines():
            stripped = line.strip()
            lower = stripped.lower()

            if "users found" in lower:
                current_section = "users"
                continue
            elif "software found" in lower:
                current_section = "software"
                continue
            elif "emails found" in lower:
                current_section = "emails"
                continue
            elif "files found" in lower or "filenames" in lower:
                current_section = "files"
                continue
            elif stripped.startswith("[") or stripped.startswith("---"):
                continue

            if not stripped:
                current_section = None
                continue

            if current_section == "users":
                users.add(stripped)
            elif current_section == "software":
                software.add(stripped)
            elif current_section == "emails":
                email = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', stripped)
                if email:
                    emails.add(email.group(0).lower())
            elif current_section == "files":
                if stripped.endswith(
                    (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx")
                ):
                    documents.append(stripped)

        # Regex fallback for emails in full output
        for email in re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', raw_output):
            emails.add(email.lower())

        # Build findings
        for user in sorted(users):
            findings.append({
                "type": IntelType.PERSON,
                "value": user,
                "source_tool": self.name,
                "confidence": 0.6,
                "tags": ["document-metadata"],
            })

        for email in sorted(emails):
            findings.append({
                "type": IntelType.EMAIL,
                "value": email,
                "source_tool": self.name,
                "confidence": 0.7,
                "tags": ["document-metadata"],
            })

        for sw in sorted(software):
            findings.append({
                "type": IntelType.TECHNOLOGY,
                "value": sw,
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["document-metadata"],
            })

        for doc in documents:
            findings.append({
                "type": IntelType.DOCUMENT,
                "value": doc,
                "source_tool": self.name,
                "confidence": 0.9,
                "tags": ["downloaded"],
            })

        output_dir = getattr(self, "_last_output_dir", "")

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "users": sorted(users),
                "emails": sorted(emails),
                "software": sorted(software),
                "documents": documents,
                "download_dir": output_dir,
                "findings": findings,
            },
        )
