"""LinkedInt — LinkedIn profile deep-scraping (Tier 2, may need patching)."""

from __future__ import annotations

import os
import re
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class LinkedInt(BaseTool):
    is_passive = False  # authenticates to LinkedIn
    name = "linkedint"
    description = "LinkedIn profile deep-scraping (archived, may need patching)"
    binary_name = "python3"
    install_cmd = (
        "git clone https://github.com/mdsecactivebreach/LinkedInt.git "
        "~/Tools/osint-deps/LinkedInt"
    )
    accepted_target_types = (TargetType.ORG_NAME,)
    requires_api_keys = ("linkedin.email", "linkedin.password")

    _script_path = os.path.expanduser("~/Tools/osint-deps/LinkedInt/LinkedInt.py")

    # This tool is archived and may not work with current LinkedIn.
    # Build the wrapper but flag it as potentially non-functional.
    is_functional = False

    def is_installed(self) -> bool:
        return os.path.isfile(self._script_path)

    def build_command(self, target: str, **kwargs) -> List[str]:
        # LinkedInt is archived and non-functional. If restored, credentials
        # should be injected via environment variables in a run() override
        # (following the pattern in github_dorks.py), NOT as CLI arguments.
        return ["python3", self._script_path]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        """Override run to warn about functionality status."""
        if not self.is_functional:
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={"findings": []},
                errors=[
                    "LinkedInt is archived and may not work with current LinkedIn. "
                    "Use CrossLinked or linkedin2username instead. "
                    "Set LinkedInt.is_functional = True to attempt execution."
                ],
                execution_time_seconds=0.0,
            )
        return super().run(target, timeout=timeout, **kwargs)

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        people = set()
        findings = []

        # Parse whatever output LinkedInt produces
        for line in raw_output.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or line.startswith("#"):
                continue
            # Look for name-like patterns
            if re.match(r'^[A-Z][a-z]+ [A-Z][a-z]+', line):
                people.add(line)

        for person in sorted(people):
            findings.append({
                "type": IntelType.PERSON,
                "value": person,
                "source_tool": self.name,
                "confidence": 0.6,
                "tags": ["linkedin", "linkedint"],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "people": sorted(people),
                "findings": findings,
            },
        )
