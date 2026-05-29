"""SecretFinder — extract secrets and API keys from JavaScript files."""

from __future__ import annotations

import re
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool
from src.tools.trufflehog_github import _redact_secret


@register_tool
class SecretFinderTool(BaseTool):
    name = "secretfinder"
    description = "JavaScript secret extractor — finds API keys, tokens, and credentials in JS files"
    binary_name = "SecretFinder"
    install_cmd = "git clone https://github.com/m4ll0k/SecretFinder.git ~/Tools/osint-deps/SecretFinder && pip install requests jsbeautifier --break-system-packages && sudo ln -sf ~/Tools/osint-deps/SecretFinder/SecretFinder.py /usr/local/bin/SecretFinder"
    accepted_target_types = (TargetType.URL,)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        input_file = kwargs.get("input_file", target)
        return ["SecretFinder", "-i", input_file, "-o", "cli"]

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        secrets = []
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            # SecretFinder output format varies; try to parse "Type: Value" or just URLs
            secret_type = "unknown"
            secret_value = line

            # Try to extract type from structured output
            match = re.match(r'^(\w[\w\s]*?):\s*(.+)$', line)
            if match:
                secret_type = match.group(1).strip()
                secret_value = match.group(2).strip()

            if not secret_value or len(secret_value) < 5:
                continue

            secrets.append({
                "type": secret_type,
                "value_redacted": _redact_secret(secret_value),
            })

            findings.append({
                "type": IntelType.LEAKED_SECRET,
                "value": f"{target}: {secret_type}",
                "source_tool": self.name,
                "confidence": 0.4,  # Low — SecretFinder has high FP rate, needs TruffleHog verification
                "tags": ["secretfinder", "javascript", "unverified"],
                "raw_data": {
                    "secret_type": secret_type,
                    "verified": False,
                    "raw_secret_redacted": _redact_secret(secret_value),
                    "source_platform": "javascript",
                    "source_url": target,
                },
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "secrets": secrets,
                "total_secrets": len(secrets),
                "findings": findings,
            },
        )
