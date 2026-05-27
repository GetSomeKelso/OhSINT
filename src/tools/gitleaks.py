"""Gitleaks — fast regex-based secret scanning for git repos."""

from __future__ import annotations

import json
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool
from src.tools.trufflehog_github import _redact_secret


@register_tool
class Gitleaks(BaseTool):
    name = "gitleaks"
    description = "Gitleaks — fast regex-based secret scanner for git repositories"
    binary_name = "gitleaks"
    install_cmd = "go install github.com/gitleaks/gitleaks/v8@latest"
    accepted_target_types = (TargetType.DOMAIN, TargetType.ORG_NAME)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        source = kwargs.get("source", target)
        cmd = [
            self.binary_name, "detect",
            "--source", source,
            "--report-format", "json",
            "--report-path", "/dev/stdout",
            "--no-banner",
        ]
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = []

        # Gitleaks outputs a JSON array
        try:
            data = json.loads(raw_output)
            if not isinstance(data, list):
                data = [data]
        except (json.JSONDecodeError, ValueError):
            # Try JSON lines
            data = []
            for line in raw_output.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    continue

        for entry in data:
            rule_id = entry.get("RuleID", entry.get("ruleID", "unknown"))
            secret = entry.get("Secret", entry.get("secret", ""))
            file_path = entry.get("File", entry.get("file", ""))
            line_num = entry.get("StartLine", entry.get("startLine", 0))
            commit = entry.get("Commit", entry.get("commit", ""))

            findings.append({
                "type": IntelType.LEAKED_SECRET,
                "value": f"{file_path}:{line_num}",
                "source_tool": self.name,
                "confidence": 0.5,  # Regex-only, not verified
                "tags": ["gitleaks", rule_id],
                "raw_data": {
                    "secret_type": rule_id,
                    "verified": False,
                    "raw_secret_redacted": _redact_secret(secret),
                    "source_platform": "github",
                    "source_url": f"{file_path}:{line_num}",
                    "commit": commit[:12] if commit else "",
                },
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "total_secrets": len(findings),
                "findings": findings,
            },
        )
