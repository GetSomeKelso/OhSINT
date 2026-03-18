"""vcsmap — scan public VCS (version control systems) for sensitive info."""

from __future__ import annotations

import re
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.tools.base import BaseTool


@register_tool
class VcsMap(BaseTool):
    name = "vcsmap"
    description = "Scan public version control systems for sensitive info"
    binary_name = "vcsmap"
    install_cmd = "gem install vcsmap"
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        mode = kwargs.get("mode", "full")
        cmd = ["vcsmap", "-t", target]
        if mode == "full":
            cmd.append("--all")
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = []
        repos = []
        sensitive_files = []

        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Repository URLs
            repo_match = re.search(
                r'(https?://(?:github|gitlab|bitbucket)\.\w+/[^\s]+)', stripped
            )
            if repo_match:
                repos.append(repo_match.group(1))

            # Sensitive file patterns
            sensitive_patterns = [
                r'(\.env|\.git-credentials|id_rsa|\.pem|\.key)',
                r'(password|secret|credential|api[_-]?key)',
                r'(wp-config|config\.php|database\.yml)',
            ]
            for pattern in sensitive_patterns:
                if re.search(pattern, stripped, re.IGNORECASE):
                    sensitive_files.append(stripped)
                    findings.append({
                        "type": IntelType.SENSITIVE_FILE,
                        "value": stripped[:200],
                        "source_tool": self.name,
                        "confidence": 0.5,
                        "tags": ["vcsmap", "vcs-leak"],
                    })
                    break

            # Credential patterns
            cred_match = re.search(
                r'(password|api[_-]?key|secret|token)\s*[:=]\s*\S+',
                stripped, re.IGNORECASE,
            )
            if cred_match:
                findings.append({
                    "type": IntelType.CREDENTIAL,
                    "value": stripped[:200],
                    "source_tool": self.name,
                    "confidence": 0.4,
                    "tags": ["vcsmap", "potential-leak"],
                })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "repos": repos,
                "sensitive_files": sensitive_files,
                "findings": findings,
            },
        )
