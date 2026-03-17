"""github-dorks — scan GitHub repos for sensitive information leaks."""

from __future__ import annotations

import re
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.tools.base import BaseTool

# Built-in dork patterns for GitHub searching
BUILTIN_DORKS = [
    "filename:.env",
    "filename:.git-credentials",
    "filename:id_rsa",
    "filename:id_dsa",
    'filename:.bash_history',
    "filename:wp-config.php",
    "filename:configuration.php",
    "filename:config.php",
    "filename:shadow",
    "filename:passwd",
    "filename:.htpasswd",
    "filename:credentials",
    "filename:secret_token.rb",
    "filename:database.yml password",
    'extension:pem private',
    'extension:ppk private',
    'extension:sql mysql dump',
    'extension:json api.forecast.io',
    '"api_key"',
    '"api_secret"',
    '"apikey"',
    '"secret_key"',
    '"access_token"',
    '"password"',
    'HEROKU_API_KEY',
    'HOMEBREW_GITHUB_API_TOKEN',
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
]


@register_tool
class GithubDorks(BaseTool):
    name = "github_dorks"
    description = "Scan GitHub repos/orgs for sensitive information leaks"
    binary_name = "github-dorks"
    install_cmd = "pip install github-dorks"
    requires_api_keys = ["github_dorks.github_token"]

    def build_command(self, target: str, **kwargs) -> List[str]:
        dork_file = kwargs.get("dork_file")
        mode = kwargs.get("mode", "org_scan")

        cmd = ["github-dorks"]

        # Target can be org or user
        if mode == "org_scan":
            cmd.extend(["-u", target])
        else:
            cmd.extend(["-u", target])

        if dork_file:
            cmd.extend(["-d", dork_file])

        # Pass GitHub token via environment (handled in run override)
        return cmd

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        """Override to inject GITHUB_TOKEN env var."""
        import os
        import subprocess
        import time

        token = self.config.get_api_key("github_dorks", "github_token")
        if not token:
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                errors=["GitHub token not configured. Set github_dorks.github_token in api_keys.yaml"],
            )

        env = os.environ.copy()
        env["GITHUB_TOKEN"] = token

        cmd = self.build_command(target, **kwargs)
        start = time.time()

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
            elapsed = time.time() - start
            result = self.parse_output(proc.stdout, target)
            result.execution_time_seconds = elapsed
            if proc.returncode != 0 and proc.stderr:
                result.errors.append(proc.stderr.strip())
            return result
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                errors=[f"github-dorks timed out after {timeout}s"],
                execution_time_seconds=time.time() - start,
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                errors=[f"Binary not found: {self.binary_name}. Install with: {self.install_cmd}"],
            )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = []
        sensitive_files = []
        credentials = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue

            # github-dorks typically outputs: [dork] repo/path — description
            # or URL patterns to matching files
            url_match = re.search(
                r'github\.com/([^/]+/[^/]+)/blob/[^/]+/(.+)', line
            )
            if url_match:
                repo = url_match.group(1)
                filepath = url_match.group(2)
                sensitive_files.append({
                    "repo": repo,
                    "file": filepath,
                    "url": line.strip(),
                })
                findings.append({
                    "type": IntelType.SENSITIVE_FILE,
                    "value": f"{repo}/{filepath}",
                    "source_tool": self.name,
                    "confidence": 0.6,
                    "tags": ["github", "dork"],
                })
                continue

            # Check for credential-like patterns in output
            cred_patterns = [
                r'(api[_-]?key|api[_-]?secret|password|secret[_-]?key|access[_-]?token)',
                r'(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)',
                r'(HEROKU_API_KEY|GITHUB_TOKEN)',
            ]
            for pattern in cred_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    credentials.append(line)
                    findings.append({
                        "type": IntelType.CREDENTIAL,
                        "value": line[:200],  # Truncate long lines
                        "source_tool": self.name,
                        "confidence": 0.5,
                        "tags": ["github", "dork", "potential-leak"],
                    })
                    break

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "sensitive_files": sensitive_files,
                "potential_credentials": credentials,
                "findings": findings,
            },
        )
