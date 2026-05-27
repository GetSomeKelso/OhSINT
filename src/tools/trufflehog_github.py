"""TruffleHog GitHub mode — scan GitHub orgs for verified leaked secrets."""

from __future__ import annotations

import json
import os
import subprocess
import time as _time
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


def _redact_secret(raw: str) -> str:
    """Redact a secret to first 6 chars + '...' — NEVER store full secrets."""
    if not raw:
        return "???"
    return raw[:6] + "..."


def _parse_trufflehog_json(raw_output: str, source_tool: str, source_platform: str) -> list[dict]:
    """Parse TruffleHog JSON-lines output into finding dicts."""
    findings = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue

        detector = data.get("DetectorName", data.get("detectorName", "unknown"))
        verified = data.get("Verified", data.get("verified", False))
        raw_secret = data.get("Raw", data.get("raw", ""))
        source_url = data.get("SourceMetadata", {}).get("Data", {})

        # Try to extract a meaningful source URL
        file_url = ""
        if isinstance(source_url, dict):
            gh = source_url.get("Github", source_url.get("github", {}))
            if isinstance(gh, dict):
                file_url = gh.get("link", gh.get("repository", ""))
            docker = source_url.get("Docker", source_url.get("docker", {}))
            if isinstance(docker, dict) and not file_url:
                file_url = docker.get("image", "")

        # Blast radius hint based on detector
        blast_hints = {
            "AWS": "AWS cloud access — potential full account compromise",
            "GitHub": "GitHub repo access — code read/write",
            "GitHubApp": "GitHub App credentials — org-level access",
            "Stripe": "Stripe payment API — financial data access",
            "Slack": "Slack workspace access — internal communications",
            "SendGrid": "SendGrid API — email sending capability",
            "Twilio": "Twilio API — SMS/voice capability",
            "HerokuAPI": "Heroku platform access — app management",
        }
        blast_radius = blast_hints.get(detector, f"{detector} service access")

        findings.append({
            "type": IntelType.LEAKED_SECRET,
            "value": file_url or f"{source_platform}:{detector}",
            "source_tool": source_tool,
            "confidence": 0.9 if verified else 0.5,
            "tags": ["trufflehog", source_platform, "verified" if verified else "unverified"],
            "raw_data": {
                "secret_type": detector,
                "verified": verified,
                "raw_secret_redacted": _redact_secret(raw_secret),
                "source_platform": source_platform,
                "source_url": file_url,
                "blast_radius_hint": blast_radius,
            },
        })

    return findings


@register_tool
class TrufflehogGithub(BaseTool):
    name = "trufflehog_github"
    description = "TruffleHog GitHub scanner — finds verified leaked secrets in public repos"
    binary_name = "trufflehog"
    install_cmd = "go install github.com/trufflesecurity/trufflehog/v3@latest"
    accepted_target_types = (TargetType.ORG_NAME, TargetType.GITHUB_HANDLE, TargetType.DOMAIN)
    requires_api_keys = ("github_dorks.github_token",)

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [
            self.binary_name, "github",
            "--org", target,
            "--json",
            "--only-verified",
            "--no-update",
        ]
        repo = kwargs.get("repo")
        if repo:
            cmd = [
                self.binary_name, "github",
                "--repo", repo,
                "--json",
                "--only-verified",
                "--no-update",
            ]
        return cmd

    def run(self, target: str, timeout: int = 600, **kwargs) -> ToolResult:
        """Override to inject GITHUB_TOKEN env var."""
        token = self.config.get_api_key("github_dorks", "github_token")
        if not token:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"findings": []},
                errors=["GitHub token not configured"],
            )

        if not self.is_installed():
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"findings": []},
                errors=[f"{self.name} not installed. Install with: {self.install_cmd}"],
            )

        cmd = self.build_command(target, **kwargs)
        env = self._build_proxy_env() or os.environ.copy()
        env["GITHUB_TOKEN"] = token

        start = _time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, shell=False, env=env,
            )
            elapsed = _time.time() - start
            result = self.parse_output(proc.stdout, target)
            result.execution_time_seconds = elapsed
            if proc.returncode != 0 and proc.stderr:
                result.errors.append(proc.stderr.strip()[:500])
            return result
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"findings": []},
                errors=[f"TruffleHog timed out after {timeout}s"],
                execution_time_seconds=_time.time() - start,
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name, target=target, raw_output="",
                structured_data={"findings": []},
                errors=[f"TruffleHog error: {e}"],
                execution_time_seconds=_time.time() - start,
            )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = _parse_trufflehog_json(raw_output, self.name, "github")
        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "total_secrets": len(findings),
                "verified_count": sum(1 for f in findings if (f.get("raw_data") or {}).get("verified")),
                "findings": findings,
            },
        )
