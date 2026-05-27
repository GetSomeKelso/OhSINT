"""gf — pattern matching against URL lists for interesting parameters and secrets."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

# Map gf pattern names to IntelType for findings
_PATTERN_TO_TYPE = {
    "redirect": IntelType.VULNERABILITY,
    "aws-keys": IntelType.CREDENTIAL,
    "s3-buckets": IntelType.SENSITIVE_FILE,
    "secrets": IntelType.CREDENTIAL,
    "interestingparams": IntelType.TECHNOLOGY,
}

# Default confidence per pattern
_PATTERN_CONFIDENCE = {
    "redirect": 0.6,
    "aws-keys": 0.8,
    "s3-buckets": 0.7,
    "secrets": 0.7,
    "interestingparams": 0.5,
}

# Bundled patterns directory
_BUNDLED_PATTERNS_DIR = Path(__file__).resolve().parent.parent.parent / "configs" / "gf_patterns"
_GF_HOME = Path.home() / ".gf"


@register_tool
class GfPatterns(BaseTool):
    name = "gf_patterns"
    description = "Pattern matching against URL lists — finds redirects, AWS keys, S3 buckets, secrets"
    binary_name = "gf"
    install_cmd = "go install github.com/tomnomnom/gf@latest"
    accepted_target_types = (TargetType.DOMAIN,)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        pattern = kwargs.get("pattern", "secrets")
        return [self.binary_name, pattern]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        """Override run() to pipe URL file through stdin to gf."""
        import time as _time

        input_file = kwargs.get("input_file")
        if not input_file:
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={"findings": []},
                errors=["gf_patterns requires input_file kwarg with a URL list"],
            )

        if not self.is_installed():
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={"findings": []},
                errors=[f"{self.name} is not installed. Install with: {self.install_cmd}"],
            )

        # Ensure gf patterns are available
        self._ensure_gf_patterns()

        pattern = kwargs.get("pattern", "secrets")
        cmd = self.build_command(target, **kwargs)

        start = _time.time()
        try:
            with open(input_file, "r", encoding="utf-8") as f:
                proc = subprocess.run(
                    cmd,
                    stdin=f,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    shell=False,
                )
            elapsed = _time.time() - start

            result = self._parse_gf_output(proc.stdout, target, pattern)
            result.execution_time_seconds = elapsed
            if proc.returncode != 0 and proc.stderr:
                result.errors.append(proc.stderr.strip())
            return result

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={"findings": []},
                errors=[f"gf timed out after {timeout}s"],
                execution_time_seconds=_time.time() - start,
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={"findings": []},
                errors=[f"gf error: {e}"],
                execution_time_seconds=_time.time() - start,
            )

    def _parse_gf_output(self, raw_output: str, target: str, pattern: str) -> ToolResult:
        """Parse gf output — each line is a URL matching the pattern."""
        matched_urls = []
        findings = []

        intel_type = _PATTERN_TO_TYPE.get(pattern, IntelType.SENSITIVE_FILE)
        confidence = _PATTERN_CONFIDENCE.get(pattern, 0.6)

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            matched_urls.append(line)
            findings.append({
                "type": intel_type,
                "value": line,
                "source_tool": self.name,
                "confidence": confidence,
                "tags": ["gf", f"pattern:{pattern}"],
                "raw_data": {"gf_pattern": pattern, "matched_url": line},
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "pattern": pattern,
                "matched_urls": matched_urls,
                "total_matches": len(matched_urls),
                "findings": findings,
            },
        )

    def _ensure_gf_patterns(self) -> None:
        """Copy bundled gf patterns to ~/.gf/ if missing."""
        if not _BUNDLED_PATTERNS_DIR.is_dir():
            return

        _GF_HOME.mkdir(parents=True, exist_ok=True)

        for pattern_file in _BUNDLED_PATTERNS_DIR.glob("*.json"):
            dest = _GF_HOME / pattern_file.name
            if not dest.exists():
                shutil.copy2(pattern_file, dest)

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        """Not used — run() handles everything."""
        return self._parse_gf_output(raw_output, target, "secrets")
