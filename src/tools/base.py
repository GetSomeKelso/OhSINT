"""Abstract base class for all OSINT tool wrappers."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

from src.config import Config, DEFAULT_TIMEOUT
from src.models import ToolResult
from src.target import TargetType

logger = logging.getLogger("ohsint.tools")

# Max bytes to read from subprocess stdout to prevent memory exhaustion
_MAX_OUTPUT_BYTES = 50 * 1024 * 1024  # 50 MB


def validate_target(target: str) -> Tuple[bool, str]:
    """Basic sanity check on target input.

    Returns (is_valid, error_message).
    Rejects empty targets and obvious garbage.  Does NOT reject valid
    domains, IPs, emails, CIDR ranges, org names, or file paths.
    """
    if not target or not target.strip():
        return False, "Target must not be empty"
    if len(target) > 500:
        return False, "Target exceeds maximum length (500 characters)"
    # Reject shell meta-characters that have no place in OSINT targets
    if re.search(r'[;`$|><&]', target):
        return False, f"Target contains disallowed characters: {target!r}"
    return True, ""


class BaseTool(ABC):
    """Every OSINT tool wrapper inherits from this."""

    name: str = ""
    description: str = ""
    binary_name: str = ""  # e.g. "theHarvester", "spiderfoot"
    install_cmd: str = ""  # e.g. "pip install theHarvester"
    requires_api_keys: Tuple[str, ...] = ()  # immutable to avoid shared-state bugs
    accepted_target_types: Tuple[TargetType, ...] = ()  # what this tool wants (order = priority)

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()

    @abstractmethod
    def build_command(self, target: str, **kwargs) -> List[str]:
        """Build the CLI command as a list of args."""
        ...

    @abstractmethod
    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        """Parse raw CLI output into structured ToolResult."""
        ...

    def is_installed(self) -> bool:
        """Check if the tool binary exists on PATH."""
        return shutil.which(self.binary_name) is not None

    def check_api_keys(self) -> List[str]:
        """Return list of missing required API keys."""
        missing = []
        for key_spec in self.requires_api_keys:
            # key_spec format: "tool_name.key_name"
            parts = key_spec.split(".", 1)
            if len(parts) == 2:
                tool, key = parts
                if not self.config.get_api_key(tool, key):
                    missing.append(key_spec)
        return missing

    def run(
        self, target: str, timeout: int = DEFAULT_TIMEOUT, **kwargs
    ) -> ToolResult:
        """Execute the tool and return parsed results."""
        # Validate target
        valid, err = validate_target(target)
        if not valid:
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={},
                errors=[f"Invalid target: {err}"],
                execution_time_seconds=0.0,
            )

        if not self.is_installed():
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={},
                errors=[
                    f"{self.name} is not installed. Install with: {self.install_cmd}"
                ],
                execution_time_seconds=0.0,
            )

        cmd = self.build_command(target, **kwargs)
        logger.info("Executing: %s", " ".join(cmd))
        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
            )
            elapsed = time.time() - start
            raw = proc.stdout
            if len(raw) > _MAX_OUTPUT_BYTES:
                logger.warning(
                    "%s produced oversized output (%d bytes), truncating",
                    self.name, len(raw),
                )
                raw = raw[:_MAX_OUTPUT_BYTES]
            errors = []
            if proc.returncode != 0 and proc.stderr:
                errors.append(proc.stderr.strip())
            result = self.parse_output(raw, target)
            result.execution_time_seconds = elapsed
            result.errors.extend(errors)
            return result
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start
            logger.warning("%s timed out after %ds", self.name, timeout)
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={},
                errors=[f"{self.name} timed out after {timeout}s"],
                execution_time_seconds=elapsed,
            )
        except FileNotFoundError:
            logger.error("Binary not found: %s", self.binary_name)
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={},
                errors=[f"Binary not found: {self.binary_name}"],
                execution_time_seconds=0.0,
            )
        except Exception as e:
            elapsed = time.time() - start
            logger.exception("Unexpected error running %s", self.name)
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={},
                errors=[f"Unexpected error: {e}"],
                execution_time_seconds=elapsed,
            )
