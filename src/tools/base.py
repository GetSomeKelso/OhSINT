"""Abstract base class for all OSINT tool wrappers."""

from __future__ import annotations

import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from typing import List, Optional

from src.config import Config, DEFAULT_TIMEOUT
from src.models import ToolResult


class BaseTool(ABC):
    """Every OSINT tool wrapper inherits from this."""

    name: str = ""
    description: str = ""
    binary_name: str = ""  # e.g. "theHarvester", "spiderfoot"
    install_cmd: str = ""  # e.g. "pip install theHarvester"
    requires_api_keys: List[str] = []

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
        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            elapsed = time.time() - start
            raw = proc.stdout
            errors = []
            if proc.returncode != 0 and proc.stderr:
                errors.append(proc.stderr.strip())
            result = self.parse_output(raw, target)
            result.execution_time_seconds = elapsed
            result.errors.extend(errors)
            return result
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={},
                errors=[f"{self.name} timed out after {timeout}s"],
                execution_time_seconds=elapsed,
            )
        except FileNotFoundError:
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
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={},
                errors=[f"Unexpected error: {e}"],
                execution_time_seconds=elapsed,
            )
