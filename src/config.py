"""Configuration management for OSINT Orchestrator."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent.parent / "configs"
DEFAULT_API_KEYS_FILE = DEFAULT_CONFIG_DIR / "api_keys.yaml"
DEFAULT_PROFILES_FILE = DEFAULT_CONFIG_DIR / "scan_profiles.yaml"
DEFAULT_RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
DEFAULT_TIMEOUT = 300  # seconds per tool
DEFAULT_DORK_DELAY = 3.0  # seconds between Google dork queries


class Config:
    """Loads and provides access to API keys, scan profiles, and defaults."""

    def __init__(
        self,
        api_keys_path: Optional[Path] = None,
        profiles_path: Optional[Path] = None,
    ):
        self.api_keys_path = api_keys_path or DEFAULT_API_KEYS_FILE
        self.profiles_path = profiles_path or DEFAULT_PROFILES_FILE
        self._api_keys: Dict[str, Any] = {}
        self._profiles: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if self.api_keys_path.exists():
            with open(self.api_keys_path) as f:
                self._api_keys = yaml.safe_load(f) or {}
        if self.profiles_path.exists():
            with open(self.profiles_path) as f:
                self._profiles = yaml.safe_load(f) or {}

    def get_api_key(self, tool: str, key_name: str) -> Optional[str]:
        """Get an API key, falling back to environment variables.

        Checks: config file → env var OSINT_<TOOL>_<KEY> (uppercased).
        """
        # Config file first
        value = (self._api_keys.get(tool) or {}).get(key_name)
        if value:
            return value
        # Environment variable fallback
        env_name = f"OSINT_{tool}_{key_name}".upper()
        return os.environ.get(env_name)

    def get_profile(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a scan profile by name, resolving inheritance."""
        profile = self._profiles.get(name)
        if profile is None:
            return None
        # Resolve 'inherits' chain
        if "inherits" in profile:
            parent = self.get_profile(profile["inherits"])
            if parent:
                merged_tools = list(parent.get("tools", []))
                # Child tools override parent tools of the same name
                child_tool_names = set()
                for t in profile.get("tools", []):
                    if isinstance(t, dict):
                        child_tool_names.update(t.keys())
                    else:
                        child_tool_names.add(t)
                merged_tools = [
                    t
                    for t in merged_tools
                    if (
                        isinstance(t, str) and t not in child_tool_names
                    )
                    or (
                        isinstance(t, dict)
                        and not any(k in child_tool_names for k in t.keys())
                    )
                ]
                merged_tools.extend(profile.get("tools", []))
                profile = {**parent, **profile, "tools": merged_tools}
                del profile["inherits"]
        return profile

    def list_profiles(self) -> Dict[str, str]:
        """Return {name: description} for all profiles."""
        return {
            name: data.get("description", "")
            for name, data in self._profiles.items()
        }

    def get_all_api_keys(self) -> Dict[str, Any]:
        """Return the full API keys dict (for install-check)."""
        return dict(self._api_keys)

    def api_keys_file_exists(self) -> bool:
        return self.api_keys_path.exists()
