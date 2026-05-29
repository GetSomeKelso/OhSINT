"""Configuration management for OSINT Orchestrator."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent.parent / "configs"
DEFAULT_API_KEYS_FILE = DEFAULT_CONFIG_DIR / "api_keys.yaml"
DEFAULT_PROFILES_FILE = DEFAULT_CONFIG_DIR / "scan_profiles.yaml"
DEFAULT_TAKEOVER_PROVIDERS_FILE = DEFAULT_CONFIG_DIR / "takeover_providers.yaml"
DEFAULT_PIPELINE_DEFAULTS_FILE = DEFAULT_CONFIG_DIR / "pipeline_defaults.yaml"
DEFAULT_OPSEC_CONFIG_FILE = DEFAULT_CONFIG_DIR / "opsec.yaml"
DEFAULT_PATHS_FILE = DEFAULT_CONFIG_DIR / "paths.yaml"
DEFAULT_RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
DEFAULT_TIMEOUT = 300  # seconds per tool
DEFAULT_DORK_DELAY = 3.0  # seconds between Google dork queries
DEFAULT_MCP_TOKEN_ENV = "OHSINT_MCP_TOKEN"

# Wordlist / data-source path resolution (Change 3 — wordlist integration)
PATH_ENV_VARS = {
    "seclists": "OHSINT_SECLISTS_PATH",
    "wordlists": "OHSINT_WORDLISTS_PATH",
}
DEFAULT_PATHS = {
    "seclists": "/opt/SecLists",
    "wordlists": "/opt/wordlists",
    "n0kovo_subdomains": "{wordlists}/n0kovo_subdomains",
}


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

    def get_mcp_token(self) -> Optional[str]:
        """Get MCP bearer token. Checks config file then env var."""
        token = (self._api_keys.get("mcp_server") or {}).get("bearer_token")
        if token:
            return str(token)
        return os.environ.get(DEFAULT_MCP_TOKEN_ENV)

    def get_takeover_providers(self) -> list[dict]:
        """Load subdomain takeover provider fingerprints from config."""
        if not hasattr(self, "_takeover_providers"):
            path = DEFAULT_TAKEOVER_PROVIDERS_FILE
            if path.exists():
                with open(path) as f:
                    data = yaml.safe_load(f) or {}
                self._takeover_providers = data.get("providers", [])
            else:
                self._takeover_providers = []
        return self._takeover_providers

    def get_pipeline_config(self, pipeline: str) -> dict:
        """Load pipeline-specific defaults from config.

        Returns the config dict for the named pipeline, or empty dict if missing.
        """
        if not hasattr(self, "_pipeline_defaults"):
            path = DEFAULT_PIPELINE_DEFAULTS_FILE
            if path.exists():
                with open(path) as f:
                    self._pipeline_defaults = yaml.safe_load(f) or {}
            else:
                self._pipeline_defaults = {}
        return dict(self._pipeline_defaults.get(pipeline, {}))

    def get_opsec_config(self) -> dict:
        """Load OPSEC/analyst protection configuration."""
        if not hasattr(self, "_opsec_config"):
            path = DEFAULT_OPSEC_CONFIG_FILE
            if path.exists():
                with open(path) as f:
                    self._opsec_config = yaml.safe_load(f) or {}
            else:
                self._opsec_config = {}
        return dict(self._opsec_config)

    # ── Filesystem paths (wordlists / data sources) ───────────────────

    def _load_paths(self) -> Dict[str, str]:
        if not hasattr(self, "_paths"):
            path = DEFAULT_PATHS_FILE
            data: Dict[str, str] = {}
            if path.exists():
                with open(path) as f:
                    raw = yaml.safe_load(f) or {}
                data = raw.get("paths", {}) or {}
            self._paths = data
        return self._paths

    def get_path(self, name: str) -> str:
        """Resolve a configured filesystem path.

        Priority: config file (paths.yaml, non-empty) → env var → built-in default.
        Tokens {wordlists}/{seclists} are interpolated from the resolved roots.
        """
        cfg = self._load_paths()
        value = str(cfg.get(name) or "").strip()

        # 2. Environment variable
        if not value:
            env_name = PATH_ENV_VARS.get(name)
            if env_name and os.environ.get(env_name):
                value = os.environ[env_name].strip()

        # 3. Built-in default
        if not value:
            value = DEFAULT_PATHS.get(name, "")

        return self.resolve_path_tokens(value)

    def resolve_path_tokens(self, value: str) -> str:
        """Interpolate {WORDLISTS_PATH}/{SECLISTS_PATH}/{wordlists}/{seclists} tokens."""
        if not value:
            return value
        # Resolve roots directly from config/env/default to avoid recursion on
        # the bare root names (seclists/wordlists never contain tokens themselves).
        wl = self._resolve_root("wordlists")
        sl = self._resolve_root("seclists")
        return (
            value.replace("{WORDLISTS_PATH}", wl)
            .replace("{SECLISTS_PATH}", sl)
            .replace("{wordlists}", wl)
            .replace("{seclists}", sl)
        )

    def _resolve_root(self, name: str) -> str:
        cfg = self._load_paths()
        value = str(cfg.get(name) or "").strip()
        if not value:
            env_name = PATH_ENV_VARS.get(name)
            if env_name and os.environ.get(env_name):
                value = os.environ[env_name].strip()
        if not value:
            value = DEFAULT_PATHS.get(name, "")
        return value

    def get_paths_status(self) -> list[dict]:
        """Return wordlist/data-source path status for install-check."""
        seclists = self.get_path("seclists")
        n0kovo = self.get_path("n0kovo_subdomains")
        api_endpoints = str(
            Path(seclists) / "Discovery" / "Web-Content" / "api" / "api-endpoints.txt"
        )
        return [
            {
                "name": "SecLists",
                "path": seclists,
                "exists": Path(seclists).is_dir(),
                "install": "apt install seclists  OR  "
                "git clone https://github.com/danielmiessler/SecLists /opt/SecLists",
            },
            {
                "name": "SecLists api-endpoints.txt",
                "path": api_endpoints,
                "exists": Path(api_endpoints).is_file(),
                "install": "included with SecLists (cd /opt/SecLists && git pull to update)",
            },
            {
                "name": "n0kovo_subdomains",
                "path": n0kovo,
                "exists": Path(n0kovo).is_dir(),
                "install": f"git clone https://github.com/n0kovo/n0kovo_subdomains {n0kovo}",
            },
        ]

    def api_keys_file_exists(self) -> bool:
        return self.api_keys_path.exists()
