"""Tests for configuration loading, profile inheritance, and API key resolution."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from src.config import Config


class TestProfileInheritance:
    def setup_method(self):
        """Create a temp profiles file with inheritance."""
        self.profiles = {
            "base": {
                "description": "Base profile",
                "tools": [
                    "theharvester",
                    {"shodan": {"mode": "search"}},
                ],
            },
            "extended": {
                "description": "Extended profile",
                "inherits": "base",
                "tools": [
                    {"shodan": {"mode": "host"}},  # override parent
                    "recon_ng",  # new tool
                ],
            },
            "deep": {
                "description": "Deep inheritance",
                "inherits": "extended",
                "tools": [
                    "datasploit",
                ],
            },
        }
        self.tmpdir = tempfile.mkdtemp()
        self.profiles_path = Path(self.tmpdir) / "profiles.yaml"
        self.api_keys_path = Path(self.tmpdir) / "api_keys.yaml"
        self.profiles_path.write_text(yaml.dump(self.profiles))
        self.api_keys_path.write_text(yaml.dump({}))
        self.config = Config(
            api_keys_path=self.api_keys_path,
            profiles_path=self.profiles_path,
        )

    def test_base_profile_no_inheritance(self):
        profile = self.config.get_profile("base")
        assert profile is not None
        assert len(profile["tools"]) == 2
        assert "theharvester" in profile["tools"]

    def test_extended_inherits_base(self):
        profile = self.config.get_profile("extended")
        assert profile is not None
        # Should have theharvester from parent + shodan override + recon_ng
        tool_names = []
        for t in profile["tools"]:
            if isinstance(t, str):
                tool_names.append(t)
            elif isinstance(t, dict):
                tool_names.extend(t.keys())
        assert "theharvester" in tool_names
        assert "recon_ng" in tool_names
        assert "shodan" in tool_names
        # The child's shodan config should be "host" not "search"
        shodan_configs = [t for t in profile["tools"] if isinstance(t, dict) and "shodan" in t]
        assert len(shodan_configs) == 1
        assert shodan_configs[0]["shodan"]["mode"] == "host"

    def test_deep_inheritance_chain(self):
        profile = self.config.get_profile("deep")
        assert profile is not None
        tool_names = []
        for t in profile["tools"]:
            if isinstance(t, str):
                tool_names.append(t)
            elif isinstance(t, dict):
                tool_names.extend(t.keys())
        assert "datasploit" in tool_names
        assert "theharvester" in tool_names  # from base

    def test_nonexistent_profile_returns_none(self):
        assert self.config.get_profile("nonexistent") is None

    def test_list_profiles(self):
        profiles = self.config.list_profiles()
        assert "base" in profiles
        assert "extended" in profiles
        assert profiles["base"] == "Base profile"


class TestApiKeys:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.api_keys_path = Path(self.tmpdir) / "api_keys.yaml"
        self.profiles_path = Path(self.tmpdir) / "profiles.yaml"
        self.profiles_path.write_text(yaml.dump({}))

    def test_get_from_file(self):
        self.api_keys_path.write_text(yaml.dump({
            "shodan": {"api_key": "test-key-123"},
        }))
        config = Config(
            api_keys_path=self.api_keys_path,
            profiles_path=self.profiles_path,
        )
        assert config.get_api_key("shodan", "api_key") == "test-key-123"

    def test_env_var_fallback(self):
        self.api_keys_path.write_text(yaml.dump({}))
        config = Config(
            api_keys_path=self.api_keys_path,
            profiles_path=self.profiles_path,
        )
        os.environ["OSINT_SHODAN_API_KEY"] = "env-key-456"
        try:
            assert config.get_api_key("shodan", "api_key") == "env-key-456"
        finally:
            del os.environ["OSINT_SHODAN_API_KEY"]

    def test_missing_key_returns_none(self):
        self.api_keys_path.write_text(yaml.dump({}))
        config = Config(
            api_keys_path=self.api_keys_path,
            profiles_path=self.profiles_path,
        )
        assert config.get_api_key("nonexistent", "key") is None

    def test_file_not_found_ok(self):
        config = Config(
            api_keys_path=Path(self.tmpdir) / "nope.yaml",
            profiles_path=self.profiles_path,
        )
        assert config.get_api_key("shodan", "api_key") is None
        assert not config.api_keys_file_exists()
