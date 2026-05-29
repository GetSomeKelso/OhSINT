"""Tests for wordlist/data-source path resolution (Change 3 — wordlist integration).

Covers the three-tier resolver in src.config.Config:
  config file (paths.yaml) > env var (OHSINT_*) > built-in default,
plus {WORDLISTS_PATH}/{SECLISTS_PATH} token interpolation.
"""

from __future__ import annotations

import pytest

from src.config import Config, DEFAULT_PATHS


@pytest.fixture
def cfg():
    return Config()


def test_config_file_value_wins(cfg):
    cfg._paths = {"seclists": "/from/file"}
    assert cfg.get_path("seclists") == "/from/file"


def test_config_beats_env(cfg, monkeypatch):
    monkeypatch.setenv("OHSINT_SECLISTS_PATH", "/from/env")
    cfg._paths = {"seclists": "/from/file"}
    assert cfg.get_path("seclists") == "/from/file"


def test_env_used_when_config_empty(cfg, monkeypatch):
    monkeypatch.setenv("OHSINT_SECLISTS_PATH", "/from/env")
    cfg._paths = {}  # no config value -> fall through to env
    assert cfg.get_path("seclists") == "/from/env"


def test_default_when_no_config_no_env(cfg, monkeypatch):
    monkeypatch.delenv("OHSINT_SECLISTS_PATH", raising=False)
    monkeypatch.delenv("OHSINT_WORDLISTS_PATH", raising=False)
    cfg._paths = {}
    assert cfg.get_path("seclists") == DEFAULT_PATHS["seclists"]
    assert cfg.get_path("wordlists") == DEFAULT_PATHS["wordlists"]


def test_n0kovo_token_interpolation_from_env(cfg, monkeypatch):
    monkeypatch.setenv("OHSINT_WORDLISTS_PATH", "/custom/wl")
    cfg._paths = {}
    assert cfg.get_path("n0kovo_subdomains") == "/custom/wl/n0kovo_subdomains"


def test_resolve_path_tokens(cfg, monkeypatch):
    monkeypatch.delenv("OHSINT_WORDLISTS_PATH", raising=False)
    cfg._paths = {"wordlists": "/opt/wordlists", "seclists": "/opt/SecLists"}
    out = cfg.resolve_path_tokens(
        "{WORDLISTS_PATH}/n0kovo_subdomains/n0kovo_subdomains_huge.txt"
    )
    assert out == "/opt/wordlists/n0kovo_subdomains/n0kovo_subdomains_huge.txt"
    assert cfg.resolve_path_tokens("{SECLISTS_PATH}/x") == "/opt/SecLists/x"
    assert cfg.resolve_path_tokens("") == ""


def test_get_paths_status_shape(cfg):
    status = cfg.get_paths_status()
    names = {item["name"] for item in status}
    assert "SecLists" in names
    assert "n0kovo_subdomains" in names
    for item in status:
        assert {"name", "path", "exists", "install"} <= set(item.keys())
        assert isinstance(item["exists"], bool)
