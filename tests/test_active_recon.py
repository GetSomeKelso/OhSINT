"""Tests for the active recon pipeline — focus on the authorization gate.

The defining safety property of ActiveReconPipeline is that it refuses to run
without confirmed authorization, since every stage sends traffic to the target.
"""

from __future__ import annotations

import pytest

from src.pipelines.active_recon import ActiveReconPipeline, AuthorizationError


def test_run_refuses_without_authorization():
    pipe = ActiveReconPipeline()
    with pytest.raises(AuthorizationError):
        pipe.run(["example.com"], authorization_confirmed=False)


def test_run_refuses_by_default():
    """authorization_confirmed defaults to False — must not run."""
    pipe = ActiveReconPipeline()
    with pytest.raises(AuthorizationError):
        pipe.run(["example.com"])


def test_dry_run_needs_no_authorization():
    """dry_run only previews commands; it must work without auth."""
    pipe = ActiveReconPipeline()
    info = pipe.dry_run(["example.com"])
    names = [i["name"] for i in info]
    # Funnel order + optional brute stage present
    assert "subfinder" in names
    assert "naabu" in names
    assert "httpx" in names
    assert "katana" in names
    assert "nuclei_scan" in names
    assert any(i.get("optional") for i in info)  # shuffledns is optional


def test_nuclei_scan_is_active():
    """nuclei_scan must be marked active so MCP _require_auth gates it."""
    from src.tools.nuclei_scan import NucleiScan
    assert NucleiScan.is_passive is False


def test_nuclei_scan_severity_default():
    from src.tools.nuclei_scan import NucleiScan
    cmd = NucleiScan().build_command("https://example.com")
    assert "-severity" in cmd
    assert "high,critical" in cmd
