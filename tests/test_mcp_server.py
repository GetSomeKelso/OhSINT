"""Tests for MCP server tool definitions and helpers."""

import pytest
import asyncio
from unittest.mock import patch, MagicMock

from src.mcp.server import (
    _format_result,
    _require_auth,
    osint_list_tools,
    osint_install_check,
)
from src.models import ToolResult, IntelType


class TestRequireAuth:
    def test_raises_when_not_confirmed(self):
        with pytest.raises(ValueError, match="Authorization not confirmed"):
            _require_auth(False)

    def test_passes_when_confirmed(self):
        _require_auth(True)  # Should not raise


class TestFormatResult:
    def test_format_basic_result(self):
        result = ToolResult(
            tool_name="test_tool",
            target="example.com",
            raw_output="raw",
            structured_data={
                "findings": [
                    {
                        "type": IntelType.EMAIL,
                        "value": "admin@example.com",
                        "confidence": 0.8,
                    }
                ]
            },
            execution_time_seconds=1.5,
        )
        md = _format_result(result)
        assert "test_tool" in md
        assert "example.com" in md
        assert "admin@example.com" in md
        assert "1.5s" in md

    def test_format_with_errors(self):
        result = ToolResult(
            tool_name="broken",
            target="x.com",
            raw_output="",
            errors=["timeout", "missing binary"],
            execution_time_seconds=0.0,
        )
        md = _format_result(result)
        assert "### Errors" in md
        assert "timeout" in md
        assert "missing binary" in md

    def test_format_non_toolresult(self):
        assert _format_result("just a string") == "just a string"

    def test_format_caps_findings_at_50(self):
        findings = [
            {"type": IntelType.IP_ADDRESS, "value": f"10.0.0.{i}", "confidence": 0.9}
            for i in range(80)
        ]
        result = ToolResult(
            tool_name="big",
            target="test",
            raw_output="",
            structured_data={"findings": findings},
            execution_time_seconds=2.0,
        )
        md = _format_result(result)
        assert "...and 30 more findings" in md

    def test_format_empty_result(self):
        result = ToolResult(
            tool_name="empty",
            target="test",
            raw_output="",
            structured_data={},
            execution_time_seconds=0.1,
        )
        md = _format_result(result)
        assert "empty Results" in md


class TestUtilityTools:
    @pytest.mark.asyncio
    async def test_list_tools_returns_table(self):
        md = await osint_list_tools()
        assert "| Tool |" in md
        assert "theharvester" in md
        assert "shodan" in md

    @pytest.mark.asyncio
    async def test_install_check_returns_status(self):
        md = await osint_install_check()
        assert "Tool Installation" in md


class TestScanToolAuthGating:
    """Verify all scan tools reject unauthorized requests."""

    @pytest.mark.asyncio
    async def test_full_recon_requires_auth(self):
        from src.mcp.server import osint_full_recon
        with pytest.raises(ValueError, match="Authorization"):
            await osint_full_recon("example.com", authorization_confirmed=False)

    @pytest.mark.asyncio
    async def test_theharvester_requires_auth(self):
        from src.mcp.server import osint_theharvester
        with pytest.raises(ValueError, match="Authorization"):
            await osint_theharvester("example.com", authorization_confirmed=False)

    @pytest.mark.asyncio
    async def test_snitch_requires_auth(self):
        from src.mcp.server import osint_snitch
        with pytest.raises(ValueError, match="Authorization"):
            await osint_snitch("example.com", authorization_confirmed=False)

    @pytest.mark.asyncio
    async def test_vcsmap_requires_auth(self):
        from src.mcp.server import osint_vcsmap
        with pytest.raises(ValueError, match="Authorization"):
            await osint_vcsmap("example.com", authorization_confirmed=False)

    @pytest.mark.asyncio
    async def test_creepy_requires_auth(self):
        from src.mcp.server import osint_creepy
        with pytest.raises(ValueError, match="Authorization"):
            await osint_creepy("johndoe", authorization_confirmed=False)

    @pytest.mark.asyncio
    async def test_goodork_requires_auth(self):
        from src.mcp.server import osint_goodork
        with pytest.raises(ValueError, match="Authorization"):
            await osint_goodork("example.com", authorization_confirmed=False)
