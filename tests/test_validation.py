"""Tests for input validation and security checks."""

import pytest

from src.tools.base import validate_target
from src.config import Config
from src.models import ToolResult


class TestValidateTarget:
    def test_valid_domain(self):
        ok, err = validate_target("example.com")
        assert ok is True
        assert err == ""

    def test_valid_ip(self):
        ok, err = validate_target("192.168.1.1")
        assert ok is True

    def test_valid_cidr(self):
        ok, err = validate_target("10.0.0.0/24")
        assert ok is True

    def test_valid_email(self):
        ok, err = validate_target("user@example.com")
        assert ok is True

    def test_valid_person_name(self):
        ok, err = validate_target("John Smith")
        assert ok is True

    def test_empty_target(self):
        ok, err = validate_target("")
        assert ok is False
        assert "empty" in err.lower()

    def test_whitespace_only(self):
        ok, err = validate_target("   ")
        assert ok is False

    def test_too_long(self):
        ok, err = validate_target("a" * 501)
        assert ok is False
        assert "length" in err.lower()

    def test_shell_metachar_semicolon(self):
        ok, err = validate_target("example.com; rm -rf /")
        assert ok is False
        assert "disallowed" in err.lower()

    def test_shell_metachar_pipe(self):
        ok, err = validate_target("example.com | cat /etc/passwd")
        assert ok is False

    def test_shell_metachar_backtick(self):
        ok, err = validate_target("`whoami`.example.com")
        assert ok is False

    def test_shell_metachar_dollar(self):
        ok, err = validate_target("$(whoami).example.com")
        assert ok is False

    def test_shell_metachar_ampersand(self):
        ok, err = validate_target("example.com & echo pwned")
        assert ok is False

    def test_shell_metachar_redirect(self):
        ok, err = validate_target("example.com > /tmp/out")
        assert ok is False


class TestBaseToolValidation:
    """Ensure BaseTool.run() calls validate_target before executing."""

    def test_run_rejects_bad_target(self):
        from src.tools.theharvester import TheHarvester
        tool = TheHarvester(config=Config())
        result = tool.run("; rm -rf /", timeout=5)
        assert len(result.errors) > 0
        assert "Invalid target" in result.errors[0]

    def test_run_rejects_empty_target(self):
        from src.tools.shodan_tool import ShodanTool
        tool = ShodanTool(config=Config())
        result = tool.run("", timeout=5)
        assert len(result.errors) > 0
        assert "Invalid target" in result.errors[0]
