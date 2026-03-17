"""Tool registry — decoupled from orchestrator to avoid circular imports."""

from __future__ import annotations

from typing import Dict

from src.tools.base import BaseTool

_TOOL_REGISTRY: Dict[str, type[BaseTool]] = {}


def register_tool(cls: type[BaseTool]) -> type[BaseTool]:
    """Decorator to register a tool wrapper class."""
    _TOOL_REGISTRY[cls.name] = cls
    return cls
