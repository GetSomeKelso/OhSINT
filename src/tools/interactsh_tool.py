"""interactsh — out-of-band interaction client for blind vulnerability detection."""

from __future__ import annotations

import json
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class InteractshTool(BaseTool):
    name = "interactsh"
    description = "OOB interaction client — generates callback URLs for blind vulnerability testing"
    binary_name = "interactsh-client"
    install_cmd = "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    accepted_target_types = ()  # Generates interaction URLs, not target-based
    requires_api_keys = ()
    is_passive = False  # Active — sets up listener and expects callbacks

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name]

        # Number of payload URLs to generate
        count = kwargs.get("count", 5)
        cmd.extend(["-n", str(count)])

        # Custom server
        server = kwargs.get("server")
        if server:
            cmd.extend(["-s", server])

        # Auth token
        token = kwargs.get("token")
        if token:
            cmd.extend(["-t", token])

        # Poll interval
        poll = kwargs.get("poll_interval", 5)
        cmd.extend(["-pi", str(poll)])

        cmd.extend(["-json", "-silent"])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        interactions = []
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            protocol = data.get("protocol", "")
            unique_id = data.get("unique-id", data.get("uid", ""))
            full_id = data.get("full-id", "")
            remote_addr = data.get("remote-address", "")
            interaction_type = data.get("type", protocol)

            if unique_id or protocol:
                interaction = {
                    "protocol": protocol,
                    "unique_id": unique_id,
                    "full_id": full_id,
                    "remote_addr": remote_addr,
                    "type": interaction_type,
                }
                interactions.append(interaction)

                if remote_addr:
                    findings.append({
                        "type": IntelType.VULNERABILITY,
                        "value": f"OOB {protocol} interaction from {remote_addr}",
                        "source_tool": self.name,
                        "confidence": 0.9,
                        "tags": ["interactsh", "oob", protocol.lower()],
                        "raw_data": interaction,
                    })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "interactions": interactions,
                "total_interactions": len(interactions),
                "findings": findings,
            },
        )
