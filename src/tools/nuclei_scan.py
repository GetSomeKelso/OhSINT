"""nuclei (general) — template-based vulnerability scanner for active recon.

Distinct from nuclei_takeovers (which is locked to http/takeovers/). This runs
the full/selected template set against confirmed-live URLs and is ACTIVE — it
sends requests to the target and requires authorization at the pipeline level.
"""

from __future__ import annotations

import json
import os
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class NucleiScan(BaseTool):
    name = "nuclei_scan"
    description = "Nuclei vulnerability scanner — runs templates against live hosts (active)"
    binary_name = "nuclei"
    install_cmd = "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    accepted_target_types = (TargetType.DOMAIN, TargetType.URL, TargetType.IP)
    requires_api_keys = ()
    is_passive = False  # Active — sends template payloads directly to target

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name]

        input_file = kwargs.get("input_file")
        if input_file:
            cmd.extend(["-l", str(input_file)])
        else:
            cmd.extend(["-u", target])

        # Severity filter (default high,critical to limit traffic + noise)
        severity = kwargs.get("severity", "high,critical")
        if severity:
            cmd.extend(["-severity", severity])

        # Optional explicit templates dir / tag selection
        templates = kwargs.get("templates")
        if templates:
            cmd.extend(["-t", str(templates)])
        tags = kwargs.get("tags")
        if tags:
            cmd.extend(["-tags", str(tags)])

        # Rate limiting — keep it polite by default
        rate = kwargs.get("rate_limit", 150)
        cmd.extend(["-rl", str(rate)])

        # interactsh server for OOB (optional)
        interactsh_server = kwargs.get("interactsh_server")
        if interactsh_server:
            cmd.extend(["-iserver", str(interactsh_server)])

        cmd.extend(["-json", "-silent"])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        vulns = []
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            matched = data.get("matched-at", data.get("host", ""))
            template_id = data.get("template-id", "")
            info = data.get("info", {}) or {}
            severity = info.get("severity", data.get("severity", "info"))
            name = info.get("name", template_id)

            if not matched and not template_id:
                continue

            entry = {
                "matched_at": matched,
                "template_id": template_id,
                "name": name,
                "severity": severity,
            }
            vulns.append(entry)

            findings.append({
                "type": IntelType.VULNERABILITY,
                "value": f"{name} @ {matched}" if matched else name,
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["nuclei", severity, template_id],
                "raw_data": entry,
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "vulnerabilities": vulns,
                "total_found": len(vulns),
                "findings": findings,
            },
        )
