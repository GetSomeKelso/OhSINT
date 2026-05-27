"""nuclei (takeover templates only) — secondary fingerprint validation for subdomain takeover."""

from __future__ import annotations

import json
import os
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class NucleiTakeovers(BaseTool):
    name = "nuclei_takeovers"
    description = "Nuclei takeover template scanner — validates dangling CNAME fingerprints"
    binary_name = "nuclei"
    install_cmd = "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    accepted_target_types = (TargetType.DOMAIN,)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name]

        input_file = kwargs.get("input_file")
        if input_file:
            cmd.extend(["-l", str(input_file)])
        else:
            cmd.extend(["-u", target])

        templates_dir = kwargs.get("templates_dir") or os.environ.get("NUCLEI_TEMPLATES_DIR", "")
        if templates_dir:
            cmd.extend(["-t", os.path.join(templates_dir, "http", "takeovers")])
        else:
            cmd.extend(["-t", "http/takeovers/"])

        cmd.extend([
            "-severity", "medium,high,critical",
            "-json",
            "-silent",
        ])

        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        takeovers = []
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            host = data.get("host", data.get("matched-at", "")).strip().lower()
            # Strip protocol prefix if present
            for prefix in ("http://", "https://"):
                if host.startswith(prefix):
                    host = host[len(prefix):]
            host = host.rstrip("/")

            template_id = data.get("template-id", "")
            matcher_name = data.get("matcher-name", "")
            severity = data.get("info", {}).get("severity", data.get("severity", "medium"))
            template_name = data.get("info", {}).get("name", data.get("template-id", ""))

            if not host:
                continue

            entry = {
                "host": host,
                "template_id": template_id,
                "template_name": template_name,
                "matcher_name": matcher_name,
                "severity": severity,
            }
            takeovers.append(entry)

            findings.append({
                "type": IntelType.SUBDOMAIN_TAKEOVER,
                "value": host,
                "source_tool": self.name,
                "confidence": 0.7,
                "tags": ["nuclei", "takeover", template_id],
                "raw_data": entry,
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "takeovers": takeovers,
                "total_found": len(takeovers),
                "findings": findings,
            },
        )
