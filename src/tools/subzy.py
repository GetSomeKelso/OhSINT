"""subzy — subdomain takeover vulnerability checker via provider fingerprints."""

from __future__ import annotations

import json
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class SubzyTool(BaseTool):
    name = "subzy"
    description = "Subdomain takeover detection — checks dangling CNAMEs against provider fingerprints"
    binary_name = "subzy"
    install_cmd = "go install -v github.com/PentestPad/subzy@latest"
    accepted_target_types = (TargetType.DOMAIN,)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        input_file = kwargs.get("input_file")
        if not input_file:
            # Standalone mode not supported — subzy requires a targets file
            self._missing_input = True
            return [self.binary_name, "run", "--targets", "MISSING"]

        self._missing_input = False
        cmd = [
            self.binary_name, "run",
            "--targets", str(input_file),
            "--hide_fails",
        ]

        concurrency = kwargs.get("concurrency", 10)
        cmd.extend(["--concurrency", str(concurrency)])

        return cmd

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        if not kwargs.get("input_file"):
            return ToolResult(
                tool_name=self.name,
                target=target,
                raw_output="",
                structured_data={"findings": []},
                errors=["subzy requires --input-file with a list of subdomains to check"],
            )
        return super().run(target, timeout, **kwargs)

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        vulnerable = []
        findings = []

        # subzy outputs a mix of text and JSON; try JSON lines first
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                # Fallback: parse text output like "[VULNERABLE] sub.example.com - Service: GitHub Pages"
                if "[VULNERABLE]" in line.upper():
                    parts = line.split("-", 1)
                    subdomain = parts[0].split("]", 1)[-1].strip() if "]" in parts[0] else ""
                    service = parts[1].split(":", 1)[-1].strip() if len(parts) > 1 and ":" in parts[1] else "unknown"
                    if subdomain:
                        entry = {"subdomain": subdomain, "service": service, "vulnerable": True}
                        vulnerable.append(entry)
                        findings.append({
                            "type": IntelType.SUBDOMAIN_TAKEOVER,
                            "value": subdomain,
                            "source_tool": self.name,
                            "confidence": 0.7,
                            "tags": ["subzy", "takeover", service.lower().replace(" ", "-")],
                            "raw_data": entry,
                        })
                continue

            if data.get("vulnerable", False):
                subdomain = data.get("subdomain", data.get("host", "")).strip().lower()
                cname = data.get("cname", "").strip().lower()
                service = data.get("service", data.get("engine", "unknown"))
                entry = {
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": service,
                    "vulnerable": True,
                }
                vulnerable.append(entry)
                findings.append({
                    "type": IntelType.SUBDOMAIN_TAKEOVER,
                    "value": subdomain,
                    "source_tool": self.name,
                    "confidence": 0.7,
                    "tags": ["subzy", "takeover", service.lower().replace(" ", "-")],
                    "raw_data": entry,
                })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "vulnerable": vulnerable,
                "total_vulnerable": len(vulnerable),
                "findings": findings,
            },
        )
