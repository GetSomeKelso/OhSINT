"""cvemap — CVE lookup with EPSS scores, KEV status, and exploit references."""

from __future__ import annotations

import json
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool


@register_tool
class CvemapTool(BaseTool):
    name = "cvemap"
    description = "CVE vulnerability mapper — EPSS scores, KEV status, exploits, vendor advisories"
    binary_name = "cvemap"
    install_cmd = "go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest"
    accepted_target_types = (TargetType.DOMAIN, TargetType.ORG_NAME)
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name]

        # Query mode
        if kwargs.get("cve_id"):
            cmd.extend(["-id", kwargs["cve_id"]])
        else:
            cmd.extend(["-q", target])

        # Severity filter
        severity = kwargs.get("severity")
        if severity:
            cmd.extend(["-severity", severity])

        # KEV only
        if kwargs.get("kev", False):
            cmd.append("-kev")

        # EPSS threshold
        epss = kwargs.get("epss_score")
        if epss:
            cmd.extend(["-epss-score", str(epss)])

        limit = kwargs.get("limit", 100)
        cmd.extend(["-limit", str(limit)])

        cmd.extend(["-json", "-silent"])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        cves = []
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            cve_id = data.get("cve_id", data.get("id", ""))
            severity = data.get("severity", data.get("cvss_severity", "unknown"))
            cvss_score = data.get("cvss_score", data.get("cvss", 0))
            epss_score = data.get("epss_score", data.get("epss", 0))
            is_kev = data.get("is_kev", data.get("kev", False))
            description = data.get("description", "")[:200]
            vendor = data.get("vendor_advisory", data.get("reference", ""))
            product = data.get("product", "")

            cve_record = {
                "cve_id": cve_id,
                "severity": severity,
                "cvss_score": cvss_score,
                "epss_score": epss_score,
                "is_kev": is_kev,
                "product": product,
                "description": description,
            }
            cves.append(cve_record)

            if cve_id:
                tags = ["cvemap", severity.lower()]
                if is_kev:
                    tags.append("kev")

                findings.append({
                    "type": IntelType.VULNERABILITY,
                    "value": f"{cve_id} ({severity}, CVSS {cvss_score})",
                    "source_tool": self.name,
                    "confidence": 0.9 if is_kev else 0.7,
                    "tags": tags,
                    "raw_data": cve_record,
                })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "cves": cves,
                "total_cves": len(cves),
                "kev_count": sum(1 for c in cves if c.get("is_kev")),
                "findings": findings,
            },
        )
