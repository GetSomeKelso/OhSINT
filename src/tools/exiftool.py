"""exiftool — metadata extraction from any file type."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.tools.base import BaseTool

# Fields of interest for OSINT
DEFAULT_FILTER = (
    "Author",
    "Creator",
    "Email",
    "Producer",
    "Template",
    "Software",
    "Company",
    "Manager",
    "LastModifiedBy",
    "LastSavedBy",
    "CreatorTool",
    "MetadataDate",
    "CreateDate",
    "ModifyDate",
    "GPSLatitude",
    "GPSLongitude",
    "GPSPosition",
    "Title",
    "Subject",
    "Description",
    "Comment",
    "Keywords",
    "OwnerName",
    "CameraModelName",
    "LensModel",
)


@register_tool
class ExifTool(BaseTool):
    name = "exiftool"
    description = "Extract metadata from downloaded files"
    binary_name = "exiftool"
    install_cmd = "apt install libimage-exiftool-perl"
    requires_api_keys = ()

    def build_command(self, target: str, **kwargs) -> List[str]:
        """target is a directory or file path for exiftool."""
        cmd = ["exiftool", "-j", "-r"]

        # Add field filter if provided
        filter_fields = kwargs.get("filter_fields")
        if filter_fields:
            for field in filter_fields.split("|"):
                cmd.extend(["-" + field.strip()])
        cmd.append(target)
        return cmd

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        findings = []
        metadata_records = []

        # exiftool -j outputs JSON
        try:
            records = json.loads(raw_output)
            if isinstance(records, list):
                metadata_records = records
        except (json.JSONDecodeError, TypeError):
            # Fallback: parse key:value lines
            metadata_records = self._parse_text_output(raw_output)

        users = set()
        emails = set()
        software = set()
        geolocations = []

        for record in metadata_records:
            filename = record.get("SourceFile", record.get("FileName", "unknown"))

            # Extract people
            for field in ("Author", "Creator", "LastModifiedBy", "LastSavedBy",
                          "Manager", "OwnerName"):
                value = record.get(field, "")
                if value and isinstance(value, str) and len(value) > 1:
                    users.add(value.strip())

            # Extract emails
            for field_name, field_value in record.items():
                if isinstance(field_value, str):
                    for email in re.findall(
                        r'[\w.+-]+@[\w-]+\.[\w.-]+', field_value
                    ):
                        emails.add(email.lower())

            # Extract software/technology
            for field in ("Producer", "Software", "CreatorTool", "Creator"):
                value = record.get(field, "")
                if value and isinstance(value, str) and len(value) > 2:
                    # Avoid adding person names that also appear in Creator
                    if value.strip() not in users:
                        software.add(value.strip())

            # Extract GPS
            lat = record.get("GPSLatitude", "")
            lon = record.get("GPSLongitude", "")
            if lat and lon:
                geolocations.append({
                    "latitude": str(lat),
                    "longitude": str(lon),
                    "source_file": filename,
                })

            # Record as document metadata finding
            interesting = {
                k: v
                for k, v in record.items()
                if k in DEFAULT_FILTER and v
            }
            if interesting:
                findings.append({
                    "type": IntelType.METADATA,
                    "value": f"{filename}: {json.dumps(interesting)}",
                    "source_tool": self.name,
                    "confidence": 0.9,
                    "tags": ["exiftool"],
                })

        # Build typed findings
        for user in sorted(users):
            findings.append({
                "type": IntelType.PERSON,
                "value": user,
                "source_tool": self.name,
                "confidence": 0.7,
                "tags": ["exiftool", "document-metadata"],
            })

        for email in sorted(emails):
            findings.append({
                "type": IntelType.EMAIL,
                "value": email,
                "source_tool": self.name,
                "confidence": 0.8,
                "tags": ["exiftool", "document-metadata"],
            })

        for sw in sorted(software):
            findings.append({
                "type": IntelType.TECHNOLOGY,
                "value": sw,
                "source_tool": self.name,
                "confidence": 0.85,
                "tags": ["exiftool", "document-metadata"],
            })

        for geo in geolocations:
            findings.append({
                "type": IntelType.GEOLOCATION,
                "value": f"{geo['latitude']}, {geo['longitude']}",
                "source_tool": self.name,
                "confidence": 0.9,
                "tags": ["exiftool", "gps", geo["source_file"]],
            })

        return ToolResult(
            tool_name=self.name,
            target=target,
            raw_output=raw_output,
            structured_data={
                "metadata_records": metadata_records,
                "users": sorted(users),
                "emails": sorted(emails),
                "software": sorted(software),
                "geolocations": geolocations,
                "findings": findings,
            },
        )

    def _parse_text_output(self, raw_output: str) -> list:
        """Parse non-JSON exiftool output (key : value per line)."""
        records = []
        current: dict = {}
        for line in raw_output.splitlines():
            if line.startswith("========"):
                if current:
                    records.append(current)
                current = {}
                # Next line after ======== is usually the filename
                continue
            match = re.match(r'^([^:]+?)\s*:\s*(.+)$', line)
            if match:
                key = match.group(1).strip().replace(" ", "")
                value = match.group(2).strip()
                current[key] = value
        if current:
            records.append(current)
        return records
