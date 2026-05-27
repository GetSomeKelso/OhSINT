"""Scope file parsers for bug bounty program asset lists.

Supports:
- Plain text target files (one domain per line)
- HackerOne/Bugcrowd-style scope tables (auto-detects asset type and eligibility)
"""

from __future__ import annotations

import re
from pathlib import Path


def parse_targets_file(path: Path) -> list[str]:
    """Read a plain text file with one domain per line."""
    domains = []
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip protocol prefix if present
        for prefix in ("https://", "http://"):
            if line.lower().startswith(prefix):
                line = line[len(prefix):]
        line = line.rstrip("/").lower()
        if "." in line and not line.startswith("*"):
            domains.append(line)
        elif line.startswith("*."):
            domains.append(line[2:])
    return sorted(set(domains))


def parse_scope_file(path: Path) -> list[dict]:
    """Parse a HackerOne/Bugcrowd-style scope table into structured assets.

    Returns a list of dicts with keys:
      asset_name, asset_type, eligible, severity, notes
    """
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    assets: list[dict] = []

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1

        if not line:
            continue

        # Skip header rows
        if line.lower().startswith("asset name") or line.lower().startswith("---"):
            continue

        # Detect asset line: starts with a domain, IP, CIDR, URL, or wildcard
        asset_name = _extract_asset_name(line)
        if not asset_name:
            continue

        asset_type = _detect_asset_type(asset_name)

        # Look ahead for metadata (type, severity, eligibility) on same or next lines
        # HackerOne format puts these as tab/space separated or on subsequent lines
        context_block = line
        while i < len(lines):
            next_line = lines[i].strip()
            if not next_line:
                i += 1
                continue
            # If next line looks like a new asset, stop
            if _extract_asset_name(next_line) and not _is_metadata_line(next_line):
                break
            context_block += " " + next_line
            i += 1

        eligible = _detect_eligibility(context_block)
        severity = _detect_severity(context_block)
        notes = _extract_notes(context_block, asset_name)

        assets.append({
            "asset_name": asset_name,
            "asset_type": asset_type,
            "eligible": eligible,
            "severity": severity,
            "notes": notes,
        })

    return assets


def extract_domains_from_scope(assets: list[dict], include_ineligible: bool = False) -> list[dict]:
    """Filter scope assets to domain/wildcard types, converting wildcards to base domains.

    Returns list of dicts with asset info, adding 'domain' key with the clean domain.
    """
    results = []
    seen = set()

    for asset in assets:
        atype = asset["asset_type"]
        if atype not in ("Domain", "Wildcard"):
            continue
        if not include_ineligible and not asset["eligible"]:
            continue

        name = asset["asset_name"]
        # Convert wildcards to base domain
        if name.startswith("*."):
            domain = name[2:].lower()
        else:
            # Strip protocol if present
            for prefix in ("https://", "http://"):
                if name.lower().startswith(prefix):
                    name = name[len(prefix):]
            domain = name.rstrip("/").lower()

        if domain not in seen:
            seen.add(domain)
            results.append({**asset, "domain": domain})

    return results


# ── Internal helpers ──────────────────────────────────────────────────

_DOMAIN_RE = re.compile(
    r'^(\*\.)?([a-zA-Z0-9][\w.-]*\.[a-zA-Z]{2,})'
)
_IP_CIDR_RE = re.compile(
    r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)'
)
_URL_RE = re.compile(
    r'^https?://([a-zA-Z0-9][\w.-]*\.[a-zA-Z]{2,})'
)


def _extract_asset_name(line: str) -> str:
    """Extract the leading asset name from a scope line."""
    line = line.strip()

    m = _URL_RE.match(line)
    if m:
        return line.split()[0]

    m = _DOMAIN_RE.match(line)
    if m:
        return m.group(0).lower()

    m = _IP_CIDR_RE.match(line)
    if m:
        return m.group(1)

    return ""


def _detect_asset_type(name: str) -> str:
    if name.startswith("*."):
        return "Wildcard"
    if name.startswith("http://") or name.startswith("https://"):
        return "URL"
    if "/" in name and _IP_CIDR_RE.match(name):
        return "CIDR"
    if _IP_CIDR_RE.match(name) and "/" not in name:
        return "IP"
    return "Domain"


def _detect_eligibility(text: str) -> bool:
    text_lower = text.lower()
    if "ineligible" in text_lower:
        return False
    if "eligible" in text_lower:
        return True
    if "out of scope" in text_lower or "out-of-scope" in text_lower:
        return False
    return True


def _detect_severity(text: str) -> str:
    text_lower = text.lower()
    for sev in ("critical", "high", "medium", "low"):
        if sev in text_lower:
            return sev.capitalize()
    if "none" in text_lower:
        return "None"
    return "Unknown"


def _is_metadata_line(line: str) -> bool:
    """Check if a line is metadata (type, severity, etc.) rather than a new asset."""
    line_lower = line.strip().lower()
    metadata_keywords = ("domain", "wildcard", "cidr", "url", "critical", "high",
                         "medium", "low", "eligible", "ineligible", "none")
    return any(line_lower.startswith(kw) for kw in metadata_keywords)


def _extract_notes(context: str, asset_name: str) -> str:
    """Extract description/notes from the context block, stripping the asset name."""
    # Remove the asset name itself
    text = context.replace(asset_name, "", 1).strip()
    # Remove common metadata keywords
    for keyword in ("Domain", "Wildcard", "CIDR", "URL", "Critical", "High",
                    "Medium", "Low", "None", "Eligible", "Ineligible"):
        text = text.replace(keyword, "").strip()
    # Clean up whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    # Remove leading/trailing punctuation artifacts
    text = text.strip("| \t")
    return text[:500] if text else ""
