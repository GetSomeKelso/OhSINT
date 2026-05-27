"""Shared URL classification constants and helpers for URL-harvesting tools.

Used by waymore, gau, waybackurls, and the url_harvest pipeline.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from src.models import IntelType


# File extensions that indicate sensitive/interesting content
SENSITIVE_EXTENSIONS = frozenset({
    ".env", ".bak", ".sql", ".log", ".conf", ".config", ".cfg",
    ".ini", ".yml", ".yaml", ".json", ".xml", ".key", ".pem",
    ".crt", ".p12", ".pfx", ".old", ".backup", ".dump", ".tar",
    ".gz", ".zip", ".rar",
})

DOCUMENT_EXTENSIONS = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp", ".csv", ".rtf",
})

TECH_PATTERNS = [
    (r'/api/', "api-endpoint"),
    (r'/v[12]/api', "api-endpoint"),
    (r'/graphql', "graphql"),
    (r'/swagger', "swagger"),
    (r'/wp-', "wordpress"),
    (r'/wp-admin', "wordpress-admin"),
    (r'/wp-content/plugins', "wordpress-plugin"),
    (r'/administrator', "admin-panel"),
    (r'/phpmyadmin', "phpmyadmin"),
    (r'\.php\?', "php"),
    (r'\.asp', "asp"),
    (r'\.jsp', "jsp"),
    (r'/cgi-bin/', "cgi"),
]

JS_EXTENSIONS = frozenset({".js", ".mjs", ".jsx", ".ts", ".tsx"})


def classify_url(url: str, source_tool: str = "unknown") -> dict | None:
    """Classify a URL into a finding dict, or return None if uninteresting.

    Returns a dict suitable for IntelFinding construction:
    {"type": IntelType, "value": str, "source_tool": str, "confidence": float, "tags": list}
    """
    try:
        parsed = urlparse(url)
        path = (parsed.path or "").lower()
    except Exception:
        return None

    lower = url.lower()

    # Sensitive files
    for ext in SENSITIVE_EXTENSIONS:
        if path.endswith(ext) or ext + "?" in path:
            return {
                "type": IntelType.SENSITIVE_FILE,
                "value": url,
                "source_tool": source_tool,
                "confidence": 0.7,
                "tags": [source_tool, "archived", f"ext:{ext}"],
            }

    # Documents
    for ext in DOCUMENT_EXTENSIONS:
        if path.endswith(ext):
            return {
                "type": IntelType.DOCUMENT,
                "value": url,
                "source_tool": source_tool,
                "confidence": 0.7,
                "tags": [source_tool, "archived", "document"],
            }

    # Tech indicators
    for pattern, tag in TECH_PATTERNS:
        if re.search(pattern, lower):
            return {
                "type": IntelType.TECHNOLOGY,
                "value": f"{tag}: {url}",
                "source_tool": source_tool,
                "confidence": 0.6,
                "tags": [source_tool, "archived", tag],
            }

    return None


def extract_subdomain(url: str, target_domain: str) -> str | None:
    """Extract subdomain from a URL if it belongs to the target domain."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if hostname and hostname.endswith(f".{target_domain}"):
            return hostname
    except Exception:
        pass
    return None


def is_js_url(url: str) -> bool:
    """Check if a URL points to a JavaScript file."""
    try:
        parsed = urlparse(url)
        path = (parsed.path or "").lower()
        return any(path.endswith(ext) for ext in JS_EXTENSIONS) or ".js?" in path.lower()
    except Exception:
        return False
