"""Smart target resolution — takes a raw input like 'Walmart' and resolves it
into the correct format for each tool (domain, GitHub handle, org name, etc.)."""

from __future__ import annotations

import logging
import re
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from typing import ClassVar
from pydantic import BaseModel, Field

logger = logging.getLogger("ohsint.target")

# ── Common TLDs for domain-guessing heuristics ──────────────────────────────
_COMMON_TLDS = frozenset({
    "com", "org", "net", "io", "co", "gov", "edu", "mil",
    "us", "uk", "ca", "au", "de", "fr", "jp", "cn", "in",
    "co.uk", "com.au", "co.jp",
})

# Well-known org-name → GitHub-handle overrides (extend as needed)
_GITHUB_OVERRIDES: dict[str, str] = {
    "walmart": "walmartlabs",
    "meta": "facebook",
    "alphabet": "google",
    "microsoft": "microsoft",
    "tesla": "teslamotors",
    "amazon": "amzn",
    "apple": "apple",
    "netflix": "netflix",
    "uber": "uber",
    "airbnb": "airbnb",
    "twitter": "twitter",
    "x": "twitter",
    "spacex": "spacex",
    "ibm": "ibm",
    "oracle": "oracle",
    "adobe": "adobe",
    "salesforce": "salesforce",
    "slack": "slackhq",
    "spotify": "spotify",
    "stripe": "stripe",
    "shopify": "shopify",
    "cloudflare": "cloudflare",
    "github": "github",
    "reddit": "reddit",
    "discord": "discord",
    "twitch": "twitchtv",
}

# Known org-name → domain overrides
_DOMAIN_OVERRIDES: dict[str, str] = {
    "meta": "meta.com",
    "alphabet": "abc.xyz",
    "x": "x.com",
    "spacex": "spacex.com",
}


# ── Target types ─────────────────────────────────────────────────────────────

class TargetType(str, Enum):
    """What kind of target a tool expects or the user provided."""
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    GITHUB_HANDLE = "github_handle"
    ORG_NAME = "org_name"
    PERSON_NAME = "person_name"
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    FILEPATH = "filepath"
    URL = "url"


# ── Resolved target ─────────────────────────────────────────────────────────

class ResolvedTarget(BaseModel):
    """All resolved variants of a user-supplied target string."""

    raw: str
    detected_type: TargetType
    confidence: float = Field(ge=0.0, le=1.0)

    domain: Optional[str] = None
    ip: Optional[str] = None
    cidr: Optional[str] = None
    github_handle: Optional[str] = None
    org_name: Optional[str] = None
    person_name: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    filepath: Optional[str] = None
    url: Optional[str] = None

    _FIELD_MAP: ClassVar[dict[TargetType, str]] = {
        TargetType.DOMAIN: "domain",
        TargetType.IP: "ip",
        TargetType.CIDR: "cidr",
        TargetType.GITHUB_HANDLE: "github_handle",
        TargetType.ORG_NAME: "org_name",
        TargetType.PERSON_NAME: "person_name",
        TargetType.USERNAME: "username",
        TargetType.EMAIL: "email",
        TargetType.PHONE: "phone",
        TargetType.FILEPATH: "filepath",
        TargetType.URL: "url",
    }

    def get_for(self, accepted: Tuple[TargetType, ...]) -> str:
        """Return the best target string for a tool that accepts *accepted* types.

        Iterates in the order given (first = highest priority) and returns the
        first variant that has a value.  Falls back to ``raw`` so tools never
        receive ``None``.
        """
        for tt in accepted:
            field = self._FIELD_MAP.get(tt)
            if field:
                val = getattr(self, field, None)
                if val is not None:
                    return val
        return self.raw

    def summary_dict(self) -> dict[str, str]:
        """Return a compact dict of non-None resolved fields (for reports)."""
        out: dict[str, str] = {
            "raw": self.raw,
            "detected_type": self.detected_type.value,
            "confidence": f"{self.confidence:.0%}",
        }
        for tt, field in self._FIELD_MAP.items():
            val = getattr(self, field, None)
            if val is not None:
                out[field] = val
        return out


# ── Detection strategies ─────────────────────────────────────────────────────

_IP_RE = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)
_CIDR_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"
)
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)
_EMAIL_RE = re.compile(
    r"^[\w.+-]+@[\w-]+\.[\w.-]+$"
)
# Phone: +1-555-867-5309, +44 20 7946 0958, (555) 867-5309, etc.
_PHONE_RE = re.compile(
    r"^\+?\d[\d\s.()-]{6,18}\d$"
)
_URL_RE = re.compile(
    r"^https?://", re.IGNORECASE
)
_GITHUB_PREFIX_RE = re.compile(
    r"^(?:gh:|github:)", re.IGNORECASE
)
_GITHUB_URL_RE = re.compile(
    r"github\.com/([A-Za-z0-9_.-]+)", re.IGNORECASE
)


def _is_valid_ip(s: str) -> bool:
    m = _IP_RE.match(s)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def _detect(raw: str) -> Tuple[TargetType, float]:
    """Classify what the raw string IS with a confidence score."""
    s = raw.strip()

    # Filepath — starts with / or drive letter or contains path seps + extension
    if (
        s.startswith("/")
        or s.startswith("./")
        or re.match(r"^[A-Za-z]:[/\\]", s)
    ):
        return TargetType.FILEPATH, 0.95

    # URL
    if _URL_RE.match(s):
        # Could also be a GitHub URL
        gh = _GITHUB_URL_RE.search(s)
        if gh:
            return TargetType.GITHUB_HANDLE, 0.9
        return TargetType.URL, 0.95

    # GitHub prefix (gh:org or github:org)
    if _GITHUB_PREFIX_RE.match(s):
        return TargetType.GITHUB_HANDLE, 0.95

    # CIDR — must come before IP check
    if _CIDR_RE.match(s):
        return TargetType.CIDR, 0.95

    # IP
    if _is_valid_ip(s):
        return TargetType.IP, 0.95

    # Email
    if _EMAIL_RE.match(s):
        return TargetType.EMAIL, 0.95

    # Phone number — after email/IP to avoid false matches
    if _PHONE_RE.match(s) and sum(c.isdigit() for c in s) >= 7:
        return TargetType.PHONE, 0.90

    # Domain — has dots and a valid TLD
    if _DOMAIN_RE.match(s) and "." in s:
        return TargetType.DOMAIN, 0.9

    # Username — starts with @
    if s.startswith("@") and len(s) > 1 and " " not in s:
        return TargetType.USERNAME, 0.85

    # At this point it's either an org name or a person name.
    # Heuristic: multiple capitalised words → person name;
    # single word or clearly-a-company → org name.
    words = s.split()
    if len(words) >= 2 and all(w[0].isupper() for w in words if w[0].isalpha()):
        # Could be person or org — check for common org suffixes
        lower = s.lower()
        if any(
            lower.endswith(suf)
            for suf in (" inc", " llc", " ltd", " corp", " co", " group",
                        " labs", " technologies", " tech")
        ):
            return TargetType.ORG_NAME, 0.7
        # Two-word names lean person, but it's ambiguous
        return TargetType.PERSON_NAME, 0.5

    # Single word — likely an org name
    return TargetType.ORG_NAME, 0.6


# ── Derivation logic ─────────────────────────────────────────────────────────

def _strip_tld(domain: str) -> str:
    """Return the second-level label from a domain.  ``walmart.com`` → ``walmart``."""
    parts = domain.rsplit(".", 1)
    if len(parts) == 2:
        sld = parts[0]
        # Handle cases like sub.walmart.co.uk → take the last sld segment
        if "." in sld:
            sld = sld.rsplit(".", 1)[-1]
        return sld
    return domain


def _derive(target: ResolvedTarget) -> None:
    """Fill in missing variants using cheap heuristics (no network calls)."""

    # ── From DOMAIN ──
    if target.domain:
        sld = _strip_tld(target.domain)
        if target.org_name is None:
            target.org_name = sld.replace("-", " ").title()
        if target.github_handle is None:
            key = sld.lower().replace("-", "")
            target.github_handle = _GITHUB_OVERRIDES.get(key, sld.lower())
        if target.url is None:
            target.url = f"https://{target.domain}"

    # ── From ORG_NAME ──
    if target.org_name:
        slug = re.sub(r"[^a-z0-9]+", "", target.org_name.lower())
        if target.domain is None:
            target.domain = _DOMAIN_OVERRIDES.get(slug, f"{slug}.com")
        if target.github_handle is None:
            target.github_handle = _GITHUB_OVERRIDES.get(slug, slug)
        if target.url is None and target.domain:
            target.url = f"https://{target.domain}"

    # ── From PERSON_NAME ──
    if target.person_name:
        if target.username is None:
            target.username = target.person_name.lower().replace(" ", "")

    # ── From USERNAME ──
    if target.username:
        clean = target.username.lstrip("@")
        if target.person_name is None:
            # Can't reliably derive a real name; leave None
            pass
        # Make sure the @ is stripped for tools
        target.username = clean

    # ── From EMAIL ──
    if target.email:
        domain_part = target.email.split("@", 1)[-1]
        if target.domain is None:
            target.domain = domain_part
        # Re-derive from the newly-set domain
        if target.domain and target.org_name is None:
            sld = _strip_tld(target.domain)
            target.org_name = sld.replace("-", " ").title()
        if target.domain and target.github_handle is None:
            sld = _strip_tld(target.domain)
            key = sld.lower().replace("-", "")
            target.github_handle = _GITHUB_OVERRIDES.get(key, sld.lower())

    # ── From URL ──
    if target.url and target.domain is None:
        parsed = urlparse(target.url)
        if parsed.hostname:
            target.domain = parsed.hostname
            # Trigger domain derivation
            _derive(target)  # safe: domain is now set so the recursion is bounded

    # ── From GITHUB_HANDLE ──
    if target.github_handle:
        # Strip prefixes if present
        handle = target.github_handle
        for prefix in ("gh:", "github:", "https://github.com/"):
            if handle.lower().startswith(prefix):
                handle = handle[len(prefix):].strip("/")
        target.github_handle = handle

    # ── From PHONE ──
    # Can't derive other fields from a bare phone number without API lookups.

    # ── From IP ──
    # Can't derive much from a bare IP without DNS.  Leave other fields as-is.

    # ── From CIDR ──
    # Similar — CIDR is network-specific.


# ── Public resolver ──────────────────────────────────────────────────────────

class TargetResolver:
    """Detects and resolves a raw target string into all useful variants."""

    def resolve(self, raw: str) -> ResolvedTarget:
        """Detect what *raw* is, then derive all useful variants."""
        raw = raw.strip()
        detected_type, confidence = _detect(raw)

        target = ResolvedTarget(
            raw=raw,
            detected_type=detected_type,
            confidence=confidence,
        )

        # Set the primary field matching the detected type
        primary_field = ResolvedTarget._FIELD_MAP.get(detected_type)
        if primary_field:
            # Special handling for GitHub prefix stripping
            value = raw
            if detected_type == TargetType.GITHUB_HANDLE:
                for prefix in ("gh:", "github:"):
                    if value.lower().startswith(prefix):
                        value = value[len(prefix):].strip()
                gh_url = _GITHUB_URL_RE.search(value)
                if gh_url:
                    value = gh_url.group(1)
            setattr(target, primary_field, value)

        # Derive all other variants
        _derive(target)

        logger.info(
            "Resolved %r → detected=%s (%.0f%%), domain=%s, github=%s, org=%s",
            raw, detected_type.value, confidence * 100,
            target.domain, target.github_handle, target.org_name,
        )

        return target
