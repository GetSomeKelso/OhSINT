"""OPSEC-aware HTTP client for OhSINT.

Provides User-Agent rotation, per-host rate limiting, cookie suppression,
and optional proxy egress for all direct HTTP calls.

All API-based tools and pipeline HTTP calls should use this client
instead of constructing httpx.Client directly.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from src.config import Config

logger = logging.getLogger("ohsint.http_client")

_DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


class OhSINTHTTPClient:
    """OPSEC-aware HTTP client with UA rotation, rate limiting, and proxy support.

    Usage:
        client = OhSINTHTTPClient(config, timeout=30)
        resp = client.get("https://api.example.com/data", params={"q": "test"})
        resp = client.post("https://api.example.com/search", json={"query": "test"})

    Tool-specific auth headers are passed via the `headers` parameter and
    get merged on top of the OPSEC headers (UA, Accept-Language).
    """

    def __init__(self, config: Optional[Config] = None, timeout: int = 30):
        self._config = config or Config()
        self._opsec = self._config.get_opsec_config()
        self._hygiene = self._opsec.get("request_hygiene", {})
        self._egress = self._opsec.get("egress", {})
        self._timeout = timeout

        # Rate limiter state: host -> last_request_timestamp
        self._rate_state: dict[str, float] = {}

        # UA pool
        self._user_agents = self._hygiene.get("user_agents", [_DEFAULT_UA])
        if not self._user_agents:
            self._user_agents = [_DEFAULT_UA]

        # Rate limits
        rate_cfg = self._hygiene.get("rate_limits", {})
        self._default_rpm = rate_cfg.get("default_rpm", 10)
        self._per_host_rpm: dict[str, int] = rate_cfg.get("per_host", {})

        # Delay config
        self._delay_min = self._hygiene.get("request_delay_min_seconds", 0.0)
        self._delay_max = self._hygiene.get("request_delay_max_seconds", 0.0)
        self._randomize_delay = self._hygiene.get("randomize_delay", False)

        # Proxy config
        self._proxy_url: str | None = None
        if self._egress.get("enabled"):
            ptype = self._egress.get("proxy_type", "socks5")
            phost = self._egress.get("proxy_host", "127.0.0.1")
            pport = self._egress.get("proxy_port", 9050)
            user = self._egress.get("proxy_username", "")
            passwd = self._egress.get("proxy_password", "")
            if user and passwd:
                self._proxy_url = f"{ptype}://{user}:{passwd}@{phost}:{pport}"
            else:
                self._proxy_url = f"{ptype}://{phost}:{pport}"
            logger.debug("OPSEC proxy enabled: %s://%s:%s", ptype, phost, pport)

    def get(
        self,
        url: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
        auth: Any = None,
        follow_redirects: bool = False,
    ) -> httpx.Response:
        """Send a GET request with OPSEC protections."""
        self._enforce_rate_limit(url)
        merged_headers = self._build_headers(headers)
        with self._make_client(auth=auth, follow_redirects=follow_redirects) as client:
            return client.get(url, params=params, headers=merged_headers)

    def post(
        self,
        url: str,
        *,
        json: Any = None,
        data: Any = None,
        headers: dict | None = None,
        auth: Any = None,
    ) -> httpx.Response:
        """Send a POST request with OPSEC protections."""
        self._enforce_rate_limit(url)
        merged_headers = self._build_headers(headers)
        with self._make_client(auth=auth) as client:
            return client.post(url, json=json, data=data, headers=merged_headers)

    def head(
        self,
        url: str,
        *,
        headers: dict | None = None,
        follow_redirects: bool = False,
    ) -> httpx.Response:
        """Send a HEAD request with OPSEC protections."""
        self._enforce_rate_limit(url)
        merged_headers = self._build_headers(headers)
        with self._make_client(follow_redirects=follow_redirects) as client:
            return client.head(url, headers=merged_headers)

    def __enter__(self):
        """Support context manager usage for drop-in httpx.Client replacement."""
        return self

    def __exit__(self, *args):
        pass

    # ── Internal helpers ──────────────────────────────────────────────

    def _make_client(self, auth: Any = None, follow_redirects: bool = False) -> httpx.Client:
        """Construct an httpx.Client with OPSEC settings."""
        kwargs: dict[str, Any] = {
            "timeout": self._timeout,
            "follow_redirects": follow_redirects,
        }

        if auth is not None:
            kwargs["auth"] = auth

        # Proxy
        if self._proxy_url:
            kwargs["proxy"] = self._proxy_url

        # Disable cookies
        if self._hygiene.get("cookies_disabled", True):
            kwargs["cookies"] = None

        return httpx.Client(**kwargs)

    def _build_headers(self, tool_headers: dict | None = None) -> dict:
        """Build request headers: random UA + Accept-Language, merged with tool-specific headers."""
        headers: dict[str, str] = {}

        # Random User-Agent
        if self._hygiene.get("rotate_user_agent", True) and self._user_agents:
            headers["User-Agent"] = random.choice(self._user_agents)
        else:
            headers["User-Agent"] = _DEFAULT_UA

        # Standard non-fingerprinting headers
        headers["Accept-Language"] = "en-US,en;q=0.9"

        # Merge tool-specific headers ON TOP (tool auth headers take precedence)
        if tool_headers:
            headers.update(tool_headers)

        return headers

    def _enforce_rate_limit(self, url: str) -> None:
        """Enforce per-host rate limiting with optional randomized delay."""
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            host = ""

        if not host:
            return

        # Get RPM limit for this host
        rpm = self._per_host_rpm.get(host, self._default_rpm)
        if rpm <= 0:
            return

        min_interval = 60.0 / rpm
        now = time.time()
        last = self._rate_state.get(host, 0.0)
        elapsed = now - last

        if elapsed < min_interval:
            wait = min_interval - elapsed
            logger.debug("Rate limiting %s: waiting %.1fs", host, wait)
            time.sleep(wait)

        # Add randomized delay if configured
        if self._randomize_delay and self._delay_max > 0:
            delay = random.uniform(self._delay_min, self._delay_max)
            time.sleep(delay)

        self._rate_state[host] = time.time()
