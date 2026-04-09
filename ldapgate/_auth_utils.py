"""Shared Basic auth parsing and rate limiting utilities."""

import base64
import binascii
import logging
import time
from collections import defaultdict
from typing import Optional

log = logging.getLogger(__name__)


def parse_basic_auth(authorization: str) -> Optional[tuple[str, str]]:
    """Parse an Authorization: Basic header. Returns (username, password) or None."""
    if not authorization.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(authorization[6:]).decode("utf-8", errors="strict")
        username, _, password = decoded.partition(":")
        if not username:
            return None
        return username, password
    except (binascii.Error, UnicodeDecodeError):
        return None


class BasicAuthRateLimiter:
    """Per-IP sliding-window rate limiter for Basic auth failures.

    After MAX_FAILURES failed attempts within WINDOW_SECONDS, the IP is locked
    out for LOCKOUT_SECONDS. A successful auth clears the counter.

    NOTE: state is per-process. With multiple uvicorn workers the effective
    threshold is MAX_FAILURES * workers. Run single-process (the default
    ``ldapgate serve``) or back this with a shared cache (Redis, etc.) if
    stricter limits are required.
    """

    MAX_FAILURES = 5
    WINDOW_SECONDS = 300   # count failures within this rolling window
    LOCKOUT_SECONDS = 60   # lockout duration once threshold is reached

    def __init__(self) -> None:
        # ip -> list of failure timestamps (monotonic)
        self._failures: dict[str, list[float]] = defaultdict(list)
        # ip -> lockout-expiry timestamp (monotonic)
        self._lockouts: dict[str, float] = {}

    def _prune_stale(self, ip: str, now: float) -> None:
        """Remove expired failure entries for an IP."""
        if ip in self._failures:
            self._failures[ip] = [t for t in self._failures[ip] if now - t < self.WINDOW_SECONDS]
            if not self._failures[ip]:
                del self._failures[ip]

    def is_locked_out(self, ip: str) -> bool:
        now = time.monotonic()
        lockout_until = self._lockouts.get(ip, 0.0)
        if now < lockout_until:
            return True
        if ip in self._lockouts:
            # Lockout expired — clear state
            del self._lockouts[ip]
            self._failures.pop(ip, None)
            return False
        self._prune_stale(ip, now)
        return False

    def record_failure(self, ip: str) -> None:
        now = time.monotonic()
        window = [t for t in self._failures[ip] if now - t < self.WINDOW_SECONDS]
        window.append(now)
        self._failures[ip] = window
        if len(window) >= self.MAX_FAILURES:
            self._lockouts[ip] = now + self.LOCKOUT_SECONDS
            log.warning("Basic auth: IP %s locked out after %d failures", ip, len(window))
        else:
            log.warning("Basic auth: failed attempt from IP %s (%d/%d)", ip, len(window), self.MAX_FAILURES)

    def record_success(self, ip: str) -> None:
        self._failures.pop(ip, None)
        self._lockouts.pop(ip, None)
