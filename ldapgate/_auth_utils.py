"""Shared Basic auth parsing and rate limiting utilities."""

import base64
import binascii
import hashlib
import json
import ipaddress
import logging
import os
import stat
import time
from collections import defaultdict
from pathlib import Path
from typing import List, Optional

import fcntl

log = logging.getLogger(__name__)


def _is_ip_in_networks(ip_str: str, networks: List[str]) -> bool:
    """Check if an IP string matches any of the CIDR or exact IP entries."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for entry in networks:
        try:
            if "/" in entry:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if ip == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


def get_client_ip(request, trusted_proxies: Optional[List[str]] = None) -> str:
    """Get the real client IP, respecting trusted proxies for X-Forwarded-For.

    When trusted_proxies are configured, walks the X-Forwarded-For chain
    from right to left (most recent first), skipping entries that match
    a trusted proxy. The first untrusted IP is the real client. Falls back
    to the direct connection IP.
    """
    direct_ip = request.client.host if request.client else "unknown"
    if not trusted_proxies:
        return direct_ip
    if not _is_ip_in_networks(direct_ip, trusted_proxies):
        return direct_ip

    xff = request.headers.get("x-forwarded-for")
    if not xff:
        return direct_ip

    # Walk right-to-left; the first non-trusted IP is the real client
    entries = [e.strip() for e in xff.split(",")]
    for entry in reversed(entries):
        if not entry:
            continue
        if not _is_ip_in_networks(entry, trusted_proxies):
            return entry

    # All entries were trusted proxies — fall back to direct
    return direct_ip


def _is_safe_host(host: str) -> bool:
    """Validate that a Host header value is a legitimate host[:port] string.

    Rejects values containing scheme prefixes, path separators, userinfo
    components, whitespace, or other characters that could indicate header
    manipulation.
    """
    if not host:
        return False
    if len(host) > 255:
        return False
    if "://" in host:
        return False
    dangerous = ("\t", "\n", "\r", "\x0b", "\x0c", "\x00", "/", "\\", "@")
    if any(c in host for c in dangerous):
        return False
    return True


def _is_trusted_host(host: str, trusted_hosts: list[str]) -> bool:
    """Check if a Host header value is in the trusted hosts list (case-insensitive)."""
    if not trusted_hosts:
        return True
    host_lower = host.lower()
    return any(th.lower() == host_lower for th in trusted_hosts)


def parse_basic_auth(authorization: str) -> Optional[tuple[str, str]]:
    """Parse an Authorization: Basic header. Returns (username, password) or None."""
    if not authorization.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(authorization[6:]).decode("utf-8", errors="strict")
        username, _, password = decoded.partition(":")
        username = username.strip()
        if not username or not password:
            return None
        return username, password
    except (binascii.Error, UnicodeDecodeError):
        return None


class BasicAuthRateLimiter:
    """Per-IP and per-username sliding-window rate limiter for auth failures.

    After MAX_FAILURES failed attempts within WINDOW_SECONDS, the IP (or user)
    is locked out for LOCKOUT_SECONDS. A successful auth clears the counter.

    By default state is per-process. Pass ``state_path`` to share counters
    across workers through a small locked JSON file.
    """

    _PRUNE_INTERVAL = 60  # minimum seconds between full pruning
    _MAX_TRACKED = 10_000  # max unique IPs + usernames tracked before forced eviction

    def __init__(
        self,
        max_failures: int = 5,
        window_seconds: int = 300,
        lockout_seconds: int = 60,
        state_path: Optional[str] = None,
        mask_usernames_in_logs: bool = True,
    ) -> None:
        self.MAX_FAILURES = max_failures
        self.WINDOW_SECONDS = window_seconds
        self.LOCKOUT_SECONDS = lockout_seconds
        # ip -> list of failure timestamps
        self._failures: dict[str, list[float]] = defaultdict(list)
        # ip -> lockout-expiry timestamp
        self._lockouts: dict[str, float] = {}
        # username -> list of failure timestamps
        self._user_failures: dict[str, list[float]] = defaultdict(list)
        # username -> lockout-expiry timestamp
        self._user_lockouts: dict[str, float] = {}
        self._last_prune: float = 0.0
        self._state_path = Path(state_path) if state_path else None
        self._mask_usernames_in_logs = mask_usernames_in_logs

    def _username_for_log(self, username: str) -> str:
        if not self._mask_usernames_in_logs:
            return username.replace("\r", "").replace("\n", "")
        h = hashlib.sha256(username.encode()).hexdigest()[:8]
        safe = username.strip()
        prefix = safe[0] if safe else "?"
        return f"{prefix}***{h}"

    def _prune_all(self, now: float) -> None:
        """Remove expired entries from all tracking dicts."""
        if now - self._last_prune < self._PRUNE_INTERVAL:
            return
        self._last_prune = now

        for ip in list(self._failures):
            self._failures[ip] = [t for t in self._failures[ip] if now - t < self.WINDOW_SECONDS]
            if not self._failures[ip]:
                del self._failures[ip]

        for ip in list(self._lockouts):
            if now >= self._lockouts[ip]:
                del self._lockouts[ip]

        for user in list(self._user_failures):
            self._user_failures[user] = [t for t in self._user_failures[user] if now - t < self.WINDOW_SECONDS]
            if not self._user_failures[user]:
                del self._user_failures[user]

        for user in list(self._user_lockouts):
            if now >= self._user_lockouts[user]:
                del self._user_lockouts[user]

    def _load_shared_state_unlocked(self, fd: int, now: float) -> None:
        self._failures = defaultdict(list)
        self._lockouts = {}
        self._user_failures = defaultdict(list)
        self._user_lockouts = {}
        os.lseek(fd, 0, os.SEEK_SET)
        raw_parts = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            raw_parts.append(chunk)
        raw = b"".join(raw_parts)
        if not raw:
            return
        try:
            data = json.loads(raw.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        if not isinstance(data, dict):
            return

        def _float_list(value):
            if not isinstance(value, list):
                return []
            return [float(v) for v in value if isinstance(v, (int, float))]

        failures = data.get("failures", {})
        if not isinstance(failures, dict):
            failures = {}
        self._failures = defaultdict(
            list,
            {
                str(k): [t for t in _float_list(v) if now - t < self.WINDOW_SECONDS]
                for k, v in failures.items()
            },
        )
        lockouts = data.get("lockouts", {})
        if not isinstance(lockouts, dict):
            lockouts = {}
        self._lockouts = {
            str(k): float(v)
            for k, v in lockouts.items()
            if isinstance(v, (int, float))
            and now < float(v)
        }
        user_failures = data.get("user_failures", {})
        if not isinstance(user_failures, dict):
            user_failures = {}
        self._user_failures = defaultdict(
            list,
            {
                str(k): [t for t in _float_list(v) if now - t < self.WINDOW_SECONDS]
                for k, v in user_failures.items()
            },
        )
        user_lockouts = data.get("user_lockouts", {})
        if not isinstance(user_lockouts, dict):
            user_lockouts = {}
        self._user_lockouts = {
            str(k): float(v)
            for k, v in user_lockouts.items()
            if isinstance(v, (int, float))
            and now < float(v)
        }

    def _save_shared_state_unlocked(self, fd: int) -> None:
        data = {
            "failures": dict(self._failures),
            "lockouts": self._lockouts,
            "user_failures": dict(self._user_failures),
            "user_lockouts": self._user_lockouts,
        }
        serialized = json.dumps(data).encode()
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, serialized)

    def _with_shared_state(self, mutate):
        if not self._state_path:
            return mutate(time.monotonic())

        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self._state_path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError:
            return mutate(time.monotonic())

        locked = False
        try:
            st = os.fstat(fd)
            if stat.S_IMODE(st.st_mode) & 0o177:
                log.error(
                    "Rate-limit state file %s has insecure permissions (%s). "
                    "Expected 0o600. Falling back to in-memory rate limiting.",
                    self._state_path, oct(stat.S_IMODE(st.st_mode)),
                )
                return mutate(time.monotonic())
            fcntl.flock(fd, fcntl.LOCK_EX)
            locked = True
            now = time.time()
            self._load_shared_state_unlocked(fd, now)
            result = mutate(now)
            self._prune_all(now)
            self._save_shared_state_unlocked(fd)
            return result
        finally:
            if locked:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _prune_ip(self, ip: str, now: float) -> None:
        """Remove expired failure entries for an IP."""
        if ip in self._failures:
            self._failures[ip] = [t for t in self._failures[ip] if now - t < self.WINDOW_SECONDS]
            if not self._failures[ip]:
                del self._failures[ip]

    def _prune_user(self, user: str, now: float) -> None:
        """Remove expired failure entries for a user."""
        if user in self._user_failures:
            self._user_failures[user] = [t for t in self._user_failures[user] if now - t < self.WINDOW_SECONDS]
            if not self._user_failures[user]:
                del self._user_failures[user]

    def _enforce_capacity(self, now: float) -> None:
        """Evict oldest entries when tracking dicts exceed _MAX_TRACKED."""
        total = len(self._failures) + len(self._user_failures)
        if total <= self._MAX_TRACKED:
            return
        self._last_prune = 0
        self._prune_all(now)
        total = len(self._failures) + len(self._user_failures)
        if total <= self._MAX_TRACKED:
            return
        for d, lockouts in ((self._failures, self._lockouts),
                            (self._user_failures, self._user_lockouts)):
            while len(d) + len(self._failures) + len(self._user_failures) > self._MAX_TRACKED and d:
                oldest_key = min(d, key=lambda k: min(d[k]) if d[k] else now)
                del d[oldest_key]
                lockouts.pop(oldest_key, None)

    def is_locked_out(self, ip: str, username: Optional[str] = None) -> bool:
        def _check(now: float) -> bool:
            self._prune_all(now)

            lockout_until = self._lockouts.get(ip, 0.0)
            if now < lockout_until:
                return True
            if ip in self._lockouts:
                del self._lockouts[ip]
                self._failures.pop(ip, None)

            if username:
                username_lower = username.lower()
                user_lockout_until = self._user_lockouts.get(username_lower, 0.0)
                if now < user_lockout_until:
                    return True
                if username_lower in self._user_lockouts:
                    del self._user_lockouts[username_lower]
                    self._user_failures.pop(username_lower, None)

            self._prune_ip(ip, now)
            return False

        return self._with_shared_state(_check)

    def record_failure(self, ip: str, username: Optional[str] = None) -> None:
        def _record(now: float) -> None:
            self._enforce_capacity(now)
            self._prune_all(now)

            window = [t for t in self._failures[ip] if now - t < self.WINDOW_SECONDS]
            window.append(now)
            self._failures[ip] = window
            if len(window) >= self.MAX_FAILURES:
                self._lockouts[ip] = now + self.LOCKOUT_SECONDS
                log.warning("Basic auth: IP %s locked out after %d failures "
                            "(NOTE: limit is per-process unless shared state is configured)",
                            ip, len(window))
            else:
                log.warning("Basic auth: failed attempt from IP %s (%d/%d)", ip, len(window), self.MAX_FAILURES)

            if username:
                username_lower = username.lower()
                user_window = [t for t in self._user_failures[username_lower] if now - t < self.WINDOW_SECONDS]
                user_window.append(now)
                self._user_failures[username_lower] = user_window
                if len(user_window) >= self.MAX_FAILURES:
                    self._user_lockouts[username_lower] = now + self.LOCKOUT_SECONDS
                    log.warning("Basic auth: user %s locked out after %d failures",
                               self._username_for_log(username_lower), len(user_window))

        self._with_shared_state(_record)

    def record_success(self, ip: str, username: Optional[str] = None) -> None:
        def _clear(_now: float) -> None:
            self._failures.pop(ip, None)
            self._lockouts.pop(ip, None)
            if username:
                username_lower = username.lower()
                self._user_failures.pop(username_lower, None)
                self._user_lockouts.pop(username_lower, None)

        self._with_shared_state(_clear)


class BasicAuthSuccessCache:
    """Short-lived in-memory cache for successful Basic auth credentials."""

    _PRUNE_INTERVAL = 60

    def __init__(self, ttl_seconds: int = 60) -> None:
        self.ttl_seconds = max(0, ttl_seconds)
        self._entries: dict[tuple[str, str], float] = {}
        self._last_prune = 0.0

    @staticmethod
    def _key(username: str, password: str) -> tuple[str, str]:
        return username.strip().lower(), hashlib.sha256(password.encode()).hexdigest()

    def is_valid(self, username: str, password: str) -> bool:
        if self.ttl_seconds <= 0:
            return False
        now = time.time()
        self._prune(now)
        expires_at = self._entries.get(self._key(username, password))
        return expires_at is not None and expires_at > now

    def record_success(self, username: str, password: str) -> None:
        if self.ttl_seconds <= 0:
            return
        now = time.time()
        self._prune(now)
        self._entries[self._key(username, password)] = now + self.ttl_seconds

    def clear(self, username: str, password: str) -> None:
        self._entries.pop(self._key(username, password), None)

    def _prune(self, now: float) -> None:
        if now - self._last_prune < self._PRUNE_INTERVAL:
            return
        self._last_prune = now
        for key, expires_at in list(self._entries.items()):
            if expires_at <= now:
                del self._entries[key]
