"""Signed-cookie session management using HMAC-SHA256 signed tokens."""

import base64
import fcntl
import hashlib
import json
import logging
import os
import stat
import threading
import time
from pathlib import Path
from typing import Optional

from ldapgate._signer import BadSignature, TimedSigner

log = logging.getLogger(__name__)


def _is_weak_secret(secret: str) -> bool:
    if len(secret) < 32:
        return True
    weak_indicators = [
        "change-me", "local-dev-secret", "test-secret", "not-for-production",
        "replace-me", "default", "secret", "password", "123456", "abcdef",
        "qwerty", "admin", "root", "ldapgate", "ldap", "proxy",
    ]
    if any(indicator in secret.lower() for indicator in weak_indicators):
        return True
    if len(set(secret)) < 8:
        return True
    return False


class _RevocationStore:
    """Cross-process revocation store using a shared file with fcntl locking.

    Falls back to in-memory only if no shared path is provided.
    """

    def __init__(self, path: Optional[Path] = None, ttl: int = 3600):
        self._path = path
        self._ttl = ttl
        self._revoked: dict[str, float] = {}
        self._lock_fd: Optional[int] = None

    def _prune(self, now: float) -> None:
        self._revoked = {
            token: expiry for token, expiry in self._revoked.items() if expiry > now
        }

    def _locked_load_and_save(self, extra: dict[str, float]) -> None:
        """Atomically load, merge, prune, and save the shared file under lock.

        Uses ``time.time()`` for expiry comparisons so that multiple
        processes (with different ``monotonic()`` baselines) agree on
        revocation timelines. Monotonic clock is not suitable for
        cross-process shared state.
        """
        if not self._path:
            return
        now = time.time()
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError:
            return
        locked = False
        try:
            st = os.fstat(fd)
            if stat.S_IMODE(st.st_mode) & 0o177:
                log.error(
                    "Revocation file %s has insecure permissions (%s). "
                    "Expected 0o600. Refusing to use it.",
                    self._path, oct(stat.S_IMODE(st.st_mode)),
                )
                return
            fcntl.flock(fd, fcntl.LOCK_EX)
            locked = True
            try:
                raw_parts = []
                while True:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    raw_parts.append(chunk)
                raw = b"".join(raw_parts)
                if raw:
                    data = json.loads(raw.decode())
                else:
                    data = {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                data = {}
            if not isinstance(data, dict):
                data = {}

            data.update(extra)
            data = {k: v for k, v in data.items() if isinstance(v, (int, float)) and v > now}
            self._revoked.update(data)
            self._prune(now)

            serialized = json.dumps(self._revoked).encode()
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, serialized)
        finally:
            if locked:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def add(self, token: str) -> None:
        now = time.time()
        self._prune(now)
        self._revoked[token] = now + self._ttl
        self._locked_load_and_save({token: now + self._ttl})

    def contains(self, token: str) -> bool:
        now = time.time()
        self._prune(now)
        if self._path:
            self._locked_load_and_save({})
        return token in self._revoked


class SessionManager:
    """Manages signed session cookies without external storage."""

    COOKIE_NAME = "ldapgate_session"

    def __init__(self, secret_key: str, session_ttl: int = 3600, revocation_path: Optional[str] = None,
                 max_sessions_per_user: int = 0, bind_client: bool = True):
        """Initialize session manager.

        Args:
            secret_key: Secret key for signing cookies
            session_ttl: Session time-to-live in seconds
            revocation_path: Optional path to a shared revocation file for
                cross-process logout support.
            max_sessions_per_user: Max concurrent sessions per user (0 = unlimited).
                When exceeded the oldest session is revoked. Per-process tracking.
            bind_client: Bind sessions and CSRF tokens to the client IP and
                User-Agent. Disable for clients using privacy relays.
        """
        if _is_weak_secret(secret_key):
            raise ValueError(
                "Secret key is too weak for production use. "
                "Generate a secure key with: "
                "python -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )
        self.serializer = TimedSigner(secret_key)
        self._csrf_serializer = TimedSigner(secret_key, salt="ldapgate-csrf")
        self.session_ttl = session_ttl
        self._revocation = _RevocationStore(
            path=Path(revocation_path) if revocation_path else None,
            ttl=session_ttl,
        )
        self.max_sessions_per_user = max_sessions_per_user
        self.bind_client = bind_client
        # username -> {cookie_hash: (cookie_value, last_seen_monotonic)}
        self._user_sessions: dict[str, dict[str, tuple[str, float]]] = {}
        self._sessions_lock = threading.Lock()
        # Tracks consumed CSRF token fingerprints to prevent replay within TTL.
        # fingerprint -> expiry (monotonic)
        self._csrf_used: dict[str, float] = {}
        self._csrf_lock = threading.Lock()

    # Limit username length to keep signed cookie well under ~4KB browser limit
    MAX_USERNAME_LENGTH = 128

    def _client_hash(self, client_ip: str, user_agent: str) -> str:
        """Bind session to client IP and User-Agent to prevent cookie replay."""
        if not self.bind_client:
            return ""
        payload = f"{client_ip}:{user_agent}"
        return hashlib.sha256(payload.encode()).hexdigest()[:32]

    def _cookie_id(self, cookie_value: str) -> str:
        """Short hash of the cookie value for in-memory session tracking."""
        return hashlib.sha256(cookie_value.encode()).hexdigest()[:16]

    def _prune_user_sessions(self, now: float) -> None:
        """Remove expired session entries from tracking."""
        with self._sessions_lock:
            for username in list(self._user_sessions):
                sessions = self._user_sessions[username]
                for cid in list(sessions):
                    _cookie_val, created = sessions[cid]
                    if now - created > self.session_ttl:
                        del sessions[cid]
                if not sessions:
                    del self._user_sessions[username]

    def _track_session(self, cookie_value: str, username: str, now: float) -> None:
        """Register a session in the tracking dict and enforce the per-user limit.

        When the limit is exceeded the oldest session is revoked via the
        revocation store so it can no longer be verified.
        """
        if self.max_sessions_per_user <= 0:
            return
        cid = self._cookie_id(cookie_value)
        with self._sessions_lock:
            sessions = self._user_sessions.setdefault(username, {})
            # If this cookie is already tracked, just update timestamp
            if cid in sessions:
                sessions[cid] = (cookie_value, now)
                return
            sessions[cid] = (cookie_value, now)
            if len(sessions) > self.max_sessions_per_user:
                sorted_cids = sorted(sessions, key=lambda c: sessions[c][1])
                for old_cid in sorted_cids[:-self.max_sessions_per_user]:
                    old_cookie, _ = sessions[old_cid]
                    self._revocation.add(old_cookie)
                    del sessions[old_cid]

    def _untrack_session(self, cookie_value: str, username: str) -> None:
        """Remove a session from tracking (on logout/revocation)."""
        if self.max_sessions_per_user <= 0:
            return
        if not username:
            return
        cid = self._cookie_id(cookie_value)
        with self._sessions_lock:
            sessions = self._user_sessions.get(username)
            if sessions:
                sessions.pop(cid, None)
                if not sessions:
                    del self._user_sessions[username]

    def create_session(self, username: str, client_ip: str = "", user_agent: str = "") -> str:
        """Create signed session cookie value.

        Args:
            username: Authenticated username
            client_ip: Client IP address for session binding
            user_agent: Client User-Agent for session binding

        Returns:
            Signed, URL-safe cookie value
        """
        if len(username) > self.MAX_USERNAME_LENGTH:
            raise ValueError(f"Username exceeds maximum length of {self.MAX_USERNAME_LENGTH}")
        payload = {
            "u": username,
            "c": self._client_hash(client_ip, user_agent),
            "n": os.urandom(16).hex(),   # random nonce ensures uniqueness
        }
        cookie = self.serializer.dumps(payload)
        now = time.monotonic()
        self._prune_user_sessions(now)
        self._track_session(cookie, username, now)
        return cookie

    def verify_session(self, cookie_value: Optional[str], client_ip: str = "", user_agent: str = "") -> Optional[str]:
        """Verify and extract username from session cookie.

        Args:
            cookie_value: Cookie value from request
            client_ip: Client IP address for session binding verification
            user_agent: Client User-Agent for session binding verification

        Returns:
            Username if valid and not expired, None otherwise
        """
        if not cookie_value:
            return None

        if self._revocation.contains(cookie_value):
            return None

        now = time.monotonic()

        try:
            payload = self.serializer.loads(cookie_value, max_age=self.session_ttl)
            if not isinstance(payload, dict):
                return None
            username = payload.get("u")
            expected_hash = payload.get("c")
            if not username:
                return None
            # If session was created with client binding, verify it
            if expected_hash:
                current_hash = self._client_hash(client_ip, user_agent)
                if current_hash != expected_hash:
                    return None
            self._track_session(cookie_value, username, now)
            return username
        except BadSignature:
            return None

    def revoke_session(self, cookie_value: Optional[str], username: Optional[str] = None) -> None:
        """Revoke a session cookie so it can no longer be used.

        Args:
            cookie_value: Cookie value to revoke
            username: Optional username for tracking cleanup.
                      If omitted, extracted from the cookie if possible.
        """
        if not cookie_value:
            return
        if not username:
            try:
                payload = self.serializer.loads(cookie_value)
                if isinstance(payload, dict):
                    username = payload.get("u")
            except BadSignature:
                pass
        self._revocation.add(cookie_value)
        if username:
            self._untrack_session(cookie_value, username)

    def generate_csrf_token(self, client_ip: str = "") -> str:
        """Generate a signed CSRF token bound to the client IP."""
        nonce = base64.b64encode(os.urandom(12)).decode()
        fingerprint = (
            hashlib.sha256(client_ip.encode()).hexdigest()[:16]
            if self.bind_client and client_ip
            else ""
        )
        return self._csrf_serializer.dumps({"n": nonce, "f": fingerprint})

    def _prune_csrf_used(self, now: float) -> None:
        """Remove expired entries from the consumed CSRF token set."""
        with self._csrf_lock:
            expired = [k for k, exp in self._csrf_used.items() if now >= exp]
            for k in expired:
                del self._csrf_used[k]

    def validate_csrf_token(self, token: Optional[str], client_ip: str = "") -> bool:
        """Validate a CSRF token, verifying client IP binding if present.

        Each token is single-use: once validated it is recorded and any
        subsequent submission of the same token is rejected.
        """
        if not token:
            return False
        try:
            data = self._csrf_serializer.loads(token, max_age=self.session_ttl)
            if not isinstance(data, dict):
                return False
            stored_fp = data.get("f", "")
            if stored_fp and client_ip:
                current_fp = hashlib.sha256(client_ip.encode()).hexdigest()[:16]
                if current_fp != stored_fp:
                    return False
            # Use the nonce as the per-token key so each issued token can only
            # be validated once, preventing replay within the TTL window.
            nonce = data.get("n", "")
            token_key = hashlib.sha256(nonce.encode()).hexdigest()
            now = time.monotonic()
            self._prune_csrf_used(now)
            with self._csrf_lock:
                if token_key in self._csrf_used:
                    return False
                self._csrf_used[token_key] = now + self.session_ttl
            return True
        except BadSignature:
            return False
