"""Custom signed-token serializer (stdlib replacement for itsdangerous).

Provides `TimedSigner` with the same dumps/loads(max_age) interface as
itsdangerous, using only Python stdlib (hmac, hashlib, json, base64, time).
"""

import base64
import binascii
import hmac
import hashlib
import json
import time
from typing import Any


class BadSignature(Exception):
    """Raised when a signature is invalid or token is expired."""


class TimedSigner:
    """Stateless signed-token serializer with embedded timestamps.

    Format: ``base64url(json({"d": data, "t": ts})).hmac_hex``

    Uses ``time.time()`` (wall clock) for token timestamps so that
    tokens remain comparable across process restarts (``monotonic()``
    resets to zero on restart, causing negative elapsed times and
    indefinite token validity when the same secret key is reused).
    """

    def __init__(self, secret_key: str, salt: str = ""):
        self._key = (salt + ":" + secret_key).encode()

    def dumps(self, data: Any) -> str:
        """Serialize + sign data, returning a URL-safe token string."""
        ts = time.time()
        payload = json.dumps({"d": data, "t": ts}, separators=(",", ":"))
        b64 = base64.urlsafe_b64encode(payload.encode()).rstrip(b"=").decode()
        sig = hmac.new(self._key, b64.encode(), hashlib.sha256).hexdigest()
        return f"{b64}.{sig}"

    _MAX_TOKEN_LENGTH = 4096  # prevent DoS from extremely long tokens

    def loads(self, token: str, max_age: int | None = None) -> Any:
        """Verify signature + expiry and return the original data.

        Raises BadSignature if the token is invalid, tampered, or expired.
        """
        try:
            if len(token) > self._MAX_TOKEN_LENGTH:
                raise BadSignature("Token too long")
            parts = token.split(".", 1)
            if len(parts) != 2:
                raise BadSignature("Invalid token format")
            b64, sig = parts

            expected = hmac.new(self._key, b64.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                raise BadSignature("Invalid signature")

            pad = 4 - len(b64) % 4
            if pad != 4:
                b64 += "=" * pad
            raw = base64.urlsafe_b64decode(b64)
            payload = json.loads(raw)

            if not isinstance(payload, dict) or "d" not in payload:
                raise BadSignature("Invalid payload structure")

            if max_age is not None:
                token_ts = payload.get("t", 0)
                # Clamp to 0 to prevent wall-clock backwards jumps
                # (NTP adjustments) from temporarily extending token lifetime.
                if max(0.0, time.time() - token_ts) > max_age:
                    raise BadSignature("Token expired")

            return payload["d"]
        except (ValueError, TypeError, json.JSONDecodeError, binascii.Error):
            raise BadSignature("Invalid token encoding")
