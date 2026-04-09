"""Signed-cookie session management using itsdangerous."""

from typing import Optional

from itsdangerous import BadSignature, URLSafeTimedSerializer


class SessionManager:
    """Manages signed session cookies without external storage."""

    COOKIE_NAME = "ldapgate_session"

    def __init__(self, secret_key: str, session_ttl: int = 3600):
        """Initialize session manager.

        Args:
            secret_key: Secret key for signing cookies
            session_ttl: Session time-to-live in seconds
        """
        self.serializer = URLSafeTimedSerializer(secret_key)
        self.session_ttl = session_ttl

    # Prevent cookie bloat from unusually long usernames
    MAX_USERNAME_LENGTH = 256

    def create_session(self, username: str) -> str:
        """Create signed session cookie value.

        Uses URLSafeTimedSerializer to produce a cookie-safe token regardless
        of characters in the username.

        Args:
            username: Authenticated username

        Returns:
            Signed, URL-safe cookie value
        """
        if len(username) > self.MAX_USERNAME_LENGTH:
            raise ValueError(f"Username exceeds maximum length of {self.MAX_USERNAME_LENGTH}")
        return self.serializer.dumps(username)

    def verify_session(self, cookie_value: Optional[str]) -> Optional[str]:
        """Verify and extract username from session cookie.

        Args:
            cookie_value: Cookie value from request

        Returns:
            Username if valid and not expired, None otherwise
        """
        if not cookie_value:
            return None

        try:
            return self.serializer.loads(cookie_value, max_age=self.session_ttl)
        except BadSignature:
            return None
