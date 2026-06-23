"""Starlette middleware for FastAPI LDAP authentication."""

import hashlib
import logging
from typing import Optional
from urllib.parse import quote

from fastapi import FastAPI
from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from ldapgate._auth_utils import BasicAuthRateLimiter, BasicAuthSuccessCache, _is_ip_in_networks, _is_safe_host, _is_trusted_host, get_client_ip, parse_basic_auth
from ldapgate.config import LDAPConfig
from ldapgate.ldap import LDAPAuthenticator
from ldapgate.sessions import SessionManager

log = logging.getLogger(__name__)


def _username_log(username: str, mask: bool = True) -> str:
    """Mask username for privacy in logs: first char + SHA-256 suffix."""
    if not mask:
        return username.replace("\r", "").replace("\n", "")
    h = hashlib.sha256(username.encode()).hexdigest()[:8]
    safe = username.strip()
    prefix = safe[0] if safe else "?"
    return f"{prefix}***{h}"

_401 = Response(
    status_code=401,
    headers={"WWW-Authenticate": 'Basic realm="LDAPGate"'},
)

# Security headers added to all responses (must match proxy.py)
_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
}
_COOP_HEADER = ("Cross-Origin-Opener-Policy", "same-origin")


class LDAPAuthMiddleware(BaseHTTPMiddleware):
    """Starlette middleware for LDAP authentication in FastAPI apps.

    Usage:
        config = load_config("ldapgate.yaml")
        app.add_middleware(LDAPAuthMiddleware, config=config)
    """

    def __init__(self, app: FastAPI, config: LDAPConfig, rate_limiter: Optional[BasicAuthRateLimiter] = None,
                 session_manager: Optional[SessionManager] = None,
                 ldap_auth: Optional[LDAPAuthenticator] = None):
        """Initialize middleware.

        Args:
            app: FastAPI application instance
            config: LDAPConfig with LDAP and session settings
            rate_limiter: Optional shared rate limiter for unified rate limiting
                          across form login and Basic auth endpoints.
            session_manager: Optional shared SessionManager for unified session
                             tracking with login router. Created from config if omitted.
            ldap_auth: Optional shared LDAPAuthenticator to avoid a duplicate
                       connection pool. Created from config if omitted.
        """
        super().__init__(app)
        self.config = config
        self.session_manager = session_manager or SessionManager(
            config.proxy.secret_key.get_secret_value(),
            config.proxy.session_ttl,
            revocation_path=config.proxy.revocation_path,
            max_sessions_per_user=config.proxy.max_sessions_per_user,
            bind_client=config.proxy.bind_client,
        )
        self.ldap_auth = ldap_auth or LDAPAuthenticator(config.ldap)
        self._basic_auth_limiter = rate_limiter or BasicAuthRateLimiter(
            max_failures=config.proxy.rate_limit_max_failures,
            window_seconds=config.proxy.rate_limit_window_seconds,
            lockout_seconds=config.proxy.rate_limit_lockout_seconds,
            state_path=config.proxy.rate_limit_state_path,
            mask_usernames_in_logs=config.proxy.mask_usernames_in_logs,
        )
        self._basic_auth_cache = BasicAuthSuccessCache(
            ttl_seconds=config.proxy.basic_auth_cache_ttl,
        )

    async def dispatch(self, request: Request, call_next) -> Response:
        """Middleware dispatch handler.

        Checks Basic auth header first (for WebDAV/API clients), then falls
        back to session cookie. If neither is valid, non-browser clients get a
        401 challenge; browsers are redirected to the login form.

        Args:
            request: Incoming request
            call_next: Next middleware/route handler

        Returns:
            Response
        """
        add_headers = lambda response: self._add_security_headers(response, request=request)

        # Enforce HTTPS when secure_cookies is enabled
        if self.config.proxy.secure_cookies:
            scheme = self._get_scheme(request)
            if scheme != "https":
                return add_headers(Response(
                    content="HTTPS required",
                    status_code=421,
                    media_type="text/plain",
                ))

        # Skip auth for login endpoints and static assets
        if self._should_skip_auth(request.url.path):
            response = await call_next(request)
            return add_headers(response)

        username: Optional[str] = None

        # Check HTTP Basic auth first (WebDAV clients, curl, etc.)
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Basic "):
            client_ip = get_client_ip(request, self.config.proxy.trusted_proxies)
            creds = parse_basic_auth(auth_header)
            if self._basic_auth_limiter.is_locked_out(client_ip, username=creds[0] if creds else None):
                log.warning("Basic auth: rejecting locked-out IP %s", client_ip)
                return add_headers(_401)
            if creds and self._basic_auth_cache.is_valid(creds[0], creds[1]):
                self._basic_auth_limiter.record_success(client_ip, creds[0])
                username = creds[0]
            elif creds and await self.ldap_auth.authenticate(creds[0], creds[1]):
                self._basic_auth_limiter.record_success(client_ip, creds[0])
                self._basic_auth_cache.record_success(creds[0], creds[1])
                username = creds[0]
            else:
                if creds:
                    self._basic_auth_cache.clear(creds[0], creds[1])
                self._basic_auth_limiter.record_failure(client_ip, creds[0] if creds else None)
                return add_headers(_401)

        # Fall back to session cookie
        if username is None:
            session_cookie = request.cookies.get(self._cookie_name)
            client_ip = get_client_ip(request, self.config.proxy.trusted_proxies)
            user_agent = request.headers.get("user-agent", "")
            username = self.session_manager.verify_session(session_cookie, client_ip=client_ip, user_agent=user_agent)

        if not username:
            # Non-browser clients won't follow a redirect — give them a 401 challenge
            accept = request.headers.get("accept", "")
            if "text/html" not in accept:
                return add_headers(_401)
            # Redirect browsers to login with original URL as redirect target
            redirect_url = request.url.path
            if request.url.query:
                redirect_url += f"?{request.url.query}"
            return add_headers(RedirectResponse(
                url=f"{self.config.proxy.login_path}?redirect={quote(redirect_url, safe='')}",
                status_code=302,
            ))

        # Validate request body size
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                cl = int(content_length)
                if cl < 0 or cl > self.config.proxy.max_body_size:
                    return add_headers(Response(
                        content="Request body too large",
                        status_code=413,
                        media_type="text/plain",
                    ))
            except ValueError:
                return add_headers(Response(
                    content="Invalid Content-Length",
                    status_code=400,
                    media_type="text/plain",
                ))

        # Store username in request state for downstream use
        request.state.user = username
        log.info("Authenticated user '%s' from IP %s", _username_log(username, self.config.proxy.mask_usernames_in_logs), get_client_ip(request, self.config.proxy.trusted_proxies))

        # Inject user header into request scope (MutableHeaders modifies scope in place)
        mutable_headers = MutableHeaders(scope=request.scope)
        # Strip CR/LF to prevent HTTP header injection
        safe_username = username.translate(str.maketrans({"\r": "", "\n": ""}))
        mutable_headers[self.config.proxy.user_header] = safe_username

        # Strip Authorization header so backend never sees raw credentials
        if "authorization" in mutable_headers:
            del mutable_headers["authorization"]

        # Strip all X-Forwarded-* headers forwarded by the client so the
        # backend only sees the authoritative values the middleware sets.
        for key in list(request.headers.keys()):
            if key.lower().startswith("x-forwarded-"):
                try:
                    del mutable_headers[key]
                except KeyError:
                    pass

        # Add X-Forwarded-For and X-Forwarded-Proto for the backend
        direct_ip = request.client.host if request.client else ""
        if direct_ip:
            mutable_headers["X-Forwarded-For"] = direct_ip
        scheme = self._get_scheme(request)
        mutable_headers["X-Forwarded-Proto"] = scheme
        if original_host := request.headers.get("host"):
            if _is_safe_host(original_host):
                if not self.config.proxy.trusted_hosts or _is_trusted_host(original_host, self.config.proxy.trusted_hosts):
                    mutable_headers["X-Forwarded-Host"] = original_host

        # Call next middleware/route
        response = await call_next(request)
        return add_headers(response)

    def _get_scheme(self, request: Request) -> str:
        """Determine the effective protocol scheme for the request.

        If the direct client is a trusted proxy, honours X-Forwarded-Proto.
        Otherwise uses the ASGI scheme directly.
        """
        direct_ip = request.client.host if request.client else ""
        if self.config.proxy.trusted_proxies and _is_ip_in_networks(direct_ip, self.config.proxy.trusted_proxies):
            return request.headers.get("x-forwarded-proto", request.url.scheme)
        return request.url.scheme

    def _add_security_headers(self, response: Response, request: Optional[Request] = None) -> Response:
        """Add security headers to a response."""
        for key, value in _SECURITY_HEADERS.items():
            if key.lower() not in response.headers:
                response.headers[key] = value
        if request is not None and self._get_scheme(request) == "https":
            key, value = _COOP_HEADER
            if key.lower() not in response.headers:
                response.headers[key] = value
        # Preserve any existing CSP (e.g. nonce from login form) rather than overwriting
        if "content-security-policy" not in {k.lower() for k in response.headers}:
            csp = (
                "default-src 'self'; form-action 'self'; script-src 'self'; "
                "style-src 'self'; img-src 'self' data:; font-src 'self' data:"
            )
            response.headers["Content-Security-Policy"] = csp
        if "permissions-policy" not in {k.lower() for k in response.headers}:
            response.headers["Permissions-Policy"] = (
                "camera=(), microphone=(), geolocation=(), interest-cohort=()"
            )
        if self.config.proxy.secure_cookies and self.config.proxy.hsts_max_age > 0:
            response.headers["Strict-Transport-Security"] = (
                f"max-age={self.config.proxy.hsts_max_age}; includeSubDomains"
            )
        return response

    @property
    def _cookie_name(self) -> str:
        name = self.config.proxy.session_cookie_name
        if self.config.proxy.secure_cookies:
            return f"__Host-{name}"
        return name

    def _should_skip_auth(self, path: str) -> bool:
        """Check if path should skip authentication.

        Args:
            path: Request path

        Returns:
            True if auth should be skipped
        """
        if path == self.config.proxy.login_path:
            return True
        if path == self.config.proxy.logout_path:
            return True
        static_prefixes = self.config.proxy.static_paths
        return any(path == prefix or path.startswith(prefix) for prefix in static_prefixes)


def add_ldap_auth(app: FastAPI, config: LDAPConfig, template_path: Optional[str] = None) -> SessionManager:
    """Add LDAP auth to a FastAPI app: login routes + session middleware.

    Registers the login form (GET/POST) on the app and attaches
    LDAPAuthMiddleware so all other routes require a valid session.

    Args:
        app: FastAPI application
        config: LDAPConfig instance
        template_path: Optional path to a custom Jinja2 login template file.
                       If omitted, uses the bundled ldapgate template.

    Returns:
        Shared SessionManager used by both the login router and middleware.
    """
    from ldapgate.proxy import create_login_router
    # Shared LDAP authenticator to avoid double connection pool
    shared_ldap_auth = LDAPAuthenticator(config.ldap)
    # Shared rate limiter so form login and Basic auth share limits
    shared_limiter = BasicAuthRateLimiter(
        max_failures=config.proxy.rate_limit_max_failures,
        window_seconds=config.proxy.rate_limit_window_seconds,
        lockout_seconds=config.proxy.rate_limit_lockout_seconds,
        state_path=config.proxy.rate_limit_state_path,
        mask_usernames_in_logs=config.proxy.mask_usernames_in_logs,
    )
    # Shared SessionManager so login and middleware share session tracking
    shared_session_mgr = SessionManager(
        config.proxy.secret_key.get_secret_value(),
        config.proxy.session_ttl,
        revocation_path=config.proxy.revocation_path,
        max_sessions_per_user=config.proxy.max_sessions_per_user,
        bind_client=config.proxy.bind_client,
    )
    app.include_router(create_login_router(
        config, ldap_auth=shared_ldap_auth, template_path=template_path,
        rate_limiter=shared_limiter, session_manager=shared_session_mgr,
    ))
    app.add_middleware(
        LDAPAuthMiddleware, config=config, rate_limiter=shared_limiter,
        session_manager=shared_session_mgr, ldap_auth=shared_ldap_auth,
    )
    return shared_session_mgr
