"""Starlette middleware for FastAPI LDAP authentication."""

import logging
from typing import Optional
from urllib.parse import quote

from fastapi import FastAPI
from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from ldapgate._auth_utils import BasicAuthRateLimiter, parse_basic_auth
from ldapgate.config import LDAPConfig
from ldapgate.ldap import LDAPAuthenticator
from ldapgate.sessions import SessionManager

log = logging.getLogger(__name__)

_401 = Response(
    status_code=401,
    headers={"WWW-Authenticate": 'Basic realm="LDAPGate"'},
)


class LDAPAuthMiddleware(BaseHTTPMiddleware):
    """Starlette middleware for LDAP authentication in FastAPI apps.

    Usage:
        config = load_config("ldapgate.yaml")
        app.add_middleware(LDAPAuthMiddleware, config=config)
    """

    def __init__(self, app: FastAPI, config: LDAPConfig):
        """Initialize middleware.

        Args:
            app: FastAPI application instance
            config: LDAPConfig with LDAP and session settings
        """
        super().__init__(app)
        self.config = config
        self.session_manager = SessionManager(
            config.proxy.secret_key, config.proxy.session_ttl
        )
        self.ldap_auth = LDAPAuthenticator(config.ldap)
        self._basic_auth_limiter = BasicAuthRateLimiter()

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
        # Skip auth for login endpoints and static assets
        if self._should_skip_auth(request.url.path):
            return await call_next(request)

        username: Optional[str] = None

        # Check HTTP Basic auth first (WebDAV clients, curl, etc.)
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Basic "):
            client_ip = request.client.host if request.client else "unknown"
            if self._basic_auth_limiter.is_locked_out(client_ip):
                log.warning("Basic auth: rejecting locked-out IP %s", client_ip)
                return _401
            creds = parse_basic_auth(auth_header)
            if creds and await self.ldap_auth.authenticate(creds[0], creds[1]):
                self._basic_auth_limiter.record_success(client_ip)
                username = creds[0]
            else:
                self._basic_auth_limiter.record_failure(client_ip)
                return _401

        # Fall back to session cookie
        if username is None:
            session_cookie = request.cookies.get(SessionManager.COOKIE_NAME)
            username = self.session_manager.verify_session(session_cookie)

        if not username:
            # Non-browser clients won't follow a redirect — give them a 401 challenge
            accept = request.headers.get("accept", "")
            if "text/html" not in accept:
                return _401
            # Redirect browsers to login with original URL as redirect target
            redirect_url = request.url.path
            if request.url.query:
                redirect_url += f"?{request.url.query}"
            return RedirectResponse(
                url=f"{self.config.proxy.login_path}?redirect={quote(redirect_url, safe='')}",
                status_code=302,
            )

        # Store username in request state for downstream use
        request.state.user = username

        # Inject user header into request scope (MutableHeaders modifies scope in place)
        MutableHeaders(scope=request.scope)[self.config.proxy.user_header] = username

        # Call next middleware/route
        response = await call_next(request)

        return response

    def _should_skip_auth(self, path: str) -> bool:
        """Check if path should skip authentication.

        Args:
            path: Request path

        Returns:
            True if auth should be skipped
        """
        # Skip login/logout endpoints
        if path.startswith(self.config.proxy.login_path):
            return True
        if path.startswith(self.config.proxy.logout_path):
            return True

        # Skip common static asset paths
        static_prefixes = ["/_static/", "/static/", "/assets/", "/favicon.ico", "/favicon.svg", "/robots.txt"]
        return any(path.startswith(prefix) for prefix in static_prefixes)


def add_ldap_auth(app: FastAPI, config: LDAPConfig, template_path: Optional[str] = None) -> None:
    """Add LDAP auth to a FastAPI app: login routes + session middleware.

    Registers the login form (GET/POST) on the app and attaches
    LDAPAuthMiddleware so all other routes require a valid session.

    Args:
        app: FastAPI application
        config: LDAPConfig instance
        template_path: Optional path to a custom Jinja2 login template file.
                       If omitted, uses the bundled ldapgate template.
    """
    from ldapgate.proxy import create_login_router
    app.include_router(create_login_router(config, template_path=template_path))
    app.add_middleware(LDAPAuthMiddleware, config=config)
