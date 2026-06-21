"""FastAPI reverse proxy application with LDAP auth."""

import asyncio
import base64
import hashlib
import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlparse

import httpx
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import RedirectResponse, StreamingResponse
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from ldapgate._auth_utils import BasicAuthRateLimiter, BasicAuthSuccessCache, _is_ip_in_networks, _is_safe_host, _is_trusted_host, get_client_ip, parse_basic_auth
from ldapgate.config import LDAPConfig
from ldapgate.ldap import LDAPAuthenticator
from ldapgate.sessions import SessionManager, _is_weak_secret

log = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_401 = Response(
    status_code=401,
    headers={"WWW-Authenticate": 'Basic realm="LDAPGate"'},
)

# Strip CR/LF control chars from usernames before they are injected into
# forwarded headers to prevent HTTP header injection.
_HEADER_UNSAFE_CHARS = str.maketrans({"\r": "", "\n": ""})

# Security headers added to all responses
_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
}
_COOP_HEADER = ("Cross-Origin-Opener-Policy", "same-origin")

# Headers that must not be forwarded between proxy hops (RFC 2616 §13.5.1)
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-encoding", "content-length",
})


def _username_log(username: str, mask: bool = True) -> str:
    """Mask username for privacy in logs: first char + SHA-256 suffix."""
    if not mask:
        return username.replace("\r", "").replace("\n", "")
    h = hashlib.sha256(username.encode()).hexdigest()[:8]
    safe = username.strip()
    prefix = safe[0] if safe else "?"
    return f"{prefix}***{h}"

# Predefined safe error messages (prevent phishing via URL parameters)
_SAFE_ERROR_MESSAGES = {
    "invalid": "Invalid username or password",
    "required": "Username and password required",
    "locked": "Too many failed attempts. Please try again later.",
}

# Inline HTML fallback if template is not available
LOGIN_FORM_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to {{ app_name }}</title>
    <style nonce="{{ csrf_nonce }}">
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
        }
        @media (prefers-color-scheme: dark) {
            body { background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%); color: #e2e8f0; }
            .card { background: #2d3748; border-color: #4a5568; }
            input { background: #1a202c; border-color: #4a5568; color: #e2e8f0; }
            button { background: #667eea; }
            button:hover { background: #5568d3; }
            .error { background: #742a2a; border-color: #c53030; color: #fed7d7; }
        }
        .card {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
            width: 100%;
            max-width: 400px;
            border: 1px solid #e2e8f0;
        }
        h1 { font-size: 24px; margin-bottom: 30px; text-align: center; }
        .form-group { margin-bottom: 20px; }
        label { display: block; font-size: 14px; font-weight: 500; margin-bottom: 6px; }
        input {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #cbd5e0;
            border-radius: 4px;
            font-size: 14px;
            transition: border-color 0.2s, outline-offset 0.2s;
        }
        input:focus { outline: 2px solid #667eea; outline-offset: 2px; border-color: #667eea; }
        button {
            width: 100%;
            padding: 10px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        button:hover { background: #5568d3; }
        button:disabled { opacity: 0.6; cursor: not-allowed; }
        .error {
            background: #fed7d7;
            border: 1px solid #fc8181;
            color: #c53030;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
            font-size: 14px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .error button { width: auto; padding: 0; background: none; color: inherit; text-decoration: underline; }
        .powered-by { margin-top: 1.5rem; text-align: center; font-size: 0.72rem; color: #475569; }
        .powered-by a { color: #64748b; text-decoration: none; }
        .powered-by a:hover { color: #94a3b8; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Sign in to {{ app_name }}</h1>
        {% if error %}<div class="error">{{ error }} <button onclick="this.parentElement.style.display='none'">×</button></div>{% endif %}
        <form method="POST" action="{{ login_path }}">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            {% if redirect %}<input type="hidden" name="redirect" value="{{ redirect }}">{% endif %}
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <button type="submit">Sign in</button>
        </form>
        <div class="powered-by">Powered by <a href="https://github.com/anudeepd/ldapgate" tabindex="-1">LDAPGate</a></div>
    </div>
</body>
</html>
"""


def _is_safe_redirect(url: str) -> bool:
    """Check if a redirect URL is a safe relative path."""
    if not url:
        return False
    # Reject whitespace characters that could be used in header injection
    # BEFORE strip() so trailing tabs/newlines are also caught
    if any(c in url for c in ("\t", "\n", "\r", "\x0b", "\x0c")):
        return False
    url = url.strip()
    if not url.startswith("/"):
        return False
    if url.startswith("//"):
        return False
    if url.startswith("/\\"):
        return False
    if "\\" in url or "\x00" in url:
        return False
    # Prevent path traversal and encoded traversal (case-insensitive for encodings)
    if "/.." in url or "\\.." in url:
        return False
    url_lower = url.lower()
    if "/%2e" in url_lower or "\\%2e" in url_lower or ".%2e" in url_lower:
        return False
    if "%2f" in url_lower or "%5c" in url_lower:
        return False
    return True


def _is_same_origin(origin: str, host: str) -> bool:
    """Check if an Origin header matches the given Host (hostname + port).

    Returns True if the Origin matches the Host case-insensitively,
    accounting for port. Handles default port omission (port 80/443)
    and IPv6 addresses (e.g. [::1]:8080).
    """
    try:
        parsed = urlparse(origin)
        if not parsed.hostname:
            return False
        # Parse the Host header using urlparse to properly handle
        # IPv6 (e.g. [::1]:8080), hostname:port, and bare hostnames.
        parsed_host = urlparse(f"//{host}")
        if not parsed_host.hostname:
            return False
        # Compare hostnames case-insensitively
        if parsed.hostname.lower() != parsed_host.hostname.lower():
            return False
        origin_port = str(parsed.port) if parsed.port else None
        host_port = str(parsed_host.port) if parsed_host.port else None
        # If one has a port and the other doesn't, check defaults
        if origin_port != host_port:
            if origin_port and not host_port:
                default_port = "443" if parsed.scheme == "https" else "80"
                return origin_port == default_port
            if host_port and not origin_port:
                default_port = "443" if parsed.scheme == "https" else "80"
                return host_port == default_port
        return True
    except Exception:
        return False


def _is_safe_origin(origin: str, host: str, trusted_hosts: list[str] | None = None) -> bool:
    """Check if an Origin header value is safe for the given Host.

    Returns False when the Host header is missing or the Origin header
    is missing or does not match the Host (strict mode for mutation endpoints).
    When trusted_hosts is provided and non-empty, the Host must be in the list.
    """
    if not host:
        return False
    if not _is_safe_host(host):
        return False
    if trusted_hosts and not _is_trusted_host(host, trusted_hosts):
        return False
    if not origin:
        return False
    return _is_same_origin(origin, host)


def _is_safe_referer(referer: str, host: str, trusted_hosts: list[str] | None = None) -> bool:
    """Check if a Referer header value is safe for the given Host.

    Returns False when the Host or Referer header is missing or the
    Referer does not match the Host. When trusted_hosts is provided and
    non-empty, the Host must be in the list.
    """
    if not host:
        return False
    if not _is_safe_host(host):
        return False
    if trusted_hosts and not _is_trusted_host(host, trusted_hosts):
        return False
    if not referer:
        return False
    try:
        parsed = urlparse(referer)
        if not parsed.hostname:
            return False
        # Referer URL includes the full path, Origin doesn't. We only
        # check the hostname+port against the Host header.
        parsed_host = urlparse(f"//{host}")
        if not parsed_host.hostname:
            return False
        if parsed.hostname.lower() != parsed_host.hostname.lower():
            return False
        referer_port = str(parsed.port) if parsed.port else None
        host_port = str(parsed_host.port) if parsed_host.port else None
        if referer_port != host_port:
            if referer_port and not host_port:
                default_port = "443" if parsed.scheme == "https" else "80"
                return referer_port == default_port
            if host_port and not referer_port:
                default_port = "443" if parsed.scheme == "https" else "80"
                return host_port == default_port
        return True
    except Exception:
        return False


def _add_security_headers(
    response: Response,
    nonce: Optional[str] = None,
    config: Optional[LDAPConfig] = None,
    scheme: Optional[str] = None,
) -> Response:
    """Add security headers to a response."""
    response_headers_lower = {k.lower() for k in response.headers}
    for key, value in _SECURITY_HEADERS.items():
        if key.lower() not in response_headers_lower:
            response.headers[key] = value
    if scheme == "https":
        key, value = _COOP_HEADER
        if key.lower() not in response_headers_lower:
            response.headers[key] = value
    # Preserve any existing CSP (e.g. nonce from login form) rather than overwriting
    if "content-security-policy" not in response_headers_lower:
        if nonce:
            csp = (
                f"default-src 'self'; "
                f"form-action 'self'; "
                f"script-src 'self' 'nonce-{nonce}'; "
                f"style-src 'self' 'nonce-{nonce}'; "
                f"img-src 'self' data:; "
                f"font-src 'self' data:"
            )
        else:
            csp = (
                "default-src 'self'; form-action 'self'; script-src 'self'; "
                "style-src 'self'; img-src 'self' data:; font-src 'self' data:"
            )
        response.headers["Content-Security-Policy"] = csp
    if config and config.proxy.secure_cookies and config.proxy.hsts_max_age > 0:
        response.headers["Strict-Transport-Security"] = (
            f"max-age={config.proxy.hsts_max_age}; includeSubDomains"
        )
    return response


def _secure_transport_required(request: Request, config: LDAPConfig) -> bool:
    """Return True when secure cookies require HTTPS for this request."""
    if not config.proxy.secure_cookies:
        return False
    direct_ip = request.client.host if request.client else ""
    if config.proxy.trusted_proxies and _is_ip_in_networks(direct_ip, config.proxy.trusted_proxies):
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    else:
        scheme = request.url.scheme
    return scheme != "https"


def _https_required_response(config: LDAPConfig) -> Response:
    return _add_security_headers(Response(
        content="HTTPS required",
        status_code=421,
        media_type="text/plain",
    ), config=config)


def _set_session_cookie(
    response: Response,
    *,
    key: str,
    value: str,
    max_age: int,
    secure: bool,
    samesite: str,
    expires: int | None = None,
) -> None:
    """Set the LDAPGate session cookie across supported Python versions.

    Starlette exposes the ``partitioned`` option before every supported
    Python version can use it. Passing ``partitioned=True`` on Python < 3.14
    raises at runtime, so only opt in where the stdlib supports it.
    """
    kwargs = {
        "key": key,
        "value": value,
        "max_age": max_age,
        "httponly": True,
        "secure": secure,
        "samesite": samesite,
        "path": "/",
    }
    if expires is not None:
        kwargs["expires"] = expires
    if secure and sys.version_info >= (3, 14):
        kwargs["partitioned"] = True
    response.set_cookie(**kwargs)


def _session_cookie_name(config: LDAPConfig) -> str:
    """Return the configured session cookie name with __Host- prefix if needed."""
    name = config.proxy.session_cookie_name
    if config.proxy.secure_cookies:
        return f"__Host-{name}"
    return name


class _BodyTooLarge(Exception):
    """Raised when the streaming request body exceeds max_body_size."""
    pass


class _ResponseTooLarge(Exception):
    """Raised when the streaming response body exceeds max_response_size."""
    pass


async def _limited_stream(request: Request, max_size: int):
    """Async generator that yields request body chunks up to max_size.

    Raises _BodyTooLarge if the total exceeds max_size.
    """
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_size:
            raise _BodyTooLarge()
        yield chunk


async def _limited_response_stream(response: httpx.Response, max_size: int):
    """Async generator that yields response body chunks up to max_size.

    Closes the backend response and raises _ResponseTooLarge if the total
    exceeds max_size so the connection is not leaked.
    """
    total = 0
    try:
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > max_size:
                raise _ResponseTooLarge()
            yield chunk
    except _ResponseTooLarge:
        await response.aclose()
        raise


class ProxyApp:
    """FastAPI reverse proxy with LDAP auth."""

    def __init__(
        self,
        config: LDAPConfig,
        ldap_auth: Optional[LDAPAuthenticator] = None,
    ):
        """Initialize proxy app.

        Args:
            config: LDAPConfig with proxy and LDAP settings
            ldap_auth: LDAPAuthenticator instance (created if not provided)
        """
        self.config = config
        if not config.proxy.backend_url:
            raise ValueError("proxy.backend_url is required when running ldapgate as a reverse proxy")
        self.ldap_auth = ldap_auth or LDAPAuthenticator(config.ldap)
        self.session_manager = SessionManager(
            config.proxy.secret_key.get_secret_value(),
            config.proxy.session_ttl,
            revocation_path=config.proxy.revocation_path,
            max_sessions_per_user=config.proxy.max_sessions_per_user,
        )
        self._basic_auth_limiter = BasicAuthRateLimiter(
            max_failures=config.proxy.rate_limit_max_failures,
            window_seconds=config.proxy.rate_limit_window_seconds,
            lockout_seconds=config.proxy.rate_limit_lockout_seconds,
            state_path=config.proxy.rate_limit_state_path,
            mask_usernames_in_logs=config.proxy.mask_usernames_in_logs,
        )
        self._basic_auth_cache = BasicAuthSuccessCache(
            ttl_seconds=config.proxy.basic_auth_cache_ttl,
        )

        if not config.proxy.secure_cookies:
            log.warning(
                "secure_cookies is disabled. Session cookies will be sent over unencrypted connections. "
                "Enable secure_cookies when behind HTTPS."
            )

        if config.proxy.rate_limit_state_path:
            log.info("Rate limiting state is shared via %s", config.proxy.rate_limit_state_path)
        else:
            log.warning(
                "Rate limiting is per-process. With N uvicorn workers the effective "
                "failure threshold is %d * N. Configure rate_limit_state_path "
                "for shared lockout counters.",
                config.proxy.rate_limit_max_failures,
            )

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            app.state.http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0),
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            )
            yield
            await app.state.http_client.aclose()
            await asyncio.to_thread(self.ldap_auth.close)

        self.app = FastAPI(lifespan=lifespan)
        self._setup_routes()

    def _add_security_headers(
        self,
        response: Response,
        nonce: Optional[str] = None,
        request: Optional[Request] = None,
    ) -> Response:
        """Add security headers including CSP nonce and HSTS to a response."""
        scheme = self._get_scheme(request) if request is not None else None
        return _add_security_headers(response, nonce=nonce, config=self.config, scheme=scheme)

    def _render_login_form(
        self, template, redirect: str = "", error: str = "", client_ip: str = "",
    ) -> Response:
        """Render the login form with CSRF token, CSP nonce, and security headers."""
        csrf_token = self.session_manager.generate_csrf_token(client_ip=client_ip)
        nonce = base64.b64encode(os.urandom(16)).decode()
        html = template.render(
            app_name=self.config.proxy.app_name,
            login_path=self.config.proxy.login_path,
            redirect=redirect,
            error=error,
            csrf_token=csrf_token,
            csrf_nonce=nonce,
        )
        return self._add_security_headers(
            Response(content=html, media_type="text/html"), nonce=nonce,
        )

    def _get_scheme(self, request: Request) -> str:
        """Determine the effective protocol scheme for the request.

        If the direct client is a trusted proxy, honours X-Forwarded-Proto.
        Otherwise uses the ASGI scheme directly.
        """
        direct_ip = request.client.host if request.client else ""
        if self.config.proxy.trusted_proxies and _is_ip_in_networks(direct_ip, self.config.proxy.trusted_proxies):
            return request.headers.get("x-forwarded-proto", request.url.scheme)
        return request.url.scheme

    def _cookie_name(self) -> str:
        """Return the session cookie name, with __Host- prefix when secure."""
        return _session_cookie_name(self.config)

    def _setup_routes(self):
        """Set up FastAPI routes."""

        # Try loading the full template from disk; fall back to inline HTML
        try:
            _jinja_env = Environment(
                loader=FileSystemLoader(str(_TEMPLATES_DIR)),
                autoescape=True,
            )
            _login_template = _jinja_env.get_template("login.html")
        except TemplateNotFound:
            _jinja_env = Environment(autoescape=True)
            _login_template = _jinja_env.from_string(LOGIN_FORM_HTML)

        @self.app.get(self.config.proxy.login_path)
        async def login_get(request: Request, redirect: Optional[str] = None, error: Optional[str] = None):
            """Display login form."""
            if _secure_transport_required(request, self.config):
                return _https_required_response(self.config)
            safe_error = _SAFE_ERROR_MESSAGES.get(error, "") if error else ""
            safe_redirect = redirect if redirect and _is_safe_redirect(redirect) else ""
            client_ip = get_client_ip(request, self.config.proxy.trusted_proxies)
            return self._render_login_form(
                _login_template, redirect=safe_redirect, error=safe_error, client_ip=client_ip,
            )

        @self.app.post(self.config.proxy.login_path)
        async def login_post(request: Request):
            """Handle login form submission."""
            if _secure_transport_required(request, self.config):
                return _https_required_response(self.config)
            client_ip = get_client_ip(request, self.config.proxy.trusted_proxies)

            # Validate Origin and Referer to prevent cross-site login CSRF
            origin = request.headers.get("origin", "")
            referer = request.headers.get("referer", "")
            host = request.headers.get("host", "")
            if not _is_safe_origin(origin, host, self.config.proxy.trusted_hosts) or not _is_safe_referer(referer, host, self.config.proxy.trusted_hosts):
                return self._add_security_headers(Response(status_code=403))

            # Reject oversized form bodies before parsing
            form_content_length = request.headers.get("content-length")
            if form_content_length is not None:
                try:
                    if int(form_content_length) > 65536:
                        return self._add_security_headers(Response(
                            content="Request body too large", status_code=413,
                            media_type="text/plain",
                        ))
                except ValueError:
                    pass

            form_data = await request.form()
            redirect = form_data.get("redirect", "/")
            if not _is_safe_redirect(redirect):
                redirect = "/"

            csrf_token = form_data.get("csrf_token", "")
            if not self.session_manager.validate_csrf_token(csrf_token, client_ip=client_ip):
                return self._render_login_form(
                    _login_template, redirect=redirect, error="Invalid form submission",
                    client_ip=client_ip,
                )

            username = form_data.get("username", "").strip()
            password = form_data.get("password", "")

            if self._basic_auth_limiter.is_locked_out(client_ip, username=username if username else None):
                return self._render_login_form(
                    _login_template, redirect=redirect,
                    error=_SAFE_ERROR_MESSAGES["locked"],
                    client_ip=client_ip,
                )

            if not username or not password:
                self._basic_auth_limiter.record_failure(client_ip, username if username else None)
                return self._render_login_form(
                    _login_template, redirect=redirect,
                    error=_SAFE_ERROR_MESSAGES["required"],
                    client_ip=client_ip,
                )

            if not await self.ldap_auth.authenticate(username, password):
                self._basic_auth_limiter.record_failure(client_ip, username)
                return self._render_login_form(
                    _login_template, redirect=redirect,
                    error=_SAFE_ERROR_MESSAGES["invalid"],
                    client_ip=client_ip,
                )

            self._basic_auth_limiter.record_success(client_ip, username)
            log.info("Successful login for user '%s' from IP %s",
                     _username_log(username, self.config.proxy.mask_usernames_in_logs), client_ip)

            # Revoke any existing session cookie to prevent session fixation
            old_cookie = request.cookies.get(self._cookie_name())
            if old_cookie:
                self.session_manager.revoke_session(old_cookie)

            user_agent = request.headers.get("user-agent", "")
            cookie = self.session_manager.create_session(username, client_ip=client_ip, user_agent=user_agent)
            response = RedirectResponse(url=redirect, status_code=status.HTTP_302_FOUND)
            _set_session_cookie(
                response,
                key=self._cookie_name(),
                value=cookie,
                max_age=self.config.proxy.session_ttl,
                secure=self.config.proxy.secure_cookies,
                samesite=self.config.proxy.cookie_samesite,
            )
            return self._add_security_headers(response)

        @self.app.post(self.config.proxy.logout_path)
        async def logout(request: Request):
            if _secure_transport_required(request, self.config):
                return _https_required_response(self.config)
            origin = request.headers.get("origin", "")
            referer = request.headers.get("referer", "")
            host = request.headers.get("host", "")
            if not _is_safe_origin(origin, host, self.config.proxy.trusted_hosts):
                return self._add_security_headers(Response(status_code=403))
            if not _is_safe_referer(referer, host, self.config.proxy.trusted_hosts):
                return self._add_security_headers(Response(status_code=403))

            session_cookie = request.cookies.get(self._cookie_name())
            self.session_manager.revoke_session(session_cookie)
            response = RedirectResponse(url=self.config.proxy.login_path, status_code=status.HTTP_302_FOUND)
            _set_session_cookie(
                response,
                key=self._cookie_name(),
                value="",
                max_age=0,
                expires=0,
                secure=self.config.proxy.secure_cookies,
                samesite=self.config.proxy.cookie_samesite,
            )
            return self._add_security_headers(response)

        @self.app.get("/_auth/health")
        async def health_check(request: Request):
            """Authenticated health check endpoint for load balancers.

            Returns 200 OK if the caller is authenticated, otherwise 401.
            This prevents unauthenticated service enumeration.
            """
            if _secure_transport_required(request, self.config):
                return _https_required_response(self.config)
            client_ip = get_client_ip(request, self.config.proxy.trusted_proxies)
            if self._basic_auth_limiter.is_locked_out(client_ip):
                return self._add_security_headers(Response(
                    content="Too Many Requests", status_code=429, media_type="text/plain",
                ))
            session_cookie = request.cookies.get(self._cookie_name())
            user_agent = request.headers.get("user-agent", "")
            username = self.session_manager.verify_session(
                session_cookie, client_ip=client_ip, user_agent=user_agent,
            )
            if not username:
                return self._add_security_headers(Response(
                    content="Unauthorized", status_code=401, media_type="text/plain",
                ))
            return self._add_security_headers(Response(
                content="OK", status_code=200, media_type="text/plain",
            ))

        @self.app.api_route(
            "/{path:path}",
            methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
                     "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"],
        )
        async def proxy(request: Request, path: str):
            """Catch-all proxy to backend."""
            username: Optional[str] = None

            # Enforce HTTPS when secure_cookies is enabled, to prevent
            # session cookies from being sent over cleartext connections.
            if self.config.proxy.secure_cookies:
                scheme = self._get_scheme(request)
                if scheme != "https":
                    return self._add_security_headers(Response(
                        content="HTTPS required",
                        status_code=421,
                        media_type="text/plain",
                    ))

            # Check for HTTP Basic auth first (WebDAV clients, curl, etc.)
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Basic "):
                client_ip = get_client_ip(request, self.config.proxy.trusted_proxies)
                creds = parse_basic_auth(auth_header)
                if self._basic_auth_limiter.is_locked_out(client_ip, username=creds[0] if creds else None):
                    log.warning("Basic auth: rejecting locked-out IP %s", client_ip)
                    return self._add_security_headers(_401)
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
                    return self._add_security_headers(_401)

            if username is None:
                # Fall back to cookie/session auth
                session_cookie = request.cookies.get(self._cookie_name())
                client_ip = get_client_ip(request, self.config.proxy.trusted_proxies)
                user_agent = request.headers.get("user-agent", "")
                username = self.session_manager.verify_session(session_cookie, client_ip=client_ip, user_agent=user_agent)

            if not username:
                # Non-browser clients (WebDAV, curl, etc.) don't accept text/html
                # and won't follow a login redirect — give them a 401 challenge
                # so they know to send Basic auth credentials.
                accept = request.headers.get("accept", "")
                if "text/html" not in accept:
                    return self._add_security_headers(_401)
                # Redirect browsers to login with original URL as redirect target
                redirect_url = request.url.path
                if request.url.query:
                    redirect_url += f"?{request.url.query}"
                return self._add_security_headers(RedirectResponse(
                    url=f"{self.config.proxy.login_path}?redirect={quote(redirect_url, safe='')}",
                    status_code=status.HTTP_302_FOUND,
                ))

            # Validate Content-Length header
            content_length = request.headers.get("content-length")
            if content_length is not None:
                try:
                    cl = int(content_length)
                    if cl < 0 or cl > self.config.proxy.max_body_size:
                        return self._add_security_headers(Response(
                            content="Request body too large",
                            status_code=413,
                            media_type="text/plain",
                        ))
                except ValueError:
                    return self._add_security_headers(Response(
                        content="Invalid Content-Length",
                        status_code=400,
                        media_type="text/plain",
                    ))

            # Forward request to backend using shared pooled client
            client: httpx.AsyncClient = request.app.state.http_client

            # Use raw_path to preserve percent-encoding (%2F, %20, etc.)
            # Falls back to decoded path if the ASGI server omits raw_path.
            raw_path = request.scope.get("raw_path")
            if isinstance(raw_path, bytes):
                try:
                    forward_path = raw_path.decode("latin-1")
                except Exception:
                    forward_path = request.url.path
            else:
                forward_path = raw_path or request.url.path

            # Path traversal prevention: reject parent directory references
            # (literal and percent-encoded) to stop authenticated users from
            # reaching arbitrary backend paths beyond the proxy root.
            if "/.." in forward_path or "\\.." in forward_path:
                return self._add_security_headers(Response(
                    content="Forbidden", status_code=403, media_type="text/plain",
                ))
            forward_lower = forward_path.lower()
            if "/%2e" in forward_lower or "\\%2e" in forward_lower or ".%2e" in forward_lower \
                    or "%2e%2e" in forward_lower:
                return self._add_security_headers(Response(
                    content="Forbidden", status_code=403, media_type="text/plain",
                ))

            backend_url = self.config.proxy.backend_url.rstrip("/") + forward_path
            if request.url.query:
                backend_url += f"?{request.url.query}"

            # Build headers, stripping hop-by-hop, host, any existing user header
            # (case-insensitive) to prevent spoofing, and authorization (already
            # consumed by LDAPGate — backends must not see raw credentials).
            # Also strip any client-provided X-Forwarded-* headers and the
            # ldapgate session cookie to prevent session leakage to backends.
            user_header_lower = self.config.proxy.user_header.lower()
            headers = {
                k: v for k, v in request.headers.items()
                if k.lower() not in ("host", user_header_lower, "authorization")
                and k.lower() not in _HOP_BY_HOP
                and not k.lower().startswith("x-forwarded-")
                and k.lower() != "cookie"
            }
            # Only strip the ldapgate session cookie, forward other cookies
            cookie_val = request.headers.get("cookie")
            if cookie_val:
                cookie_self = self.config.proxy.session_cookie_name
                cookie_host = f"__Host-{cookie_self}"
                filtered = [
                    c.strip() for c in cookie_val.split(";")
                    if not any(
                        c.strip().lower().startswith(n.lower() + "=")
                        for n in (cookie_self, cookie_host)
                    )
                ]
                if filtered:
                    headers["cookie"] = "; ".join(filtered)
            headers[self.config.proxy.user_header] = username.translate(_HEADER_UNSAFE_CHARS)
            # Let backends behind --rproxy (e.g. copyparty) know the original
            # host so their CORS / redirect checks use the public-facing URL.
            if original_host := request.headers.get("host"):
                if _is_safe_host(original_host):
                    if not self.config.proxy.trusted_hosts or _is_trusted_host(original_host, self.config.proxy.trusted_hosts):
                        headers["X-Forwarded-Host"] = original_host
            # Add X-Forwarded-For using only the verified direct client IP
            direct_ip = request.client.host if request.client else ""
            if direct_ip:
                headers["X-Forwarded-For"] = direct_ip
            # Add X-Forwarded-Proto
            scheme = self._get_scheme(request)
            headers["X-Forwarded-Proto"] = scheme

            try:
                # Stream the request body with size enforcement.
                # When Content-Length is "0", use empty bytes to avoid
                # hanging on an empty stream (e.g. mocked test clients).
                if content_length == "0":
                    body_content = b""
                else:
                    body_content = _limited_stream(request, self.config.proxy.max_body_size)

                req = client.build_request(
                    method=request.method,
                    url=backend_url,
                    headers=headers,
                    content=body_content,
                )
                backend_response = await client.send(req, stream=True, follow_redirects=False)
            except _BodyTooLarge:
                return self._add_security_headers(Response(
                    content="Request body too large",
                    status_code=413,
                    media_type="text/plain",
                ))
            except httpx.RequestError:
                log.warning("Backend request failed for %s", urlparse(backend_url).path)
                return self._add_security_headers(Response(
                    content="Bad Gateway: backend service unavailable",
                    status_code=502,
                    media_type="text/plain",
                ))

            # Validate response Content-Length against max_response_size
            resp_content_length = backend_response.headers.get("content-length")
            if resp_content_length is not None:
                try:
                    rcl = int(resp_content_length)
                    if rcl < 0 or rcl > self.config.proxy.max_response_size:
                        await backend_response.aclose()
                        return self._add_security_headers(Response(
                            content="Backend response too large",
                            status_code=502,
                            media_type="text/plain",
                        ))
                except ValueError:
                    pass

            resp_headers = {
                k: v for k, v in backend_response.headers.items()
                if k.lower() not in _HOP_BY_HOP
            }
            # Rewrite Location header if it points to the backend
            location = resp_headers.get("location")
            if location:
                resp_headers["location"] = self._rewrite_location(location)
            # After rewriting, validate it's a safe redirect (relative path);
            # log and strip external redirects to prevent open-redirect phishing.
            location = resp_headers.get("location")
            if location and not _is_safe_redirect(location):
                log.warning("Backend returned external Location header: %s — stripped", location)
                del resp_headers["location"]
            # Rewrite WebDAV Destination header if present
            destination = resp_headers.get("destination")
            if destination:
                resp_headers["destination"] = self._rewrite_location(destination)
            destination = resp_headers.get("destination")
            if destination and not _is_safe_redirect(destination):
                log.warning("Backend returned external Destination header: %s — stripped", destination)
                del resp_headers["destination"]
            # Strip Refresh header to prevent open redirect via compromised backend
            resp_headers.pop("refresh", None)
            return self._add_security_headers(StreamingResponse(
                _limited_response_stream(backend_response, self.config.proxy.max_response_size),
                status_code=backend_response.status_code,
                headers=resp_headers,
            ))

    def _rewrite_location(self, location: str) -> str:
        """Rewrite backend URLs in Location/Destination headers to proxy URLs."""
        backend = self.config.proxy.backend_url.rstrip("/")
        prefix = backend + "/"
        if location.lower().startswith(prefix.lower()):
            return location[len(backend):]
        return location

    def get_app(self) -> FastAPI:
        """Get the FastAPI application.

        Returns:
            FastAPI app instance
        """
        return self.app


def create_proxy_app(config: LDAPConfig) -> FastAPI:
    """Factory function to create proxy app.

    Args:
        config: LDAPConfig instance

    Returns:
        FastAPI app ready to run
    """
    proxy = ProxyApp(config)
    return proxy.get_app()


def create_login_router(
    config: LDAPConfig,
    ldap_auth: Optional[LDAPAuthenticator] = None,
    template_path: Optional[Path] = None,
    rate_limiter: Optional[BasicAuthRateLimiter] = None,
    session_manager: Optional[SessionManager] = None,
):
    """Create a FastAPI router with login GET/POST endpoints.

    Used when mounting ldapgate auth onto an existing FastAPI app via
    add_ldap_auth(), rather than running as a standalone reverse proxy.

    Args:
        config: LDAPConfig instance
        ldap_auth: Optional pre-built LDAPAuthenticator; created from config if omitted
        template_path: Optional path to a custom login.html Jinja2 template file.
                       Falls back to the bundled ldapgate template, then inline HTML.
        rate_limiter: Optional shared BasicAuthRateLimiter for unified rate limiting.
        session_manager: Optional shared SessionManager for unified session tracking
                         with middleware. Created from config if omitted.

    Returns:
        APIRouter with login routes registered
    """
    from fastapi import APIRouter

    auth = ldap_auth or LDAPAuthenticator(config.ldap)
    session_manager = session_manager or SessionManager(
        config.proxy.secret_key.get_secret_value(),
        config.proxy.session_ttl,
        revocation_path=config.proxy.revocation_path,
        max_sessions_per_user=config.proxy.max_sessions_per_user,
    )

    # Resolve template: custom path → bundled ldapgate template → inline fallback
    template_file = Path(template_path) if template_path else None
    if template_file and template_file.exists():
        _jinja_env = Environment(
            loader=FileSystemLoader(str(template_file.parent)),
            autoescape=True,
        )
        _login_template = _jinja_env.get_template(template_file.name)
    else:
        try:
            _jinja_env = Environment(
                loader=FileSystemLoader(str(_TEMPLATES_DIR)),
                autoescape=True,
            )
            _login_template = _jinja_env.get_template("login.html")
        except TemplateNotFound:
            _jinja_env = Environment(autoescape=True)
            _login_template = _jinja_env.from_string(LOGIN_FORM_HTML)

    router = APIRouter()
    _login_limiter = rate_limiter or BasicAuthRateLimiter(
        max_failures=config.proxy.rate_limit_max_failures,
        window_seconds=config.proxy.rate_limit_window_seconds,
        lockout_seconds=config.proxy.rate_limit_lockout_seconds,
        state_path=config.proxy.rate_limit_state_path,
        mask_usernames_in_logs=config.proxy.mask_usernames_in_logs,
    )
    _cookie_name = _session_cookie_name(config)

    def _render_login(redirect: str = "", error: str = "", client_ip: str = "") -> Response:
        csrf_token = session_manager.generate_csrf_token(client_ip=client_ip)
        nonce = base64.b64encode(os.urandom(16)).decode()
        html = _login_template.render(
            app_name=config.proxy.app_name,
            login_path=config.proxy.login_path,
            redirect=redirect,
            error=error,
            csrf_token=csrf_token,
            csrf_nonce=nonce,
        )
        return _add_security_headers(
            Response(content=html, media_type="text/html"), nonce=nonce, config=config,
        )

    @router.get(config.proxy.login_path, include_in_schema=False)
    async def login_get(request: Request, redirect: Optional[str] = None, error: Optional[str] = None):
        if _secure_transport_required(request, config):
            return _https_required_response(config)
        safe_error = _SAFE_ERROR_MESSAGES.get(error, "") if error else ""
        safe_redirect = redirect if redirect and _is_safe_redirect(redirect) else ""
        client_ip = get_client_ip(request, config.proxy.trusted_proxies)
        return _render_login(redirect=safe_redirect, error=safe_error, client_ip=client_ip)

    @router.post(config.proxy.login_path, include_in_schema=False)
    async def login_post(request: Request):
        if _secure_transport_required(request, config):
            return _https_required_response(config)
        client_ip = get_client_ip(request, config.proxy.trusted_proxies)

        origin = request.headers.get("origin", "")
        referer = request.headers.get("referer", "")
        host = request.headers.get("host", "")
        if not _is_safe_origin(origin, host, config.proxy.trusted_hosts) or not _is_safe_referer(referer, host, config.proxy.trusted_hosts):
            return _add_security_headers(Response(status_code=403), config=config)

        # Reject oversized form bodies before parsing
        form_content_length = request.headers.get("content-length")
        if form_content_length is not None:
            try:
                if int(form_content_length) > 65536:
                    return _add_security_headers(Response(
                        content="Request body too large", status_code=413,
                        media_type="text/plain",
                    ), config=config)
            except ValueError:
                pass

        form_data = await request.form()
        redirect = form_data.get("redirect", "/")
        if not _is_safe_redirect(redirect):
            redirect = "/"

        csrf_token = form_data.get("csrf_token", "")
        if not session_manager.validate_csrf_token(csrf_token, client_ip=client_ip):
            return _render_login(redirect=redirect, error="Invalid form submission", client_ip=client_ip)

        username = form_data.get("username", "").strip()
        password = form_data.get("password", "")

        if _login_limiter.is_locked_out(client_ip, username=username if username else None):
            return _render_login(redirect=redirect, error=_SAFE_ERROR_MESSAGES["locked"], client_ip=client_ip)

        if not username or not password:
            _login_limiter.record_failure(client_ip, username if username else None)
            return _render_login(redirect=redirect, error=_SAFE_ERROR_MESSAGES["required"], client_ip=client_ip)

        if not await auth.authenticate(username, password):
            _login_limiter.record_failure(client_ip, username)
            return _render_login(redirect=redirect, error=_SAFE_ERROR_MESSAGES["invalid"], client_ip=client_ip)

        _login_limiter.record_success(client_ip, username)
        log.info("Successful login for user '%s' from IP %s",
                 _username_log(username, config.proxy.mask_usernames_in_logs), client_ip)

        # Revoke existing session cookie to prevent session fixation
        old_cookie = request.cookies.get(_cookie_name)
        if old_cookie:
            session_manager.revoke_session(old_cookie)

        user_agent = request.headers.get("user-agent", "")
        cookie = session_manager.create_session(username, client_ip=client_ip, user_agent=user_agent)
        response = RedirectResponse(url=redirect, status_code=status.HTTP_302_FOUND)
        _set_session_cookie(
            response,
            key=_cookie_name,
            value=cookie,
            max_age=config.proxy.session_ttl,
            secure=config.proxy.secure_cookies,
            samesite=config.proxy.cookie_samesite,
        )
        return _add_security_headers(response, config=config)

    @router.post(config.proxy.logout_path, include_in_schema=False)
    async def logout(request: Request):
        if _secure_transport_required(request, config):
            return _https_required_response(config)
        origin = request.headers.get("origin", "")
        referer = request.headers.get("referer", "")
        host = request.headers.get("host", "")
        if not _is_safe_origin(origin, host, config.proxy.trusted_hosts):
            return _add_security_headers(Response(status_code=403), config=config)
        if not _is_safe_referer(referer, host, config.proxy.trusted_hosts):
            return _add_security_headers(Response(status_code=403), config=config)

        session_cookie = request.cookies.get(_cookie_name)
        session_manager.revoke_session(session_cookie)
        response = RedirectResponse(url=config.proxy.login_path, status_code=status.HTTP_302_FOUND)
        _set_session_cookie(
            response,
            key=_cookie_name,
            value="",
            max_age=0,
            expires=0,
            secure=config.proxy.secure_cookies,
            samesite=config.proxy.cookie_samesite,
        )
        return _add_security_headers(response, config=config)

    return router
