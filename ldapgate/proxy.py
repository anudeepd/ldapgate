"""FastAPI reverse proxy application with LDAP auth."""

import base64
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import httpx
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import RedirectResponse
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from ldapgate.config import LDAPConfig
from ldapgate.ldap import LDAPAuthenticator
from ldapgate.sessions import SessionManager

_TEMPLATES_DIR = Path(__file__).parent / "templates"

# Headers that must not be forwarded between proxy hops (RFC 2616 §13.5.1)
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-encoding", "content-length",
})

# Inline HTML fallback if template is not available
LOGIN_FORM_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to {{ app_name }}</title>
    <style>
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
            <button type="submit">Sign in</button>
        </form>
    </div>
    <p style="text-align:center;margin-top:2rem;font-size:0.75rem;color:#9ca3af;">
        Powered by <a href="https://github.com/anudeepd/ldapgate" style="color:#9ca3af;">LDAPGate</a>
    </p>
</body>
</html>
"""


def _parse_basic_auth(authorization: str) -> Optional[tuple[str, str]]:
    """Parse an Authorization: Basic header. Returns (username, password) or None."""
    if not authorization.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(authorization[6:]).decode("utf-8", errors="strict")
        username, _, password = decoded.partition(":")
        if not username:
            return None
        return username, password
    except Exception:
        return None


class _BasicAuthRateLimiter:
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

    def is_locked_out(self, ip: str) -> bool:
        now = time.monotonic()
        lockout_until = self._lockouts.get(ip, 0.0)
        if now < lockout_until:
            return True
        if ip in self._lockouts:
            del self._lockouts[ip]
            self._failures.pop(ip, None)
            return False
        # No active lockout — prune stale window entries and drop empty records.
        if ip in self._failures:
            self._failures[ip] = [t for t in self._failures[ip] if now - t < self.WINDOW_SECONDS]
            if not self._failures[ip]:
                del self._failures[ip]
        return False

    def record_failure(self, ip: str) -> None:
        now = time.monotonic()
        window = [t for t in self._failures[ip] if now - t < self.WINDOW_SECONDS]
        window.append(now)
        self._failures[ip] = window
        if len(window) >= self.MAX_FAILURES:
            self._lockouts[ip] = now + self.LOCKOUT_SECONDS

    def record_success(self, ip: str) -> None:
        self._failures.pop(ip, None)
        self._lockouts.pop(ip, None)


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
        self.ldap_auth = ldap_auth or LDAPAuthenticator(config.ldap)
        self.session_manager = SessionManager(
            config.proxy.secret_key, config.proxy.session_ttl
        )
        self._basic_auth_limiter = _BasicAuthRateLimiter()

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            app.state.http_client = httpx.AsyncClient()
            yield
            await app.state.http_client.aclose()

        self.app = FastAPI(lifespan=lifespan)
        self._setup_routes()

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
        async def login_get(redirect: Optional[str] = None, error: Optional[str] = None):
            """Display login form."""
            html = _login_template.render(
                app_name=self.config.proxy.app_name,
                login_path=self.config.proxy.login_path,
                redirect=redirect or "",
                error=error or "",
            )
            return Response(content=html, media_type="text/html")

        @self.app.post(self.config.proxy.login_path)
        async def login_post(request: Request):
            """Handle login form submission."""
            form_data = await request.form()
            username = form_data.get("username", "").strip()
            password = form_data.get("password", "")
            redirect = form_data.get("redirect", "/")

            # Prevent open redirect: only allow relative paths (/ but not //)
            if not redirect or not redirect.startswith("/") or redirect.startswith("//"):
                redirect = "/"

            if not username or not password:
                return await login_get(
                    redirect=redirect, error="Username and password required"
                )

            # Authenticate against LDAP
            if not await self.ldap_auth.authenticate(username, password):
                return await login_get(
                    redirect=redirect, error="Invalid username or password"
                )

            # Create session and redirect
            cookie = self.session_manager.create_session(username)
            response = RedirectResponse(url=redirect, status_code=status.HTTP_302_FOUND)
            response.set_cookie(
                SessionManager.COOKIE_NAME,
                cookie,
                max_age=self.config.proxy.session_ttl,
                httponly=True,
                secure=self.config.proxy.secure_cookies,
                samesite="lax",
            )
            return response

        @self.app.get(self.config.proxy.logout_path)
        async def logout(request: Request):
            response = RedirectResponse(url=self.config.proxy.login_path, status_code=status.HTTP_302_FOUND)
            response.delete_cookie(SessionManager.COOKIE_NAME)
            origin = request.headers.get("origin")
            if origin:
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Credentials"] = "true"
            return response

        @self.app.api_route(
            "/{path:path}",
            methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
                     "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"],
        )
        async def proxy(request: Request, path: str):
            """Catch-all proxy to backend."""
            username: Optional[str] = None

            # Check for HTTP Basic auth first (WebDAV clients, curl, etc.)
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Basic "):
                client_ip = (request.client.host if request.client else "unknown")
                _401 = Response(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    headers={"WWW-Authenticate": 'Basic realm="LDAPGate"'},
                )
                if self._basic_auth_limiter.is_locked_out(client_ip):
                    return _401
                creds = _parse_basic_auth(auth_header)
                if creds:
                    ba_user, ba_pass = creds
                    if await self.ldap_auth.authenticate(ba_user, ba_pass):
                        self._basic_auth_limiter.record_success(client_ip)
                        username = ba_user
                    else:
                        self._basic_auth_limiter.record_failure(client_ip)
                        return _401
                else:
                    self._basic_auth_limiter.record_failure(client_ip)
                    return _401

            if username is None:
                # Fall back to cookie/session auth
                session_cookie = request.cookies.get(SessionManager.COOKIE_NAME)
                username = self.session_manager.verify_session(session_cookie)

            if not username:
                # Redirect to login with original URL as redirect target
                redirect_url = request.url.path
                if request.url.query:
                    redirect_url += f"?{request.url.query}"
                return RedirectResponse(
                    url=f"{self.config.proxy.login_path}?redirect={quote(redirect_url, safe='')}",
                    status_code=status.HTTP_302_FOUND,
                )

            # Forward request to backend using shared pooled client
            client: httpx.AsyncClient = request.app.state.http_client

            # Use raw_path to preserve percent-encoding (%2F, %20, etc.)
            # Falls back to decoded path if the ASGI server omits raw_path.
            raw_path = request.scope.get("raw_path")
            forward_path = raw_path.decode("ascii") if raw_path else request.url.path
            backend_url = self.config.proxy.backend_url.rstrip("/") + forward_path
            if request.url.query:
                backend_url += f"?{request.url.query}"

            # Build headers, stripping hop-by-hop, host, any existing user header
            # (case-insensitive) to prevent spoofing, and authorization (already
            # consumed by LDAPGate — backends must not see raw credentials).
            user_header_lower = self.config.proxy.user_header.lower()
            headers = {
                k: v for k, v in request.headers.items()
                if k.lower() not in ("host", user_header_lower, "authorization")
            }
            headers[self.config.proxy.user_header] = username

            try:
                backend_response = await client.request(
                    method=request.method,
                    url=backend_url,
                    headers=headers,
                    content=await request.body(),
                    follow_redirects=False,
                )
                resp_headers = {
                    k: v for k, v in backend_response.headers.items()
                    if k.lower() not in _HOP_BY_HOP
                }
                return Response(
                    content=backend_response.content,
                    status_code=backend_response.status_code,
                    headers=resp_headers,
                )
            except httpx.RequestError as e:
                return Response(
                    content=f"Backend error: {str(e)}",
                    status_code=502,
                    media_type="text/plain",
                )

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
):
    """Create a FastAPI router with login GET/POST endpoints.

    Used when mounting ldapgate auth onto an existing FastAPI app via
    add_ldap_auth(), rather than running as a standalone reverse proxy.

    Args:
        config: LDAPConfig instance
        ldap_auth: Optional pre-built LDAPAuthenticator; created from config if omitted
        template_path: Optional path to a custom login.html Jinja2 template file.
                       Falls back to the bundled ldapgate template, then inline HTML.

    Returns:
        APIRouter with login routes registered
    """
    from fastapi import APIRouter

    auth = ldap_auth or LDAPAuthenticator(config.ldap)
    session_manager = SessionManager(config.proxy.secret_key, config.proxy.session_ttl)

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

    @router.get(config.proxy.login_path, include_in_schema=False)
    async def login_get(redirect: Optional[str] = None, error: Optional[str] = None):
        html = _login_template.render(
            app_name=config.proxy.app_name,
            login_path=config.proxy.login_path,
            redirect=redirect or "",
            error=error or "",
        )
        return Response(content=html, media_type="text/html")

    @router.post(config.proxy.login_path, include_in_schema=False)
    async def login_post(request: Request):
        form_data = await request.form()
        username = form_data.get("username", "").strip()
        password = form_data.get("password", "")
        redirect = form_data.get("redirect", "/")

        if not redirect or not redirect.startswith("/") or redirect.startswith("//"):
            redirect = "/"

        if not username or not password:
            return await login_get(redirect=redirect, error="Username and password required")

        if not await auth.authenticate(username, password):
            return await login_get(redirect=redirect, error="Invalid username or password")

        cookie = session_manager.create_session(username)
        response = RedirectResponse(url=redirect, status_code=status.HTTP_302_FOUND)
        response.set_cookie(
            SessionManager.COOKIE_NAME,
            cookie,
            max_age=config.proxy.session_ttl,
            httponly=True,
            secure=config.proxy.secure_cookies,
            samesite="lax",
        )
        return response

    @router.get(config.proxy.logout_path, include_in_schema=False)
    async def logout(request: Request):
        response = RedirectResponse(url=config.proxy.login_path, status_code=status.HTTP_302_FOUND)
        response.delete_cookie(SessionManager.COOKIE_NAME)
        origin = request.headers.get("origin")
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

    return router
