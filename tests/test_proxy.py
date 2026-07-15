"""Tests for proxy application."""

import base64
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI, Response
from starlette.testclient import TestClient

from ldapgate.config import LDAPConfig, LDAPSettings, ProxySettings
from ldapgate.middleware import LDAPAuthMiddleware, add_ldap_auth
from ldapgate.proxy import (
    LOGIN_FORM_HTML,
    ProxyApp,
    _add_security_headers,
    _https_required_response,
    _secure_transport_required,
    _session_cookie_name,
    _set_session_cookie,
    create_login_router,
    create_proxy_app,
)
from ldapgate.sessions import SessionManager


def make_test_client(*args, **kwargs):
    """Create a TestClient using uvloop to avoid asyncio portal hangs on Python 3.13."""
    kwargs.setdefault('backend_options', {'use_uvloop': True})
    return TestClient(*args, **kwargs)


def _test_config() -> LDAPConfig:
    return LDAPConfig(
        ldap=LDAPSettings(
            url='ldap://localhost:389',
            bind_dn='cn=admin,dc=example,dc=org',
            bind_password='admin',
            base_dn='dc=example,dc=org',
            user_filter='(uid={username})',
            allowed_users=['alice'],
            block_plaintext_ldap=False,
        ),
        proxy=ProxySettings(
            backend_url='http://localhost:8080',
            secret_key='a4f8c2e1b7d9e3f6a1b4c7d0e3f6a9b2c5d8e1f4a7b0c3d6e9f2a5b8c1d4e7',
            secure_cookies=False,
        ),
    )


@pytest.fixture
def client():
    """Create a test client for the proxy app."""
    config = _test_config()
    app = create_proxy_app(config)
    with make_test_client(app) as tc:
        yield tc


def test_login_page_has_security_headers(client):
    """Test login page returns security headers."""
    resp = client.get('/_auth/login')
    assert resp.status_code == 200
    assert resp.headers['X-Frame-Options'] == 'DENY'
    assert resp.headers['X-Content-Type-Options'] == 'nosniff'
    assert 'Cross-Origin-Opener-Policy' not in resp.headers
    assert resp.headers['Cache-Control'] == 'no-store, no-cache, must-revalidate, max-age=0'
    assert "font-src 'self' data:" in resp.headers['Content-Security-Policy']


def test_coop_header_is_only_added_for_https_scheme():
    """COOP is ignored on plain HTTP and creates console noise there."""
    http_response = _add_security_headers(Response(), config=_test_config(), scheme='http')
    assert 'Cross-Origin-Opener-Policy' not in http_response.headers

    https_response = _add_security_headers(Response(), config=_test_config(), scheme='https')
    assert https_response.headers['Cross-Origin-Opener-Policy'] == 'same-origin'


def test_login_page_rejects_unknown_error_param(client):
    """Test login page only accepts predefined error codes."""
    resp = client.get('/_auth/login?error=Phishing+message')
    assert resp.status_code == 200
    # The arbitrary error message should be stripped
    assert 'Phishing message' not in resp.text


def test_login_page_accepts_safe_error_param(client):
    """Test login page accepts predefined safe error codes."""
    resp = client.get('/_auth/login?error=invalid')
    assert resp.status_code == 200
    assert 'Invalid username or password' in resp.text
    assert 'id="password-toggle" aria-label="Show password"' in resp.text
    assert "password.type = visible ? 'password' : 'text';" in resp.text


def test_inline_login_fallback_includes_password_toggle():
    assert 'id="password-toggle" aria-label="Show password"' in LOGIN_FORM_HTML
    assert "password.type = visible ? 'password' : 'text';" in LOGIN_FORM_HTML


def test_secure_transport_required_for_http_requests():
    """secure_cookies=True must require HTTPS before credentials are accepted."""
    config = _test_config()
    config.proxy.secure_cookies = True

    request = SimpleNamespace(
        client=SimpleNamespace(host='testclient'),
        headers={},
        url=SimpleNamespace(scheme='http'),
    )
    assert _secure_transport_required(request, config) is True
    response = _https_required_response(config)
    assert response.status_code == 421
    assert response.body == b'HTTPS required'

    request.url.scheme = 'https'
    assert _secure_transport_required(request, config) is False


def test_secure_session_cookie_does_not_require_python_314():
    """Secure cookies must not crash from partitioned=True on Python < 3.14."""
    from starlette.responses import Response

    response = Response()
    _set_session_cookie(
        response,
        key='__Host-ldapgate_session',
        value='abc',
        max_age=60,
        secure=True,
        samesite='lax',
    )
    assert '__Host-ldapgate_session=abc' in response.headers['set-cookie']
    assert 'Secure' in response.headers['set-cookie']


def test_session_cookie_name_uses_configured_base_name():
    config = _test_config()
    config.proxy.session_cookie_name = 'torrus_session'
    assert _session_cookie_name(config) == 'torrus_session'

    config.proxy.secure_cookies = True
    assert _session_cookie_name(config) == '__Host-torrus_session'


def _make_mock_http_client(**kwargs):
    """Create a MagicMock that mimics httpx.AsyncClient for lifespan compatibility."""
    mock_client = MagicMock()
    mock_client.build_request = MagicMock(return_value=MagicMock())

    # Wrap the response so aiter_bytes() yields its .content
    if 'return_value' in kwargs:
        resp = kwargs['return_value']
        resp.aclose = AsyncMock()

        async def _aiter():
            yield resp.content

        resp.aiter_bytes = _aiter

    mock_client.send = AsyncMock(**kwargs)
    mock_client.aclose = AsyncMock()
    return mock_client


def test_backend_error_generic_message():
    """Test backend errors return generic message without leaking internals."""
    config = _test_config()
    proxy = ProxyApp(config)
    app = proxy.get_app()

    with make_test_client(app) as tc:
        mock_client = _make_mock_http_client(side_effect=httpx.ConnectError('Connection refused to internal-host:8080'))
        tc.app.state.http_client = mock_client

        with patch.object(proxy.session_manager, 'verify_session', return_value='alice'):
            resp = tc.get('/some-path')
            assert resp.status_code == 502
            assert 'backend service unavailable' in resp.text
            assert 'internal-host' not in resp.text
            assert '8080' not in resp.text


def test_options_request_requires_auth():
    """Test OPTIONS requests require authentication like other methods."""
    config = _test_config()
    proxy = ProxyApp(config)
    app = proxy.get_app()

    with make_test_client(app) as tc:
        resp = tc.options('/some-path')
        assert resp.status_code == 401


def test_location_header_rewrite():
    """Test Location header is rewritten from backend to proxy URL."""
    config = _test_config()
    proxy = ProxyApp(config)
    app = proxy.get_app()

    with make_test_client(app) as tc:
        mock_response = MagicMock()
        mock_response.content = b''
        mock_response.status_code = 302
        mock_response.headers = {'location': 'http://localhost:8080/internal/redirect'}
        mock_client = _make_mock_http_client(return_value=mock_response)
        tc.app.state.http_client = mock_client

        with patch.object(proxy.session_manager, 'verify_session', return_value='alice'):
            resp = tc.get('/some-path', follow_redirects=False)
            assert resp.status_code == 302
            assert resp.headers['location'] == '/internal/redirect'


def test_create_login_router_has_security_headers():
    """Test login router responses include security headers."""
    config = _test_config()
    router = create_login_router(config)
    app = FastAPI()
    app.include_router(router)

    with make_test_client(app) as tc:
        resp = tc.get('/_auth/login')
        assert resp.status_code == 200
        assert resp.headers['X-Frame-Options'] == 'DENY'
        assert resp.headers['X-Content-Type-Options'] == 'nosniff'
        assert "font-src 'self' data:" in resp.headers['Content-Security-Policy']


def test_add_ldap_auth_returns_shared_session_manager():
    config = _test_config()
    app = FastAPI()

    session_manager = add_ldap_auth(app, config)

    assert isinstance(session_manager, SessionManager)


def test_proxy_app_requires_backend_url():
    """Reverse-proxy mode must fail clearly when no backend is configured."""
    config = _test_config()
    config.proxy.backend_url = None

    with pytest.raises(ValueError, match='backend_url'):
        ProxyApp(config)


def test_middleware_does_not_skip_app_assets_by_default():
    """Middleware mode should protect app bundles unless explicitly configured."""
    from ldapgate.middleware import LDAPAuthMiddleware

    config = _test_config()
    app = FastAPI()

    @app.get('/assets/app.js')
    async def asset():
        return {'ok': True}

    app.add_middleware(LDAPAuthMiddleware, config=config)

    with make_test_client(app) as tc:
        resp = tc.get('/assets/app.js')
        assert resp.status_code == 401
        assert 'Cross-Origin-Opener-Policy' not in resp.headers
        assert "font-src 'self' data:" in resp.headers['Content-Security-Policy']


def test_middleware_basic_auth_success_cache_reuses_ldap_auth():
    """Chatty WebDAV clients should not force an LDAP bind on every request."""
    from ldapgate.middleware import LDAPAuthMiddleware

    config = _test_config()
    config.proxy.basic_auth_cache_ttl = 60
    ldap_auth = SimpleNamespace(authenticate=AsyncMock(return_value=True))
    app = FastAPI()

    @app.get('/')
    async def root():
        return {'ok': True}

    app.add_middleware(LDAPAuthMiddleware, config=config, ldap_auth=ldap_auth)
    auth = base64.b64encode(b'alice:secret').decode()

    with make_test_client(app) as tc:
        for _ in range(2):
            resp = tc.get('/', headers={'Authorization': f'Basic {auth}'})
            assert resp.status_code == 200

    assert ldap_auth.authenticate.await_count == 1


def test_middleware_basic_auth_cache_can_be_disabled():
    """A zero TTL keeps the old per-request Basic auth validation behavior."""
    from ldapgate.middleware import LDAPAuthMiddleware

    config = _test_config()
    config.proxy.basic_auth_cache_ttl = 0
    ldap_auth = SimpleNamespace(authenticate=AsyncMock(return_value=True))
    app = FastAPI()

    @app.get('/')
    async def root():
        return {'ok': True}

    app.add_middleware(LDAPAuthMiddleware, config=config, ldap_auth=ldap_auth)
    auth = base64.b64encode(b'alice:secret').decode()

    with make_test_client(app) as tc:
        for _ in range(2):
            resp = tc.get('/', headers={'Authorization': f'Basic {auth}'})
            assert resp.status_code == 200

    assert ldap_auth.authenticate.await_count == 2


def test_logout_rejects_cross_origin():
    """Test logout rejects requests with invalid Origin/Referer."""
    config = _test_config()
    app = create_proxy_app(config)

    with make_test_client(app, follow_redirects=False) as tc:
        # Valid origin + referer (same host)
        resp = tc.post(
            '/_auth/logout',
            headers={
                'Origin': 'http://testserver',
                'Referer': 'http://testserver/_auth/login',
                'Host': 'testserver',
            },
        )
        assert resp.status_code == 302

        # Invalid origin (subdomain spoof)
        resp = tc.post(
            '/_auth/logout',
            headers={
                'Origin': 'http://evil.testserver',
                'Referer': 'http://evil.testserver/login',
                'Host': 'testserver',
            },
        )
        assert resp.status_code == 403

        # Missing origin (rejected now)
        resp = tc.post(
            '/_auth/logout',
            headers={
                'Referer': 'http://testserver/login',
                'Host': 'testserver',
            },
        )
        assert resp.status_code == 403


def test_safe_redirect_validation():
    """Test that _is_safe_redirect rejects path traversal."""
    from ldapgate.proxy import _is_safe_redirect

    assert _is_safe_redirect('/safe/path') is True
    assert _is_safe_redirect('//evil.com') is False
    assert _is_safe_redirect('/..\\') is False
    assert _is_safe_redirect('/path/../other') is False
    assert _is_safe_redirect('/path/%2e%2e/other') is False
    assert _is_safe_redirect('/path\t') is False


def test_weak_secret_detection():
    """Test that _is_weak_secret catches weak keys."""
    from ldapgate.sessions import _is_weak_secret

    assert _is_weak_secret('change-me') is True
    assert _is_weak_secret('a' * 32) is True
    assert _is_weak_secret('abc123def456ghi789jkl012mno345') is True
    assert _is_weak_secret('local-dev-secret') is True
    # A strong key should pass (needs >= 32 chars)
    assert _is_weak_secret('x9Q#mK2vL$pN4wR8tJ6bY3cH7fG1eA5!') is False


def test_content_length_validation():
    """Test that invalid Content-Length is rejected."""
    config = _test_config()
    proxy = ProxyApp(config)
    app = proxy.get_app()

    with make_test_client(app) as tc, patch.object(proxy.session_manager, 'verify_session', return_value='alice'):
        resp = tc.post('/some-path', headers={'Content-Length': 'abc'})
        assert resp.status_code == 400

        resp = tc.post('/some-path', headers={'Content-Length': '-1'})
        assert resp.status_code == 413


def test_trusted_proxies_cidr():
    """Test that trusted_proxies CIDR matching works."""
    from ldapgate._auth_utils import _is_ip_in_networks

    assert _is_ip_in_networks('10.0.0.5', ['10.0.0.0/8']) is True
    assert _is_ip_in_networks('10.0.0.5', ['192.168.0.0/24']) is False
    assert _is_ip_in_networks('127.0.0.1', ['127.0.0.1']) is True
    assert _is_ip_in_networks('127.0.0.1', ['10.0.0.0/8']) is False


def test_health_endpoint_requires_auth():
    """Test that health endpoint requires authentication."""
    config = _test_config()
    app = create_proxy_app(config)

    with make_test_client(app) as tc:
        resp = tc.get('/_auth/health')
        assert resp.status_code == 401


def test_middleware_redirects_after_idle_timeout(monkeypatch):
    config = _test_config()
    config.proxy.bind_client = False
    config.proxy.idle_timeout = 10
    manager = SessionManager(
        config.proxy.secret_key.get_secret_value(),
        session_ttl=config.proxy.session_ttl,
        bind_client=False,
        idle_timeout=config.proxy.idle_timeout,
    )

    now = 1000.0
    monkeypatch.setattr('ldapgate.sessions.time.monotonic', lambda: now)
    cookie = manager.create_session('alice')

    app = FastAPI()

    @app.get('/')
    async def index():
        return {'ok': True}

    app.add_middleware(
        LDAPAuthMiddleware,
        config=config,
        session_manager=manager,
        ldap_auth=MagicMock(),
    )

    with make_test_client(app, follow_redirects=False) as tc:
        tc.cookies.set('ldapgate_session', cookie)
        assert tc.get('/', headers={'Accept': 'text/html'}).status_code == 200

        now = 1011.0
        resp = tc.get('/', headers={'Accept': 'text/html'})
        assert resp.status_code == 302
        assert resp.headers['location'].startswith('/_auth/login?redirect=')


def test_login_router_post_works():
    """Test that create_login_router login POST parses form correctly."""
    from unittest.mock import patch

    config = _test_config()
    router = create_login_router(config)
    app = FastAPI()
    app.include_router(router)

    with (
        make_test_client(app, follow_redirects=False) as tc,
        patch('ldapgate.proxy.LDAPAuthenticator.authenticate', return_value=True),
        patch.object(router, '_login_limiter', create=True),
        patch('ldapgate.sessions.SessionManager.validate_csrf_token', return_value=True),
    ):
        resp = tc.post(
            '/_auth/login',
            data={
                'username': 'alice',
                'password': 'secret',
                'csrf_token': 'dummy',
                'redirect': '/',
            },
            headers={
                'Origin': 'http://testserver',
                'Referer': 'http://testserver/_auth/login',
                'Host': 'testserver',
            },
        )
        assert resp.status_code == 302


def test_middleware_https_bypass_without_trusted_proxy():
    """Test that middleware HTTPS enforcement cannot be bypassed by a
    client sending X-Forwarded-Proto when no trusted proxies are configured.
    """
    from ldapgate.middleware import LDAPAuthMiddleware

    config = _test_config()
    config.proxy.secure_cookies = True

    app = FastAPI()
    app.add_middleware(LDAPAuthMiddleware, config=config)

    with make_test_client(app) as tc:
        # Client pretending to be HTTPS via X-Forwarded-Proto should still be blocked
        resp = tc.get('/', headers={'X-Forwarded-Proto': 'https'})
        assert resp.status_code == 421


def test_middleware_get_scheme_trusted_proxy():
    """Test that _get_scheme honours X-Forwarded-Proto from a trusted proxy."""
    from unittest.mock import MagicMock

    from ldapgate.middleware import LDAPAuthMiddleware

    config = _test_config()
    config.proxy.secure_cookies = True
    config.proxy.trusted_proxies = ['127.0.0.1']

    app = FastAPI()
    middleware = LDAPAuthMiddleware(app, config=config)

    mock_request = MagicMock()
    mock_request.client.host = '127.0.0.1'
    mock_request.headers.get = lambda key, default=None: 'https' if key == 'x-forwarded-proto' else default
    mock_request.url.scheme = 'http'

    assert middleware._get_scheme(mock_request) == 'https'

    # Untrusted proxy should not honour X-Forwarded-Proto
    mock_request.client.host = '192.168.1.1'
    assert middleware._get_scheme(mock_request) == 'http'


def test_safe_host_validation():
    """Test that _is_safe_host rejects dangerous Host values."""
    from ldapgate.proxy import _is_safe_host

    assert _is_safe_host('example.com') is True
    assert _is_safe_host('example.com:9000') is True
    assert _is_safe_host('192.168.1.1') is True
    assert _is_safe_host('') is False
    assert _is_safe_host('http://evil.com') is False
    assert _is_safe_host('evil.com\n') is False
    assert _is_safe_host('evil.com\t') is False
    assert _is_safe_host('evil.com@real.com') is False
    assert _is_safe_host('evil.com/') is False
    assert _is_safe_host('a' * 300) is False
