"""Tests for session management."""

import time

from ldapgate.sessions import SessionManager

_TEST_SECRET = 'x9Q#mK2vL$pN4wR8tJ6bY3cH7fG1eA5!'


def test_create_and_verify_session():
    """Test creating and verifying a valid session."""
    manager = SessionManager(_TEST_SECRET, session_ttl=3600)

    username = 'testuser'
    cookie = manager.create_session(username, client_ip='10.0.0.1', user_agent='Mozilla/5.0')

    assert cookie is not None
    assert manager.verify_session(cookie, client_ip='10.0.0.1', user_agent='Mozilla/5.0') == username


def test_verify_invalid_signature():
    """Test that invalid signature returns None."""
    manager = SessionManager(_TEST_SECRET, session_ttl=3600)

    # Try to verify with wrong signature
    result = manager.verify_session('invalid.signature')
    assert result is None


def test_verify_none_cookie():
    """Test that None cookie returns None."""
    manager = SessionManager(_TEST_SECRET, session_ttl=3600)
    assert manager.verify_session(None) is None


def test_verify_empty_cookie():
    """Test that empty cookie returns None."""
    manager = SessionManager(_TEST_SECRET, session_ttl=3600)
    assert manager.verify_session('') is None


def test_session_expiry():
    """Test that expired sessions are rejected.

    itsdangerous uses integer-second timestamps and a strict > comparison,
    so we need to sleep long enough for the integer difference to exceed max_age.
    """
    manager = SessionManager(_TEST_SECRET, session_ttl=1)

    username = 'testuser'
    cookie = manager.create_session(username, client_ip='10.0.0.1', user_agent='Mozilla/5.0')

    # Session should be valid immediately
    assert manager.verify_session(cookie, client_ip='10.0.0.1', user_agent='Mozilla/5.0') == username

    # Sleep 2.5s — guarantees integer-second delta > 1 regardless of when
    # within the current second the cookie was signed
    time.sleep(2.5)

    # Session should be expired
    assert manager.verify_session(cookie, client_ip='10.0.0.1', user_agent='Mozilla/5.0') is None


def test_idle_timeout_disabled_by_default(monkeypatch):
    """Idle tracking is opt-in; default sessions keep old absolute-TTL behavior."""
    now = 1000.0
    monkeypatch.setattr('ldapgate.sessions.time.monotonic', lambda: now)
    manager = SessionManager(_TEST_SECRET, session_ttl=3600)

    cookie = manager.create_session('testuser')

    now = 2000.0
    assert manager.verify_session(cookie) == 'testuser'


def test_idle_timeout_rejects_inactive_session(monkeypatch):
    """Sessions expire after idle_timeout seconds without authenticated requests."""
    now = 1000.0
    monkeypatch.setattr('ldapgate.sessions.time.monotonic', lambda: now)
    manager = SessionManager(_TEST_SECRET, session_ttl=3600, idle_timeout=60)

    cookie = manager.create_session('testuser')
    assert manager.verify_session(cookie) == 'testuser'

    now = 1061.0
    assert manager.verify_session(cookie) is None


def test_idle_timeout_refreshes_on_activity(monkeypatch):
    """Successful verification touches activity and extends the idle window."""
    now = 1000.0
    monkeypatch.setattr('ldapgate.sessions.time.monotonic', lambda: now)
    manager = SessionManager(_TEST_SECRET, session_ttl=3600, idle_timeout=60)

    cookie = manager.create_session('testuser')

    now = 1050.0
    assert manager.verify_session(cookie) == 'testuser'

    now = 1101.0
    assert manager.verify_session(cookie) == 'testuser'

    now = 1162.0
    assert manager.verify_session(cookie) is None


def test_different_keys_dont_verify():
    """Test that sessions signed with different keys don't verify."""
    manager1 = SessionManager('x9Q#mK2vL$pN4wR8tJ6bY3cH7fG1eA5!', session_ttl=3600)
    manager2 = SessionManager('y8R@nJ1wM%oO5xS7uK5aZ2bG6eH0fB9#', session_ttl=3600)

    cookie = manager1.create_session('testuser', client_ip='10.0.0.1', user_agent='Mozilla/5.0')

    # Should not verify with different key
    assert manager2.verify_session(cookie, client_ip='10.0.0.1', user_agent='Mozilla/5.0') is None


def test_session_revocation():
    """Test that revoked sessions are rejected."""
    manager = SessionManager(_TEST_SECRET, session_ttl=3600)

    username = 'testuser'
    cookie = manager.create_session(username, client_ip='10.0.0.1', user_agent='Mozilla/5.0')

    # Session should be valid before revocation
    assert manager.verify_session(cookie, client_ip='10.0.0.1', user_agent='Mozilla/5.0') == username

    # Revoke the session
    manager.revoke_session(cookie)

    # Session should be rejected after revocation
    assert manager.verify_session(cookie, client_ip='10.0.0.1', user_agent='Mozilla/5.0') is None


def test_revocation_file_with_insecure_permissions_does_not_crash(tmp_path):
    """Unsafe revocation store permissions should disable file use without raising."""
    revocation_path = tmp_path / 'revoked.json'
    revocation_path.write_text('{}')
    revocation_path.chmod(0o644)
    manager = SessionManager(_TEST_SECRET, session_ttl=3600, revocation_path=str(revocation_path))

    cookie = manager.create_session('testuser')
    manager.revoke_session(cookie)

    assert manager.verify_session(cookie) is None


def test_revoke_none_session():
    """Test that revoking None does not raise."""
    manager = SessionManager(_TEST_SECRET, session_ttl=3600)
    manager.revoke_session(None)
    manager.revoke_session('')
    # Should not raise


def test_session_binding_blocks_replay():
    """Test that a session bound to one IP cannot be replayed from another."""
    manager = SessionManager(_TEST_SECRET, session_ttl=3600)

    cookie = manager.create_session('testuser', client_ip='10.0.0.1', user_agent='Mozilla/5.0')

    # Same IP should work
    assert manager.verify_session(cookie, client_ip='10.0.0.1', user_agent='Mozilla/5.0') == 'testuser'

    # Different IP should fail
    assert manager.verify_session(cookie, client_ip='10.0.0.2', user_agent='Mozilla/5.0') is None

    # Different User-Agent should fail
    assert manager.verify_session(cookie, client_ip='10.0.0.1', user_agent='Mozilla/6.0') is None


def test_csrf_token_validity():
    """Test CSRF token generation and validation."""
    manager = SessionManager(_TEST_SECRET, session_ttl=3600)

    token = manager.generate_csrf_token(client_ip='10.0.0.1')
    assert manager.validate_csrf_token(token, client_ip='10.0.0.1')
    assert not manager.validate_csrf_token('invalid')
    assert not manager.validate_csrf_token('')
    assert not manager.validate_csrf_token(None)


def test_csrf_token_ip_binding():
    """Test that CSRF tokens are bound to client IP."""
    manager = SessionManager(_TEST_SECRET, session_ttl=3600)

    token = manager.generate_csrf_token(client_ip='10.0.0.1')
    assert manager.validate_csrf_token(token, client_ip='10.0.0.1')
    assert not manager.validate_csrf_token(token, client_ip='10.0.0.2')


def test_client_binding_can_be_disabled_for_unstable_addresses():
    manager = SessionManager(_TEST_SECRET, session_ttl=3600, bind_client=False)

    cookie = manager.create_session('testuser', client_ip='10.0.0.1', user_agent='Safari/1')
    assert manager.verify_session(cookie, client_ip='10.0.0.2', user_agent='Safari/2') == 'testuser'

    token = manager.generate_csrf_token(client_ip='10.0.0.1')
    assert manager.validate_csrf_token(token, client_ip='10.0.0.2')


def test_csrf_token_without_ip():
    """Test CSRF tokens work without IP binding (backward compat)."""
    manager = SessionManager(_TEST_SECRET, session_ttl=3600)

    token = manager.generate_csrf_token()
    assert manager.validate_csrf_token(token)
    token = manager.generate_csrf_token()
    assert manager.validate_csrf_token(token, client_ip='10.0.0.1')


def test_csrf_token_expiry():
    """Test that CSRF tokens expire with session_ttl."""
    manager = SessionManager(_TEST_SECRET, session_ttl=1)

    token = manager.generate_csrf_token(client_ip='10.0.0.1')
    assert manager.validate_csrf_token(token, client_ip='10.0.0.1')

    time.sleep(2.5)
    assert not manager.validate_csrf_token(token, client_ip='10.0.0.1')


def test_max_sessions_enforces_limit():
    """Test that max_sessions_per_user revokes the oldest session."""
    manager = SessionManager(_TEST_SECRET, session_ttl=3600, max_sessions_per_user=2)

    cookie1 = manager.create_session('alice', client_ip='10.0.0.1', user_agent='A')
    cookie2 = manager.create_session('alice', client_ip='10.0.0.1', user_agent='B')
    cookie3 = manager.create_session('alice', client_ip='10.0.0.1', user_agent='C')

    # Only the last two should be valid
    assert manager.verify_session(cookie1, client_ip='10.0.0.1', user_agent='A') is None
    assert manager.verify_session(cookie2, client_ip='10.0.0.1', user_agent='B') == 'alice'
    assert manager.verify_session(cookie3, client_ip='10.0.0.1', user_agent='C') == 'alice'


def test_max_sessions_unlimited_by_default():
    """Test that max_sessions_per_user=0 allows unlimited sessions."""
    manager = SessionManager(_TEST_SECRET, session_ttl=3600, max_sessions_per_user=0)

    cookies = [manager.create_session('alice') for _ in range(10)]
    for c in cookies:
        assert manager.verify_session(c) == 'alice'


def test_revoke_session_stops_tracking():
    """Test that revoking a session also removes it from tracking."""
    manager = SessionManager(_TEST_SECRET, session_ttl=3600, max_sessions_per_user=2)

    cookie = manager.create_session('alice')
    # Create another to verify limit isn't affected by revoked session
    cookie2 = manager.create_session('alice')

    manager.revoke_session(cookie)
    assert manager.verify_session(cookie) is None
    assert manager.verify_session(cookie2) == 'alice'

    # Creating a third should keep both cookie2 and cookie3 (max=2, and
    # cookie was already revoked so cookie2 is the only tracked session)
    cookie3 = manager.create_session('alice')
    assert manager.verify_session(cookie) is None
    assert manager.verify_session(cookie2) == 'alice'
    assert manager.verify_session(cookie3) == 'alice'

    # A fourth session should push out the oldest remaining (cookie2)
    cookie4 = manager.create_session('alice')
    assert manager.verify_session(cookie2) is None
    assert manager.verify_session(cookie3) == 'alice'
    assert manager.verify_session(cookie4) == 'alice'
