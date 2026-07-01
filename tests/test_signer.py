"""Tests for the custom stdlib-based token signer."""

import time

import pytest

from ldapgate._signer import BadSignature, TimedSigner

_TEST_KEY = 'x9Q#mK2vL$pN4wR8tJ6bY3cH7fG1eA5!'


def test_dumps_and_loads():
    """Basic round-trip: sign then verify."""
    s = TimedSigner(_TEST_KEY)
    token = s.dumps({'u': 'alice'})
    assert s.loads(token) == {'u': 'alice'}


def test_expiry_rejected():
    """Loads with max_age rejects expired tokens."""
    s = TimedSigner(_TEST_KEY)
    token = s.dumps('data')
    assert s.loads(token, max_age=3600) == 'data'
    # Negative max_age means the token is already expired
    time.sleep(0.01)  # ensure monotonic time has advanced
    with pytest.raises(BadSignature):
        s.loads(token, max_age=-1)


def test_tampered_token_rejected():
    """Modified token raises BadSignature."""
    s = TimedSigner(_TEST_KEY)
    token = s.dumps('data')
    with pytest.raises(BadSignature):
        s.loads(token + 'x')


def test_wrong_key():
    """Token signed with one key fails to verify with another."""
    s1 = TimedSigner(_TEST_KEY)
    s2 = TimedSigner('y8R@nJ1wM%oO5xS7uK5aZ2bG6eH0fB9#')
    token = s1.dumps('data')
    with pytest.raises(BadSignature):
        s2.loads(token)


def test_salt_isolation():
    """Same key but different salt produces different signatures."""
    s1 = TimedSigner(_TEST_KEY, salt='one')
    s2 = TimedSigner(_TEST_KEY, salt='two')
    token = s1.dumps('data')
    with pytest.raises(BadSignature):
        s2.loads(token)


def test_empty_token():
    """Empty or malformed tokens raise BadSignature."""
    s = TimedSigner(_TEST_KEY)
    with pytest.raises(BadSignature):
        s.loads('')
    with pytest.raises(BadSignature):
        s.loads('.')
    with pytest.raises(BadSignature):
        s.loads('a.b.c')


def test_string_payload():
    """String payloads (like CSRF nonces) round-trip correctly."""
    s = TimedSigner(_TEST_KEY, salt='csrf')
    token = s.dumps('random-nonce-123')
    assert s.loads(token) == 'random-nonce-123'


def test_int_payload():
    """Integer payloads round-trip correctly."""
    s = TimedSigner(_TEST_KEY)
    token = s.dumps(42)
    assert s.loads(token) == 42
