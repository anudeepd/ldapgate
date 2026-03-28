"""Tests for session management."""

import time

import pytest

from ldapgate.sessions import SessionManager


def test_create_and_verify_session():
    """Test creating and verifying a valid session."""
    manager = SessionManager("test-secret-key", session_ttl=3600)

    username = "testuser"
    cookie = manager.create_session(username)

    assert cookie is not None
    assert manager.verify_session(cookie) == username


def test_verify_invalid_signature():
    """Test that invalid signature returns None."""
    manager = SessionManager("test-secret-key", session_ttl=3600)

    # Try to verify with wrong signature
    result = manager.verify_session("invalid.signature")
    assert result is None


def test_verify_none_cookie():
    """Test that None cookie returns None."""
    manager = SessionManager("test-secret-key", session_ttl=3600)
    assert manager.verify_session(None) is None


def test_verify_empty_cookie():
    """Test that empty cookie returns None."""
    manager = SessionManager("test-secret-key", session_ttl=3600)
    assert manager.verify_session("") is None


def test_session_expiry():
    """Test that expired sessions are rejected.

    itsdangerous uses integer-second timestamps and a strict > comparison,
    so we need to sleep long enough for the integer difference to exceed max_age.
    """
    manager = SessionManager("test-secret-key", session_ttl=1)

    username = "testuser"
    cookie = manager.create_session(username)

    # Session should be valid immediately
    assert manager.verify_session(cookie) == username

    # Sleep 2.5s — guarantees integer-second delta > 1 regardless of when
    # within the current second the cookie was signed
    time.sleep(2.5)

    # Session should be expired
    assert manager.verify_session(cookie) is None


def test_different_keys_dont_verify():
    """Test that sessions signed with different keys don't verify."""
    manager1 = SessionManager("secret-key-1", session_ttl=3600)
    manager2 = SessionManager("secret-key-2", session_ttl=3600)

    cookie = manager1.create_session("testuser")

    # Should not verify with different key
    assert manager2.verify_session(cookie) is None
