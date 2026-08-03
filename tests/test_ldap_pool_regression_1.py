"""Regression coverage for bounded LDAP login completion."""

import asyncio
import concurrent.futures
import threading
from unittest.mock import MagicMock, patch

import pytest

from ldapgate.config import LDAPSettings
from ldapgate.ldap import LDAPAuthenticator, _LDAPConnectionPool


def _settings(**kwargs) -> LDAPSettings:
    values = {
        'url': 'ldap://127.0.0.1:389',
        'bind_dn': 'cn=service,dc=example,dc=com',
        'bind_password': 'secret',
        'base_dn': 'dc=example,dc=com',
        'allowed_users': ['alice'],
        'block_plaintext_ldap': False,
        'timeout': 1,
        'pool_size': 1,
    }
    values.update(kwargs)
    return LDAPSettings(**values)


def test_pool_slot_returns_after_cross_thread_lease():
    """A completed login must let another worker use the sole pool slot."""
    # Regression: ISSUE-001 — thread-local connections retained the only pool slot forever
    # Found by /qa on 2026-08-03
    # Report: .gstack/qa-reports/qa-report-ldap-login-2026-08-03.md
    release_first = threading.Event()
    first_entered = threading.Event()
    second_entered = threading.Event()

    class FakeConnection:
        def __init__(self, *_args, **_kwargs):
            self.bound = False

        def open(self):
            return True

        def bind(self):
            self.bound = True
            return True

        def unbind(self):
            self.bound = False
            return True

    with patch('ldapgate.ldap.Connection', FakeConnection):
        pool = _LDAPConnectionPool(_settings())

        def first_worker():
            with pool.connection():
                first_entered.set()
                assert release_first.wait(timeout=1)

        def second_worker():
            with pool.connection():
                second_entered.set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(first_worker)
            assert first_entered.wait(timeout=1)
            second = executor.submit(second_worker)
            assert not second_entered.wait(timeout=0.1)
            release_first.set()
            first.result(timeout=1)
            second.result(timeout=1)

        assert second_entered.is_set()
        pool.release()


def test_connections_receive_configured_read_timeout():
    """Connected LDAP sockets must not wait forever for a server response."""
    # Regression: ISSUE-001 — ldap3 receive_timeout was left unbounded
    # Found by /qa on 2026-08-03
    # Report: .gstack/qa-reports/qa-report-ldap-login-2026-08-03.md
    connection = MagicMock(bound=True)
    with patch('ldapgate.ldap.Connection', return_value=connection) as create_connection:
        auth = LDAPAuthenticator(_settings(timeout=7))
        auth._pool._open_connection()
        assert create_connection.call_args.kwargs['receive_timeout'] == 7

        create_connection.reset_mock()
        auth._connect('uid=alice,dc=example,dc=com', 'password')
        assert create_connection.call_args.kwargs['receive_timeout'] == 7


@pytest.mark.asyncio
async def test_authentication_has_total_deadline(monkeypatch):
    """A stalled LDAP worker must resolve as a failed login, not a pending request."""
    # Regression: ISSUE-001 — login_post awaited LDAP authentication without a deadline
    # Found by /qa on 2026-08-03
    # Report: .gstack/qa-reports/qa-report-ldap-login-2026-08-03.md
    auth = LDAPAuthenticator(_settings())
    auth.config.timeout = 0.05

    async def stalled_worker(*_args):
        await asyncio.Event().wait()

    monkeypatch.setattr('ldapgate.ldap.asyncio.to_thread', stalled_worker)

    assert await auth.authenticate('alice', 'password') is False
