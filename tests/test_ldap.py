"""Tests for LDAP authentication helpers."""

import ssl
from unittest.mock import patch

import pytest
from ldap3 import Tls

from ldapgate.config import LDAPSettings
from ldapgate.ldap import LDAPAuthenticator, _build_tls


def _base_settings(**kwargs) -> LDAPSettings:
    defaults = {
        'url': 'ldaps://dc.example.com:636',
        'bind_dn': 'CN=svc,CN=Users,DC=example,DC=com',
        'bind_password': 'secret',
        'base_dn': 'DC=example,DC=com',
        'allowed_users': ['alice'],
    }
    defaults.update(kwargs)
    return LDAPSettings(**defaults)


@pytest.fixture
def pem_files(tmp_path):
    """Create minimal placeholder PEM files on disk (ldap3 Tls checks existence)."""
    ca = tmp_path / 'ca.pem'
    crt = tmp_path / 'client.crt.pem'
    key = tmp_path / 'client.key.pem'
    for f in (ca, crt, key):
        f.write_text('placeholder')
    return {'ca': str(ca), 'crt': str(crt), 'key': str(key)}


def test_build_tls_returns_none_by_default():
    """No TLS fields set on plain ldap:// → _build_tls returns None."""
    config = _base_settings(url='ldap://dc.example.com:389')
    assert _build_tls(config) is None


def test_build_tls_with_ca_cert(pem_files):
    """tls_ca_cert_file set → returns Tls with ca_certs_file populated."""
    config = _base_settings(tls_ca_cert_file=pem_files['ca'])
    tls = _build_tls(config)
    assert isinstance(tls, Tls)
    assert tls.ca_certs_file == pem_files['ca']


def test_build_tls_mutual_tls(pem_files):
    """All cert fields set → returns Tls with key, cert, and CA."""
    config = _base_settings(
        tls_ca_cert_file=pem_files['ca'],
        tls_client_cert_file=pem_files['crt'],
        tls_client_key_file=pem_files['key'],
    )
    tls = _build_tls(config)
    assert isinstance(tls, Tls)
    assert tls.ca_certs_file == pem_files['ca']
    assert tls.certificate_file == pem_files['crt']
    assert tls.private_key_file == pem_files['key']


def test_build_tls_validate_none():
    """tls_validate='NONE' → returns Tls with ssl.CERT_NONE."""
    config = _base_settings(tls_validate='NONE')
    tls = _build_tls(config)
    assert isinstance(tls, Tls)
    assert tls.validate == ssl.CERT_NONE


def test_build_tls_ldaps_triggers_tls_object():
    """ldaps:// → returns Tls with REQUIRED validation even without cert files."""
    config = _base_settings()
    tls = _build_tls(config)
    assert isinstance(tls, Tls)
    assert tls.validate == ssl.CERT_REQUIRED


def test_build_tls_starttls_triggers_tls_object():
    """use_starttls=True → returns Tls even without cert files."""
    config = _base_settings(use_starttls=True)
    tls = _build_tls(config)
    assert isinstance(tls, Tls)


def test_authenticator_uses_tls_server(pem_files):
    """LDAPAuthenticator.__init__ passes the Tls object to Server."""
    config = _base_settings(tls_ca_cert_file=pem_files['ca'])
    with patch('ldapgate.ldap.Server') as mock_server:
        LDAPAuthenticator(config)
        # Server is called twice (once for self.server, once for pool)
        calls = mock_server.call_args_list
        assert len(calls) >= 1
        for call in calls:
            call_kwargs = call.kwargs
            assert isinstance(call_kwargs.get('tls'), Tls)


def test_authenticator_referral_following_reuses_tls(pem_files):
    """Allowed referral searches should reuse the authenticator TLS config."""
    config = _base_settings(
        tls_ca_cert_file=pem_files['ca'],
        follow_referrals=True,
        referral_allowed_hosts=['dc2.example.com'],
    )
    with patch('ldapgate.ldap.Server') as mock_server, patch('ldapgate.ldap.Connection') as mock_connection:
        auth = LDAPAuthenticator(config)
        mock_server.reset_mock()
        ref_conn = mock_connection.return_value
        ref_conn.entries = ['entry']
        ref_conn.result = {'description': 'success'}
        conn = type(
            'Conn', (), {'result': {'referrals': ['ldaps://dc2.example.com/DC=example,DC=com']}, 'entries': []}
        )()

        auth._follow_search_referrals(conn, config.base_dn, '(uid=alice)', 'SUBTREE')  # type: ignore[arg-type]

        assert mock_server.call_args.kwargs['tls'] is auth.tls
        assert conn.entries == ['entry']  # type: ignore[attr-defined]


def test_authenticator_no_tls_when_defaults():
    """LDAPAuthenticator passes tls=None to Server when no TLS fields are set on plain ldap://."""
    config = _base_settings(url='ldap://dc.example.com:389', block_plaintext_ldap=False)
    with patch('ldapgate.ldap.Server') as mock_server:
        LDAPAuthenticator(config)
        calls = mock_server.call_args_list
        assert len(calls) >= 1
        for call in calls:
            call_kwargs = call.kwargs
            assert call_kwargs.get('tls') is None
