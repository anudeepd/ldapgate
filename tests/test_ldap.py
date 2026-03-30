"""Tests for LDAP authentication helpers."""

import ssl
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from ldap3 import Tls

from ldapgate.config import LDAPSettings
from ldapgate.ldap import LDAPAuthenticator, _build_tls


def _base_settings(**kwargs) -> LDAPSettings:
    defaults = dict(
        url="ldaps://dc.example.com:636",
        bind_dn="CN=svc,CN=Users,DC=example,DC=com",
        bind_password="secret",
        base_dn="DC=example,DC=com",
    )
    defaults.update(kwargs)
    return LDAPSettings(**defaults)


@pytest.fixture()
def pem_files(tmp_path):
    """Create minimal placeholder PEM files on disk (ldap3 Tls checks existence)."""
    ca = tmp_path / "ca.pem"
    crt = tmp_path / "client.crt.pem"
    key = tmp_path / "client.key.pem"
    for f in (ca, crt, key):
        f.write_text("placeholder")
    return {"ca": str(ca), "crt": str(crt), "key": str(key)}


def test_build_tls_returns_none_by_default():
    """No TLS fields set → _build_tls returns None."""
    config = _base_settings()
    assert _build_tls(config) is None


def test_build_tls_with_ca_cert(pem_files):
    """tls_ca_cert_file set → returns Tls with ca_certs_file populated."""
    config = _base_settings(tls_ca_cert_file=pem_files["ca"])
    tls = _build_tls(config)
    assert isinstance(tls, Tls)
    assert tls.ca_certs_file == pem_files["ca"]


def test_build_tls_mutual_tls(pem_files):
    """All cert fields set → returns Tls with key, cert, and CA."""
    config = _base_settings(
        tls_ca_cert_file=pem_files["ca"],
        tls_client_cert_file=pem_files["crt"],
        tls_client_key_file=pem_files["key"],
    )
    tls = _build_tls(config)
    assert isinstance(tls, Tls)
    assert tls.ca_certs_file == pem_files["ca"]
    assert tls.certificate_file == pem_files["crt"]
    assert tls.private_key_file == pem_files["key"]


def test_build_tls_validate_none():
    """tls_validate='NONE' → returns Tls with ssl.CERT_NONE."""
    config = _base_settings(tls_validate="NONE")
    tls = _build_tls(config)
    assert isinstance(tls, Tls)
    assert tls.validate == ssl.CERT_NONE


def test_build_tls_starttls_triggers_tls_object():
    """use_starttls=True → returns Tls even without cert files."""
    config = _base_settings(use_starttls=True)
    tls = _build_tls(config)
    assert isinstance(tls, Tls)


def test_authenticator_uses_tls_server(pem_files):
    """LDAPAuthenticator.__init__ passes the Tls object to Server."""
    config = _base_settings(tls_ca_cert_file=pem_files["ca"])
    with patch("ldapgate.ldap.Server") as MockServer:
        LDAPAuthenticator(config)
        call_kwargs = MockServer.call_args.kwargs
        assert isinstance(call_kwargs["tls"], Tls)


def test_authenticator_no_tls_when_defaults():
    """LDAPAuthenticator passes tls=None to Server when no TLS fields are set."""
    config = _base_settings()
    with patch("ldapgate.ldap.Server") as MockServer:
        LDAPAuthenticator(config)
        call_kwargs = MockServer.call_args.kwargs
        assert call_kwargs["tls"] is None
