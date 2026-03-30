"""Tests for configuration management."""

import tempfile
from pathlib import Path

import pytest
import yaml

from ldapgate.config import LDAPConfig, LDAPSettings, ProxySettings, load_config


def test_load_config_from_yaml():
    """Test loading configuration from YAML file."""
    config_data = {
        "ldap": {
            "url": "ldaps://dc.example.com:636",
            "bind_dn": "CN=svc,CN=Users,DC=example,DC=com",
            "bind_password": "secret",
            "base_dn": "DC=example,DC=com",
            "user_filter": "(sAMAccountName={username})",
        },
        "proxy": {
            "listen_host": "0.0.0.0",
            "listen_port": 9000,
            "backend_url": "http://localhost:8080",
            "secret_key": "my-secret-key",
            "session_ttl": 3600,
            "user_header": "X-Forwarded-User",
            "login_path": "/_auth/login",
            "app_name": "myapp",
        },
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(config_data, f)
        temp_path = f.name

    try:
        config = load_config(temp_path)

        assert config.ldap.url == "ldaps://dc.example.com:636"
        assert config.ldap.bind_dn == "CN=svc,CN=Users,DC=example,DC=com"
        assert config.proxy.listen_port == 9000
        assert config.proxy.backend_url == "http://localhost:8080"
    finally:
        Path(temp_path).unlink()


def test_config_missing_file():
    """Test that missing file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path/config.yaml")


def test_config_empty_file():
    """Test that empty YAML file raises ValueError."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("")
        temp_path = f.name

    try:
        with pytest.raises(ValueError):
            load_config(temp_path)
    finally:
        Path(temp_path).unlink()


def test_ldap_settings_defaults():
    """Test LDAP settings with defaults."""
    settings = LDAPSettings(
        url="ldaps://dc.example.com:636",
        bind_dn="CN=svc,CN=Users,DC=example,DC=com",
        bind_password="secret",
        base_dn="DC=example,DC=com",
    )

    assert settings.user_filter == "(sAMAccountName={username})"
    assert settings.group_dn is None
    assert settings.timeout == 10


def test_ldap_settings_tls_defaults():
    """Verify all TLS fields default to None/False/REQUIRED."""
    settings = LDAPSettings(
        url="ldaps://dc.example.com:636",
        bind_dn="CN=svc,CN=Users,DC=example,DC=com",
        bind_password="secret",
        base_dn="DC=example,DC=com",
    )

    assert settings.tls_ca_cert_file is None
    assert settings.tls_client_cert_file is None
    assert settings.tls_client_key_file is None
    assert settings.tls_validate == "REQUIRED"
    assert settings.use_starttls is False
    assert settings.follow_referrals is True


def test_ldap_settings_tls_full():
    """Verify TLS fields parse correctly."""
    settings = LDAPSettings(
        url="ldaps://dc.example.com:636",
        bind_dn="CN=svc,CN=Users,DC=example,DC=com",
        bind_password="secret",
        base_dn="DC=example,DC=com",
        tls_ca_cert_file="/etc/ssl/ca.pem",
        tls_client_cert_file="/etc/ssl/client.crt.pem",
        tls_client_key_file="/etc/ssl/client.key.pem",
        tls_validate="OPTIONAL",
        follow_referrals=False,
    )

    assert settings.tls_ca_cert_file == "/etc/ssl/ca.pem"
    assert settings.tls_client_cert_file == "/etc/ssl/client.crt.pem"
    assert settings.tls_client_key_file == "/etc/ssl/client.key.pem"
    assert settings.tls_validate == "OPTIONAL"
    assert settings.follow_referrals is False


def test_ldap_settings_starttls():
    """Verify use_starttls: true loads correctly."""
    settings = LDAPSettings(
        url="ldap://dc.example.com:389",
        bind_dn="CN=svc,CN=Users,DC=example,DC=com",
        bind_password="secret",
        base_dn="DC=example,DC=com",
        use_starttls=True,
    )

    assert settings.use_starttls is True


def test_proxy_settings_defaults():
    """Test proxy settings with defaults."""
    settings = ProxySettings(
        backend_url="http://localhost:8080",
        secret_key="my-secret-key",
    )

    assert settings.listen_host == "0.0.0.0"
    assert settings.listen_port == 9000
    assert settings.session_ttl == 3600
    assert settings.user_header == "X-Forwarded-User"
    assert settings.login_path == "/_auth/login"
    assert settings.app_name == "ldapgate"
