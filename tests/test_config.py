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
            "allowed_users": ["alice"],
        },
        "proxy": {
            "listen_host": "0.0.0.0",
            "listen_port": 9000,
            "backend_url": "http://localhost:8080",
            "secret_key": "x9Q#mK2vL$pN4wR8tJ6bY3cH7fG1eA5!",
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
        allowed_users=["alice"],
    )

    assert settings.user_filter == "(sAMAccountName={username})"
    assert settings.group_dn is None
    assert settings.allowed_users == ["alice"]
    assert settings.require_authorization_rule is True
    assert settings.timeout == 10
    assert settings.block_plaintext_ldap is True
    assert settings.block_tls_verify_none is True


def test_ldap_settings_tls_defaults():
    """Verify all TLS fields default to None/False/REQUIRED."""
    settings = LDAPSettings(
        url="ldaps://dc.example.com:636",
        bind_dn="CN=svc,CN=Users,DC=example,DC=com",
        bind_password="secret",
        base_dn="DC=example,DC=com",
        allowed_users=["alice"],
    )

    assert settings.tls_ca_cert_file is None
    assert settings.tls_client_cert_file is None
    assert settings.tls_client_key_file is None
    assert settings.tls_validate == "REQUIRED"
    assert settings.use_starttls is False
    assert settings.follow_referrals is False


def test_ldap_settings_tls_full():
    """Verify TLS fields parse correctly."""
    settings = LDAPSettings(
        url="ldaps://dc.example.com:636",
        bind_dn="CN=svc,CN=Users,DC=example,DC=com",
        bind_password="secret",
        base_dn="DC=example,DC=com",
        allowed_users=["alice"],
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
        allowed_users=["alice"],
        use_starttls=True,
    )

    assert settings.use_starttls is True


def test_proxy_settings_defaults():
    """Test proxy settings with defaults."""
    settings = ProxySettings(
        secret_key="x9Q#mK2vL$pN4wR8tJ6bY3cH7fG1eA5!",
    )

    assert settings.listen_host == "0.0.0.0"
    assert settings.listen_port == 9000
    assert settings.backend_url is None
    assert settings.session_ttl == 3600
    assert settings.user_header == "X-Forwarded-User"
    assert settings.login_path == "/_auth/login"
    assert settings.app_name == "ldapgate"
    assert settings.static_paths == []
    assert settings.basic_auth_cache_ttl == 60


def test_ldap_settings_invalid_tls_validate():
    """Test that invalid tls_validate value raises ValueError."""
    with pytest.raises(ValueError):
        LDAPSettings(
            url="ldaps://dc.example.com:636",
            bind_dn="CN=svc,CN=Users,DC=example,DC=com",
            bind_password="secret",
            base_dn="DC=example,DC=com",
            allowed_users=["alice"],
            tls_validate="INVALID",
        )


def test_config_extra_fields_forbidden():
    """Test that extra fields in config raise ValueError."""
    with pytest.raises(ValueError):
        LDAPSettings(
            url="ldaps://dc.example.com:636",
            bind_dn="CN=svc,CN=Users,DC=example,DC=com",
            bind_password="secret",
            base_dn="DC=example,DC=com",
            allowed_users=["alice"],
            unknown_field="should_fail",
        )


def test_backend_url_blocks_non_local_http():
    """Test that backend_url rejects non-local HTTP URLs."""
    with pytest.raises(ValueError):
        ProxySettings(
            backend_url="http://192.168.1.1:8080",
            secret_key="x9Q#mK2vL$pN4wR8tJ6bY3cH7fG1eA5!",
        )


def test_backend_url_allows_local_http():
    """Test that backend_url allows localhost HTTP."""
    settings = ProxySettings(
        backend_url="http://localhost:8080",
        secret_key="x9Q#mK2vL$pN4wR8tJ6bY3cH7fG1eA5!",
    )
    assert settings.backend_url == "http://localhost:8080"


def test_backend_url_allows_https():
    """Test that backend_url allows HTTPS for any host."""
    settings = ProxySettings(
        backend_url="https://api.example.com:443",
        secret_key="x9Q#mK2vL$pN4wR8tJ6bY3cH7fG1eA5!",
    )
    assert settings.backend_url == "https://api.example.com:443"


def test_ldap_url_validation():
    """Test that LDAP URL must start with ldap:// or ldaps://."""
    with pytest.raises(ValueError):
        LDAPSettings(
            url="ftp://invalid.example.com:389",
            bind_dn="CN=svc,CN=Users,DC=example,DC=com",
            bind_password="secret",
            base_dn="DC=example,DC=com",
            allowed_users=["alice"],
        )


def test_cookie_samesite_validation():
    """Test that cookie_samesite must be lax or strict."""
    with pytest.raises(ValueError):
        ProxySettings(
            backend_url="http://localhost:8080",
            secret_key="x9Q#mK2vL$pN4wR8tJ6bY3cH7fG1eA5!",
            cookie_samesite="none",
        )
    settings = ProxySettings(
        backend_url="http://localhost:8080",
        secret_key="x9Q#mK2vL$pN4wR8tJ6bY3cH7fG1eA5!",
        cookie_samesite="strict",
    )
    assert settings.cookie_samesite == "strict"


def test_session_cookie_name_validation():
    """Session cookie names can be app-specific but must be valid names."""
    settings = ProxySettings(
        backend_url="http://localhost:8080",
        secret_key="x9Q#mK2vL$pN4wR8tJ6bY3cH7fG1eA5!",
        session_cookie_name="torrus_session",
    )
    assert settings.session_cookie_name == "torrus_session"

    with pytest.raises(ValueError):
        ProxySettings(
            backend_url="http://localhost:8080",
            secret_key="x9Q#mK2vL$pN4wR8tJ6bY3cH7fG1eA5!",
            session_cookie_name="bad name",
        )

    with pytest.raises(ValueError):
        ProxySettings(
            backend_url="http://localhost:8080",
            secret_key="x9Q#mK2vL$pN4wR8tJ6bY3cH7fG1eA5!",
            session_cookie_name="__Host-torrus_session",
        )


def test_pool_size_default():
    """Test that pool_size defaults to 1."""
    settings = LDAPSettings(
        url="ldaps://dc.example.com:636",
        bind_dn="CN=svc,CN=Users,DC=example,DC=com",
        bind_password="secret",
        base_dn="DC=example,DC=com",
        allowed_users=["alice"],
    )
    assert settings.pool_size == 1


def test_ldap_requires_allowed_users_or_group():
    """LDAP auth must be explicitly scoped to users or a group by default."""
    with pytest.raises(ValueError, match="allowed_users"):
        LDAPSettings(
            url="ldaps://dc.example.com:636",
            bind_dn="CN=svc,CN=Users,DC=example,DC=com",
            bind_password="secret",
            base_dn="DC=example,DC=com",
        )


def test_ldap_can_disable_authorization_requirement_for_dev():
    """Local dev/tests can opt out explicitly."""
    settings = LDAPSettings(
        url="ldaps://dc.example.com:636",
        bind_dn="CN=svc,CN=Users,DC=example,DC=com",
        bind_password="secret",
        base_dn="DC=example,DC=com",
        require_authorization_rule=False,
    )
    assert settings.require_authorization_rule is False


def test_ldap_user_filter_requires_username_placeholder():
    """A filter that does not depend on the username is unsafe."""
    with pytest.raises(ValueError, match="username"):
        LDAPSettings(
            url="ldaps://dc.example.com:636",
            bind_dn="CN=svc,CN=Users,DC=example,DC=com",
            bind_password="secret",
            base_dn="DC=example,DC=com",
            user_filter="(objectClass=person)",
            allowed_users=["alice"],
        )


def test_ldap_allowed_users_rejects_blank_entries():
    """Blank allowlist entries must not satisfy the authorization rule."""
    with pytest.raises(ValueError, match="non-empty"):
        LDAPSettings(
            url="ldaps://dc.example.com:636",
            bind_dn="CN=svc,CN=Users,DC=example,DC=com",
            bind_password="secret",
            base_dn="DC=example,DC=com",
            allowed_users=["alice", " "],
        )


def test_max_sessions_per_user_default():
    """Test that max_sessions_per_user defaults to 0 (unlimited)."""
    settings = ProxySettings(
        backend_url="http://localhost:8080",
        secret_key="x9Q#mK2vL$pN4wR8tJ6bY3cH7fG1eA5!",
    )
    assert settings.max_sessions_per_user == 0
