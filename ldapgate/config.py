"""Configuration management for ldapgate."""

import re
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from ldapgate.sessions import _is_weak_secret


def validate_backend_url(url: str) -> str:
    """Validate a backend URL: must be http(s) and not cleartext over network.

    Returns the validated URL on success, raises ValueError on failure.
    """
    v_lower = url.lower()
    if not v_lower.startswith(('http://', 'https://')):
        raise ValueError('Backend URL must start with http:// or https://')
    if v_lower.startswith('http://') and not re.match(r'^http://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(/|$)', v_lower):
        raise ValueError(
            'Backend URL must use https:// for non-localhost addresses. Plain HTTP over the network is insecure.'
        )
    return url


class LDAPSettings(BaseModel):
    """LDAP/AD configuration."""

    model_config = SettingsConfigDict(extra='forbid')

    url: str = Field(..., description='LDAP server URL (e.g., ldaps://dc.example.com:636)')
    bind_dn: str = Field(..., description='Service account DN for binding')
    bind_password: SecretStr = Field(..., description='Service account password')
    base_dn: str = Field(..., description='Base DN for user searches')
    user_filter: str = Field(
        '(sAMAccountName={username})',
        description='LDAP filter for user lookup (e.g., AD: sAMAccountName, OpenLDAP: uid)',
    )
    group_dn: str | None = Field(None, description='Optional group DN to restrict access (e.g., CN=app-users,...')
    allowed_users: list[str] | None = Field(
        None, description='Optional list of usernames allowed through (local allowlist)'
    )
    require_authorization_rule: bool = Field(
        True,
        description='Require allowed_users or group_dn to be configured. Disable only for local development or tests.',
    )
    timeout: int = Field(10, description='LDAP connection timeout in seconds')
    block_plaintext_ldap: bool = Field(
        True,
        description='Refuse to start if using plain ldap:// without STARTTLS. Set to False only for testing.',
    )

    # TLS configuration (all optional — only needed for custom certs or mutual TLS)
    tls_ca_cert_file: str | None = Field(
        None, description='Path to CA certificate PEM file for server certificate validation'
    )
    tls_client_cert_file: str | None = Field(None, description='Path to client certificate PEM file (for mutual TLS)')
    tls_client_key_file: str | None = Field(None, description='Path to client private key PEM file (for mutual TLS)')
    tls_validate: str = Field('REQUIRED', description='Server cert validation: NONE, OPTIONAL, or REQUIRED')
    block_tls_verify_none: bool = Field(
        True,
        description='Refuse to start if tls_validate=NONE. Set to False only for testing.',
    )
    use_starttls: bool = Field(False, description='Use STARTTLS extension (for ldap:// URLs; not needed for ldaps://)')
    follow_referrals: bool = Field(False, description='Automatically follow LDAP referrals (default: False)')
    referral_allowed_hosts: list[str] = Field(
        default_factory=list,
        description="Restrict LDAP referrals to specific hosts (e.g., ['dc2.example.com']). "
        'Only used when follow_referrals=True. When empty, all referrals are followed.',
    )
    block_unrestricted_referrals: bool = Field(
        True,
        description='Refuse to start if follow_referrals=True and referral_allowed_hosts is empty. '
        'Set to False only if you trust your LDAP server unconditionally.',
    )
    pool_size: int = Field(
        1,
        ge=1,
        le=16,
        description='Number of LDAP connections to pool (default: 1). '
        'Increase for high concurrency to reduce lock contention.',
    )

    @field_validator('tls_validate')
    @classmethod
    def _validate_tls_validate(cls, v: str) -> str:
        v = v.upper()
        if v not in {'NONE', 'OPTIONAL', 'REQUIRED'}:
            raise ValueError('tls_validate must be NONE, OPTIONAL, or REQUIRED')
        return v

    @field_validator('url')
    @classmethod
    def _validate_url(cls, v: str) -> str:
        v_lower = v.lower()
        if not v_lower.startswith(('ldap://', 'ldaps://')):
            raise ValueError('LDAP URL must start with ldap:// or ldaps://')
        return v

    @field_validator('user_filter')
    @classmethod
    def _validate_user_filter(cls, v: str) -> str:
        if '{username}' not in v:
            raise ValueError('user_filter must contain the {username} placeholder')
        return v

    @field_validator('allowed_users')
    @classmethod
    def _validate_allowed_users(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        cleaned = [user.strip() for user in v if user and user.strip()]
        if len(cleaned) != len(v):
            raise ValueError('allowed_users entries must be non-empty usernames')
        return cleaned

    @model_validator(mode='after')
    def _validate_authorization_rule(self) -> 'LDAPSettings':
        has_allowed_users = self.allowed_users is not None and len(self.allowed_users) > 0
        has_group = bool(self.group_dn)
        if self.require_authorization_rule and not (has_allowed_users or has_group):
            raise ValueError(
                'LDAP authorization is not restricted. Configure ldap.allowed_users '
                'or ldap.group_dn, or set require_authorization_rule=false only for '
                'local development/tests.'
            )
        return self


class ProxySettings(BaseModel):
    """Reverse proxy configuration."""

    model_config = SettingsConfigDict(extra='forbid')

    listen_host: str = Field('0.0.0.0', description='Host to listen on')
    listen_port: int = Field(9000, description='Port to listen on')
    backend_url: str | None = Field(
        None,
        description='Backend service URL to proxy to. Required in reverse-proxy mode; unused in middleware mode.',
    )
    secret_key: SecretStr = Field(..., description='Secret key for signing session cookies')
    session_ttl: int = Field(3600, description='Session time-to-live in seconds')
    idle_timeout: int = Field(
        0,
        ge=0,
        description='Expire browser sessions after this many seconds without authenticated requests (0 = disabled)',
    )
    bind_client: bool = Field(
        True,
        description='Bind browser sessions and login CSRF tokens to the client IP and User-Agent. Disable for clients using privacy relays or unstable addresses.',
    )
    user_header: str = Field('X-Forwarded-User', description='Header name for authenticated username')
    login_path: str = Field('/_auth/login', description='Login page path')
    logout_path: str = Field('/_auth/logout', description='Logout page path')
    app_name: str = Field('ldapgate', description='Application name for login form')
    mask_usernames_in_logs: bool = Field(
        True,
        description='Mask usernames in ldapgate logs. Set false only when full usernames are required for operations.',
    )
    trusted_proxies: list[str] = Field(
        default_factory=list,
        description="List of trusted proxy IPs/CIDRs for X-Forwarded-For (e.g., ['127.0.0.1', '10.0.0.0/8'])",
    )
    max_body_size: int = Field(
        10 * 1024 * 1024,
        description='Maximum request body size in bytes (default: 10MB)',
    )
    max_response_size: int = Field(
        10 * 1024 * 1024,
        description='Maximum response body size to accept from backend in bytes (default: 10MB)',
    )
    rate_limit_max_failures: int = Field(
        5,
        description='Number of auth failures before lockout (per IP / per username)',
    )
    rate_limit_window_seconds: int = Field(
        300,
        description='Sliding window for counting auth failures in seconds',
    )
    rate_limit_lockout_seconds: int = Field(
        60,
        description='Lockout duration after exceeding failure threshold in seconds',
    )
    cookie_samesite: str = Field(
        'lax',
        description='SameSite attribute for session cookies: lax (default) or strict',
    )
    session_cookie_name: str = Field(
        'ldapgate_session',
        description=(
            'Base session cookie name. Use a distinct value per localhost app '
            'because browser cookies are scoped by host/path, not port.'
        ),
    )
    max_sessions_per_user: int = Field(
        0,
        ge=0,
        description='Maximum concurrent sessions per user (0 = unlimited). '
        'When exceeded, the oldest session is revoked.',
    )
    hsts_max_age: int = Field(
        31536000,
        description='HSTS max-age in seconds (default: 1 year; only active when secure_cookies is True)',
    )
    secure_cookies: bool = Field(
        True,
        description='Set Secure flag on session cookies (enable when behind HTTPS proxy)',
    )
    revocation_path: str | None = Field(
        None,
        description='Optional path to a shared file for cross-process session revocation',
    )
    trusted_hosts: list[str] = Field(
        default_factory=list,
        description='List of allowed Host header values for CSRF Origin/Referer validation '
        "(e.g., ['myapp.example.com:443']). When empty, the Host header is used "
        'directly — set this in production to prevent CSRF bypass via Host header injection.',
    )
    static_paths: list[str] = Field(
        default_factory=list,
        description='List of path prefixes that bypass authentication in middleware mode',
    )
    rate_limit_state_path: str | None = Field(
        None,
        description='Optional path to a shared file for cross-process rate-limiter state. '
        'When set, lockout counters are shared across all uvicorn workers. '
        'When unset, rate limiting is per-process.',
    )
    basic_auth_cache_ttl: int = Field(
        60,
        ge=0,
        description='Seconds to cache successful Basic auth checks in memory. '
        'Set to 0 to disable. Useful for chatty WebDAV clients.',
    )

    @field_validator('backend_url')
    @classmethod
    def _validate_backend_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return validate_backend_url(v)

    @field_validator('cookie_samesite')
    @classmethod
    def _validate_cookie_samesite(cls, v: str) -> str:
        v = v.lower()
        if v not in {'lax', 'strict'}:
            raise ValueError("cookie_samesite must be 'lax' or 'strict'")
        return v

    @field_validator('session_cookie_name')
    @classmethod
    def _validate_session_cookie_name(cls, v: str) -> str:
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', v):
            raise ValueError('session_cookie_name must be a valid cookie name')
        if v.startswith('__Host-'):
            raise ValueError('session_cookie_name must not include the __Host- prefix')
        return v

    @field_validator('secret_key')
    @classmethod
    def _validate_secret_key(cls, v: SecretStr) -> SecretStr:
        if _is_weak_secret(v.get_secret_value()):
            raise ValueError(
                'Secret key is too weak for production use. '
                'Generate a secure key with: '
                "python -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )
        return v

    @field_validator('login_path', 'logout_path')
    @classmethod
    def _validate_auth_paths(cls, v: str) -> str:
        if not v.startswith('/'):
            raise ValueError("login_path and logout_path must start with '/'")
        if not v.startswith('/_auth/'):
            import logging as _logging

            _logging.getLogger(__name__).warning(
                "Auth path '%s' is not under '/_auth/'. Ensure it does not overlap with backend application routes.", v
            )
        return v

    @field_validator('logout_path')
    @classmethod
    def _validate_paths_distinct(cls, v: str, info) -> str:
        login = (info.data or {}).get('login_path', '')
        if login and v == login:
            raise ValueError('login_path and logout_path must be different paths')
        return v


class LDAPConfig(BaseSettings):
    """Complete ldapgate configuration."""

    ldap: LDAPSettings
    proxy: ProxySettings

    model_config = SettingsConfigDict(
        env_nested_delimiter='__',
        extra='forbid',
    )

    @classmethod
    def from_yaml(cls, path: str | Path) -> 'LDAPConfig':
        """Load configuration from YAML file.

        Args:
            path: Path to YAML config file

        Returns:
            Configured LDAPConfig instance

        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If YAML is invalid
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f'Config file not found: {path}')

        with open(path) as f:
            data = yaml.safe_load(f)

        if not data:
            raise ValueError('Empty config file')

        return cls(**data)

    @classmethod
    def from_env(cls) -> 'LDAPConfig':
        """Load configuration from environment variables.

        Expected format:
        - LDAP__URL
        - LDAP__BIND_DN
        - LDAP__BIND_PASSWORD
        - etc.

        Returns:
            Configured LDAPConfig instance
        """
        return cls()


def load_config(yaml_path: str | Path | None = None) -> LDAPConfig:
    """Load configuration from YAML or environment.

    Args:
        yaml_path: Optional path to YAML config file.
                  If provided, loads from file. Otherwise uses environment vars.

    Returns:
        Configured LDAPConfig instance
    """
    if yaml_path:
        return LDAPConfig.from_yaml(yaml_path)
    return LDAPConfig.from_env()
