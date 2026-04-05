"""Configuration management for ldapgate."""

from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LDAPSettings(BaseModel):
    """LDAP/AD configuration."""

    url: str = Field(
        ..., description="LDAP server URL (e.g., ldaps://dc.example.com:636)"
    )
    bind_dn: str = Field(..., description="Service account DN for binding")
    bind_password: str = Field(..., description="Service account password")
    base_dn: str = Field(..., description="Base DN for user searches")
    user_filter: str = Field(
        "(sAMAccountName={username})",
        description="LDAP filter for user lookup (e.g., AD: sAMAccountName, OpenLDAP: uid)",
    )
    group_dn: Optional[str] = Field(
        None, description="Optional group DN to restrict access (e.g., CN=app-users,..."
    )
    allowed_users: Optional[List[str]] = Field(
        None, description="Optional list of usernames allowed through (local allowlist)"
    )
    timeout: int = Field(10, description="LDAP connection timeout in seconds")

    # TLS configuration (all optional — only needed for custom certs or mutual TLS)
    tls_ca_cert_file: Optional[str] = Field(
        None, description="Path to CA certificate PEM file for server certificate validation"
    )
    tls_client_cert_file: Optional[str] = Field(
        None, description="Path to client certificate PEM file (for mutual TLS)"
    )
    tls_client_key_file: Optional[str] = Field(
        None, description="Path to client private key PEM file (for mutual TLS)"
    )
    tls_validate: str = Field(
        "REQUIRED", description="Server cert validation: NONE, OPTIONAL, or REQUIRED"
    )
    use_starttls: bool = Field(
        False, description="Use STARTTLS extension (for ldap:// URLs; not needed for ldaps://)"
    )
    follow_referrals: bool = Field(
        True, description="Automatically follow LDAP referrals (default: True)"
    )


class ProxySettings(BaseModel):
    """Reverse proxy configuration."""

    listen_host: str = Field("0.0.0.0", description="Host to listen on")
    listen_port: int = Field(9000, description="Port to listen on")
    backend_url: str = Field(..., description="Backend service URL to proxy to")
    secret_key: str = Field(..., description="Secret key for signing session cookies")
    session_ttl: int = Field(3600, description="Session time-to-live in seconds")
    user_header: str = Field(
        "X-Forwarded-User", description="Header name for authenticated username"
    )
    login_path: str = Field("/_auth/login", description="Login page path")
    logout_path: str = Field("/_auth/logout", description="Logout page path")
    app_name: str = Field("ldapgate", description="Application name for login form")
    secure_cookies: bool = Field(
        False,
        description="Set Secure flag on session cookies (enable when behind HTTPS proxy)",
    )


class LDAPConfig(BaseSettings):
    """Complete ldapgate configuration."""

    ldap: LDAPSettings
    proxy: ProxySettings

    model_config = SettingsConfigDict(
        env_nested_delimiter="__",
    )

    @classmethod
    def from_yaml(cls, path: str | Path) -> "LDAPConfig":
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
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path) as f:
            data = yaml.safe_load(f)

        if not data:
            raise ValueError("Empty config file")

        return cls(**data)

    @classmethod
    def from_env(cls) -> "LDAPConfig":
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
