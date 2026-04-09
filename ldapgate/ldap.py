"""LDAP/AD authentication core using ldap3."""

import asyncio
import logging
import ssl
from typing import Optional

from ldap3 import BASE, NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException

from ldapgate.config import LDAPSettings

log = logging.getLogger(__name__)


def _escape_ldap(value: str) -> str:
    """Escape special characters in LDAP filter values (RFC 4515)."""
    replacements = [
        ("\\", "\\5c"),
        ("*", "\\2a"),
        ("(", "\\28"),
        (")", "\\29"),
        ("\x00", "\\00"),
    ]
    for char, escaped in replacements:
        value = value.replace(char, escaped)
    return value


def _build_tls(config: LDAPSettings) -> Optional[Tls]:
    """Build an ldap3 Tls object from config if any TLS settings are specified."""
    needs_tls = (
        config.use_starttls
        or config.tls_ca_cert_file is not None
        or config.tls_client_cert_file is not None
        or config.tls_validate.upper() != "REQUIRED"
    )
    if not needs_tls:
        return None

    validate_map = {
        "NONE": ssl.CERT_NONE,
        "OPTIONAL": ssl.CERT_OPTIONAL,
        "REQUIRED": ssl.CERT_REQUIRED,
    }
    validate = validate_map.get(config.tls_validate.upper(), ssl.CERT_REQUIRED)

    return Tls(
        local_private_key_file=config.tls_client_key_file,
        local_certificate_file=config.tls_client_cert_file,
        ca_certs_file=config.tls_ca_cert_file,
        validate=validate,
    )


class LDAPAuthenticator:
    """Authenticates users against LDAP/AD directory."""

    def __init__(self, config: LDAPSettings):
        """Initialize LDAP authenticator.

        Args:
            config: LDAP configuration with server details and filters
        """
        self.config = config
        tls = _build_tls(config)
        self.server = Server(config.url, connect_timeout=config.timeout, get_info=NONE, tls=tls)

    def _connect(self, user: str, password: str) -> Connection:
        """Open a bound LDAP connection, applying STARTTLS if configured."""
        conn = Connection(
            self.server,
            user=user,
            password=password,
            raise_exceptions=True,
            auto_referrals=self.config.follow_referrals,
        )
        conn.open()
        if self.config.use_starttls:
            conn.start_tls()
        conn.bind()
        return conn

    async def authenticate(self, username: str, password: str) -> bool:
        """Authenticate user against LDAP directory.

        Process:
        1. Bind as service account
        2. Search for user DN matching user_filter
        3. Re-bind with user DN + supplied password
        4. Optionally check group membership

        Args:
            username: Username to authenticate
            password: Password to verify

        Returns:
            True if authentication successful, False otherwise
        """
        return await asyncio.to_thread(
            self._authenticate_sync, username, password
        )

    def _authenticate_sync(self, username: str, password: str) -> bool:
        """Synchronous authentication logic (run in thread pool)."""
        if not username or not password:
            return False

        try:
            # Step 1+2: Bind as service account and search for user DN
            conn = self._connect(self.config.bind_dn, self.config.bind_password)
            try:
                # Escape special LDAP characters to prevent injection
                safe_username = _escape_ldap(username)
                user_filter = self.config.user_filter.format(username=safe_username)
                conn.search(
                    search_base=self.config.base_dn,
                    search_filter=user_filter,
                    search_scope=SUBTREE,
                )

                if not conn.entries:
                    return False

                user_dn = conn.entries[0].entry_dn
            finally:
                conn.unbind()

            # Step 3: Try to bind as the user with supplied password.
            # This conn has its own try/finally — unbind() here is intentional
            # and independent of the service-account conn unbound above.
            conn = self._connect(user_dn, password)
            conn.unbind()

            # Step 4: Optional group membership check
            if self.config.group_dn:
                if not self._check_group_membership(user_dn):
                    return False

            # Step 5: Optional local allowlist check
            if self.config.allowed_users is not None:
                if username not in self.config.allowed_users:
                    return False

            return True

        except LDAPException as e:
            log.debug("LDAP authentication failed: %s", e)
            return False
        except Exception as e:
            log.warning("Unexpected error during LDAP authentication: %s", e)
            return False

    def _check_group_membership(self, user_dn: str) -> bool:
        """Check if user is member of configured group.

        Args:
            user_dn: User's distinguished name

        Returns:
            True if user is in group (or no group configured), False otherwise
        """
        try:
            conn = self._connect(self.config.bind_dn, self.config.bind_password)
            try:
                # Use BASE scope to check a single group entry for membership.
                # Supports both AD (member=) and OpenLDAP (uniqueMember=) via OR filter.
                # Escape the DN for filter safety — DNs can contain (, ), *, \ chars.
                safe_dn = _escape_ldap(user_dn)
                group_filter = (
                    f"(|(member={safe_dn})(uniqueMember={safe_dn}))"
                )
                conn.search(
                    search_base=self.config.group_dn,
                    search_filter=group_filter,
                    search_scope=BASE,
                    attributes=["cn"],
                )
                return bool(conn.entries)
            finally:
                conn.unbind()

        except LDAPException as e:
            log.debug("LDAP group membership check failed: %s", e)
            return False
        except Exception as e:
            log.warning("Unexpected error during group membership check: %s", e)
            return False
