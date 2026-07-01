"""LDAP/AD authentication core using ldap3."""

import asyncio
import logging
import ssl
import threading
import time
import warnings
from urllib.parse import urlparse

# Suppress deprecation warnings from pyasn1's legacy tagMap/typeMap aliases
# that ldap3 still imports. These are harmless third-party compatibility warnings.
warnings.filterwarnings(
    'ignore',
    message=r'tagMap is deprecated\. Please use TAG_MAP instead\.',
    category=DeprecationWarning,
)
warnings.filterwarnings(
    'ignore',
    message=r'typeMap is deprecated\. Please use TYPE_MAP instead\.',
    category=DeprecationWarning,
)

import contextlib

from ldap3 import BASE, NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException

from ldapgate.config import LDAPSettings

log = logging.getLogger(__name__)

# How often to refresh the service-account connection (seconds)
_POOL_KEEPALIVE_INTERVAL = 300


def _escape_ldap(value: str) -> str:
    """Escape special characters in LDAP filter values (RFC 4515).

    Escapes the five RFC 4515 reserved ASCII characters plus all non-ASCII
    bytes after UTF-8 encoding, and strips embedded NUL bytes.
    """
    # Encode to UTF-8 and escape byte-by-byte for full RFC 4515 compliance.
    result = []
    for byte in value.encode('utf-8'):
        if byte == 0x5C:  # backslash
            result.append('\\5c')
        elif byte == 0x2A:  # asterisk
            result.append('\\2a')
        elif byte == 0x28:  # left paren
            result.append('\\28')
        elif byte == 0x29:  # right paren
            result.append('\\29')
        elif byte == 0x00:  # NUL
            result.append('\\00')
        elif byte < 0x20 or byte > 0x7E:  # non-printable / non-ASCII
            result.append(f'\\{byte:02x}')
        else:
            result.append(chr(byte))
    return ''.join(result)


def _build_user_filter(template: str, username: str) -> str:
    """Substitute the escaped username into the configured filter template.

    Uses plain string ``replace`` instead of ``str.format`` so that curly
    braces in the template cannot cause unexpected interpolation or
    injection should an admin accidentally include them in the filter.
    """
    return template.replace('{username}', username)


def _build_tls(config: LDAPSettings) -> Tls | None:
    """Build an ldap3 Tls object from config if any TLS settings are specified."""
    is_ldaps = config.url.lower().startswith('ldaps://')
    needs_tls = (
        is_ldaps
        or config.use_starttls
        or config.tls_ca_cert_file is not None
        or config.tls_client_cert_file is not None
        or config.tls_client_key_file is not None
    )
    if not needs_tls:
        return None

    validate_map = {
        'NONE': ssl.CERT_NONE,
        'OPTIONAL': ssl.CERT_OPTIONAL,
        'REQUIRED': ssl.CERT_REQUIRED,
    }
    validate = validate_map.get(config.tls_validate.upper(), ssl.CERT_REQUIRED)

    return Tls(
        local_private_key_file=config.tls_client_key_file,
        local_certificate_file=config.tls_client_cert_file,
        ca_certs_file=config.tls_ca_cert_file,
        validate=validate,
    )


class _LDAPConnectionPool:
    """Per-thread connection pool for the service account.

    Each OS thread gets its own LDAP connection, so concurrent
    ``asyncio.to_thread`` workers never block on each other.
    Connections are lazily created and kept alive via keepalive checks.

    Uses a semaphore (pool_size) to limit the total number of concurrent
    connections across all threads, preventing LDAP server overload.
    """

    def __init__(self, config: LDAPSettings):
        self.config = config
        self.tls = _build_tls(config)
        self.server = Server(config.url, connect_timeout=config.timeout, get_info=NONE, tls=self.tls)
        self._local = threading.local()
        self._semaphore = threading.BoundedSemaphore(config.pool_size)

    def _acquire(self) -> None:
        """Acquire a pool slot, blocking if at capacity."""
        self._semaphore.acquire()

    def _release(self) -> None:
        """Release a pool slot."""
        with contextlib.suppress(ValueError):
            self._semaphore.release()

    def _get_conn(self) -> Connection:
        now = time.monotonic()
        conn: Connection | None = getattr(self._local, 'conn', None)
        last_used: float = getattr(self._local, 'last_used', 0.0)

        if conn is not None:
            # Proactive keepalive: if the connection has been idle too
            # long, refresh it to avoid stale-connection errors.
            if now - last_used > _POOL_KEEPALIVE_INTERVAL:
                with contextlib.suppress(LDAPException):
                    conn.unbind()
                conn = None
                self._release()
            elif not conn.bound:
                try:
                    conn.bind()
                except LDAPException:
                    conn = None
                    self._release()

        if conn is None:
            self._acquire()
            try:
                _auto_ref = self.config.follow_referrals and not self.config.referral_allowed_hosts
                conn = Connection(
                    self.server,
                    user=self.config.bind_dn,
                    password=self.config.bind_password.get_secret_value(),
                    raise_exceptions=True,
                    auto_referrals=_auto_ref,
                )
                conn.open()
                if self.config.use_starttls:
                    conn.start_tls()
                conn.bind()
            except LDAPException:
                self._release()
                raise

        self._local.conn = conn
        self._local.last_used = now
        return conn

    def release(self) -> None:
        conn: Connection | None = getattr(self._local, 'conn', None)
        if conn:
            with contextlib.suppress(LDAPException):
                conn.unbind()
            self._local.conn = None
        self._release()


class LDAPAuthenticator:
    """Authenticates users against LDAP/AD directory."""

    def __init__(self, config: LDAPSettings):
        """Initialize LDAP authenticator.

        Args:
            config: LDAP configuration with server details and filters
        """
        self.config = config
        self.tls = _build_tls(config)
        self.server = Server(config.url, connect_timeout=config.timeout, get_info=NONE, tls=self.tls)
        self._pool = _LDAPConnectionPool(config)

        if config.tls_validate.upper() == 'NONE':
            if config.block_tls_verify_none:
                raise ValueError(
                    'TLS certificate validation is set to NONE, which is '
                    'insecure and enables MITM attacks. '
                    'Set tls_validate=REQUIRED or disable block_tls_verify_none.'
                )
            log.error(
                'LDAP TLS certificate validation is DISABLED (tls_validate=NONE). '
                'This is insecure and enables MITM attacks. Use tls_validate=REQUIRED in production.'
            )
        if config.url.lower().startswith('ldap://') and not config.use_starttls:
            if config.block_plaintext_ldap:
                raise ValueError(
                    'Plaintext LDAP (ldap://) without STARTTLS is blocked by '
                    'block_plaintext_ldap=True. Use ldaps:// or enable use_starttls.'
                )
            log.error(
                'Using plain LDAP (ldap://) without STARTTLS. '
                'Credentials will be transmitted in cleartext. '
                'Use ldaps:// or enable use_starttls in production.'
            )

        if config.follow_referrals:
            if config.referral_allowed_hosts:
                log.info(
                    'follow_referrals is enabled with referral_allowed_hosts=%s. '
                    'Only referrals to these hosts will be followed.',
                    config.referral_allowed_hosts,
                )
            elif config.block_unrestricted_referrals:
                raise ValueError(
                    'follow_referrals is enabled but referral_allowed_hosts is empty. '
                    'This would allow a malicious LDAP server to return referrals to '
                    'internal network addresses (SSRF risk). Either set '
                    'referral_allowed_hosts or disable follow_referrals. '
                    'To override, set block_unrestricted_referrals=False.'
                )
            else:
                log.error(
                    'follow_referrals is enabled with no referral_allowed_hosts set. '
                    'A malicious LDAP server could return referrals to internal '
                    'network addresses (SSRF risk). Set referral_allowed_hosts to '
                    'restrict which referral targets are allowed, or disable '
                    'follow_referrals unless explicitly required.'
                )

    def _connect(self, user: str, password: str) -> Connection:
        """Open a bound LDAP connection, applying STARTTLS if configured."""
        _auto_ref = self.config.follow_referrals and not self.config.referral_allowed_hosts
        conn = Connection(
            self.server,
            user=user,
            password=password,
            raise_exceptions=True,
            auto_referrals=_auto_ref,
        )
        conn.open()
        if self.config.use_starttls:
            conn.start_tls()
        conn.bind()
        return conn

    def _is_referral_allowed(self, hostname: str) -> bool:
        """Check if a referral host is in the allowed list (case-insensitive)."""
        if not self.config.referral_allowed_hosts:
            return True
        return hostname.lower() in [h.lower() for h in self.config.referral_allowed_hosts]

    def _follow_search_referrals(
        self,
        conn: Connection,
        search_base: str,
        search_filter: str,
        search_scope: str,
        attributes=None,
    ) -> None:
        """Follow LDAP referrals from a search result, validating against allowed hosts.

        Only follows referrals whose hostname matches referral_allowed_hosts.
        Modifies conn.entries and conn.result in place with the first successful
        referral result. Silently skips disallowed and unreachable referrals.
        """
        referrals = conn.result.get('referrals')
        if not referrals:
            return
        for ref_url in referrals:
            try:
                parsed = urlparse(ref_url)
                if not parsed.hostname:
                    continue
                if not self._is_referral_allowed(parsed.hostname):
                    log.warning(
                        'LDAP referral to %s is not in referral_allowed_hosts — blocked',
                        parsed.hostname,
                    )
                    continue
                log.debug('Following LDAP referral to %s', parsed.hostname)
                ref_server = Server(
                    ref_url,
                    connect_timeout=self.config.timeout,
                    get_info=NONE,
                    tls=self.tls,
                )
                ref_conn = Connection(
                    ref_server,
                    user=self.config.bind_dn,
                    password=self.config.bind_password.get_secret_value(),
                    raise_exceptions=True,
                    auto_referrals=False,
                )
                ref_conn.open()
                if self.config.use_starttls:
                    ref_conn.start_tls()
                ref_conn.bind()
                ref_base = parsed.path.lstrip('/') if parsed.path else search_base
                ref_conn.search(
                    search_base=ref_base,
                    search_filter=search_filter,
                    search_scope=search_scope,  # type: ignore[arg-type]
                    attributes=attributes,
                )
                if ref_conn.entries:
                    conn.entries = ref_conn.entries  # type: ignore[attr-defined]
                conn.result = ref_conn.result
                ref_conn.unbind()
                return
            except LDAPException:
                continue

    async def authenticate(self, username: str, password: str) -> bool:
        """Authenticate user against LDAP directory.

        Process:
        1. Check local allowlist first (if configured)
        2. Bind as service account and search for user DN
        3. Re-bind with user DN + supplied password
        4. Optionally check group membership

        Args:
            username: Username to authenticate
            password: Password to verify

        Returns:
            True if authentication successful, False otherwise
        """
        return await asyncio.to_thread(self._authenticate_sync, username, password)

    _MIN_AUTH_TIME = 0.5  # minimum seconds for auth path to prevent timing leaks

    def _authenticate_sync(self, username: str, password: str) -> bool:
        """Synchronous authentication logic (run in thread pool)."""
        if not username or not password:
            return False

        # Enforce reasonable input length limits to prevent abuse
        if len(username) > 256 or len(password) > 1024:
            return False

        _start = time.time()

        # Step 1: Optional local allowlist check.
        # Pad to _MIN_AUTH_TIME on rejection so an attacker cannot use
        # timing to distinguish allowlist membership from other failures.
        if self.config.allowed_users is not None and username.lower() not in [
            u.lower() for u in self.config.allowed_users
        ]:
            _elapsed = time.time() - _start
            _remaining = max(0.0, self._MIN_AUTH_TIME - _elapsed)
            time.sleep(_remaining)
            return False

        auth_ok = False
        user_dn = None

        try:
            # Step 2: Bind as service account and search for user DN.
            conn = self._pool._get_conn()

            # Escape special LDAP characters to prevent injection
            safe_username = _escape_ldap(username)
            user_filter = _build_user_filter(self.config.user_filter, safe_username)
            conn.search(
                search_base=self.config.base_dn,
                search_filter=user_filter,
                search_scope=SUBTREE,
            )

            if self.config.follow_referrals and self.config.referral_allowed_hosts:
                self._follow_search_referrals(conn, self.config.base_dn, user_filter, SUBTREE)

            if not conn.entries:
                # Timing-attack mitigation: ensure a minimum wall-clock time
                # so that "user not found" takes roughly as long as a failed
                # bind attempt, preventing user enumeration via timing.
                _elapsed = time.time() - _start
                _remaining = max(0.0, self._MIN_AUTH_TIME - _elapsed)
                time.sleep(_remaining)
            elif len(conn.entries) != 1:
                log.warning(
                    'LDAP user_filter returned %d entries; refusing ambiguous login',
                    len(conn.entries),
                )
                _elapsed = time.time() - _start
                _remaining = max(0.0, self._MIN_AUTH_TIME - _elapsed)
                time.sleep(_remaining)
            else:
                user_dn = conn.entries[0].entry_dn

                # Step 3: Try to bind as the user with supplied password.
                conn = self._connect(user_dn, password)
                conn.unbind()
                auth_ok = True

                # Top up to constant time so success path also takes
                # at least _MIN_AUTH_TIME (failures finish here via sleep
                # above; ok path adds bind latency, top up any remainder).
                _elapsed = time.time() - _start
                _remaining = max(0.0, self._MIN_AUTH_TIME - _elapsed)
                time.sleep(_remaining)

        except LDAPException:
            log.debug('LDAP authentication failed')
            _elapsed = time.time() - _start
            _remaining = max(0.0, self._MIN_AUTH_TIME - _elapsed)
            time.sleep(_remaining)
        except Exception as e:
            log.warning('Unexpected error during LDAP authentication: %s', e)
            _elapsed = time.time() - _start
            _remaining = max(0.0, self._MIN_AUTH_TIME - _elapsed)
            time.sleep(_remaining)

        # Step 4: Optional group membership check.
        # Always run the group check when configured, regardless of auth
        # outcome, so an attacker cannot use timing to distinguish between
        # wrong-password failures and right-password-but-wrong-group failures.
        if self.config.group_dn:
            if auth_ok:
                assert user_dn is not None
                if not self._check_group_membership(user_dn):
                    return False
            else:
                self._check_group_membership('cn=nonexistent,dc=invalid')
            return auth_ok

        return auth_ok

    def _check_group_membership(self, user_dn: str) -> bool:
        """Check if user is member of configured group.

        Args:
            user_dn: User's distinguished name

        Returns:
            True if user is in group (or no group configured), False otherwise
        """
        assert self.config.group_dn is not None
        try:
            conn = self._pool._get_conn()
            # Search for the group entry and retrieve its member attributes
            conn.search(
                search_base=self.config.group_dn,
                search_filter='(objectClass=groupOfNames)',
                search_scope=BASE,
                attributes=['member', 'uniqueMember', 'memberOf'],
            )
            if self.config.follow_referrals and self.config.referral_allowed_hosts:
                self._follow_search_referrals(
                    conn,
                    self.config.group_dn,
                    '(objectClass=groupOfNames)',
                    BASE,
                    attributes=['member', 'uniqueMember', 'memberOf'],
                )
            if not conn.entries:
                # Fallback: try a broader search for Active Directory groups
                conn.search(
                    search_base=self.config.group_dn,
                    search_filter='(objectClass=*)',
                    search_scope=BASE,
                    attributes=['member', 'uniqueMember', 'memberOf'],
                )
                if not conn.entries:
                    return False

            group = conn.entries[0]
            members = set()
            for attr in ('member', 'uniqueMember'):
                if attr in group:
                    members.update(str(v) for v in group[attr].values)
            return user_dn in members

        except LDAPException as e:
            log.debug('LDAP group membership check failed: %s', e)
            return False
        except Exception as e:
            log.warning('Unexpected error during group membership check: %s', e)
            return False

    def close(self) -> None:
        """Release the service-account connection pool."""
        with contextlib.suppress(Exception):
            self._pool.release()
