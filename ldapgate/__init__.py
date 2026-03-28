"""ldapgate - LDAP/AD authentication proxy and FastAPI middleware"""

__version__ = "0.1.0"

__all__ = [
    "LDAPAuthenticator",
    "LDAPConfig",
    "LDAPAuthMiddleware",
    "SessionManager",
    "create_proxy_app",
    "create_login_router",
    "add_ldap_auth",
]

from ldapgate.config import LDAPConfig
from ldapgate.ldap import LDAPAuthenticator
from ldapgate.middleware import LDAPAuthMiddleware, add_ldap_auth
from ldapgate.proxy import create_proxy_app, create_login_router
from ldapgate.sessions import SessionManager
