"""ldapgate - LDAP/AD authentication proxy and FastAPI middleware"""

__version__ = '0.1.16'

__all__ = [
    'LDAPAuthMiddleware',
    'LDAPAuthenticator',
    'LDAPConfig',
    'SessionManager',
    'add_ldap_auth',
    'create_login_router',
    'create_proxy_app',
]

from ldapgate.config import LDAPConfig
from ldapgate.ldap import LDAPAuthenticator
from ldapgate.middleware import LDAPAuthMiddleware, add_ldap_auth
from ldapgate.proxy import create_login_router, create_proxy_app
from ldapgate.sessions import SessionManager
