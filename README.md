<p align="center">
  <img src="https://raw.githubusercontent.com/anudeepd/ldapgate/main/assets/logo.svg" alt="LDAPGate" width="120"/>
</p>

<h1 align="center">LDAPGate</h1>

<p align="center">Lightweight LDAP/AD authentication gateway for Python web apps. Install it, configure it, done.</p>

## Features

- **Two deployment modes** — standalone reverse proxy or drop-in FastAPI middleware
- **WebDAV + browser in one** — browsers get a login form; WebDAV clients (Windows, macOS Finder, curl) get a Basic auth challenge — same endpoint, no extra config
- **Pure Python LDAP** — no OS-level libs required, uses `ldap3`
- **Signed cookie sessions** — stateless, no server-side session storage
- **OpenLDAP and Active Directory** — `uid=` and `sAMAccountName=` out of the box
- **Optional group gating** — restrict access to members of a specific LDAP group
- **Header injection** — injects `X-Forwarded-User` for downstream apps
- **Bundled login form** — responsive, dark/light mode, customisable, works air-gapped

## Install

```bash
pip install ldapgate
```

## Config file

Both modes share the same `ldapgate.yaml`:

```yaml
ldap:
  url: ldaps://dc.example.com:636
  bind_dn: CN=svc,CN=Users,DC=example,DC=com
  bind_password: secret
  base_dn: DC=example,DC=com
  user_filter: "(sAMAccountName={username})"         # AD; OpenLDAP: (uid={username})
  group_dn: CN=app-users,CN=Users,DC=example,DC=com  # optional — restrict by group
  allowed_users:                                      # optional — local allowlist
    - alice
    - bob
  timeout: 10
  tls_validate: REQUIRED                             # NONE | OPTIONAL | REQUIRED
  tls_ca_cert_file: /etc/ssl/certs/internal-ca.pem  # optional — custom CA bundle
  tls_client_cert_file: /etc/ssl/certs/client.pem   # optional — mutual TLS client cert
  tls_client_key_file: /etc/ssl/private/client.key  # optional — mutual TLS client key

proxy:
  listen_host: 0.0.0.0
  listen_port: 9000
  backend_url: http://localhost:8080
  secret_key: change-me-to-something-random
  session_ttl: 3600
  user_header: X-Forwarded-User
  login_path: /_auth/login
  logout_path: /_auth/logout
  app_name: MyApp
  secure_cookies: false                              # set true when behind HTTPS
```

All settings can also be provided via environment variables using `__` as a separator — e.g. `LDAP__URL`, `PROXY__SECRET_KEY`.

## Corporate / Active Directory setup

For corp environments with internal CAs where cert validation isn't feasible:

```yaml
ldap:
  url: ldaps://dc.example.com:636
  tls_validate: NONE
  # ... other settings ...
```

For plain LDAP with STARTTLS:

```yaml
ldap:
  url: ldap://dc.example.com:389
  use_starttls: true
```

---

## Mode 1 — Standalone Reverse Proxy

Run ldapgate as a standalone process in front of any app.

```
Browser / WebDAV client → ldapgate :9000 → backend app :8080
```

```bash
ldapgate serve --config ldapgate.yaml
```

All traffic is intercepted by ldapgate before reaching the backend. Authenticated requests are forwarded with the `X-Forwarded-User` header set to the verified username. Apps can point their logout link at the configured `logout_path` (default `/_auth/logout`) to clear the session.

**WebDAV clients** receive a `401 WWW-Authenticate: Basic` challenge automatically and authenticate per-request via HTTP Basic auth — no session cookie needed.

---

## Mode 2 — FastAPI Middleware

Drop ldapgate auth directly into an existing FastAPI app — no separate process.

```python
from fastapi import FastAPI
from ldapgate.config import load_config
from ldapgate.middleware import add_ldap_auth

app = FastAPI()
config = load_config("ldapgate.yaml")
add_ldap_auth(app, config)

@app.get("/api/data")
async def data(request):
    return {"user": request.state.user}  # authenticated username
```

`add_ldap_auth` registers the login/logout routes and attaches the middleware in one call. The authenticated username is available as `request.state.user` and is also injected as the configured `user_header` into the request headers.

### WebDAV with middleware

The middleware handles both browser and WebDAV clients on the same app instance:

| Client | Auth flow |
|--------|-----------|
| Browser | Redirected to login form → session cookie |
| WebDAV (Windows, macOS Finder, curl) | `401 WWW-Authenticate: Basic` challenge → Basic auth per-request |

No extra routes or config needed — if a request arrives without a session cookie and without `Accept: text/html`, the middleware issues a `401` with a `WWW-Authenticate: Basic` header. The client sends credentials, the middleware validates against LDAP, and the request proceeds.

`allowed_users` and `group_dn` apply to both flows — a user blocked by those settings is rejected regardless of whether they authenticated via cookie or Basic auth.

**Example — xwing file server with WebDAV:**

```python
from fastapi import FastAPI
from ldapgate.config import load_config
from ldapgate.middleware import add_ldap_auth
from xwing.app import create_app
from xwing.config import Settings

xwing_settings = Settings(root_dir="/srv/files", users_config="users.yaml")
app = create_app(xwing_settings)

ldap_config = load_config("ldapgate.yaml")
add_ldap_auth(app, ldap_config)
```

Windows users can now map `http://your-server:8989/` as a network drive:

```cmd
net use Z: http://your-server:8989/ /user:alice /persistent:yes
```

macOS Finder: **Go → Connect to Server** (⌘K) → `http://your-server:8989/`

---

## CLI reference

```
ldapgate serve [OPTIONS]

  --config PATH     Path to ldapgate.yaml (reads env vars if omitted)
  --host TEXT       Override listen host
  --port INTEGER    Override listen port
  --backend TEXT    Override backend URL
  --reload          Enable auto-reload (dev only)
```

---

## Development

Requires [uv](https://github.com/astral-sh/uv).

```bash
git clone https://github.com/anudeepd/ldapgate
cd ldapgate
uv sync
uv run pytest
```

## License

MIT
