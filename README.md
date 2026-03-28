<p align="center">
  <img src="https://raw.githubusercontent.com/anudeepd/ldapgate/main/assets/logo.svg" alt="LDAPGate" width="120"/>
</p>

<h1 align="center">LDAPGate</h1>

<p align="center">Lightweight LDAP/AD authentication gateway for Python web apps. Install it, configure it, done.</p>

## Features

- **Two deployment modes** — standalone reverse proxy or drop-in FastAPI middleware
- **Pure Python LDAP** — no OS-level libs required, uses `ldap3`
- **Signed cookie sessions** — stateless, no server-side session storage
- **OpenLDAP and Active Directory** — `uid=` and `sAMAccountName=` out of the box
- **Optional group gating** — restrict access to members of a specific LDAP group
- **Header injection** — injects `X-Forwarded-User` for apps that support it
- **Bundled login form** — responsive, dark/light mode, works air-gapped

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
  user_filter: "(sAMAccountName={username})"        # AD; OpenLDAP: (uid={username})
  group_dn: CN=app-users,CN=Users,DC=example,DC=com # optional

proxy:
  listen_host: 0.0.0.0
  listen_port: 9000
  backend_url: http://localhost:8080
  secret_key: change-me-to-something-random
  session_ttl: 3600
  user_header: X-Forwarded-User
  login_path: /_auth/login
  app_name: MyApp
```

All settings can also be provided via environment variables with `__` separators (e.g. `LDAP__URL`, `PROXY__SECRET_KEY`).

## Mode 1 — Standalone Reverse Proxy

Run ldapgate as a standalone process in front of any app. Only authenticated requests are forwarded to the backend.

```
Browser → ldapgate :9000 → backend app :8080
```

```bash
ldapgate serve --config ldapgate.yaml
```

**Example: copyparty**

Start copyparty with IDP header auth and point its logout at ldapgate:

```bash
copyparty -p 8080 --idp-h-usr X-Forwarded-User --idp-logout /_auth/logout -v ~/Documents:/:rw
```

copyparty trusts the `X-Forwarded-User` header injected by ldapgate, and its logout button redirects to `/_auth/logout` which clears the ldapgate session before sending the user back to the login page.

## Mode 2 — FastAPI Middleware

Drop ldapgate auth directly into an existing FastAPI app — no separate process needed.

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

**Example: lagun** — see [lagun](https://github.com/anudeepd/lagun) and [torrus](https://github.com/anudeepd/torrus) for real-world integrations.

## CLI Options

```
ldapgate serve --config PATH   Path to ldapgate.yaml [default: ldapgate.yaml]
               --host TEXT     Override listen host
               --port INTEGER  Override listen port
               --backend TEXT  Override backend URL
               --reload        Enable auto-reload (dev)
```

## Development

Requires [uv](https://github.com/astral-sh/uv).

```bash
git clone https://github.com/anudeepd/ldapgate
cd ldapgate
uv sync
pytest tests/
```

## License

MIT
