"""CLI for ldapgate reverse proxy."""

import os
from pathlib import Path

import click
import uvicorn

from ldapgate.config import load_config
from ldapgate.proxy import create_proxy_app

# Env var used to pass config path to the module-level app factory for --reload mode
_CONFIG_ENV_VAR = "LDAPGATE_CONFIG_PATH"


@click.group()
def cli():
    """ldapgate - LDAP/AD authentication proxy."""
    pass


@cli.command()
@click.option(
    "--config",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to ldapgate.yaml config file (reads env vars if omitted)",
)
@click.option(
    "--host",
    default=None,
    help="Override listen host (default: 0.0.0.0)",
)
@click.option(
    "--port",
    type=int,
    default=None,
    help="Override listen port (default: 9000)",
)
@click.option(
    "--backend",
    default=None,
    help="Override backend URL",
)
@click.option(
    "--reload",
    is_flag=True,
    help="Enable auto-reload on code changes",
)
def serve(config: Path, host: str, port: int, backend: str, reload: bool):
    """Start ldapgate reverse proxy server.

    Example:
        ldapgate serve --config ldapgate.yaml
        ldapgate serve --backend http://localhost:3923
    """
    try:
        cfg = load_config(config)

        if host:
            cfg.proxy.listen_host = host
        if port:
            cfg.proxy.listen_port = port
        if backend:
            cfg.proxy.backend_url = backend

        click.echo(
            f"Starting ldapgate proxy on {cfg.proxy.listen_host}:{cfg.proxy.listen_port}"
        )
        click.echo(f"Backend: {cfg.proxy.backend_url}")
        click.echo(f"Login path: {cfg.proxy.login_path}")

        if reload:
            # Reload mode requires an import string; pass config + overrides via env vars
            # so the factory in this module can reconstruct the app identically.
            if config:
                os.environ[_CONFIG_ENV_VAR] = str(config)
            if backend:
                os.environ["LDAPGATE_BACKEND_URL"] = backend
            uvicorn.run(
                "ldapgate.cli:_reload_app_factory",
                factory=True,
                host=cfg.proxy.listen_host,
                port=cfg.proxy.listen_port,
                reload=True,
                log_level="info",
            )
        else:
            app = create_proxy_app(cfg)
            uvicorn.run(
                app,
                host=cfg.proxy.listen_host,
                port=cfg.proxy.listen_port,
                log_level="info",
            )

    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(1)


def _reload_app_factory():
    """App factory used by uvicorn --reload (needs importable callable)."""
    config_path = os.environ.get(_CONFIG_ENV_VAR)
    cfg = load_config(config_path)
    backend = os.environ.get("LDAPGATE_BACKEND_URL")
    if backend:
        cfg.proxy.backend_url = backend
    return create_proxy_app(cfg)


def main():
    """Entry point for ldapgate CLI."""
    cli()


if __name__ == "__main__":
    main()
