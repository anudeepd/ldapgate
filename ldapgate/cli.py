"""CLI for ldapgate reverse proxy."""

import contextlib
import json
import logging
import os
import tempfile
from pathlib import Path

import click
import uvicorn

from ldapgate.config import load_config, validate_backend_url
from ldapgate.proxy import create_proxy_app

# Env var used to pass reload configuration via a secure temporary file.
# The file itself (not the env var) holds the config path and overrides.
_RELOAD_FILE_ENV = 'LDAPGATE_RELOAD_FILE'


def _sanitize_error_message(exc: Exception) -> str:
    """Sanitize an exception message to avoid leaking config details."""
    msg = str(exc)
    # Redact paths, passwords, and connection details
    redactions = [
        (r'/[^\s]+\.(yaml|yml|json|toml|env|txt|ini)', '[REDACTED_CONFIG_PATH]'),
        (r'password[^\s]*', '[REDACTED_PASSWORD]'),
        (r'secret[^\s]*', '[REDACTED_SECRET]'),
        (r'bind_dn[^\s]*', '[REDACTED_DN]'),
        (r'ldap://[^\s]+', '[REDACTED_URL]'),
        (r'ldaps://[^\s]+', '[REDACTED_URL]'),
    ]
    import re

    for pattern, replacement in redactions:
        msg = re.sub(pattern, replacement, msg, flags=re.IGNORECASE)
    return msg


@click.group()
def cli():
    """ldapgate - LDAP/AD authentication proxy."""


def _configure_logging(log_file: Path | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding='utf-8'))
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)-8s %(name)s %(message)s',
        datefmt='%H:%M:%S',
        handlers=handlers,
    )


@cli.command()
@click.option(
    '--config',
    type=click.Path(path_type=Path),
    default=None,
    help='Path to ldapgate.yaml config file (reads env vars if omitted)',
)
@click.option(
    '--host',
    default=None,
    help='Override listen host (default: 0.0.0.0)',
)
@click.option(
    '--port',
    type=int,
    default=None,
    help='Override listen port (default: 9000)',
)
@click.option(
    '--backend',
    default=None,
    help='Override backend URL',
)
@click.option(
    '--reload',
    is_flag=True,
    help='Enable auto-reload on code changes',
)
@click.option(
    '--log-file',
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help='Append application logs to this file.',
)
def serve(config: Path, host: str, port: int, backend: str, reload: bool, log_file: Path | None):
    """Start ldapgate reverse proxy server.

    Example:
        ldapgate serve --config ldapgate.yaml
        ldapgate serve --backend http://localhost:3923
    """
    try:
        _configure_logging(log_file)
        cfg = load_config(config)

        if host:
            cfg.proxy.listen_host = host
        if port:
            cfg.proxy.listen_port = port
        if backend:
            cfg.proxy.backend_url = validate_backend_url(backend)
        if not cfg.proxy.backend_url:
            raise ValueError('proxy.backend_url is required for `ldapgate serve`')

        click.echo(f'Starting ldapgate proxy on {cfg.proxy.listen_host}:{cfg.proxy.listen_port}')
        click.echo(f'Backend: {cfg.proxy.backend_url}')
        click.echo(f'Login path: {cfg.proxy.login_path}')

        if reload:
            # Write reload config to a private temp file instead of env vars
            # so config paths are not exposed via /proc/*/environ.
            reload_cfg = {}
            if config:
                reload_cfg['config'] = str(config)
            if backend:
                reload_cfg['backend'] = backend
            if host:
                reload_cfg['host'] = host
            if port:
                reload_cfg['port'] = port
            if log_file:
                reload_cfg['log_file'] = str(log_file)
            fd, tmp_path = tempfile.mkstemp(suffix='.json', prefix='ldapgate_reload_')
            os.close(fd)
            with open(tmp_path, 'w') as f:
                json.dump(reload_cfg, f)
            os.environ[_RELOAD_FILE_ENV] = tmp_path
            uvicorn.run(
                'ldapgate.cli:_reload_app_factory',
                factory=True,
                host=cfg.proxy.listen_host,
                port=cfg.proxy.listen_port,
                reload=True,
                log_level='info',
                log_config=None,
            )
        else:
            app = create_proxy_app(cfg)
            uvicorn.run(
                app,
                host=cfg.proxy.listen_host,
                port=cfg.proxy.listen_port,
                log_level='info',
                log_config=None,
            )

    except FileNotFoundError:
        click.echo('Error: Config file not found', err=True)
        raise SystemExit(1) from None
    except Exception as e:
        safe_msg = _sanitize_error_message(e)
        click.echo(f'Error: {safe_msg}', err=True)
        raise SystemExit(1) from None


def _reload_app_factory():
    """App factory used by uvicorn --reload (needs importable callable).

    Reads configuration from a private temp file (set by the parent
    process) rather than environment variables to avoid leaking paths.
    """

    tmp_path = os.environ.pop(_RELOAD_FILE_ENV, None)
    reload_cfg = {}
    if tmp_path:
        try:
            with open(tmp_path) as f:
                reload_cfg = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            pass
        finally:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)

    config_path = reload_cfg.get('config')
    log_file = reload_cfg.get('log_file')
    _configure_logging(Path(log_file) if log_file else None)
    try:
        cfg = load_config(config_path)
    except Exception as e:
        safe_msg = _sanitize_error_message(e)
        click.echo(f'ldapgate: failed to load config: {safe_msg}', err=True)
        raise

    backend = reload_cfg.get('backend')
    if backend:
        cfg.proxy.backend_url = validate_backend_url(backend)
    if not cfg.proxy.backend_url:
        raise ValueError('proxy.backend_url is required for `ldapgate serve`')
    host = reload_cfg.get('host')
    if host:
        cfg.proxy.listen_host = host
    port = reload_cfg.get('port')
    if port:
        cfg.proxy.listen_port = int(port)
    return create_proxy_app(cfg)


def main():
    """Entry point for ldapgate CLI."""
    cli()


if __name__ == '__main__':
    main()
