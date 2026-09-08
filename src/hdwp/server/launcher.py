# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Lance le serveur FastAPI et ouvre la fenêtre pywebview (ou le navigateur)."""
from __future__ import annotations

import socket
import threading
import time
import urllib.parse
from pathlib import Path

import httpx
import structlog

log = structlog.get_logger()

_DEFAULT_PORT = 7860
_HOST = "127.0.0.1"


def _find_free_port(host: str, start: int, max_attempts: int = 20) -> int:
    """Return *start* if available, otherwise probe upward until a free port is found."""
    for offset in range(max_attempts):
        port = start + offset
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No free port found in range {start}–{start + max_attempts - 1}")


def _load_env_file() -> None:
    """Charge ~/.hdwp/.env dans os.environ (format KEY=VALUE, ignore # et lignes vides)."""
    import os

    env_path = Path.home() / ".hdwp" / ".env"
    if not env_path.exists():
        return
    for raw in env_path.read_text().splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped:
            k, v = stripped.split("=", 1)
            key, val = k.strip(), v.strip()
            if key and key not in os.environ:
                os.environ[key] = val
                log.debug("env.loaded", key=key)


def _setup_proxy() -> None:
    """
    Configuration complète du proxy au démarrage — exécutée dans le terminal.
    1. Installe certutil (libnss3-tools) si absent — sudo fonctionne ici
    2. Génère le certificat CA (~/.hdwp/ca.crt) si absent
    3. Installe le CA dans tous les navigateurs et le store système
    Silencieux si tout est déjà en place.
    """
    try:
        from hdwp.core.observation.ca_installer import (
            ensure_certutil,
            install_ca_everywhere,
            is_ca_already_installed,
        )
        from hdwp.core.observation.hdwp_proxy import CA_CERT_PATH, _load_or_create_ca

        # Étape 1 : certutil (libnss3-tools)
        ensure_certutil()

        # Étape 2 : CA
        _load_or_create_ca()

        # Étape 3 : installation uniquement si pas déjà en place
        if CA_CERT_PATH.exists() and not is_ca_already_installed(CA_CERT_PATH):
            results = install_ca_everywhere(CA_CERT_PATH)
            ok = [k for k, v in results.items() if v.get("ok")]
            if ok:
                log.info("proxy.ca_installed_on_startup", browsers=ok)
        else:
            log.debug("proxy.ca_already_installed")
    except Exception as exc:
        log.debug("proxy.setup_error", error=str(exc))


def start_native_app(
    context_path: Path | None = None,
    db_url: str | None = None,
    auto_start_url: str | None = None,
) -> None:
    """Lance le serveur FastAPI + ouvre la fenêtre native (pywebview ou navigateur)."""
    _load_env_file()
    _setup_proxy()   # tout-en-un : certutil + CA + install navigateurs

    port = _find_free_port(_HOST, _DEFAULT_PORT)
    if port != _DEFAULT_PORT:
        log.info("launcher.port_busy", default=_DEFAULT_PORT, using=port)

    server_thread = threading.Thread(target=_run_uvicorn, args=(port,), daemon=True)
    server_thread.start()

    health_url = f"http://{_HOST}:{port}/api/health"
    if not _wait_for_health(health_url, timeout=10.0):
        raise RuntimeError(
            f"Le serveur HDWP n'a pas démarré en 10s sur {_HOST}:{port}. "
            "Vérifiez les logs."
        )

    startup_url = f"http://{_HOST}:{port}"
    if auto_start_url:
        startup_url += f"?target={urllib.parse.quote(auto_start_url, safe='')}"

    log.info("launcher.ready", url=startup_url)
    _open_window(startup_url)


def _run_uvicorn(port: int) -> None:
    import uvicorn
    uvicorn.run(
        "hdwp.server.app:create_app",
        factory=True,
        host=_HOST,
        port=port,
        log_level="warning",
        access_log=False,
    )


def _wait_for_health(url: str, timeout: float = 10.0) -> bool:
    """Boucle retry 100ms — robuste vs time.sleep() arbitraire."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(url, timeout=0.5)
            if resp.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.1)
    return False


def _open_window(url: str) -> None:
    """Ouvre l'interface via pywebview (natif) ou le navigateur système en fallback."""
    try:
        import webview  # pywebview installe le module sous le nom 'webview'
        webview.create_window(
            "HDWP Engine",
            url,
            width=1440,
            height=900,
            min_size=(1024, 600),
        )
        # webview.start() DOIT être appelé depuis le thread principal (macOS/Windows)
        webview.start()
    except ImportError:
        log.warning("launcher.pywebview_not_installed", fallback="browser")
        import webbrowser
        webbrowser.open(url)
        # Garder le thread principal vivant jusqu'à Ctrl+C
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
