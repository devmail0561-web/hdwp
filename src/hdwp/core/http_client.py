# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Fabrique centrale pour les clients HTTP — injecte le proxy Tor par défaut.

Tous les composants qui font des requêtes vers la cible (crawl, expériences,
exploitation, chaînes, passive checks) doivent passer par `build_client()` pour
garantir que le trafic sort via Tor Browser (ou tout proxy configuré).

Configuration via `configure()` au démarrage du moteur.
"""
from __future__ import annotations

import httpx
import structlog

log = structlog.get_logger()

# Port SOCKS5 de Tor Browser (9150) — le daemon Tor standard utilise 9050.
# socks5h:// = résolution DNS via le proxy (évite les fuites DNS).
TOR_BROWSER_PROXY = "socks5h://127.0.0.1:9150"

# Proxy actif pour toute la session — modifiable via configure()
_active_proxy: str | None = TOR_BROWSER_PROXY


def configure(proxy_url: str | None) -> None:
    """Définit le proxy global pour tous les clients créés par build_client().

    Appelé une seule fois au démarrage du moteur depuis HDWPEngine.
    proxy_url=None désactive le proxy (connexion directe).
    """
    global _active_proxy
    _active_proxy = proxy_url
    if proxy_url:
        log.info("http_client.proxy_configured", proxy=proxy_url)
    else:
        log.info("http_client.proxy_disabled")


def get_proxy() -> str | None:
    """Retourne le proxy actif (lecture seule)."""
    return _active_proxy


def build_client(
    *,
    timeout: float = 15.0,
    follow_redirects: bool = True,
    proxy_url: str | None = ...,  # type: ignore[assignment]
) -> httpx.AsyncClient:
    """Crée un AsyncClient httpx avec le proxy configuré.

    Args:
        timeout: Timeout en secondes (défaut 15s).
        follow_redirects: Suivre les redirections (défaut True).
        proxy_url: Override le proxy global. None = direct. Ellipsis = utiliser global.

    Returns:
        AsyncClient configuré avec le proxy actif.
    """
    effective_proxy: str | None = _active_proxy if proxy_url is ... else proxy_url

    kwargs: dict = {
        "follow_redirects": follow_redirects,
        "timeout": httpx.Timeout(timeout),
    }

    if effective_proxy:
        kwargs["proxy"] = effective_proxy
        # Désactiver SSL verification uniquement pour les proxies MITM (http/https)
        # → Tor (socks5h://) se connecte aux vrais serveurs : garder la vérification SSL.
        if effective_proxy.startswith(("http://", "https://")):
            kwargs["verify"] = False

    return httpx.AsyncClient(**kwargs)
