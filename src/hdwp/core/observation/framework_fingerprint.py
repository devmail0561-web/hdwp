# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
FrameworkFingerprintInspector : peuple les tags `framework:`, `db:`, `cms:`
dans les observations, complétant HeaderInspector qui ne produit que `server:`.

Les tags produits alimentent ApplicationModel._tech_stack et déclenchent les
plugins tech-adaptatifs (PrototypePollution, ELInjection, SpringActuator, etc.).

Appelé depuis ObservationEngine ou ApplicationModel._on_observation().
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hdwp.core.model.schemas import RawObservation


@dataclass
class FingerprintRule:
    source: str           # "header" | "cookie" | "path" | "body_key" | "body_value"
    key: str | None       # nom du header/cookie, None = wildcard
    patterns: list[tuple[re.Pattern, str]] = field(default_factory=list)


_FINGERPRINTS: list[FingerprintRule] = [
    # ── Headers ──────────────────────────────────────────────────────────────
    FingerprintRule("header", "x-powered-by", [
        (re.compile(r'php', re.IGNORECASE),              "framework:php"),
        (re.compile(r'express', re.IGNORECASE),          "framework:express"),
        (re.compile(r'next\.js', re.IGNORECASE),         "framework:nextjs"),
        (re.compile(r'asp\.net', re.IGNORECASE),         "framework:aspnet"),
        (re.compile(r'nestjs', re.IGNORECASE),           "framework:nestjs"),
        (re.compile(r'fastapi', re.IGNORECASE),          "framework:fastapi"),
        (re.compile(r'django', re.IGNORECASE),           "framework:django"),
        (re.compile(r'rails', re.IGNORECASE),            "framework:rails"),
    ]),
    FingerprintRule("header", "server", [
        (re.compile(r'gunicorn', re.IGNORECASE),         "server:gunicorn"),  # Python
        (re.compile(r'puma', re.IGNORECASE),             "server:puma"),      # Rails
        (re.compile(r'unicorn', re.IGNORECASE),          "server:unicorn"),   # Rails
        (re.compile(r'passenger', re.IGNORECASE),        "server:passenger"), # Rails/Ruby
        (re.compile(r'iis', re.IGNORECASE),              "server:iis"),
        (re.compile(r'jetty', re.IGNORECASE),            "server:jetty"),     # Java
        (re.compile(r'tomcat', re.IGNORECASE),           "server:tomcat"),    # Java
        (re.compile(r'undertow', re.IGNORECASE),         "server:undertow"),  # WildFly
        (re.compile(r'werkzeug', re.IGNORECASE),         "server:werkzeug"),  # Flask dev
        (re.compile(r'uvicorn', re.IGNORECASE),          "server:uvicorn"),   # Python async
    ]),
    FingerprintRule("header", "x-generator", [
        (re.compile(r'wordpress', re.IGNORECASE),        "cms:wordpress"),
        (re.compile(r'drupal', re.IGNORECASE),           "cms:drupal"),
        (re.compile(r'joomla', re.IGNORECASE),           "cms:joomla"),
    ]),
    FingerprintRule("header", "x-drupal-cache", [
        (re.compile(r'.*'),                     "cms:drupal"),
    ]),
    FingerprintRule("header", "x-wp-total", [
        (re.compile(r'.*'),                     "cms:wordpress"),
    ]),

    # ── Cookies ───────────────────────────────────────────────────────────────
    FingerprintRule("cookie", "*", [
        (re.compile(r'^laravel_session', re.IGNORECASE), "framework:laravel"),
        (re.compile(r'^PHPSESSID$', re.IGNORECASE),      "framework:php"),
        (re.compile(r'^JSESSIONID$', re.IGNORECASE),     "framework:java"),
        (re.compile(r'^_rails_session', re.IGNORECASE),  "framework:rails"),
        (re.compile(r'^csrftoken$', re.IGNORECASE),      "framework:django"),
        (re.compile(r'^sessionid$', re.IGNORECASE),      "framework:django"),
        (re.compile(r'^__RequestVerificationToken', re.IGNORECASE), "framework:aspnet"),
        (re.compile(r'^wordpress_', re.IGNORECASE),      "cms:wordpress"),
        (re.compile(r'^wp-settings', re.IGNORECASE),     "cms:wordpress"),
        (re.compile(r'^Drupal', re.IGNORECASE),          "cms:drupal"),
        (re.compile(r'^connect\.sid', re.IGNORECASE),    "framework:express"),
        (re.compile(r'^flask_', re.IGNORECASE),          "framework:flask"),
    ]),

    # ── URL path patterns ─────────────────────────────────────────────────────
    FingerprintRule("path", None, [
        (re.compile(r'/wp-admin|/wp-content|/wp-includes', re.IGNORECASE), "cms:wordpress"),
        (re.compile(r'/actuator/',  re.IGNORECASE),       "framework:spring"),
        (re.compile(r'\.php\b',    re.IGNORECASE),        "framework:php"),
        (re.compile(r'\.aspx?\b',  re.IGNORECASE),        "framework:aspnet"),
        (re.compile(r'/rails/info',re.IGNORECASE),        "framework:rails"),
        (re.compile(r'/_next/',    re.IGNORECASE),        "framework:nextjs"),
        (re.compile(r'/nuxt/',     re.IGNORECASE),        "framework:nuxt"),
        (re.compile(r'/graphql\b', re.IGNORECASE),        "framework:graphql"),
        (re.compile(r'/api/v\d+/', re.IGNORECASE),        "server:rest-api"),
        (re.compile(r'/swagger|/api-docs', re.IGNORECASE), "server:openapi"),
        (re.compile(r'/sites/default/', re.IGNORECASE),   "cms:drupal"),
        (re.compile(r'/administrator/', re.IGNORECASE),   "cms:joomla"),
    ]),
]


def fingerprint_observation(obs: RawObservation) -> list[str]:
    """
    Retourne la liste de tags framework:/db:/cms: détectés pour cette observation.
    Ces tags sont destinés à être ajoutés à ApplicationModel._tech_stack.
    """
    if obs.response is None or obs.request is None:
        return []

    tags: list[str] = []
    headers = {k.lower(): v for k, v in (obs.response.headers or {}).items()}
    url_path = obs.request.url or ""

    for rule in _FINGERPRINTS:
        if rule.source == "header":
            assert rule.key is not None
            val = headers.get(rule.key.lower(), "")
            if not val:
                continue
            for pattern, tag in rule.patterns:
                if pattern.search(val) and tag not in tags:
                    tags.append(tag)

        elif rule.source == "cookie":
            # Chercher dans les noms de cookies du Set-Cookie header
            set_cookie = headers.get("set-cookie", "")
            if not set_cookie:
                continue
            # Extraire le nom du cookie (première partie avant =)
            for cookie_part in set_cookie.split(";"):
                cookie_name = cookie_part.strip().split("=")[0].strip()
                for pattern, tag in rule.patterns:
                    if pattern.search(cookie_name) and tag not in tags:
                        tags.append(tag)

        elif rule.source == "path":
            for pattern, tag in rule.patterns:
                if pattern.search(url_path) and tag not in tags:
                    tags.append(tag)

    return tags
