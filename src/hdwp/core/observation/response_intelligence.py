# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
ResponseIntelligence : analyse sémantique des corps de réponse HTTP.

Peuple les champs d'EndpointNode que l'ApplicationModel ne peut pas inférer
structurellement :
  - contains_privilege_field / observed_roles : champs role/permissions/scope détectés
  - jwt_field_names : champs contenant des JWTs dans la réponse
  - error_tech_signals : signaux technologiques extraits des messages d'erreur

Appelé depuis ApplicationModel._on_observation() après _update_data_objects().
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hdwp.core.model.schemas import EndpointNode, RawObservation

# ── Détection de champs privilège ──────────────────────────────────────────────

_PRIVILEGE_KEYS = frozenset({
    "role", "roles", "permissions", "permission", "scope", "scopes",
    "groups", "group", "is_admin", "is_staff", "is_superuser",
    "access_level", "capabilities", "authorities", "grants",
    "user_type", "account_type", "tier", "plan", "subscription",
})

# ── Détection de JWTs ─────────────────────────────────────────────────────────

_JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}')

# ── Signaux technologiques dans les erreurs ───────────────────────────────────

_ERROR_TECH_MAP: dict[str, list[re.Pattern]] = {
    "db:oracle":    [re.compile(r'ORA-\d+', re.IGNORECASE), re.compile(r'Oracle.*SQL', re.IGNORECASE)],
    "db:mysql":     [re.compile(r'MySQL.*error', re.IGNORECASE), re.compile(r"You have an error.*SQL syntax", re.IGNORECASE)],
    "db:mssql":     [re.compile(r'Microsoft SQL Server', re.IGNORECASE), re.compile(r'Incorrect syntax near', re.IGNORECASE)],
    "db:pgsql":     [re.compile(r'PostgreSQL.*ERROR', re.IGNORECASE), re.compile(r'PG::', re.IGNORECASE)],
    "db:sqlite":    [re.compile(r'SQLite.*error', re.IGNORECASE), re.compile(r'no such column', re.IGNORECASE)],
    "db:mongodb":   [re.compile(r'MongoError', re.IGNORECASE), re.compile(r'BSONTypeError', re.IGNORECASE)],
    "framework:django":  [re.compile(r'Django.*Exception', re.IGNORECASE), re.compile(r'DJANGO_SETTINGS_MODULE')],
    "framework:laravel": [re.compile(r'Illuminate\\', re.IGNORECASE), re.compile(r'Laravel.*Whoops', re.IGNORECASE)],
    "framework:rails":   [re.compile(r'ActionController', re.IGNORECASE), re.compile(r'Ruby on Rails', re.IGNORECASE)],
    "framework:spring":  [re.compile(r'org\.springframework', re.IGNORECASE), re.compile(r'HibernateException', re.IGNORECASE)],
    "framework:flask":   [re.compile(r'flask\.exceptions', re.IGNORECASE), re.compile(r'Werkzeug Debugger', re.IGNORECASE)],
    "framework:php":     [re.compile(r'Fatal error.*PHP', re.IGNORECASE), re.compile(r'Parse error.*PHP', re.IGNORECASE)],
    "framework:java":    [re.compile(r'java\.lang\.', re.IGNORECASE), re.compile(r'at .*\.java:\d+')],
    "framework:aspnet":  [re.compile(r'System\.Web\.', re.IGNORECASE), re.compile(r'ASP\.NET', re.IGNORECASE)],
}


def _extract_string_values(obj: object, depth: int = 0) -> list[str]:
    """Extrait récursivement les valeurs string d'un objet JSON (limite 3 niveaux)."""
    if depth > 3:
        return []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        result: list[str] = []
        for v in obj.values():
            result.extend(_extract_string_values(v, depth + 1))
        return result
    if isinstance(obj, list):
        result = []
        for item in obj[:10]:
            result.extend(_extract_string_values(item, depth + 1))
        return result
    return []


def _collect_role_values(obj: object, depth: int = 0) -> list[str]:
    """Collecte les valeurs de rôle depuis un body JSON."""
    if depth > 3 or not isinstance(obj, dict):
        return []
    roles: list[str] = []
    for k, v in obj.items():
        if k.lower() in _PRIVILEGE_KEYS:
            if isinstance(v, str) and v:
                roles.append(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str) and item:
                        roles.append(item)
        elif isinstance(v, dict):
            roles.extend(_collect_role_values(v, depth + 1))
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            roles.extend(_collect_role_values(v[0], depth + 1))
    return roles


def _has_privilege_key(obj: object, depth: int = 0) -> bool:
    """Vérifie si un body JSON contient une clé de privilège à n'importe quel niveau."""
    if depth > 3 or not isinstance(obj, dict):
        return False
    for k, v in obj.items():
        if k.lower() in _PRIVILEGE_KEYS:
            return True
        if isinstance(v, dict) and _has_privilege_key(v, depth + 1):
            return True
        if isinstance(v, list) and v and isinstance(v[0], dict):
            if _has_privilege_key(v[0], depth + 1):
                return True
    return False


def analyze_response(
    obs: RawObservation,
    endpoint: EndpointNode,
    tech_stack: set[str],
) -> None:
    """
    Analyse la réponse et enrichit l'EndpointNode + tech_stack en place.
    Aucune valeur de retour — modifie directement endpoint et tech_stack.
    """
    if obs.response is None:
        return
    body = obs.response.body
    status = obs.response.status_code
    headers = obs.response.headers or {}

    # ── a) Détection des champs de privilège dans le body ─────────────────────
    if isinstance(body, dict):
        if _has_privilege_key(body):
            endpoint.contains_privilege_field = True
            for role_val in _collect_role_values(body):
                if role_val not in endpoint.observed_roles:
                    endpoint.observed_roles.append(role_val)

    # ── b) Détection de JWTs dans le body et les headers ─────────────────────
    # Body : chercher dans les valeurs string
    if isinstance(body, dict):
        for k, v in body.items():
            if isinstance(v, str) and _JWT_RE.match(v):
                if k not in endpoint.jwt_field_names:
                    endpoint.jwt_field_names.append(k)
                _record_jwt_claims(v, endpoint, tech_stack)  # return value intentionnellement ignoré ici
                # (les claims sont exploités dans SecurityModelGraph via IdentityFlow)

    # Headers : Set-Cookie, Authorization
    for hdr_name in ("set-cookie", "authorization"):
        hdr_val = headers.get(hdr_name, "")
        if hdr_val:
            m = _JWT_RE.search(hdr_val)
            if m:
                field_label = f"header:{hdr_name}"
                if field_label not in endpoint.jwt_field_names:
                    endpoint.jwt_field_names.append(field_label)
                _record_jwt_claims(m.group(0), endpoint, tech_stack)

    # ── c) Signaux technologiques dans les messages d'erreur ─────────────────
    # Uniquement sur les réponses d'erreur (4xx/5xx) pour réduire le bruit
    if status >= 400:
        all_strings = _extract_string_values(body)
        for tech_tag, patterns in _ERROR_TECH_MAP.items():
            if tech_tag in tech_stack:
                continue  # déjà détecté
            for text in all_strings:
                if any(p.search(text) for p in patterns):
                    tech_stack.add(tech_tag)
                    if tech_tag not in endpoint.error_tech_signals:
                        endpoint.error_tech_signals.append(tech_tag)
                    break


def _record_jwt_claims(token: str, endpoint: EndpointNode, tech_stack: set[str]) -> dict[str, Any]:
    """Décode un JWT sans vérification et enrichit le tech_stack si des claims significatifs sont trouvés."""
    try:
        from hdwp.core.experiment.jwt_mutator import decode_jwt_insecure
        _, payload, _ = decode_jwt_insecure(token)
        if payload:
            # Détecter des indices technologiques dans les claims (iss, aud)
            iss = str(payload.get("iss", "")).lower()
            if "cognito" in iss:
                tech_stack.add("framework:aws-cognito")
            elif "okta" in iss:
                tech_stack.add("framework:okta")
            elif "auth0" in iss:
                tech_stack.add("framework:auth0")
            return payload
    except Exception:
        pass
    return {}
