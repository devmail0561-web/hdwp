# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
OpenAPISeeder: génère des observations synthétiques depuis une spec OpenAPI.

Permet de pré-alimenter l'ApplicationModel avec les endpoints définis dans
une spec OpenAPI/Swagger sans nécessiter de crawl HTML ni de proxy.

Supporte aussi `discovery.seed_endpoints` pour des URLs manuelles.

Toutes les URLs sont filtrées par le scope avant émission.
Pour les endpoints avec security requirement, une observation 401 pour anonymous
est émise afin de déclencher la détection auth_required.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import httpx
import structlog
import yaml

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import OBSERVATION_RAW
from hdwp.core.context.loader import EngineContext
from hdwp.core.model.schemas import ObservationType, RawObservation, generate_id
from hdwp.core.observation.normalizer import normalize_request, normalize_response

log = structlog.get_logger()

_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

_SWAGGER_DISCOVERY_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/api-docs",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/.well-known/openapi.json",
]


async def auto_discover_spec(
    base_url: str,
    delay_between_requests: float = 0.0,
) -> dict[str, Any] | None:
    """
    Tente de découvrir automatiquement la spec OpenAPI de la cible.
    Essaie les chemins swagger/openapi courants.
    Retourne le dict de la spec si trouvée, None sinon.

    Args:
        delay_between_requests: délai en secondes entre les requêtes (respecter le rate limit).
    """
    import asyncio
    base = base_url.rstrip("/")
    from hdwp.core.http_client import build_client
    async with build_client(timeout=5.0) as client:
        for path in _SWAGGER_DISCOVERY_PATHS:
            if delay_between_requests > 0:
                await asyncio.sleep(delay_between_requests)
            try:
                resp = await client.get(f"{base}{path}")
                if resp.status_code != 200:
                    continue
                ct = resp.headers.get("content-type", "")
                if "json" in ct or "yaml" in ct or path.endswith(".json"):
                    spec = _parse_spec_content(resp.text)
                    if spec and ("paths" in spec or "openapi" in spec or "swagger" in spec):
                        log.info(
                            "openapi.auto_discovered",
                            path=path,
                            endpoints=len(spec.get("paths", {})),
                        )
                        return spec
            except Exception:  # noqa: BLE001, S112
                continue
    return None


def _parse_spec_content(content: str) -> dict[str, Any] | None:
    """Parse JSON ou YAML, retourne None si invalide."""
    try:
        return json.loads(content)
    except Exception:  # noqa: BLE001, S110
        pass
    try:
        return yaml.safe_load(content)
    except Exception:  # noqa: BLE001, S110
        pass
    return None


def _in_scope(url: str, include: list[str], exclude: list[str]) -> bool:
    """Vérifie que l'URL respecte le scope (include/exclude patterns glob)."""
    for pattern in exclude:
        if fnmatch(url, pattern):
            return False
    return any(fnmatch(url, pattern) for pattern in include)


async def seed_from_openapi(bus: AsyncEventBus, context: EngineContext) -> int:
    """
    Émet des observations synthétiques depuis :
    - Une spec OpenAPI (discovery.openapi_spec)
    - Des URLs manuelles (discovery.seed_endpoints)

    Filtre le scope. Retourne le nombre d'observations émises.
    """
    count = 0
    discovery = context.config.discovery
    roles = context.config.roles[:2]
    base_url = context.config.target.base_url.rstrip("/")
    include = context.config.scope.include
    exclude = context.config.scope.exclude

    if discovery.openapi_spec:
        spec = await _load_spec(discovery.openapi_spec)
        if spec is not None:
            count += await _seed_from_paths(
                bus, context, spec.get("paths", {}), roles, base_url,
                include, exclude, spec,
            )

    if discovery.seed_endpoints:
        count += await _seed_manual_endpoints(
            bus, context, discovery.seed_endpoints, roles, base_url, include, exclude,
        )

    return count


async def seed_from_openapi_spec(
    bus: AsyncEventBus, context: EngineContext, spec: dict[str, Any]
) -> int:
    """
    Émet des observations synthétiques depuis une spec OpenAPI pré-chargée
    (utilisé par auto-discovery dans ObservationEngine.start()).
    """
    roles = context.config.roles[:2]
    base_url = context.config.target.base_url.rstrip("/")
    include = context.config.scope.include
    exclude = context.config.scope.exclude
    return await _seed_from_paths(
        bus, context, spec.get("paths", {}), roles, base_url, include, exclude, spec,
    )


async def _seed_from_paths(
    bus: AsyncEventBus,
    context: EngineContext,
    paths: dict[str, Any],
    roles: list,
    base_url: str,
    include: list[str],
    exclude: list[str],
    spec: dict[str, Any],
) -> int:
    count = 0
    # Sécurité globale définie dans la spec (s'applique à tous les endpoints)
    global_security = bool(spec.get("security")) or bool(spec.get("components", {}).get("securitySchemes"))

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.upper() not in _HTTP_METHODS:
                continue
            url = f"{base_url}{path}"
            if not _in_scope(url, include, exclude):
                log.debug("openapi_seeder.url_out_of_scope", url=url)
                continue

            requires_auth = (
                global_security
                or bool(path_item.get("security"))
                or (isinstance(operation, dict) and bool(operation.get("security")))
            )
            body = _infer_response_body(operation) if isinstance(operation, dict) else None
            count += await _emit_synthetic_obs(
                bus, context, url, method.upper(), roles, body, requires_auth,
            )

    log.info("openapi_seeder.spec_done", endpoints=len(paths), observations=count)
    return count


async def _seed_manual_endpoints(
    bus: AsyncEventBus,
    context: EngineContext,
    endpoints: list[str],
    roles: list,
    base_url: str,
    include: list[str],
    exclude: list[str],
) -> int:
    count = 0
    for path in endpoints:
        url = f"{base_url}{path}" if path.startswith("/") else path
        if not _in_scope(url, include, exclude):
            log.debug("openapi_seeder.url_out_of_scope", url=url)
            continue
        count += await _emit_synthetic_obs(bus, context, url, "GET", roles, None, False)

    log.info("openapi_seeder.manual_done", endpoints=len(endpoints), observations=count)
    return count


async def _emit_synthetic_obs(
    bus: AsyncEventBus,
    context: EngineContext,
    url: str,
    method: str,
    roles: list,
    body: Any = None,
    requires_auth: bool = False,
) -> int:
    """
    Émet une observation synthétique par rôle.

    Si requires_auth=True :
    - anonymous → status 401 (pour déclencher auth_required dans ApplicationModel)
    - autres rôles → status 200 avec body
    """
    count = 0
    for role in roles:
        is_anon = role.name == "anonymous"
        if requires_auth and is_anon:
            status = 401
            resp_body: Any = {"error": "Unauthorized"}
        else:
            status = 200
            resp_body = body

        norm_req = normalize_request(method=method, url=url)
        norm_resp = normalize_response(status_code=status, headers={}, body=resp_body)
        obs = RawObservation(
            id=generate_id("OBS"),
            timestamp=datetime.now(UTC).isoformat(),
            source="active",
            type=ObservationType.HTTP,
            request=norm_req,
            response=norm_resp,
            session_id=context.session_id,
            tags=[f"role:{role.name}", "source:openapi_spec"],
        )
        await bus.emit(OBSERVATION_RAW, obs.model_dump(), source="openapi_seeder")
        count += 1
    return count


async def _load_spec(spec_path: str) -> dict[str, Any] | None:
    """Charge une spec OpenAPI depuis un chemin local ou une URL HTTP."""
    try:
        if spec_path.startswith(("http://", "https://")):
            from hdwp.core.http_client import build_client
            async with build_client(timeout=10.0) as client:
                resp = await client.get(spec_path)
                resp.raise_for_status()
                content = resp.text
        else:
            content = Path(spec_path).read_text(encoding="utf-8")

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return yaml.safe_load(content)
    except Exception as exc:  # noqa: BLE001
        log.warning("openapi_seeder.load_failed", path=spec_path, error=str(exc))
        return None


def _infer_response_body(operation: dict[str, Any]) -> dict[str, Any] | None:
    """Génère un body de réponse exemple depuis le schéma OpenAPI."""
    responses = operation.get("responses", {})
    for status_code in ("200", "201", "2XX"):
        resp_obj = responses.get(status_code, {})
        content = resp_obj.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})
        if schema:
            return _schema_to_example(schema)
    return None


def _schema_to_example(schema: dict[str, Any]) -> Any:
    """
    Exemple minimal depuis un schéma JSON Schema.
    Note: les $ref ne sont pas résolus — les specs avec $ref produiront {}.
    """
    if schema.get("type") == "object":
        props = schema.get("properties", {})
        return {
            k: _type_to_value(v.get("type", "string") if isinstance(v, dict) else "string")
            for k, v in list(props.items())[:5]
        }
    if schema.get("type") == "array":
        items = schema.get("items", {})
        return [_schema_to_example(items)] if items else []
    return {}


def _type_to_value(type_name: str) -> Any:
    match type_name:
        case "integer" | "number":
            return 1
        case "boolean":
            return True
        case "array":
            return []
        case "object":
            return {}
        case _:
            return "example"
