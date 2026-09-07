# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
HttpSemanticsInference : déduit des SecurityProperty depuis la sémantique HTTP.

Un hacker raisonne systématiquement sur les verbes HTTP + la structure du path :
  DELETE /resources/{id}  → BOLA destructif (HIGH confidence)
  PUT    /resources/{id}  → mass assignment (remplacement total de l'objet)
  PATCH  /resources/{id}  → mass assignment (mise à jour partielle)
  POST   /resources       → mass assignment à la création

Ces inférences s'ajoutent aux inférences structurelles existantes et génèrent des
SecurityProperty avec des confidence calibrées selon le risque du verbe.
"""
from __future__ import annotations

import re

from hdwp.core.model.schemas import (
    ApplicationModelData,
    PropertyType,
    SecurityProperty,
    generate_id,
)

# ── Risque par verbe HTTP ─────────────────────────────────────────────────────

_VERB_RISK: dict[str, tuple[PropertyType, float]] = {
    "DELETE": (PropertyType.AUTHORIZATION, 0.82),  # destruction BOLA
    "PUT":    (PropertyType.INTEGRITY,     0.78),  # mass assignment (remplacement total)
    "PATCH":  (PropertyType.INTEGRITY,     0.74),  # mass assignment (mise à jour partielle)
    "POST":   (PropertyType.INTEGRITY,     0.62),  # création — mass assignment possible
}

# Pattern de path avec un paramètre {id} → endpoint sur une ressource individuelle
_ID_PATH_RE = re.compile(r'\{[a-z_]*(?:id|uuid|slug|key|ref|hash)[a-z_]*\}', re.I)
# Aussi matcher les segments numériques pure (/{123}/) après normalisation
_NUMERIC_PATH_RE = re.compile(r'/\{[a-z_]+\}', re.I)


class HttpSemanticsInference:
    """Inférence depuis la sémantique verbe HTTP × structure de path."""

    def provider_id(self) -> str:
        return "builtin.http_semantics"

    def infer(self, model: ApplicationModelData) -> list[SecurityProperty]:
        props: list[SecurityProperty] = []
        seen: set[tuple[str, str, str]] = set()

        for ep in model.endpoints:
            has_id_param = bool(
                _ID_PATH_RE.search(ep.path)
                or _NUMERIC_PATH_RE.search(ep.path)
                or any(
                    p.affects_object or p.type_inferred in ("integer", "uuid")
                    for p in model.parameters
                    if p.id in ep.parameters
                )
            )

            for method in ep.methods:
                if method.upper() not in _VERB_RISK:
                    continue

                prop_type, base_confidence = _VERB_RISK[method.upper()]

                # Boost si l'endpoint opère sur une ressource individuelle ({id})
                confidence = base_confidence + (0.08 if has_id_param else 0.0)
                confidence = min(0.93, confidence)

                # Déduplier par (path, method, property_type)
                key = (ep.path, method.upper(), prop_type.value)
                if key in seen:
                    continue
                seen.add(key)

                verb_desc = {
                    "DELETE": "destruction d'un objet appartenant à un autre utilisateur",
                    "PUT":    "remplacement total d'un objet (mass assignment)",
                    "PATCH":  "mise à jour partielle d'un objet (mass assignment)",
                    "POST":   "création avec mass assignment de champs privilégiés",
                }.get(method.upper(), "")

                props.append(SecurityProperty(
                    id=generate_id("PROP"),
                    type=prop_type,
                    formal_statement=(
                        f"HTTP {method.upper()} '{ep.path}' : {verb_desc}"
                    ),
                    model_nodes=[ep.id],
                    inference_confidence=confidence,
                    source_observations=[],
                ))

        return props
