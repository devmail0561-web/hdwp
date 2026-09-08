# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.model.schemas import EndpointNode, ParameterNode

_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
_PARAM_TYPES = ["integer", "string", "uuid", "boolean", "object", "array"]
_PARAM_LOCS = ["query", "body", "path", "header", "cookie"]


class EndpointEmbedder:
    """
    Encode un EndpointNode en vecteur de features de dimension fixe 30.

    Layout :
      [0:6]   method one-hot (GET / POST / PUT / DELETE / PATCH / OPTIONS)
      [6]     profondeur de path normalisée (/ 6.0, clamped [0, 1])
      [7]     auth_required (bool)
      [8]     role count normalisé (len(roles_observed) / 10.0, clamped [0, 1])
      [9:15]  distribution des types de paramètres (6 types, somme=1 si params)
      [15:20] distribution des locations de paramètres (5 locs, somme=1 si params)
      [20]    behavioral_profile.mean normalisé (/ 1000.0, clamped [0, 1])
      [21]    behavioral_profile.std normalisé (/ 500.0, clamped [0, 1])
      [22]    ratio status 2xx dans status_by_role
      [23]    ratio status 4xx dans status_by_role
      [24]    ratio status 5xx dans status_by_role
      [25]    contains_privilege_field (bool)
      [26]    WAF détecté (bool)
      [27]    error_tech_signals count normalisé (/ 5.0, clamped [0, 1])
      [28]    is_graphql (bool)
      [29]    accepts_xml (bool)
    """

    DIM: int = 30

    def embed(
        self,
        endpoint: EndpointNode,
        params: list[ParameterNode] | None = None,
    ) -> list[float]:
        vec: list[float] = []

        # [0:6] method one-hot
        methods_upper = {m.upper() for m in (endpoint.methods or [])}
        vec += [1.0 if m in methods_upper else 0.0 for m in _METHODS]

        # [6] path depth
        path_depth = len([s for s in endpoint.path.split("/") if s])
        vec.append(min(path_depth / 6.0, 1.0))

        # [7] auth_required
        vec.append(1.0 if endpoint.auth_required else 0.0)

        # [8] role count
        vec.append(min(len(endpoint.roles_observed or []) / 10.0, 1.0))

        # [9:15] param type distribution
        if params:
            type_counts = {t: 0 for t in _PARAM_TYPES}
            for p in params:
                t = p.type_inferred or "string"
                if t in type_counts:
                    type_counts[t] += 1
            total = len(params)
            vec += [type_counts[t] / total for t in _PARAM_TYPES]
        else:
            vec += [0.0] * len(_PARAM_TYPES)

        # [15:20] param location distribution
        if params:
            loc_counts = {loc: 0 for loc in _PARAM_LOCS}
            for p in params:
                loc = p.location or "query"
                if loc in loc_counts:
                    loc_counts[loc] += 1
            total = len(params)
            vec += [loc_counts[loc] / total for loc in _PARAM_LOCS]
        else:
            vec += [0.0] * len(_PARAM_LOCS)

        # [20:22] behavioral profile
        bp = endpoint.behavioral_profile
        if bp is not None:
            vec.append(min(bp.mean / 1000.0, 1.0))
            vec.append(min(bp.std / 500.0, 1.0))
        else:
            vec += [0.0, 0.0]

        # [22:25] status_by_role distribution
        statuses = list((endpoint.status_by_role or {}).values())
        if statuses:
            n = len(statuses)
            vec.append(sum(1 for s in statuses if 200 <= s < 300) / n)
            vec.append(sum(1 for s in statuses if 400 <= s < 500) / n)
            vec.append(sum(1 for s in statuses if 500 <= s < 600) / n)
        else:
            vec += [0.0, 0.0, 0.0]

        # [25] contains_privilege_field
        vec.append(1.0 if getattr(endpoint, "contains_privilege_field", False) else 0.0)

        # [26] WAF detected
        vec.append(1.0 if endpoint.detected_waf else 0.0)

        # [27] error_tech_signals count
        signals = getattr(endpoint, "error_tech_signals", None) or []
        vec.append(min(len(signals) / 5.0, 1.0))

        # [28] is_graphql
        vec.append(1.0 if endpoint.is_graphql else 0.0)

        # [29] accepts_xml
        vec.append(1.0 if endpoint.accepts_xml else 0.0)

        assert len(vec) == self.DIM, f"EndpointEmbedder: dim={len(vec)} != {self.DIM}"
        return vec
