# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
PayloadOptimizer — V4 Sprint 4.

Thompson Sampling bandit contextuel sur (endpoint_fingerprint, mutation_type).

Apprend quelles mutations réussissent sur quels types d'endpoints en accumulant
des récompenses au fil des sessions.

Différence avec HypothesisBandit :
  - HypothesisBandit : bras = (property_type, mutation_type), sans contexte endpoint
  - PayloadOptimizer : bras = (fingerprint, mutation_type), fingerprint encode le profil endpoint

Fingerprint = "{method}:{has_auth}:{has_path_params}:{content_type_bucket}"
  method              : GET | POST | PUT | DELETE | PATCH | OTHER
  has_auth            : 0 | 1  (présence header Authorization ou Cookie)
  has_path_params     : 0 | 1  (segment numérique/UUID ou {param} dans le chemin)
  content_type_bucket : json | form | none

→ 6 × 2 × 2 × 3 = 72 fingerprints uniques max (tractable).

Cycle de vie :
  1. Startup          : chargement des stats inter-sessions depuis KB
  2. Avant expériences: sort_hypotheses() réordonne les hypothèses PENDING
  3. Après verdict    : update() appelé par engine.py sur FINDING_CONFIRMED / REFUTED / AMBIGUOUS
  4. Fin de session   : save stats → KB, RL_TRANSITION émis par engine.py à chaque update
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urlparse

log = logging.getLogger(__name__)

_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_KNOWN_METHODS: frozenset[str] = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH"})

_REWARDS: dict[str, float] = {
    "CONFIRMED": 1.0,
    "REFUTED": 0.0,
    "INSUFFICIENT_DATA": 0.3,
    "AMBIGUOUS": 0.3,
}

_FALLBACK_FINGERPRINT = "UNKNOWN:0:0:none"


@dataclass
class ArmState:
    alpha: float = 1.0  # prior uniforme : Beta(1,1) = uniforme sur [0,1]
    beta: float = 1.0
    pulls: int = 0

    def update(self, reward: float) -> None:
        """Mise à jour bayésienne : reward ∈ [0, 1]."""
        self.alpha += reward
        self.beta += 1.0 - reward
        self.pulls += 1

    def sample(self) -> float:
        """Tire un échantillon Thompson depuis Beta(alpha, beta)."""
        import random
        return random.betavariate(self.alpha, self.beta)

    @property
    def estimated_rate(self) -> float:
        return self.alpha / (self.alpha + self.beta)


class PayloadOptimizer:
    """
    Thompson Sampling bandit contextuel sur (endpoint_fingerprint, mutation_type).

    Dégradation silencieuse : si aucune stat n'est chargée, le prior uniforme
    Beta(1,1) est utilisé — comportement identique à l'absence de l'optimizer.

    Sprint 7 : cluster map optionnel (EndpointClusterer) pour fingerprints enrichis.
    Quand le cluster map est défini, le fingerprint devient "C{id}:{base_fp}",
    augmentant la granularité de l'apprentissage bandit.
    """

    def __init__(self) -> None:
        self._arms: dict[tuple[str, str], ArmState] = {}
        self._cluster_map: dict[str, int] = {}  # path → cluster_id

    # ── Fingerprint ───────────────────────────────────────────────────────────

    @staticmethod
    def fingerprint_from_request(request: object) -> str:
        """Fingerprint compact depuis une NormalizedRequest."""
        method = (getattr(request, "method", None) or "GET").upper()[:6]
        method_bucket = method if method in _KNOWN_METHODS else "OTHER"

        headers: dict = dict(getattr(request, "headers", None) or {})
        header_keys_lower = {k.lower() for k in headers}
        has_auth = int(
            "authorization" in header_keys_lower or "cookie" in header_keys_lower
        )

        url = getattr(request, "url", None) or ""
        path_parts = [p for p in urlparse(url).path.split("/") if p]
        has_path_params = int(
            any(_NUMERIC.match(p) or _UUID.match(p) for p in path_parts)
        )

        ct_raw = (headers.get("content-type") or headers.get("Content-Type") or "").lower()
        ct_bucket = "json" if "json" in ct_raw else ("form" if "form" in ct_raw else "none")

        return f"{method_bucket}:{has_auth}:{has_path_params}:{ct_bucket}"

    @staticmethod
    def fingerprint_from_endpoint(endpoint: object) -> str:
        """Fingerprint depuis un EndpointNode (sans requête concrète)."""
        methods = getattr(endpoint, "methods", None) or []
        method = (methods[0].upper() if methods else "GET")
        method_bucket = method if method in _KNOWN_METHODS else "OTHER"

        has_auth = int(getattr(endpoint, "auth_required", False))

        path = getattr(endpoint, "path", "") or ""
        path_parts = [p for p in path.split("/") if p]
        has_path_params = int(
            any(
                _NUMERIC.match(p)
                or _UUID.match(p)
                or (p.startswith("{") and p.endswith("}"))
                for p in path_parts
            )
        )

        ct_raw = (getattr(endpoint, "response_content_type", "") or "").lower()
        ct_bucket = "json" if "json" in ct_raw else ("form" if "form" in ct_raw else "none")

        return f"{method_bucket}:{has_auth}:{has_path_params}:{ct_bucket}"

    @staticmethod
    def fingerprint_from_url(url: str, auth_required: bool = False) -> str:
        """Fingerprint minimal depuis une URL seule (fallback pour les verdicts post-hoc)."""
        path_parts = [p for p in urlparse(url).path.split("/") if p]
        has_path_params = int(
            any(_NUMERIC.match(p) or _UUID.match(p) for p in path_parts)
        )
        return f"GET:{int(auth_required)}:{has_path_params}:none"

    # ── Cluster map (Sprint 7) ────────────────────────────────────────────────

    def set_cluster_map(self, cluster_map: dict[str, int]) -> None:
        """Injecte le path→cluster_id map depuis EndpointClusterer."""
        self._cluster_map = dict(cluster_map)
        log.info("payload_optimizer.cluster_map_set n_paths=%d", len(self._cluster_map))

    def _cluster_fp(self, ep_path: str, base_fp: str) -> str:
        """Retourne le fingerprint enrichi si ep_path est dans le cluster map."""
        cid = self._cluster_map.get(ep_path)
        return f"C{cid}:{base_fp}" if cid is not None else base_fp

    # ── Bandit API ────────────────────────────────────────────────────────────

    def _arm(self, fingerprint: str, mutation_type: str) -> ArmState:
        key = (fingerprint, mutation_type)
        if key not in self._arms:
            self._arms[key] = ArmState()
        return self._arms[key]

    def update(
        self,
        fingerprint: str,
        mutation_type: str,
        verdict: str,
        ep_path: str = "",
    ) -> None:
        """
        Met à jour le bras après un verdict oracle.

        Si ep_path est fourni et dans le cluster map, met aussi à jour le bras
        cluster-augmenté pour une généralisation plus rapide.
        """
        reward = _REWARDS.get(verdict, 0.0)
        self._arm(fingerprint, mutation_type).update(reward)
        if ep_path:
            cluster_fp = self._cluster_fp(ep_path, fingerprint)
            if cluster_fp != fingerprint:
                self._arm(cluster_fp, mutation_type).update(reward)
        log.debug(
            "payload_optimizer.update fp=%s mt=%s verdict=%s reward=%.1f",
            fingerprint, mutation_type, verdict, reward,
        )

    def suggest_order(self, fingerprint: str, mutation_types: list[str]) -> list[str]:
        """Retourne les mutation_types réordonnés par Thompson Sampling."""
        return sorted(
            mutation_types,
            key=lambda mt: -self._arm(fingerprint, mt).sample(),
        )

    def sort_hypotheses(self, hypotheses: list, model_snapshot: object) -> list:
        """
        Réordonne les hypothèses PENDING par score PayloadOptimizer.

        Complémentaire au HypothesisBandit : celui-ci trie par (property_type, mutation_type)
        sans contexte endpoint ; PayloadOptimizer ajoute la dimension du profil d'endpoint.
        """
        if not hypotheses:
            return hypotheses

        ep_index: dict[str, object] = {}
        if model_snapshot is not None:
            for ep in (getattr(model_snapshot, "endpoints", None) or []):
                ep_index[getattr(ep, "path", "")] = ep

        def _score(hyp: object) -> float:
            ep_path = _extract_hyp_endpoint(hyp)
            ep = ep_index.get(ep_path)
            fp = (
                self.fingerprint_from_endpoint(ep)
                if ep is not None
                else _FALLBACK_FINGERPRINT
            )
            fp = self._cluster_fp(ep_path, fp)  # enrichi si cluster map défini
            return self._arm(fp, _hyp_mutation(hyp)).sample()

        return sorted(hypotheses, key=_score, reverse=True)

    # ── Persistence ───────────────────────────────────────────────────────────

    def to_serializable(self) -> list[dict]:
        """Sérialise les stats des bras pour la KB."""
        return [
            {
                "fingerprint": fp,
                "mutation_type": mt,
                "alpha": round(arm.alpha, 6),
                "beta": round(arm.beta, 6),
                "pulls": arm.pulls,
            }
            for (fp, mt), arm in sorted(
                self._arms.items(),
                key=lambda x: -x[1].estimated_rate,
            )
        ]

    def load_serializable(self, stats: list[dict]) -> None:
        """Restaure les stats depuis la KB."""
        loaded = 0
        for s in stats:
            fp = s.get("fingerprint", "")
            mt = s.get("mutation_type", "")
            if fp and mt:
                self._arms[(fp, mt)] = ArmState(
                    alpha=float(s.get("alpha", 1.0)),
                    beta=float(s.get("beta", 1.0)),
                    pulls=int(s.get("pulls", 0)),
                )
                loaded += 1
        if loaded:
            log.info("payload_optimizer.loaded arms=%d", loaded)

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> list[dict]:
        """Stats des bras triées par taux estimé descendant."""
        return [
            {
                "fingerprint": fp,
                "mutation_type": mt,
                "alpha": round(arm.alpha, 3),
                "beta": round(arm.beta, 3),
                "pulls": arm.pulls,
                "estimated_rate": round(arm.estimated_rate, 3),
            }
            for (fp, mt), arm in sorted(
                self._arms.items(),
                key=lambda x: -x[1].estimated_rate,
            )
        ]

    @property
    def total_pulls(self) -> int:
        return sum(arm.pulls for arm in self._arms.values())

    @property
    def n_arms(self) -> int:
        return len(self._arms)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _extract_hyp_endpoint(hyp: object) -> str:
    """Extrait le chemin d'endpoint d'une Hypothesis."""
    for exp in (getattr(hyp, "required_experiments", None) or []):
        params: dict = getattr(exp, "mutation_params", {}) or {}
        ep = (
            params.get("endpoint_path", "")
            or params.get("target_endpoint", "")
            or params.get("authenticated_endpoint", "")
        )
        if ep:
            return ep
    return ""


def _hyp_mutation(hyp: object) -> str:
    """Extrait le mutation_type d'une Hypothesis."""
    exps = getattr(hyp, "required_experiments", None) or []
    return getattr(exps[0], "mutation_type", "unknown") if exps else "unknown"
