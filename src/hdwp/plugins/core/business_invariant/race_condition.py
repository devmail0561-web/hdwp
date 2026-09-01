# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
RaceConditionPlugin: détecte les conditions de course sur des opérations critiques.

Cible : endpoints POST/PUT sur des chemins sémantiquement critiques
(paiement, réservation, transfert, coupon) — opérations non-idempotentes
susceptibles d'être exécutées deux fois si envoyées simultanément.
"""
from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
    PropertyType,
    SecurityProperty,
)
from hdwp.plugins.base import HDWPPlugin

_RACE_KEYWORDS = frozenset({
    "payment", "pay", "order", "transfer", "redeem",
    "coupon", "stock", "booking", "reserve", "checkout",
    "withdraw", "deposit", "vote",
})


class RaceConditionPlugin(HDWPPlugin):
    """Génère des hypothèses de race condition sur les endpoints critiques."""

    @property
    def id(self) -> str:
        return "core.business_invariant.race_condition"

    @property
    def name(self) -> str:
        return "Race Condition Detection"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "business_invariant"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A04:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-362"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        race_eps = self._race_endpoints(model)
        if not race_eps:
            return []
        return [SecurityProperty(
            type=PropertyType.CONCURRENCY,
            formal_statement=(
                f"concurrent(R1..Rn) on '{race_eps[0].path}' => invariant(state_final)"
            ),
            model_nodes=[ep.id for ep in race_eps[:2]],
            inference_confidence=0.5,
        )]

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        hyps: list[Hypothesis] = []
        for ep in self._race_endpoints(model)[:2]:
            method = "POST" if "POST" in ep.methods else ep.methods[0] if ep.methods else "POST"
            hyps.append(Hypothesis(
                source_plugin=self.id,
                property_id="",
                statement=f"L'endpoint '{ep.path}' est vulnérable à une condition de course",
                priority="HIGH",
                priority_rationale="Opération critique potentiellement non-atomique",
                required_experiments=[ExperimentSpec(
                    mutation_type="race_condition",
                    base_request=NormalizedRequest(method=method, url=""),
                    mutation_params={
                        "endpoint_path": ep.path,
                        "concurrency": 10,
                    },
                    description=f"Race condition : 10 requêtes simultanées sur {ep.path}",
                )],
            ))
        return hyps

    @staticmethod
    def _race_endpoints(model: ApplicationModelData) -> list:
        return [
            ep for ep in model.endpoints
            if any(kw in ep.path.lower() for kw in _RACE_KEYWORDS)
            and any(m in ep.methods for m in ("POST", "PUT"))
        ]
