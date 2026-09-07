# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
SemanticOracle: orchestre diff sémantique, verdict de violation et calcul de confiance.

Souscrit à :
- experiment.result             → bufferise les résultats par hypothesis_id
- hypothesis.experiments_ready  → déclenche l'évaluation du lot complet

Publie :
- diff.computed             → SemanticDiff
- hypothesis.status_changed → {id, old_status, new_status}
- finding.confirmed         → Finding
- finding.refuted           → Finding
"""
from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import (
    DIFF_COMPUTED,
    EXPERIMENT_RESULT,
    FINDING_CONFIRMED,
    FINDING_REFUTED,
    HYPOTHESIS_AMBIGUOUS,
    HYPOTHESIS_EXPERIMENTS_READY,
    HYPOTHESIS_STATUS_CHANGED,
    HDWPEvent,
)
from hdwp.core.model.schemas import (
    ConfidenceScore,
    ExperimentResult,
    Finding,
    generate_id,
)
from hdwp.core.oracle.confidence import (
    CONFIRMED_THRESHOLD,
    compute_behavioral_specificity,
    compute_confidence,
    compute_observation_quality,
)
from hdwp.core.oracle.semantic_diff import compute_semantic_diff
from hdwp.core.oracle.violation_oracle import (
    ViolationAssessment,
    ViolationVerdict,
    assess_violation,
)

if TYPE_CHECKING:
    from hdwp.core.llm.layer import LLMLayerProtocol
    from hdwp.store.repository import Repository

log = structlog.get_logger()


class SemanticOracle:
    """
    Orchestre diff sémantique, verdict de violation et calcul de confiance.
    Abonnement aux événements experiment.result et hypothesis.experiments_ready.
    """

    def __init__(
        self,
        bus: AsyncEventBus,
        repository: Repository,
        llm_layer: LLMLayerProtocol | None = None,
        model_accessor: object = None,
        tuning: object = None,
    ) -> None:
        self._bus = bus
        self._repo = repository
        self._llm_layer = llm_layer
        self._model_accessor = model_accessor  # Callable[[], ApplicationModel] | None
        self._tuning = tuning  # TuningConfig | None — None = use module defaults
        self._results: dict[str, list[ExperimentResult]] = {}
        bus.on(EXPERIMENT_RESULT, self._on_experiment_result)
        bus.on(HYPOTHESIS_EXPERIMENTS_READY, self._on_experiments_ready)

    async def _on_experiment_result(self, event: HDWPEvent) -> None:
        data = event.payload
        result = ExperimentResult.model_validate(data) if isinstance(data, dict) else data
        self._results.setdefault(result.hypothesis_id, []).append(result)

    async def _on_experiments_ready(self, event: HDWPEvent) -> None:
        payload = event.payload
        if not isinstance(payload, dict):
            return
        await self._evaluate_hypothesis(
            hyp_id=payload["hypothesis_id"],
            baseline_id=payload["baseline_id"],
            experiment_ids=payload["experiment_ids"],
        )

    async def _evaluate_hypothesis(
        self,
        hyp_id: str,
        baseline_id: str,
        experiment_ids: list[str],
    ) -> None:
        all_results = self._results.get(hyp_id, [])

        baseline = next((r for r in all_results if r.id == baseline_id), None)
        if baseline is None:
            log.warning("oracle.baseline_not_found", hypothesis_id=hyp_id)
            return

        experiment_id_set = set(experiment_ids)
        mutations = [
            r for r in all_results
            if r.id in experiment_id_set and r.replayed_from is None
        ]
        replays = [
            r for r in all_results
            if r.id in experiment_id_set and r.replayed_from is not None
        ]

        mutation_type = baseline.experiment_spec.mutation_type
        assessments: list[ViolationAssessment] = []
        diffs = []

        for mut in mutations:
            # Calcul du Z-score comportemental si le modèle est disponible
            # (connecte le behavioral profiling de ApplicationModel à l'oracle)
            zscore: float | None = None
            if self._model_accessor is not None:
                try:
                    model = self._model_accessor()
                    if model is not None and hasattr(model, "get_response_zscore"):
                        from hdwp.core.model.url_utils import normalize_url_path
                        path_pat = normalize_url_path(baseline.request_sent.url)
                        zscore = model.get_response_zscore(path_pat, mut.response_received.body)
                except Exception:
                    pass

            diff = compute_semantic_diff(
                baseline.response_received,
                mut.response_received,
                baseline.id,
                mut.id,
                response_zscore=zscore,
            )
            diffs.append(diff)
            await self._bus.emit(DIFF_COMPUTED, diff.model_dump(), source="semantic_oracle")
            await self._repo.save_diff(diff)
            assessments.append(assess_violation(mutation_type, baseline, mut, diff))

        if not assessments:
            log.warning("oracle.no_assessments", hypothesis_id=hyp_id)
            return

        primary_verdict = assessments[0].verdict

        if replays:
            confirming = sum(
                1 for r in replays
                if _verdict_matches(
                    assess_violation(
                        mutation_type,
                        baseline,
                        r,
                        compute_semantic_diff(
                            baseline.response_received,
                            r.response_received,
                            baseline.id,
                            r.id,
                        ),
                    ).verdict,
                    primary_verdict,
                )
            )
            reproducibility = confirming / len(replays)
        else:
            reproducibility = 0.3  # pas de replay → confiance minimale, exige des preuves réelles

        obs_quality = compute_observation_quality(max(1, len(all_results)))
        behavioral_spec = compute_behavioral_specificity(
            mutation_type, diffs[0], mutations[0], assessments[0]
        )
        # n_experiments_done / n_required : compter mutations ET replays ensemble.
        # Ainsi : 1 mutation sans replay → coverage < 1.0 (preuve insuffisante)
        #          1 mutation + 1 replay → coverage = 1.0 (reproductibilité vérifiée)
        # Évite que experiment_coverage = n/n = 1.0 avec une seule expérience sans replay.
        all_experiments_count = len(mutations) + len(replays)
        tuning_weights = _tuning_weights(self._tuning)
        score = compute_confidence(
            assessment=assessments[0],
            reproducibility=reproducibility,
            observation_quality=obs_quality,
            behavioral_specificity=behavioral_spec,
            n_experiments_done=all_experiments_count,
            n_experiments_required=max(2, all_experiments_count),
            weights=tuning_weights,
        )

        all_refuted = all(a.verdict == ViolationVerdict.REFUTED for a in assessments)
        any_confirmed = any(a.verdict == ViolationVerdict.CONFIRMED for a in assessments)

        confirmed_threshold = (
            self._tuning.confirmed_threshold if self._tuning is not None else CONFIRMED_THRESHOLD
        )
        severity_high = getattr(self._tuning, "severity_high_threshold", 0.90) if self._tuning else 0.90
        severity_medium = getattr(self._tuning, "severity_medium_threshold", 0.80) if self._tuning else 0.80
        if score.overall >= confirmed_threshold and any_confirmed:
            # Extraire l'ErrorIntel depuis la mutation qui a déclenché le verdict
            if mutations:
                try:
                    from hdwp.core.oracle.injection_oracle import try_extract_error_intel
                    from hdwp.core.bus.events import TECH_STACK_UPDATED
                    intel = try_extract_error_intel(mutations[0])
                    if intel is not None:
                        for tag in getattr(intel, "tech_tags", []):
                            await self._bus.emit(
                                TECH_STACK_UPDATED, {"tag": tag}, source="error_intel"
                            )
                except Exception:
                    pass
            finding = _build_finding(
                hyp_id, score, assessments[0], diffs, all_results, baseline,
                severity_high=severity_high, severity_medium=severity_medium,
                winning_experiment=mutations[0] if mutations else None,
            )
            # Enrichir le conseil de remédiation via LLM si disponible
            if self._llm_layer is not None:
                try:
                    enhanced_hint = await self._llm_layer.generate_remediation_hint(finding)
                    finding = finding.model_copy(update={"remediation_hint": enhanced_hint})
                except Exception as exc:  # noqa: BLE001
                    log.warning("oracle.remediation_hint_failed", error=str(exc))
            await self._repo.save_finding(finding)
            await self._repo.update_hypothesis_status(hyp_id, "CONFIRMED", score.overall)
            await self._bus.emit(
                HYPOTHESIS_STATUS_CHANGED,
                {"id": hyp_id, "old_status": "PENDING", "new_status": "CONFIRMED"},
                source="semantic_oracle",
            )
            await self._bus.emit(FINDING_CONFIRMED, finding.model_dump(), source="semantic_oracle")
            log.info("oracle.finding_confirmed", hypothesis_id=hyp_id, confidence=score.overall)

        elif all_refuted:
            finding = _build_finding(
                hyp_id, score, assessments[0], diffs, all_results, baseline, status="REFUTED",
                severity_high=severity_high, severity_medium=severity_medium,
            )
            await self._repo.update_hypothesis_status(hyp_id, "REFUTED", score.overall)
            await self._bus.emit(
                HYPOTHESIS_STATUS_CHANGED,
                {"id": hyp_id, "old_status": "PENDING", "new_status": "REFUTED"},
                source="semantic_oracle",
            )
            await self._bus.emit(FINDING_REFUTED, finding.model_dump(), source="semantic_oracle")
            log.info("oracle.hypothesis_refuted", hypothesis_id=hyp_id)

        else:
            # Tenter la désambiguïsation LLM si disponible
            if self._llm_layer is not None and diffs and mutations:
                llm_assessment = await self._llm_layer.disambiguate_diff(
                    diff=diffs[0],
                    mutation_type=mutation_type,
                    baseline_body=baseline.response_received.body,
                    experiment_body=mutations[0].response_received.body,
                )
                if llm_assessment is not None:
                    llm_score = compute_confidence(
                        assessment=llm_assessment,
                        reproducibility=reproducibility,
                        observation_quality=obs_quality,
                        behavioral_specificity=compute_behavioral_specificity(
                            mutation_type, diffs[0], mutations[0], llm_assessment
                        ),
                        n_experiments_done=len(mutations),
                        n_experiments_required=max(1, len(mutations)),
                        weights=tuning_weights,
                    )
                    log.info(
                        "oracle.llm_disambiguation",
                        hypothesis_id=hyp_id,
                        verdict=llm_assessment.verdict.value,
                        confidence=llm_score.overall,
                    )
                    score = llm_score

            await self._repo.update_hypothesis_status(
                hyp_id, "INSUFFICIENT_DATA", score.overall
            )
            await self._bus.emit(
                HYPOTHESIS_STATUS_CHANGED,
                {"id": hyp_id, "old_status": "PENDING", "new_status": "INSUFFICIENT_DATA"},
                source="semantic_oracle",
            )
            # Signal dédié pour AmbiguityResolver — inclut le diff et la spec de la baseline
            if diffs:
                await self._bus.emit(
                    HYPOTHESIS_AMBIGUOUS,
                    {
                        "hypothesis_id": hyp_id,
                        "mutation_type": mutation_type,
                        "score": score.overall,
                        "diff": diffs[0].model_dump(),
                        "baseline_spec": baseline.experiment_spec.model_dump() if baseline else None,
                    },
                    source="semantic_oracle",
                )
            log.info(
                "oracle.insufficient_data",
                hypothesis_id=hyp_id,
                confidence=score.overall,
            )


# ── helpers ───────────────────────────────────────────────────────────────────

def _build_finding(
    hyp_id: str,
    score: ConfidenceScore,
    assessment: ViolationAssessment,
    diffs: list,
    all_results: list[ExperimentResult],
    baseline: ExperimentResult,
    status: str = "CONFIRMED",
    severity_high: float = 0.90,
    severity_medium: float = 0.80,
    winning_experiment: ExperimentResult | None = None,
) -> Finding:
    mutation_type = baseline.experiment_spec.mutation_type
    from hdwp.core.mutation_registry import owasp_cwe, remediation

    # winning_request doit être la requête mutée (avec le payload), pas la baseline propre.
    # Les règles de chaîne (ex: rule_sqli_exfil) l'inspectent pour trouver le payload SQL.
    winning = winning_experiment or baseline
    owasp, cwe = owasp_cwe(mutation_type)
    return Finding(
        id=generate_id("FIND"),
        hypothesis_id=hyp_id,
        property_id=baseline.experiment_spec.mutation_params.get("property_id", ""),
        status=status,  # type: ignore[arg-type]
        confidence=score.overall,
        confidence_breakdown=score,
        owasp_category=owasp,
        cwe_id=cwe,
        severity=_severity_from_score(score, severity_high, severity_medium),
        affected_endpoints=[_extract_endpoint(baseline.request_sent.url)],
        proof={
            "experiments": [r.id for r in all_results],
            "diffs": [d.id for d in diffs],
            "reproduction_steps": _build_repro_steps(baseline, assessment),
            "mutation_type": mutation_type,
            "winning_request": winning.request_sent.model_dump() if winning else None,
            "winning_response_sample": str(winning.response_received.body)[:2000] if winning and winning.response_received else None,
        },
        remediation_hint=remediation(mutation_type),
    )


def _severity_from_score(
    score: ConfidenceScore,
    high_threshold: float = 0.90,
    medium_threshold: float = 0.80,
) -> str:
    if score.overall >= high_threshold:
        return "HIGH"
    if score.overall >= medium_threshold:
        return "MEDIUM"
    return "LOW"


def _tuning_weights(tuning: object) -> dict[str, float] | None:
    """Extrait le dict de poids du TuningConfig, ou None pour utiliser les défauts."""
    if tuning is None:
        return None
    return {
        "oracle_strength": getattr(tuning, "weight_oracle_strength", 0.25),
        "reproducibility": getattr(tuning, "weight_reproducibility", 0.30),
        "observation_quality": getattr(tuning, "weight_observation_quality", 0.15),
        "behavioral_specificity": getattr(tuning, "weight_behavioral_specificity", 0.15),
        "experiment_coverage": getattr(tuning, "weight_experiment_coverage", 0.15),
    }


def _build_repro_steps(
    baseline: ExperimentResult, assessment: ViolationAssessment
) -> list[str]:
    return [
        f"1. Envoyer {baseline.request_sent.method} {baseline.request_sent.url}",
        "2. Avec les credentials de l'attaquant",
        f"3. Observer : {assessment.rationale}",
    ]


def _extract_endpoint(url: str) -> str:
    return urlparse(url).path


def _verdict_matches(v1: ViolationVerdict, v2: ViolationVerdict) -> bool:
    return v1 == v2
