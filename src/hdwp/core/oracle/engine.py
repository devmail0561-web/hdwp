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
    CROSSROLE_DIFF_CONFIRMED,
    DIFF_COMPUTED,
    EXPERIMENT_RESULT,
    FINDING_CONFIRMED,
    FINDING_REFUTED,
    HYPOTHESIS_AMBIGUOUS,
    HYPOTHESIS_EXPERIMENTS_READY,
    HYPOTHESIS_STATUS_CHANGED,
    INVARIANT_VIOLATED,
    ML_ORACLE_VERDICT,
    PAYLOAD_ADAPTED,
    TEMPORAL_ANOMALY_DETECTED,
    HDWPEvent,
)
from hdwp.core.model.schemas import (
    ConfidenceScore,
    ExperimentResult,
    Finding,
    FindingExplanation,
    generate_id,
)
from hdwp.core.oracle.confidence import (
    CONFIRMED_THRESHOLD,
    ConfidenceModelV2,
    compute_behavioral_specificity,
    compute_confidence,
    compute_observation_quality,
    extract_v2_weights_from_tuning,
)
from hdwp.core.oracle.semantic_diff import compute_semantic_diff
from hdwp.core.oracle.violation_oracle import (
    ViolationAssessment,
    ViolationVerdict,
    assess_violation,
)

if TYPE_CHECKING:
    from hdwp.core.llm.layer import LLMLayerProtocol
    from hdwp.core.ml.models.oracle_model import OracleModel
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
        oracle_ml_model: OracleModel | None = None,
    ) -> None:
        self._bus = bus
        self._repo = repository
        self._llm_layer = llm_layer
        self._model_accessor = model_accessor  # Callable[[], ApplicationModel] | None
        self._tuning = tuning  # TuningConfig | None — None = use module defaults
        self._results: dict[str, list[ExperimentResult]] = {}
        self._oracle_ml = oracle_ml_model  # OracleModel Phase 1 — None si non entraîné

        self.invariant_store: Any = None  # injecté par l'engine après création

        # V4 — ConfidenceModelV2 (10D logistic) et collecte des signaux V3
        # Phase 0: lire V2 weights depuis TuningConfig si fourni
        v2_weights, v2_bias = extract_v2_weights_from_tuning(tuning)
        self._confidence_v2 = ConfidenceModelV2(weights=v2_weights, bias=v2_bias)
        self._temporal_signals: dict[str, float] = {}    # hyp_id → signal [0,1]
        self._crossrole_signals: dict[str, float] = {}   # normalized path → signal [0,1]
        self._invariant_signals: dict[str, float] = {}   # normalized path → 0.0|1.0
        self._waf_bypass_attempted: set[str] = set()     # hyp_ids ayant déclenché un WAF

        bus.on(EXPERIMENT_RESULT, self._on_experiment_result)
        bus.on(HYPOTHESIS_EXPERIMENTS_READY, self._on_experiments_ready)
        bus.on(TEMPORAL_ANOMALY_DETECTED, self._on_temporal_anomaly)
        bus.on(CROSSROLE_DIFF_CONFIRMED, self._on_crossrole_diff)
        bus.on(INVARIANT_VIOLATED, self._on_invariant_violated)
        bus.on(PAYLOAD_ADAPTED, self._on_payload_adapted)

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

    # ── V4 : collecte des signaux V3 pour ConfidenceModelV2 ──────────────────

    async def _on_temporal_anomaly(self, event: HDWPEvent) -> None:
        data = event.payload
        if not isinstance(data, dict):
            return
        hyp_id = data.get("hypothesis_id", "")
        escalation = int(data.get("escalation_level", 0))
        signal = min((escalation + 1) / 3.0, 1.0)  # 0→0.33, 1→0.67, 2→1.0
        if hyp_id:
            self._temporal_signals[hyp_id] = max(
                self._temporal_signals.get(hyp_id, 0.0), signal
            )

    async def _on_crossrole_diff(self, event: HDWPEvent) -> None:
        data = event.payload
        if not isinstance(data, dict):
            return
        url = data.get("endpoint_path", "")
        conf = float(data.get("confidence", 0.0))
        if url:
            ep = _extract_endpoint(url)
            self._crossrole_signals[ep] = max(
                self._crossrole_signals.get(ep, 0.0), conf
            )

    async def _on_invariant_violated(self, event: HDWPEvent) -> None:
        data = event.payload
        if not isinstance(data, dict):
            return
        raw = data.get("endpoint_path", "")
        if raw:
            ep = _extract_endpoint(raw)
            self._invariant_signals[ep] = 1.0

    async def _on_payload_adapted(self, event: HDWPEvent) -> None:
        data = event.payload
        if not isinstance(data, dict):
            return
        hyp_id = data.get("hypothesis_id", "")
        # Clé "endpoint" (pas "endpoint_path") — vérifié dans adaptive_payload.py
        adaptation = data.get("adaptation", "")
        if hyp_id and adaptation == "waf_bypass":
            self._waf_bypass_attempted.add(hyp_id)

    @property
    def oracle_ml_model(self) -> Any:
        """Expose l'OracleModel pour la retraining loop de l'engine."""
        return self._oracle_ml

    def update_v2_weights(self, weights: dict[str, float], bias: float | None = None) -> None:
        """Injecte les poids appris par FeedbackLoop dans ConfidenceModelV2."""
        self._confidence_v2.update_weights(weights)
        if bias is not None:
            self._confidence_v2.bias = bias
        log.debug("oracle.v2_weights_updated from=feedback_loop")

    @property
    def oracle_results(self) -> dict[str, list[ExperimentResult]]:
        """Vue en lecture seule des résultats accumulés, pour la collecte ML."""
        return dict(self._results)

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

        # Trouver l'index de la première mutation CONFIRMED (fallback sur 0).
        # Corrige le bug : assessments[0] peut être REFUTED même si une mutation
        # ultérieure est CONFIRMED — ne pas utiliser le premier aveuglément.
        _confirmed_idx = next(
            (i for i, a in enumerate(assessments) if a.verdict == ViolationVerdict.CONFIRMED),
            0,
        )
        primary_verdict = assessments[_confirmed_idx].verdict
        _all_ambiguous = all(a.verdict == ViolationVerdict.AMBIGUOUS for a in assessments)

        if replays and not _all_ambiguous:
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
            # Pas de replay, ou toutes les mutations sont AMBIGUOUS : confiance minimale.
            # Dans le cas all_ambiguous, on ne peut pas mesurer la reproductibilité
            # par rapport à un verdict CONFIRMED/REFUTED — on utilise le fallback.
            reproducibility = 0.3

        obs_quality = compute_observation_quality(max(1, len(all_results)))
        behavioral_spec = compute_behavioral_specificity(
            mutation_type,
            diffs[_confirmed_idx],
            mutations[_confirmed_idx],
            assessments[_confirmed_idx],
        )
        # n_experiments_done / n_required :
        #   n_required = max(len(mutations), 1) — coverage atteint 1.0 dès que toutes
        #   les mutations sont faites ; les replays supplémentaires sont comptabilisés mais
        #   cappés à n_expected pour ne pas gonfler le score au-delà de 1.0.
        #   Si 1 mutation, 0 replays → coverage = 1/1 = 1.0
        #   Si 1 mutation, 1 replay  → coverage = min(2,1)/1 = 1.0 (cappé)
        #   Si 3 mutations, 0 replays → coverage = 3/3 = 1.0
        n_expected = max(len(mutations), 1)
        # Coverage = mutations réellement exécutées / mutations planifiées.
        # Les replays (re-jeu d'un winning request) ne comptent pas — ils confirment
        # une vuln déjà détectée plutôt que d'explorer de nouveaux vecteurs.
        n_done_capped = min(len(mutations), n_expected)
        tuning_weights = _tuning_weights(self._tuning)
        score = compute_confidence(
            assessment=assessments[_confirmed_idx],
            reproducibility=reproducibility,
            observation_quality=obs_quality,
            behavioral_specificity=behavioral_spec,
            n_experiments_done=n_done_capped,
            n_experiments_required=n_expected,
            weights=tuning_weights,
        )

        all_refuted = all(a.verdict == ViolationVerdict.REFUTED for a in assessments)
        any_confirmed = any(a.verdict == ViolationVerdict.CONFIRMED for a in assessments)

        # ── V4 : boost ConfidenceModelV2 avec les signaux V3 ─────────────────
        endpoint_path = _extract_endpoint(baseline.request_sent.url)
        temporal_sig = self._temporal_signals.get(hyp_id, 0.0)
        crossrole_sig = self._crossrole_signals.get(endpoint_path, 0.0)
        invariant_sig = self._invariant_signals.get(endpoint_path, 0.0)
        waf_bypass_sig = (
            1.0 if hyp_id in self._waf_bypass_attempted and any_confirmed else 0.0
        )
        causal_depth_sig = min(len(replays) / 3.0, 1.0)

        v2_overall = self._confidence_v2.compute_v2(
            v1_score=score,
            temporal_signal=temporal_sig,
            crossrole_signal=crossrole_sig,
            invariant_violated=invariant_sig,
            waf_bypass_success=waf_bypass_sig,
            causal_depth=causal_depth_sig,
        )
        v1_overall = score.overall
        if v2_overall > score.overall:
            log.debug(
                "oracle.v2_confidence_boost",
                hypothesis_id=hyp_id,
                v1=round(score.overall, 4),
                v2=round(v2_overall, 4),
            )
            score = score.model_copy(update={"overall": v2_overall, "v2_boost": v2_overall - v1_overall})

        await self._bus.emit(
            ML_ORACLE_VERDICT,
            {
                "hypothesis_id": hyp_id,
                "mutation_type": mutation_type,
                "v1_overall": round(v1_overall, 4),
                "v2_overall": round(v2_overall, 4),
                "signals": {
                    "temporal": temporal_sig,
                    "crossrole": crossrole_sig,
                    "invariant": invariant_sig,
                    "waf_bypass": waf_bypass_sig,
                    "causal_depth": causal_depth_sig,
                },
            },
            source="semantic_oracle",
        )
        # Sprint 8 fix : vérifier les violations d'invariants sur la réponse mutation
        if self.invariant_store is not None and mutations and any_confirmed:
            try:
                mut_resp = mutations[_confirmed_idx].response_received
                if mut_resp is not None:
                    await self.invariant_store.check_response_violations(
                        endpoint_path=endpoint_path,
                        response_body=mut_resp.body,
                        experiment_id=mutations[_confirmed_idx].id,
                    )
            except Exception:
                pass

        # Éviction des signaux par hypothesis_id (ephémères — un seul consommateur par hyp).
        # Les signaux endpoint-path (crossrole, invariant) ne sont PAS évincés ici :
        # plusieurs hypothèses peuvent partager le même endpoint et toutes doivent
        # bénéficier du signal (ex : BOLA + SQLi + JWT sur /api/users/{id}).
        self._temporal_signals.pop(hyp_id, None)
        self._waf_bypass_attempted.discard(hyp_id)
        # ─────────────────────────────────────────────────────────────────────

        # ── V4 Phase 1 : OracleModel (A/B avec V2) ───────────────────────────
        # Boost applicable si au moins une mutation est CONFIRMED.
        # On utilise diffs[_confirmed_idx] (la mutation confirmée), pas [0].
        if self._oracle_ml is not None and self._oracle_ml.is_trained and diffs and any_confirmed:
            try:
                from hdwp.core.ml.embedders.diff_embedder import DiffEmbedder
                ml_emb = DiffEmbedder().embed(
                    baseline.response_received,
                    mutations[_confirmed_idx].response_received,
                    diffs[_confirmed_idx] if diffs else None,
                )
                ml_pred = self._oracle_ml.predict(ml_emb)
                ml_confirmed = ml_pred.get("confirmed", 0.0)
                if ml_confirmed > score.overall:
                    log.debug(
                        "oracle.ml_boost",
                        hypothesis_id=hyp_id,
                        v2=round(score.overall, 4),
                        ml=round(ml_confirmed, 4),
                    )
                    score = score.model_copy(update={"overall": ml_confirmed, "ml_boost": ml_confirmed - score.overall})
            except Exception as _ml_exc:  # noqa: BLE001
                log.debug("oracle.ml_predict_failed", error=str(_ml_exc))
        # ─────────────────────────────────────────────────────────────────────

        confirmed_threshold = (
            self._tuning.confirmed_threshold if self._tuning is not None else CONFIRMED_THRESHOLD
        )
        severity_high = getattr(self._tuning, "severity_high_threshold", 0.90) if self._tuning else 0.90
        severity_medium = getattr(self._tuning, "severity_medium_threshold", 0.80) if self._tuning else 0.80
        if score.overall >= confirmed_threshold and any_confirmed:
            # Extraire l'ErrorIntel depuis la mutation qui a déclenché le verdict
            if mutations:
                try:
                    from hdwp.core.bus.events import TECH_STACK_UPDATED
                    from hdwp.core.oracle.injection_oracle import try_extract_error_intel
                    intel = try_extract_error_intel(mutations[_confirmed_idx])
                    if intel is not None:
                        for tag in getattr(intel, "tech_tags", []):
                            await self._bus.emit(
                                TECH_STACK_UPDATED, {"tag": tag}, source="error_intel"
                            )
                except Exception:
                    pass
            _v3_signals = {
                "oracle_strength": score.oracle_strength,
                "reproducibility": score.reproducibility,
                "observation_quality": score.observation_quality,
                "behavioral_specificity": score.behavioral_specificity,
                "experiment_coverage": score.experiment_coverage,
                "temporal_signal": temporal_sig,
                "crossrole_signal": crossrole_sig,
                "invariant_violated": invariant_sig,
                "waf_bypass_success": waf_bypass_sig,
                "causal_depth": causal_depth_sig,
            }
            finding = _build_finding(
                hyp_id, score, assessments[_confirmed_idx], diffs, all_results, baseline,
                severity_high=severity_high, severity_medium=severity_medium,
                winning_experiment=mutations[_confirmed_idx] if mutations else None,
                v3_signals=_v3_signals,
                confidence_v2=self._confidence_v2,
                v1_overall=v1_overall,
                v2_overall=v2_overall,
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
            # Sprint 8 : FeedbackLoop — features 10D + verdict pour SGD
            try:
                from hdwp.core.bus.events import ML_FEEDBACK as _ML_FB
                await self._bus.emit(_ML_FB, {
                    "hypothesis_id": hyp_id,
                    "features": {
                        "oracle_strength": score.oracle_strength,
                        "reproducibility": score.reproducibility,
                        "observation_quality": score.observation_quality,
                        "behavioral_specificity": score.behavioral_specificity,
                        "experiment_coverage": score.experiment_coverage,
                        "temporal_signal": temporal_sig,
                        "crossrole_signal": crossrole_sig,
                        "invariant_violated": invariant_sig,
                        "waf_bypass_success": waf_bypass_sig,
                        "causal_depth": causal_depth_sig,
                    },
                    "verdict": "CONFIRMED",
                }, source="semantic_oracle")
            except Exception:
                pass

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
            # Sprint 8 : FeedbackLoop — features 10D + verdict REFUTED
            try:
                from hdwp.core.bus.events import ML_FEEDBACK as _ML_FB
                await self._bus.emit(_ML_FB, {
                    "hypothesis_id": hyp_id,
                    "features": {
                        "oracle_strength": score.oracle_strength,
                        "reproducibility": score.reproducibility,
                        "observation_quality": score.observation_quality,
                        "behavioral_specificity": score.behavioral_specificity,
                        "experiment_coverage": score.experiment_coverage,
                        "temporal_signal": temporal_sig,
                        "crossrole_signal": crossrole_sig,
                        "invariant_violated": invariant_sig,
                        "waf_bypass_success": waf_bypass_sig,
                        "causal_depth": causal_depth_sig,
                    },
                    "verdict": "REFUTED",
                }, source="semantic_oracle")
            except Exception:
                pass

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
                        n_experiments_done=n_done_capped,
                        n_experiments_required=n_expected,
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
                        "endpoint_path": endpoint_path,
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
    v3_signals: dict[str, float] | None = None,
    confidence_v2: ConfidenceModelV2 | None = None,
    v1_overall: float = 0.0,
    v2_overall: float = 0.0,
) -> Finding:
    mutation_type = baseline.experiment_spec.mutation_type
    from hdwp.core.mutation_registry import owasp_cwe, remediation

    winning = winning_experiment or baseline
    owasp, cwe = owasp_cwe(mutation_type)

    explanation = None
    if v3_signals is not None and confidence_v2 is not None:
        top = confidence_v2.explain(v3_signals)
        active = [c for c in top if abs(c.contribution) > 0.01]
        if active:
            parts = [f"{c.label} ({c.contribution:+.2f})" for c in active[:3]]
            rationale = "Principaux signaux : " + ", ".join(parts)
        else:
            rationale = "Aucun signal V3 significatif — confiance basée sur le modèle V1"
        explanation = FindingExplanation(
            v1_score=round(v1_overall, 4),
            v2_score=round(v2_overall, 4),
            ml_score=round(score.ml_boost + v2_overall, 4) if score.ml_boost > 0 else 0.0,
            signals=v3_signals,
            top_contributors=active[:5],
            verdict_rationale=rationale,
        )

    return Finding(
        id=generate_id("FIND"),
        hypothesis_id=hyp_id,
        property_id=baseline.experiment_spec.mutation_params.get("property_id", ""),
        status=status,  # type: ignore[arg-type]
        confidence=score.overall,
        confidence_breakdown=score,
        explanation=explanation,
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
