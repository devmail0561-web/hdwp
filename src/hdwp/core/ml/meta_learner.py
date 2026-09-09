# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
MetaLearner — V4 Sprint 10.

Façade unifiée pour tous les composants ML du stack V4.

Problème résolu :
  Les 8 composants ML (OracleModel, VulnClassifier, PayloadOptimizer,
  ActiveLearner, SimilarityIndex, EndpointClusterer, FeedbackLoop,
  CrossSessionTransfer) étaient initialisés et sauvegardés dans ~350 lignes
  éparpillées dans engine.py, rendant :
    - engine.py difficile à lire/modifier
    - le stack ML impossible à tester en isolation
    - l'ajout de nouveaux composants ML coûteux

MetaLearner centralise le cycle de vie complet :
  1. load()         — init + chargement KB de tous les composants
  2. inject_feedback_into_oracle() — après création oracle
  3. wire()         — abonnements bus (PayloadOptimizer, FeedbackLoop)
  4. apply_boosts() — prédictions VulnClassifier + SimilarityIndex post-observation
  5. fit_clusterer() — fit EndpointClusterer post-observation
  6. sort_hypotheses() — tri ActiveLearner + PayloadOptimizer
  7. save_session() — collecte données + réentraînement + sauvegarde KB

Propriétés :
  - Chaque composant est optionnel (ImportError ou données insuffisantes → None).
  - Tous les composants ML sont accessibles via des propriétés typées.
  - Aucune dépendance sur engine.py (direction : engine → MetaLearner, jamais l'inverse).

ADR-ML-011 : MetaLearner est une façade sans logique métier propre.
  Chaque méthode délègue aux composants concernés, sans introduire
  de couplage entre eux. Les composants restent indépendants.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus
    from hdwp.core.knowledge.base import KnowledgeBase
    from hdwp.core.ml.models.active_learner import ActiveLearner
    from hdwp.core.ml.models.endpoint_clusterer import EndpointClusterer
    from hdwp.core.ml.models.feedback_loop import FeedbackLoop
    from hdwp.core.ml.models.oracle_model import OracleModel
    from hdwp.core.ml.models.payload_optimizer import PayloadOptimizer
    from hdwp.core.ml.models.similarity_index import SimilarityIndex
    from hdwp.core.ml.models.vuln_classifier import VulnClassifier
    from hdwp.core.model.schemas import ApplicationModelData, Finding
    from hdwp.core.oracle.engine import SemanticOracle

log = logging.getLogger(__name__)

# Même mapping que engine.py — maintenu ici pour l'end-of-session
_OWASP_TO_VULN: dict[str, str] = {
    "A01:2021": "bola",
    "A02:2021": "jwt",
    "A03:2021": "sqli",
    "A05:2021": "cors",
}
_MUTATION_TO_VULN: dict[str, str] = {
    "identity_swap": "bola",
    "object_ref_change": "bola",
    "privilege_escalation": "authz",
    "jwt_manipulation": "jwt",
    "origin_test": "cors",
    "field_injection": "sqli",
    "nosqli": "sqli",
    "path_traversal": "path_traversal",
    "ssrf": "ssrf",
    "http_smuggling": "http_smuggling",
}


def _owasp_to_vuln_class(owasp: str, mutation_type: str) -> str:
    return (
        _MUTATION_TO_VULN.get(mutation_type, "")
        or _OWASP_TO_VULN.get(owasp, "")
    )


class MetaLearner:
    """
    Façade unifiée pour le cycle de vie des composants ML V4.

    Instanciation via classmethod async :
        ml = await MetaLearner.load(kb, target_hash=..., target_type=...)
    """

    def __init__(self) -> None:
        self._oracle_model: OracleModel | None = None
        self._vuln_classifier: VulnClassifier | None = None
        self._payload_optimizer: PayloadOptimizer | None = None
        self._active_learner: ActiveLearner | None = None
        self._similarity_index: SimilarityIndex | None = None
        self._endpoint_clusterer: EndpointClusterer | None = None
        self._feedback_loop: FeedbackLoop | None = None
        # poids à injecter dans oracle après sa création
        self._fb_weights_to_inject: dict | None = None

    # ── Propriétés ────────────────────────────────────────────────────────────

    @property
    def oracle_model(self) -> OracleModel | None:
        return self._oracle_model

    @property
    def vuln_classifier(self) -> VulnClassifier | None:
        return self._vuln_classifier

    @property
    def payload_optimizer(self) -> PayloadOptimizer | None:
        return self._payload_optimizer

    @property
    def active_learner(self) -> ActiveLearner | None:
        return self._active_learner

    @property
    def similarity_index(self) -> SimilarityIndex | None:
        return self._similarity_index

    @property
    def endpoint_clusterer(self) -> EndpointClusterer | None:
        return self._endpoint_clusterer

    @property
    def feedback_loop(self) -> FeedbackLoop | None:
        return self._feedback_loop

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    async def load(
        cls,
        kb: KnowledgeBase,
        target_hash: str,
        target_type: str,
        tuning: "TuningConfig | None" = None,  # Phase 0: config externalization
    ) -> MetaLearner:
        """
        Initialise et charge tous les composants ML depuis la KB.

        Chaque composant est optionnel : un ImportError ou des données
        insuffisantes laisse le composant à None sans planter l'engine.
        """
        self = cls()
        await self._load_oracle_model()
        await self._load_vuln_classifier()
        await self._load_payload_optimizer(kb)
        await self._load_active_learner()
        await self._load_similarity_index(kb)
        await self._load_feedback_loop(kb, target_hash, target_type, tuning=tuning)
        await self._load_endpoint_clusterer(kb)
        return self

    async def _load_oracle_model(self) -> None:
        try:
            from hdwp.core.ml.models.oracle_model import OracleModel
            m = OracleModel()
            if m.load():
                self._oracle_model = m
        except ImportError:
            pass

    async def _load_vuln_classifier(self) -> None:
        try:
            from hdwp.core.ml.models.vuln_classifier import VulnClassifier
            m = VulnClassifier()
            if m.load():
                self._vuln_classifier = m
        except ImportError:
            pass

    async def _load_payload_optimizer(self, kb: KnowledgeBase) -> None:
        try:
            from hdwp.core.ml.models.payload_optimizer import PayloadOptimizer
            m = PayloadOptimizer()
            stats = await kb.get_payload_optimizer_stats()
            if stats:
                m.load_serializable(stats)
                log.info(
                    "meta_learner.payload_optimizer_loaded",
                    arms=m.n_arms, pulls=m.total_pulls,
                )
            self._payload_optimizer = m
        except ImportError:
            pass

    async def _load_active_learner(self) -> None:
        try:
            from hdwp.core.ml.models.active_learner import ActiveLearner
            self._active_learner = ActiveLearner()
        except ImportError:
            pass

    async def _load_similarity_index(self, kb: KnowledgeBase) -> None:
        try:
            from hdwp.core.ml.models.similarity_index import SimilarityIndex
            entries = await kb.get_finding_embeddings()
            if entries:
                m = SimilarityIndex()
                m.load(entries)
                self._similarity_index = m
                log.info("meta_learner.similarity_index_loaded", entries=m.n_entries)
        except ImportError:
            pass

    async def _load_feedback_loop(
        self, kb: KnowledgeBase, target_hash: str, target_type: str, tuning: "TuningConfig | None" = None
    ) -> None:
        try:
            from hdwp.core.ml.models.feedback_loop import FeedbackLoop

            fl = FeedbackLoop(tuning=tuning)  # Phase 0: init depuis TuningConfig
            # Priorité 1 : poids persistés pour ce target exact
            fb_data = await kb.get_feedback_weights_for_target(target_hash)
            if fb_data is None:
                # Priorité 2 : poids globaux 'current'
                fb_data = await kb.get_feedback_weights()
            if fb_data:
                fl.load_serializable(fb_data)
                self._fb_weights_to_inject = fb_data
                log.info("meta_learner.feedback_loop_loaded", n_updates=fl.n_updates)
            else:
                # Priorité 3 : CrossSessionTransfer
                try:
                    from hdwp.core.ml.models.cross_session_transfer import CrossSessionTransfer
                    snapshots = await kb.list_feedback_weights_snapshots()
                    if snapshots:
                        transferred = CrossSessionTransfer().select_and_blend(
                            snapshots=snapshots,
                            dest_target_hash=target_hash,
                            dest_target_type=target_type,
                        )
                        if transferred:
                            fl.load_serializable(transferred)
                            self._fb_weights_to_inject = transferred
                            log.info(
                                "meta_learner.cross_session_transfer_applied",
                                dest_target_type=target_type,
                                n_sources=len(snapshots),
                            )
                except ImportError:
                    pass
                except Exception as exc:
                    log.warning("meta_learner.cross_session_transfer_failed", error=str(exc))

            fl.apply_session_decay()
            self._feedback_loop = fl
        except ImportError:
            pass

    async def _load_endpoint_clusterer(self, kb: KnowledgeBase) -> None:
        try:
            from hdwp.core.ml.models.endpoint_clusterer import EndpointClusterer
            m = EndpointClusterer()
            data = await kb.get_cluster_centroids()
            if data:
                m.load_serializable(data)
                log.info("meta_learner.clusterer_loaded", k=m.k, n_samples=m.n_samples)
            self._endpoint_clusterer = m
        except ImportError:
            pass

    # ── Injection oracle ──────────────────────────────────────────────────────

    def inject_feedback_into_oracle(self, oracle: SemanticOracle) -> None:
        """Injecte les poids FeedbackLoop chargés dans l'oracle (appelé après création oracle)."""
        if self._feedback_loop is not None and self._fb_weights_to_inject is not None:
            try:
                oracle.update_v2_weights(
                    self._feedback_loop.current_weights(),
                    self._feedback_loop.current_bias(),
                )
            except Exception as exc:
                log.warning("meta_learner.feedback_inject_failed", error=str(exc))

    # ── Abonnements bus ───────────────────────────────────────────────────────

    def wire(self, bus: AsyncEventBus, oracle: SemanticOracle) -> None:
        """Abonne les composants ML aux events du bus."""
        self._wire_payload_optimizer(bus)
        self._wire_feedback_loop(bus, oracle)

    def _wire_payload_optimizer(self, bus: AsyncEventBus) -> None:
        opt = self._payload_optimizer
        if opt is None:
            return

        from hdwp.core.bus.events import (
            FINDING_CONFIRMED, FINDING_REFUTED, HYPOTHESIS_AMBIGUOUS, RL_TRANSITION,
        )

        async def _on_confirmed(event: Any) -> None:
            payload = event.payload
            if not isinstance(payload, dict):
                return
            endpoint = (payload.get("affected_endpoints") or [""])[0]
            mutation_type = (payload.get("proof") or {}).get("mutation_type", "unknown")
            fp = opt.fingerprint_from_url(endpoint)
            from urllib.parse import urlparse as _up
            ep_path = _up(endpoint).path if endpoint else ""
            opt.update(fp, mutation_type, "CONFIRMED", ep_path=ep_path)
            await bus.emit(
                RL_TRANSITION,
                {"fingerprint": fp, "mutation_type": mutation_type, "verdict": "CONFIRMED", "reward": 1.0},
                source="meta_learner",
            )

        async def _on_refuted(event: Any) -> None:
            payload = event.payload
            if not isinstance(payload, dict):
                return
            endpoint = (payload.get("affected_endpoints") or [""])[0]
            mutation_type = (payload.get("proof") or {}).get("mutation_type", "unknown")
            fp = opt.fingerprint_from_url(endpoint)
            from urllib.parse import urlparse as _up
            ep_path = _up(endpoint).path if endpoint else ""
            opt.update(fp, mutation_type, "REFUTED", ep_path=ep_path)
            await bus.emit(
                RL_TRANSITION,
                {"fingerprint": fp, "mutation_type": mutation_type, "verdict": "REFUTED", "reward": 0.0},
                source="meta_learner",
            )

        async def _on_ambiguous(event: Any) -> None:
            payload = event.payload
            if not isinstance(payload, dict):
                return
            mutation_type = payload.get("mutation_type", "unknown")
            endpoint = payload.get("endpoint_path", "")
            fp = opt.fingerprint_from_url(endpoint) if endpoint else "UNKNOWN:0:0:none"
            opt.update(fp, mutation_type, "INSUFFICIENT_DATA", ep_path=endpoint)
            await bus.emit(
                RL_TRANSITION,
                {"fingerprint": fp, "mutation_type": mutation_type, "verdict": "INSUFFICIENT_DATA", "reward": 0.3},
                source="meta_learner",
            )

        bus.on(FINDING_CONFIRMED, _on_confirmed)
        bus.on(FINDING_REFUTED, _on_refuted)
        bus.on(HYPOTHESIS_AMBIGUOUS, _on_ambiguous)

    def _wire_feedback_loop(self, bus: AsyncEventBus, oracle: SemanticOracle) -> None:
        fl = self._feedback_loop
        if fl is None:
            return

        from hdwp.core.bus.events import ML_FEEDBACK

        async def _on_ml_feedback(event: Any) -> None:
            payload = event.payload
            if not isinstance(payload, dict):
                return
            features = payload.get("features", {})
            verdict = payload.get("verdict", "")
            if not features or not verdict:
                return
            fl.observe(features, verdict)
            oracle.update_v2_weights(fl.current_weights(), fl.current_bias())

        bus.on(ML_FEEDBACK, _on_ml_feedback)

    # ── Post-observation ──────────────────────────────────────────────────────

    async def apply_boosts(
        self,
        bus: AsyncEventBus,
        snapshot: ApplicationModelData | None,
    ) -> dict[str, float]:
        """
        Calcule les boosts de type par VulnClassifier + SimilarityIndex.

        Retourne un dict {property_type → boost} à injecter dans le prioritizer.
        Émet ML_VULN_PREDICTED sur le bus pour chaque endpoint prédit.
        """
        type_boosts: dict[str, float] = {}

        if snapshot is None:
            return type_boosts

        try:
            from hdwp.core.ml.embedders.endpoint_embedder import EndpointEmbedder
            from hdwp.core.bus.events import ML_VULN_PREDICTED

            embedder = EndpointEmbedder()
            clf = self._vuln_classifier
            sim = self._similarity_index

            for ep in (snapshot.endpoints or []):
                emb = embedder.embed(ep)

                if clf is not None:
                    boosts = clf.property_type_boosts(emb)
                    for pt, proba in boosts.items():
                        type_boosts[pt] = max(type_boosts.get(pt, 0.0), proba)
                    if boosts:
                        await bus.emit(
                            ML_VULN_PREDICTED,
                            {"endpoint": ep.path, "predictions": boosts},
                            source="meta_learner",
                        )
                        if self._active_learner is not None:
                            self._active_learner.update_endpoint_entropy(ep.path, boosts)

                if sim is not None and sim.n_entries > 0:
                    sim_boosts = sim.property_type_boosts(emb)
                    for pt, score in sim_boosts.items():
                        type_boosts[pt] = max(type_boosts.get(pt, 0.0), score)

            if type_boosts:
                log.info("meta_learner.boosts_applied", boosts=type_boosts)

        except ImportError:
            pass
        except Exception as exc:
            log.warning("meta_learner.apply_boosts_failed", error=str(exc))

        return type_boosts

    async def fit_clusterer(self, snapshot: ApplicationModelData | None) -> None:
        """Fit l'EndpointClusterer sur les endpoints courants + lie le cluster map au PayloadOptimizer."""
        cl = self._endpoint_clusterer
        if cl is None or snapshot is None:
            return
        try:
            from hdwp.core.ml.embedders.endpoint_embedder import EndpointEmbedder
            embedder = EndpointEmbedder()
            if not snapshot.endpoints:
                return
            paths = [ep.path for ep in snapshot.endpoints]
            embs = [embedder.embed(ep) for ep in snapshot.endpoints]
            if len(embs) >= cl.k:
                cl.fit(embs, paths)
                log.info("meta_learner.clusterer_fit", k=cl.k, n=len(embs))
            elif cl.is_trained:
                path_map = cl.assign_paths(embs, paths)
                cl.set_path_cluster_map(path_map)
                log.debug("meta_learner.clusterer_assigned n=%d", len(path_map))
            if cl.is_trained and self._payload_optimizer is not None:
                self._payload_optimizer.set_cluster_map(cl.path_cluster_map)
        except Exception as exc:
            log.warning("meta_learner.fit_clusterer_failed", error=str(exc))

    # ── Tri des hypothèses ────────────────────────────────────────────────────

    def sort_hypotheses(
        self,
        pending: list,
        snapshot: ApplicationModelData | None,
    ) -> list:
        """Trie les hypothèses par exploitation (PayloadOptimizer) + exploration (ActiveLearner)."""
        al = self._active_learner
        opt = self._payload_optimizer
        if not pending:
            return pending
        if al is not None:
            return al.sort_hypotheses(pending, snapshot, optimizer=opt)
        if opt is not None:
            return opt.sort_hypotheses(pending, snapshot)
        return pending

    # ── Sauvegarde fin de session ─────────────────────────────────────────────

    async def save_session(
        self,
        kb: KnowledgeBase,
        session_id: str,
        findings: list[Finding],
        oracle: SemanticOracle,
        snapshot: ApplicationModelData | None,
        target_hash: str,
        target_type: str,
    ) -> None:
        """
        Collecte les données d'entraînement, réentraîne si seuil atteint,
        et persiste tous les composants ML dans la KB.
        """
        await self._collect_oracle_samples(kb, session_id, findings, oracle)
        await self._retrain_oracle_model(kb, oracle)
        await self._collect_vuln_samples(kb, session_id, findings, snapshot)
        await self._retrain_vuln_classifier(kb)
        await self._collect_finding_embeddings(kb, session_id, findings, snapshot)
        await self._save_feedback_loop(kb, target_hash, target_type)
        await self._save_clusterer(kb)
        await self._save_payload_optimizer(kb)

    async def _collect_oracle_samples(
        self,
        kb: KnowledgeBase,
        session_id: str,
        findings: list[Finding],
        oracle: SemanticOracle,
    ) -> None:
        if not findings:
            return
        try:
            from hdwp.core.ml.embedders.diff_embedder import DiffEmbedder
            stored = await kb.store_oracle_samples_from_session(
                session_id=session_id,
                oracle_results=oracle.oracle_results,
                findings=findings,
                embedder=DiffEmbedder(),
            )
            if stored:
                log.info("meta_learner.oracle_samples_stored", count=stored)
        except ImportError:
            pass
        except Exception as exc:
            log.warning("meta_learner.oracle_samples_failed", error=str(exc))

    async def _retrain_oracle_model(self, kb: KnowledgeBase, oracle: SemanticOracle) -> None:
        if oracle.oracle_ml_model is None:
            return
        try:
            from hdwp.core.ml.models.oracle_model import MIN_SAMPLES_FOR_TRAINING
            from hdwp.core.bus.events import ML_MODEL_RETRAINED
            total = await kb.count_oracle_training_data(only_validated=False)
            if total < MIN_SAMPLES_FOR_TRAINING:
                return
            result = await kb.train_oracle_model(oracle.oracle_ml_model, only_validated=False)
            if result is not None and result.trained:
                log.info(
                    "meta_learner.oracle_model_retrained",
                    n=result.n_samples,
                    acc=round(result.val_accuracy, 3),
                )
        except ImportError:
            pass
        except Exception as exc:
            log.warning("meta_learner.oracle_retrain_failed", error=str(exc))

    async def _collect_vuln_samples(
        self,
        kb: KnowledgeBase,
        session_id: str,
        findings: list[Finding],
        snapshot: ApplicationModelData | None,
    ) -> None:
        if not findings or snapshot is None:
            return
        try:
            from hdwp.core.ml.embedders.endpoint_embedder import EndpointEmbedder
            from hdwp.core.ml.models.vuln_classifier import VULN_TO_PROPERTY_TYPE
            embedder = EndpointEmbedder()
            ep_index = {ep.path: ep for ep in (snapshot.endpoints or [])}
            for finding in findings:
                ep_path = (getattr(finding, "affected_endpoints", None) or [""])[0]
                ep_node = ep_index.get(ep_path) if ep_path else None
                if ep_node is None:
                    continue
                pt = (getattr(finding, "property_type", None) or "").lower()
                vuln_type = next((vt for vt, p in VULN_TO_PROPERTY_TYPE.items() if p == pt), "")
                if vuln_type:
                    emb = embedder.embed(ep_node)
                    await kb.store_vuln_sample(
                        endpoint_embedding=emb,
                        vuln_labels={vuln_type: 1.0},
                        session_id=session_id,
                    )
        except ImportError:
            pass
        except Exception as exc:
            log.warning("meta_learner.vuln_samples_failed", error=str(exc))

    async def _retrain_vuln_classifier(self, kb: KnowledgeBase) -> None:
        clf = self._vuln_classifier
        if clf is None:
            return
        try:
            from hdwp.core.ml.models.vuln_classifier import MIN_SAMPLES_FOR_TRAINING
            total = await kb.count_vuln_training_data()
            if total < MIN_SAMPLES_FOR_TRAINING:
                return
            result = await kb.train_vuln_model(clf)
            if result is not None and result.trained:
                log.info(
                    "meta_learner.vuln_classifier_retrained",
                    n=result.n_samples,
                    types=result.vuln_types_trained,
                )
        except ImportError:
            pass
        except Exception as exc:
            log.warning("meta_learner.vuln_retrain_failed", error=str(exc))

    async def _collect_finding_embeddings(
        self,
        kb: KnowledgeBase,
        session_id: str,
        findings: list[Finding],
        snapshot: ApplicationModelData | None,
    ) -> None:
        if not findings or snapshot is None:
            return
        try:
            from hdwp.core.ml.embedders.endpoint_embedder import EndpointEmbedder
            embedder = EndpointEmbedder()
            ep_index = {ep.path: ep for ep in (snapshot.endpoints or [])}
            for finding in findings:
                ep_path = (finding.affected_endpoints or [""])[0] if hasattr(finding, "affected_endpoints") else ""
                ep_node = ep_index.get(ep_path)
                if ep_node is None:
                    continue
                proof = getattr(finding, "proof", {}) or {}
                owasp = getattr(finding, "owasp_category", "") or ""
                vuln_class = _owasp_to_vuln_class(owasp, proof.get("mutation_type", ""))
                if not vuln_class:
                    continue
                emb = embedder.embed(ep_node)
                await kb.store_finding_embedding(
                    finding_id=finding.id,
                    embedding=emb,
                    vuln_class=vuln_class,
                    session_id=session_id,
                    confidence=finding.confidence,
                )
                if self._similarity_index is not None:
                    self._similarity_index.add(emb, vuln_class, finding.confidence, finding.id)
        except ImportError:
            pass
        except Exception as exc:
            log.warning("meta_learner.finding_embeddings_failed", error=str(exc))

    async def _save_feedback_loop(
        self, kb: KnowledgeBase, target_hash: str, target_type: str
    ) -> None:
        fl = self._feedback_loop
        if fl is None or fl.n_updates == 0:
            return
        try:
            serialized = fl.to_serializable()
            await kb.store_feedback_weights(serialized)
            await kb.store_feedback_weights_for_target(
                target_hash=target_hash,
                target_type=target_type,
                data=serialized,
            )
            log.info(
                "meta_learner.feedback_loop_saved",
                n_updates=fl.n_updates,
                target_hash=target_hash,
                target_type=target_type,
            )
        except Exception as exc:
            log.warning("meta_learner.feedback_loop_save_failed", error=str(exc))

    async def _save_clusterer(self, kb: KnowledgeBase) -> None:
        cl = self._endpoint_clusterer
        if cl is None or not cl.is_trained:
            return
        try:
            data = cl.to_serializable()
            await kb.store_cluster_centroids(
                centroids=data["centroids"],
                k=data["k"],
                n_samples=data["n_samples"],
            )
            log.info("meta_learner.clusterer_saved", k=cl.k, n_samples=cl.n_samples)
        except Exception as exc:
            log.warning("meta_learner.clusterer_save_failed", error=str(exc))

    async def _save_payload_optimizer(self, kb: KnowledgeBase) -> None:
        opt = self._payload_optimizer
        if opt is None or opt.total_pulls == 0:
            return
        try:
            await kb.save_payload_optimizer_stats(opt.to_serializable())
            log.info("meta_learner.payload_optimizer_saved", arms=opt.n_arms, pulls=opt.total_pulls)
        except Exception as exc:
            log.warning("meta_learner.payload_optimizer_save_failed", error=str(exc))

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Retourne un résumé de l'état de tous les composants ML actifs."""
        return {
            "oracle_model": self._oracle_model is not None,
            "vuln_classifier": self._vuln_classifier is not None,
            "payload_optimizer": (
                {"arms": self._payload_optimizer.n_arms, "pulls": self._payload_optimizer.total_pulls}
                if self._payload_optimizer is not None else None
            ),
            "active_learner": self._active_learner is not None,
            "similarity_index": (
                {"entries": self._similarity_index.n_entries}
                if self._similarity_index is not None else None
            ),
            "endpoint_clusterer": (
                {"k": self._endpoint_clusterer.k, "trained": self._endpoint_clusterer.is_trained}
                if self._endpoint_clusterer is not None else None
            ),
            "feedback_loop": (
                {"n_updates": self._feedback_loop.n_updates}
                if self._feedback_loop is not None else None
            ),
        }
