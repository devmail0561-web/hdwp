# Progression de l'implémentation — HDWP Engine

Dernière mise à jour : 2026-09-07

---

## Vue d'ensemble

```
Phase 0  Scaffolding              [DONE] ████████████████████ 100%
Phase 1  Fondations               [DONE] ████████████████████ 100%
Phase 2  Observation & Modèle     [DONE] ████████████████████ 100%
Phase 3  Propriétés & Hypothèses  [DONE] ████████████████████ 100%
Phase 4  Expériences & Oracle     [DONE] ████████████████████ 100%
Robustesse (corrections audit)    [DONE] ████████████████████ 100%
Phase 5  Rapports & CLI           [DONE] ████████████████████ 100%
Phase 5.5 LLM minimaliste         [DONE] ████████████████████ 100%
Phase 6  Proxy, FSM, Alembic, OpenAPI [DONE] ████████████████████ 100%
Audit corrections (v0.3.1)            [DONE] ████████████████████ 100%
Phase 7  LLM complet                  [DONE] ████████████████████ 100%
Apprentissage adaptatif                [DONE] ████████████████████ 100%
V3 Sprint 1  Reasoning Foundation      [DONE] ████████████████████ 100%
V3 Sprint 2  Enriched Oracle           [DONE] ████████████████████ 100%
V3 UI Sync + Proxy fixes               [DONE] ████████████████████ 100%
```

**Version : 3.0.0** | Fichiers source Python : ~110 | Composants TypeScript : 12 stores/hooks/composants v3

---

## Composants V3 (ajoutés depuis v2.2.0)

### V3 Backend

| Composant | Fichier | Event émis |
|---|---|---|
| ThreatModelEngine | `core/threat/engine.py` | `threat.model.updated` |
| AssetRegistry + AttackSurfaceScorer | `core/threat/asset_registry.py`, `scorer.py` | — |
| InvariantStore | `core/model/invariant_store.py` | `invariant.violated` |
| ContextualHypothesisEngine | `core/reasoning/layer.py` | — |
| CrossRoleDiffEngine | `core/oracle/crossrole_diff.py` | `crossrole.diff.confirmed` |
| TemporalAnomalyDetector | `core/oracle/temporal_detector.py` | `temporal.anomaly.detected` |
| AdaptivePayloadEngine | `core/experiment/adaptive_payload.py` | `payload.adapted`, `waf.signature.detected` |
| WAFDialogEngine | `core/experiment/waf_dialog.py` | — |
| AttackGraphPlanner (A*) | `core/attack_graph/planner.py` | `goal.reached` |
| PreconditionSolver | `core/attack_graph/precondition_solver.py` | `precondition.missing` |
| AttackState / StateEffects / AttackTransition | `core/attack_graph/state.py` | — |
| EvidenceGraph | `core/knowledge/evidence_graph.py` | — |
| StructuralIndex | `core/knowledge/structural_index.py` | — |

### V3 Frontend

| Composant | Fichier | Rôle |
|---|---|---|
| v3Store | `app/src/stores/v3Store.ts` | Collections v3 (listes bornées à 100) |
| IntelTab | `app/src/components/IntelTab.tsx` | Onglet INTEL — 6 sections temps réel |
| useWebSocket (v3) | `app/src/hooks/useWebSocket.ts` | 8 handlers events v3 |
| types/hdwp.ts (v3) | `app/src/types/hdwp.ts` | 8 interfaces + discriminated unions |
| MetricsPanel (V3 INTEL) | `app/src/components/MetricsPanel.tsx` | Threat score, violations, WAF |

---

## Composants par statut (v1-v2)

### IMPLEMENTES

| Composant | Fichier | Tests |
|---|---|---|
| AsyncEventBus | `core/bus/event_bus.py` | 8 |
| HDWPEventMap (12 events) | `core/bus/events.py` | — |
| Domain Models (20+) | `core/model/schemas.py` | — |
| ContextLoader | `core/context/loader.py` | 8 |
| ScopeGuard | `core/context/scope_guard.py` | 9 |
| TokenBucket (rate limiter) | `core/experiment/rate_limiter.py` | 5 |
| Repository (SQLite) | `store/repository.py` | 6 |
| CredentialFilter | `store/credential_filter.py` | 7 |
| Normalizer | `core/observation/normalizer.py` | 10 |
| HeaderInspector | `core/observation/header_inspector.py` | 7 |
| ActiveCrawler | `core/observation/active_crawler.py` | 9 |
| ObservationEngine | `core/observation/engine.py` | — |
| ApplicationModel | `core/model/application_model.py` | 10 |
| SecurityPropertyEngine | `core/property_engine/engine.py` | 12 |
| AuthorizationInference | `core/property_engine/inference/authorization.py` | (dans test_property_engine) |
| ConfidentialityInference | `core/property_engine/inference/confidentiality.py` | (dans test_property_engine) |
| HypothesisEngine | `core/hypothesis/engine.py` | 7 |
| HypothesisPrioritizer | `core/hypothesis/prioritizer.py` | (dans test_hypothesis_engine) |
| HDWPPlugin ABC | `plugins/base.py` | — |
| PluginRegistry | `plugins/registry.py` | 6 |
| BOLAPlugin | `plugins/core/authorization/bola.py` | 5 |
| AuthZPlugin | `plugins/core/authorization/authz.py` | — |
| RequestSelector | `core/experiment/request_selector.py` | 12 |
| SessionManager | `core/experiment/session_manager.py` | 16 |
| MutationModule | `core/experiment/mutation_module.py` | 10 |
| ExperimentEngine | `core/experiment/engine.py` | 5 |
| JWTMutator | `core/experiment/jwt_mutator.py` | 10 |
| TemporalModule | `core/experiment/temporal_module.py` | 6 |
| SemanticDiff | `core/oracle/semantic_diff.py` | 8 |
| ViolationOracle | `core/oracle/violation_oracle.py` | 11 |
| InjectionOracle | `core/oracle/injection_oracle.py` | 14 |
| PassiveFindingEngine | `core/oracle/passive_engine.py` | 9 |
| SemanticOracle | `core/oracle/engine.py` | 10 |
| ConfidenceModel | `core/oracle/confidence.py` | 12 |
| KnowledgeBase | `core/knowledge/base.py` | 23 |
| InferenceRegistry | `core/property_engine/inference_registry.py` | (dans test_knowledge_base) |
| HDWPEngine | `core/engine.py` | (via intégration) |
| JWTPlugin | `plugins/core/session_property/jwt.py` | — |
| CORSPlugin | `plugins/core/configuration/cors.py` | 8 |
| VulnerableAppTransport (mock) | `tests/fixtures/mock_server.py` | 14 |

### PARTIELLEMENT IMPLÉMENTÉS

| Composant | Fichier | Statut |
|---|---|---|
| StateInference | `core/property_engine/inference/state.py` | Stub — FSM implémentée mais inférence state peu peuplée |
| CoherenceInference | `core/property_engine/inference/coherence.py` | CORS/headers partiellement via PassiveFindingEngine |
| ConcurrencyInference | `core/property_engine/inference/concurrency.py` | Stub — TemporalModule intégré mais TOCTOU expérimental |

---

## Décisions architecturales prises

| ADR | Décision | Raison |
|---|---|---|
| ADR-001 | Event Bus (pub/sub), zéro import direct | Couplage minimal, testabilité |
| ADR-002 | LLM non-décisionnel | Prévenir les faux positifs non empiriques |
| ADR-003 | Plugin = package pip (entry_points) | Extensibilité communauté sans modifier le noyau |
| ADR-004 | SQLite par défaut, PostgreSQL optionnel | Zéro infrastructure pour usage solo |
| ADR-005 | ScopeGuard non-débrayable au runtime | Protection éthique par défaut |
| ADR-006 | Propriétés comme primitives de premier ordre | OWASP/CWE = classifications a posteriori, pas points de départ |
| ADR-007 | Tor opt-in (non par défaut) | `_active_proxy=None` par défaut — évite les échecs silencieux si Tor Browser absent |
| ADR-008 | V3 events bridgés via EventBridge sans modification | `ALL_EVENT_TYPES` itéré exhaustivement — nouveaux events forwarded automatiquement |
| ADR-007 | Confiance multi-dimensionnelle 5D | Un scalaire unique masque les sources d'incertitude |
| ADR-008 | ViolationOracle conscient du type de mutation | `identity_swap` : similar=vuln (inversé vs diff classique) |
| ADR-009 | L* remplacé par clustering de séquences | L* = 2-4 semaines, hors portée pour Phase 6 |
| ADR-010 | Payloads event bus = `model_dump()` | Standardisation, sérialisation JSON garantie |

---

## Métriques

| Métrique | Valeur |
|---|---|
| Fichiers source Python | 37 |
| Tests | 182 |
| Couverture de code | non mesurée |
| `ruff check src/` | 0 erreurs |
| `mypy --strict` | non configuré (à ajouter en Phase 4) |
| Lignes de code (hors tests) | ~3 200 |
| Lignes de tests | ~2 100 |

---

## Dernière implémentation

**Apprentissage adaptatif** — Le moteur adapte désormais son comportement au fil des sessions :
- Classification de cible (`api`, `cms`, `spa`, `graphql`) pour poids per-target
- Poids de priorité adaptatifs par type de cible (`get_adapted_weights(target_type=)`)
- Poids de confiance modèle adaptatifs (`get_confidence_weights()`)
- Confiance BOLA adaptative via `kb_stats` injectés dans `InferenceRegistry`
- API `/knowledge/learning-health` + section frontend
- Migration backward-compatible de la KB (3-column PK pour `pattern_stats`)
- 12 nouveaux tests, 4 tests pré-existants corrigés → 491 tests passants
