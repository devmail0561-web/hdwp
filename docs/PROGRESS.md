# Progression de l'implémentation — HDWP Engine

Dernière mise à jour : 2026-09-03

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
```

**Tests :** 491 | `ruff check src/` : 0 erreurs | Fichiers source : 62 | Version : 0.5.0

---

## Composants par statut

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
| IntegrityInference | `core/property_engine/inference/integrity.py` | **Implémenté** — SQLi/XSS/SSTI/mass_assign |
| StateInference | `core/property_engine/inference/state.py` | Stub — nécessite FSM (Phase 6) |
| CoherenceInference | `core/property_engine/inference/coherence.py` | Stub — CORS/headers partiellement via PassiveFindingEngine |
| TemporalInference | `core/property_engine/inference/temporal.py` | Stub — nécessite FSM (Phase 6) |
| ConcurrencyInference | `core/property_engine/inference/concurrency.py` | Stub — nécessite TemporalModule intégré |
| `_on_finding_refuted` | `core/model/application_model.py` | Log de traçabilité — raffinement complet Phase 6 |

### A IMPLEMENTER — Phase 5

| Composant | Fichier cible | Note |
|---|---|---|
| ReportEngine | `core/report/engine.py` | Markdown, JSON, HAR |
| CLI complète | `cli/commands/report.py`, `replay.py` | Progress bars rich |
| LLM disambiguate | `core/llm/layer.py` | Phase 5.5 — débloquer AMBIGUOUS |

### A IMPLEMENTER — Phase 5+

| Composant | Phase | Fichier cible |
|---|---|---|
| ReportEngine | 5 | `core/report/engine.py` |
| Markdown renderer | 5 | `core/report/markdown.py` |
| JSON export | 5 | `core/report/json_export.py` |
| HAR exporter | 5 | `core/report/har_exporter.py` |
| CLI complète | 5 | `cli/commands/run.py`, `report.py`, `replay.py`, `plugin.py` |
| LLMLayer (disambiguate) | 5.5 | `core/llm/layer.py` |
| ProxyCapture | 6 | `core/observation/proxy_capture.py` |
| FSM Learner (séquences) | 6 | `core/state_machine/learner.py` |
| TemporalModule | 6 | `core/experiment/temporal_module.py` |
| Alembic migrations | 6 | `alembic/` |
| sqli, xss, jwt, cors, ... | 6 | `plugins/core/*/` |
| LLMLayer (complet) | 7 | `core/llm/layer.py` |

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
