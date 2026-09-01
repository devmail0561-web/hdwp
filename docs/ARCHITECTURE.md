# HDWP Engine — Document d'architecture

**Version :** 0.3.1  
**Auteur :** M. TENDENG  
**Date :** 2026-09-01

---

## 1. Vue d'ensemble

### 1.1 Philosophie

Les scanners de sécurité web traditionnels fonctionnent par injection de payloads sur une liste d'URLs et comparaison des réponses à des signatures connues :

```
URL → Crawler → Payloads → Signatures → Résultat
```

Cette approche est aveugle aux vulnérabilités logiques (BOLA, AuthZ, business logic flaws) car elle ne comprend pas le comportement de l'application.

Le HDWP Engine fonctionne différemment. Il observe l'application, reconstruit son modèle comportemental, en déduit les propriétés de sécurité qui devraient être vraies, génère des expériences minimales pour les falsifier, et ne conclut à une vulnérabilité que sur preuve empirique reproductible.

### 1.2 Boucle fondamentale

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   OBSERVE ──► MODEL ──► INFER PROPERTIES ──► HYPOTHESIZE       │
│      ▲                                           │              │
│      │                                           ▼              │
│   [holds]                               SELECT MINIMAL          │
│      │                                    EXPERIMENT            │
│   REFINE                                      │                 │
│   MODEL ◄──────────────────────── EXECUTE ◄───┘                │
│                                       │                         │
│                                       ▼                         │
│                                    ORACLE                       │
│                                       │                         │
│                         ┌────────────┴────────────┐            │
│                         ▼                          ▼            │
│                     [violated]                 [holds]          │
│                         │                          │            │
│                         ▼                          └──► REFINE  │
│                  EVIDENCE + FINDING                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

La clé : les classifications OWASP/CWE sont appliquées *a posteriori* sur les findings confirmés — elles ne sont jamais le point de départ du raisonnement.

---

## 2. Composants

Tous les composants communiquent exclusivement via l'Event Bus. Aucun composant n'importe un autre composant directement.

| Composant | Fichier | Responsabilité |
|---|---|---|
| `AsyncEventBus` | `core/bus/event_bus.py` | Canal de communication pub/sub entre tous les composants |
| `ContextLoader` | `core/context/loader.py` | Charge et valide `hdwp-context.yaml`, résout les variables d'environnement |
| `ScopeGuard` | `core/context/scope_guard.py` | Filtre toutes les requêtes actives : scope, méthodes destructives |
| `ObservationEngine` | `core/observation/engine.py` | Orchestre le crawl actif et le proxy passif |
| `ActiveCrawler` | `core/observation/active_crawler.py` | BFS sur l'application cible, émet `observation.raw` par rôle |
| `ProxyCapture` | `core/observation/proxy_capture.py` | Capture passive via mitmproxy (optionnel) |
| `HeaderInspector` | `core/observation/header_inspector.py` | Détecte les headers de sécurité manquants ou révélateurs |
| `ApplicationModel` | `core/model/application_model.py` | Graphe comportemental incrémental : endpoints, paramètres, objets, rôles, FSM |
| `StateMachineLearner` | `core/state_machine/learner.py` | Inférence FSM par clustering de séquences d'observations |
| `SecurityPropertyEngine` | `core/property_engine/engine.py` | Infère les 7 types de propriétés de sécurité depuis le modèle |
| `HypothesisEngine` | `core/hypothesis/engine.py` | Génère des hypothèses falsifiables, les persiste, priorise |
| `RequestSelector` | `core/experiment/request_selector.py` | Résout les ExperimentSpec abstraites en plans HTTP concrets |
| `SessionManager` | `core/experiment/session_manager.py` | Maintient les sessions HTTP par rôle, gère les tokens CSRF |
| `MutationModule` | `core/experiment/mutation_module.py` | 6 axes de mutation : identity_swap, object_ref_change, privilege_escalation, field_injection, origin_test, jwt_manipulation |
| `ExperimentEngine` | `core/experiment/engine.py` | Exécute les plans : baseline + mutation + replay, inject credentials |
| `JWTMutator` | `core/experiment/jwt_mutator.py` | Forge les tokens JWT (alg:none, expiration, brute-force HS256) |
| `TemporalModule` | `core/experiment/temporal_module.py` | Race conditions concurrentes, token reuse |
| `SemanticOracle` | `core/oracle/engine.py` | Orchestre diff + ViolationOracle + ConfidenceModel → CONFIRMED/REFUTED |
| `ViolationOracle` | `core/oracle/violation_oracle.py` | Verdict par type de mutation (6 types supportés) |
| `InjectionOracle` | `core/oracle/injection_oracle.py` | Détection SQLi, XSS, SSTI, mass assignment, SSRF |
| `PassiveFindingEngine` | `core/oracle/passive_engine.py` | Findings depuis observations : headers, cookies, server disclosure, stack traces |
| `LLMLayer` | `core/llm/layer.py` | Désambiguïsation LLM des diffs AMBIGUOUS (jamais CONFIRMED seul) |
| `ReportEngine` | `core/report/engine.py` | Génère Markdown, JSON, HAR depuis les findings |
| `Repository` | `store/repository.py` | Persistance async SQLite de toutes les entités |
| `TokenBucket` | `core/experiment/rate_limiter.py` | Contrôle du débit des requêtes actives |
| `PluginRegistry` | `plugins/registry.py` | Découverte des plugins via `importlib.metadata.entry_points` |

---

## 3. Event Bus

### 3.1 Architecture

L'`AsyncEventBus` est un wrapper typé sur `pyee.AsyncIOEventEmitter`. Tous les payloads sont des dicts JSON (produits par `model.model_dump()`). Les handlers s'enregistrent avec `.on(event_type, handler)` ; l'émission est asynchrone et non-bloquante.

```python
bus = AsyncEventBus()
bus.on("observation.raw", my_handler)  # subscription
await bus.emit("observation.raw", obs.model_dump(), source="active_crawler")
await bus.drain()  # attend que tous les handlers aient terminé
```

### 3.2 Carte des événements (HDWPEventMap)

| Événement | Payload | Émetteur | Consommateurs |
|---|---|---|---|
| `observation.raw` | `RawObservation` | `ActiveCrawler`, `ProxyCapture` | `ApplicationModel`, `PassiveFindingEngine`, `StateMachineLearner` |
| `model.updated` | `ApplicationModelData` | `ApplicationModel` | `SecurityPropertyEngine` |
| `fsm.updated` | `ApplicationFSM` | `StateMachineLearner` | `ApplicationModel` (stocke la FSM dans snapshot) |
| `property.inferred` | `SecurityProperty` | `SecurityPropertyEngine` | `HypothesisEngine` |
| `property.invalidated` | `{id, reason}` | `SecurityPropertyEngine` | `HypothesisEngine` |
| `hypothesis.generated` | `Hypothesis` | `HypothesisEngine` | `ExperimentEngine` |
| `hypothesis.experiments_ready` | `{hypothesis_id, baseline_id, experiment_ids}` | `ExperimentEngine` | `SemanticOracle` |
| `hypothesis.status_changed` | `{id, old_status, new_status}` | `SemanticOracle` | `ReportEngine` |
| `experiment.result` | `ExperimentResult` | `ExperimentEngine` | `SemanticOracle` |
| `diff.computed` | `SemanticDiff` | `SemanticOracle` | (log/debug) |
| `finding.confirmed` | `Finding` | `SemanticOracle`, `PassiveFindingEngine` | `ReportEngine` |
| `finding.refuted` | `Finding` | `SemanticOracle` | `ApplicationModel` (learning loop) |
| `report.generated` | `{path, summary}` | `ReportEngine` | `CLI` |

Note : la persistance en base est assurée **directement** par les composants (Repository injecté), pas via le bus. Les entités sont sauvegardées au moment de leur création (hypothèses → `HypothesisEngine`, findings → `SemanticOracle` + `PassiveFindingEngine`, diffs → `SemanticOracle`).

---

## 4. Modèles de données

Tous les modèles sont des `pydantic.BaseModel`. Les IDs sont des chaînes préfixées générées par `generate_id(prefix)` → `PREFIX-{hex8}`.

### 4.1 Préfixes d'entités

| Préfixe | Entité | Description |
|---|---|---|
| `OBS-` | `RawObservation` | Observation HTTP capturée |
| `EP-` | `EndpointNode` | Nœud d'endpoint dans le graphe |
| `PARAM-` | `ParameterNode` | Paramètre (query, body, path, header, cookie) |
| `OBJ-` | `DataObjectNode` | Objet de données inféré depuis les réponses JSON |
| `ROLE-` | `RoleNode` | Rôle observé dans l'application |
| `FSM-` | `ApplicationFSM` | Machine à états finis applicative |
| `PROP-` | `SecurityProperty` | Propriété de sécurité inférée |
| `HYP-` | `Hypothesis` | Hypothèse falsifiable |
| `EXP-` | `ExperimentResult` | Résultat d'expérience |
| `DIFF-` | `SemanticDiff` | Diff comportemental entre deux réponses |
| `FIND-` | `Finding` | Vulnérabilité confirmée ou réfutée |

### 4.2 Entités principales

**`RawObservation`**
```
id: str          # OBS-XXXX
timestamp: str   # ISO8601
source: str      # "passive" | "active"
type: ObservationType  # HTTP | DOM | JS | COOKIE | HEADER | WS | GRAPHQL
request: NormalizedRequest | None
response: NormalizedResponse | None
session_id: str
tags: list[str]  # ex: ["role:user_a", "missing:CSP"]
```

**`SecurityProperty`**
```
id: str              # PROP-XXXX
type: PropertyType   # AUTHORIZATION | STATE | INTEGRITY | CONFIDENTIALITY |
                     # COHERENCE | TEMPORAL | CONCURRENCY
formal_statement: str  # ex: "access(S, resource) via 'user_id' => owner(resource) = S"
model_nodes: list[str] # IDs des nœuds du modèle impliqués
inference_confidence: float  # 0.0–1.0
source_observations: list[str]  # IDs OBS ayant conduit à cette inférence
status: str          # "active" | "invalidated"
```

**`Hypothesis`**
```
id: str              # HYP-XXXX
status: HypothesisStatus  # PENDING | CONFIRMED | REFUTED | INSUFFICIENT_DATA
source_plugin: str
property_id: str     # PROP-XXXX
statement: str       # proposition falsifiable en langage naturel
priority: str        # "HIGH" | "MEDIUM" | "LOW"
priority_rationale: str
required_experiments: list[ExperimentSpec]
confidence: float
```

**`Finding`**
```
id: str              # FIND-XXXX
hypothesis_id: str   # HYP-XXXX
property_id: str     # PROP-XXXX
status: str          # "CONFIRMED" | "REFUTED"
confidence: float
confidence_breakdown: ConfidenceScore  # 5 dimensions détaillées
owasp_category: str  # ex: "A01:2021" — classification a posteriori
cwe_id: str
severity: str        # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
affected_endpoints: list[str]
proof: dict          # observations[], experiments[], diffs[], reproduction_steps[]
remediation_hint: str
```

---

## 5. Oracle de violation

### 5.1 Principe

Le `SemanticDiff` compare deux réponses HTTP et produit un verdict `SIGNIFICANT | AMBIGUOUS | INSIGNIFICANT`. Mais ce verdict seul ne suffit pas : la signification d'une "différence significative" dépend du type de mutation testé.

Le `ViolationOracle` (`core/oracle/violation_oracle.py`) est conscient du type de mutation :

| Mutation | Violation si... | Propriété tenue si... |
|---|---|---|
| `identity_swap` | Les réponses sont **similaires** (attaquant reçoit les données de la victime) | L'expérimentateur reçoit 401/403 |
| `object_ref_change` | L'expérience retourne **2xx avec des données** (pas de vérification ownership) | Retourne 401/403/404 |
| `privilege_escalation` | L'expérience retourne **2xx** (endpoint accessible sans autorisation) | Retourne 401/403 ou 3xx |

Note critique : pour `identity_swap`, la logique est **inversée** par rapport à un diff naïf. Une violation BOLA se manifeste quand les deux réponses se ressemblent (l'attaquant obtient les mêmes données que la victime) — pas quand elles diffèrent.

### 5.2 Seuils de similarité (identity_swap)

```
body_similarity >= 0.7  OU  structural_difference == False
    → CONFIRMED (confidence_hint = 0.9 si similarity >= 0.9, sinon 0.7)

exp_status in (401, 403)
    → REFUTED (confidence_hint = 0.9)

autres cas
    → AMBIGUOUS ou INSUFFICIENT
```

### 5.3 Champs volatils filtrés

Le `SemanticDiff` ignore les champs suivants dans la comparaison de valeurs :
`timestamp`, `created_at`, `updated_at`, `date`, `time`, `nonce`, `csrf_token`,
`request_id`, `trace_id`, `correlation_id`, `_timestamp`, `ts`, `iat`, `exp`, `jti`

---

## 6. Modèle de confiance 5 dimensions

Chaque hypothèse confirmée reçoit un `ConfidenceScore` calculé sur 5 dimensions indépendantes :

```
overall = 0.25 × oracle_strength
        + 0.30 × reproducibility
        + 0.15 × observation_quality
        + 0.15 × behavioral_specificity
        + 0.15 × experiment_coverage
```

| Dimension | Poids | Définition opérationnelle |
|---|---|---|
| `oracle_strength` | 0.25 | `confidence_hint` de la `ViolationAssessment` (0.0–0.95 selon la certitude du verdict) |
| `reproducibility` | 0.30 | Fraction des replays qui confirment le résultat initial |
| `observation_quality` | 0.15 | `log(1 + n_obs) / log(6)` — sature à 5 observations de l'endpoint |
| `behavioral_specificity` | 0.15 | Spécificité du diff au type de mutation (ex : similarity pour identity_swap) |
| `experiment_coverage` | 0.15 | `log(1 + n_done) / log(1 + n_required)` |

**Seuils :**
- `overall >= 0.85` → `CONFIRMED`
- Toutes expériences INSIGNIFICANT → `REFUTED`
- Sinon → `INSUFFICIENT_DATA` (génère de nouvelles expériences)

---

## 7. Inférence de propriétés

### 7.1 Les 7 types de propriétés

| Type | Schéma formel |
|---|---|
| `AUTHORIZATION` | `access(S, R) ⟹ authorized(S, R, policy)` |
| `STATE` | `reachable(Sn) ⟹ ∀ Si ∈ predecessors(Sn), visited(Si)` |
| `INTEGRITY` | `cancelled(O) ⟹ ¬committed(state(O))` |
| `CONFIDENTIALITY` | `query(A, resource) ⟹ owner(resource) = A` |
| `COHERENCE` | `∀ n, execute(action, n) → state = execute(action, 1)` |
| `TEMPORAL` | `expired(token) ⟹ ∀ protected_action, denied(action)` |
| `CONCURRENCY` | `concurrent(R1..Rn) ⟹ invariant(state_final)` |

### 7.2 Règles d'inférence implémentées

**AUTHORIZATION (3 règles)** — `core/property_engine/inference/authorization.py`
1. **BOLA** : tout `ParameterNode` avec `affects_object` et `type_inferred in ("integer", "uuid")` → propriété d'autorisation sur l'ownership
2. **Endpoint auth** : tout endpoint avec `auth_required=True` et `roles_observed` non vide → propriété de contrôle d'accès
3. **Séparation de rôles** : si ≥ 2 rôles avec des permissions exclusives → propriété d'isolation de rôles

**CONFIDENTIALITY (1 règle)** — `core/property_engine/inference/confidentiality.py`
1. Tout `DataObjectNode` avec `sensitivity in ("private", "sensitive")` et `owner_parameter` → propriété de confidentialité

Les 5 autres types (STATE, INTEGRITY, COHERENCE, TEMPORAL, CONCURRENCY) ont des stubs qui retournent `[]` — implémentation Phase 6.

---

## 8. Modèle d'application

L'`ApplicationModel` (`core/model/application_model.py`) construit incrémentalement le graphe comportemental depuis les observations.

### 8.1 Normalisation des chemins

Les segments numériques ou UUID dans les URLs sont normalisés :
- `/api/users/42` → `/api/users/{id_0}`
- `/api/items/f47ac10b-58cc` → `/api/items/{uuid_0}`

Un seul `EndpointNode` par chemin normalisé accumule les méthodes observées.

### 8.2 Corpus de requêtes

Le modèle maintient un `_request_corpus : dict[path_pattern, list[(role_name, NormalizedRequest)]]`. Ce corpus est la source des requêtes concrètes pour le `RequestSelector`.

### 8.3 Indicateur de maturité

```python
model.model_confidence  # float 0.0–1.0
model.is_ready          # True si model_confidence >= 0.3
```

Formule :
```
confidence = 0.4 × log(1 + n_endpoints) / log(11)
           + 0.4 × min(1.0, n_roles / 2)
           + 0.2 × min(1.0, n_bola_params / 2)
```

---

## 9. ScopeGuard et sécurité interne

### 9.1 ScopeGuard

Toute requête active passe par `ScopeGuard.check(url, method) → ScopeVerdict` avant d'être émise.

| Verdict | Condition |
|---|---|
| `ALLOWED` | URL dans le scope, méthode non destructive ou `allow_write=True` |
| `BLOCKED_OUT_OF_SCOPE` | URL ne correspond à aucun pattern `include`, ou correspond à un pattern `exclude` |
| `BLOCKED_DESTRUCTIVE` | Méthode POST/PUT/PATCH/DELETE sans flag `allow_write=True` |

Le ScopeGuard ne peut pas être désactivé au runtime.

### 9.2 Gestion des credentials

- Les tokens sont chargés depuis les variables d'environnement via `${ENV_VAR}` dans le fichier de contexte
- Le `credential_filter.py` filtre les headers sensibles (`Authorization`, `Cookie`, `X-Api-Key`, etc.) avant toute persistance dans l'Evidence Store
- Le `SessionManager` injecte les tokens de manière centralisée et extrait les CSRF tokens des réponses

### 9.3 Rate limiting

Le `TokenBucket` (token bucket algorithm) garantit le respect de `max_requests_per_minute` défini dans le contexte. Créé via `TokenBucket.from_rpm(rpm)`.

---

## 10. Flux de données

### 10.1 Mode actif (implémenté)

```
hdwp run --context hdwp-context.yaml
│
├─► ContextLoader.load()          → EngineContext (frozen)
│                                     └─► ScopeGuard initialisé
│                                     └─► Repository initialisé (SQLite)
│
├─► ObservationEngine.start()
│    └─► ActiveCrawler.crawl()    → BFS par rôle
│         └─► [chaque page]       → observation.raw émis
│
├─► ApplicationModel              → s'abonne à observation.raw
│    └─► [chaque observation]     → graphe mis à jour, model.updated émis
│
├─► SecurityPropertyEngine        → s'abonne à model.updated
│    └─► [chaque delta]           → règles d'inférence appliquées, property.inferred émis
│
├─► HypothesisEngine              → s'abonne à property.inferred
│    └─► [chaque propriété]       → hypothèses générées, hypothesis.generated émis
│
├─► ExperimentEngine (Phase 4)    → s'abonne à hypothesis.generated
│    ├─► RequestSelector          → résout les ExperimentSpec en plans concrets
│    ├─► SessionManager           → gère les sessions et les CSRF tokens
│    └─► [chaque plan]            → requête HTTP envoyée, experiment.result émis
│
├─► SemanticOracle (Phase 4)      → s'abonne à experiment.result
│    ├─► compute_semantic_diff()  → SemanticDiff calculé
│    ├─► assess_violation()       → ViolationAssessment par type de mutation
│    ├─► compute_confidence()     → ConfidenceScore 5D
│    └─► [si confidence >= 0.85]  → finding.confirmed émis
│
└─► ReportEngine (Phase 5)        → s'abonne à finding.confirmed
     └─► génère report.md, findings.json, evidence/*.har
```

### 10.2 Boucle d'apprentissage

Quand une hypothèse est réfutée, les réponses des expériences enrichissent le modèle :

```
finding.refuted
    └─► ApplicationModel._on_finding_refuted()
         └─► nouvelles observations ajoutées au corpus
              └─► model.updated émis
                   └─► nouvelles propriétés inférées
                        └─► nouvelles hypothèses générées
```

### 10.3 Mode passif (Phase 6)

Le mode passif utilise `mitmproxy` comme proxy MITM. Le testeur navigue manuellement ; chaque requête capturée est normalisée et émise sur `observation.raw`. Le reste de la pipeline est identique.

---

## 11. Evidence Store

Toutes les entités sont persistées dans SQLite (`evidence_store.db` par défaut, PostgreSQL via URL de connexion).

Chaque table a un schéma minimal (colonnes indexées pour les requêtes courantes) + une colonne `data_json` (sérialisation Pydantic complète).

Tables : `observations`, `properties`, `hypotheses`, `experiments`, `diffs`, `findings`, `model_snapshots`.

Accès via `Repository` (`store/repository.py`) — API async, credential filtering appliqué automatiquement sur les observations.

---

## 12. Structure des répertoires

```
src/hdwp/
├── cli/
│   └── main.py                          # CLI typer : run, model, report, replay, plugin
├── core/
│   ├── bus/
│   │   ├── event_bus.py                 # AsyncEventBus
│   │   └── events.py                    # 12 constantes d'événements + HDWPEvent
│   ├── context/
│   │   ├── config_schema.py             # Pydantic models pour hdwp-context.yaml
│   │   ├── loader.py                    # ContextLoader + EngineContext
│   │   └── scope_guard.py               # ScopeGuard
│   ├── experiment/
│   │   ├── rate_limiter.py              # TokenBucket
│   │   ├── request_selector.py          # RequestSelector + ConcreteExperimentPlan
│   │   └── session_manager.py           # SessionManager + TokenExpiredError
│   ├── hypothesis/
│   │   ├── engine.py                    # HypothesisEngine
│   │   └── prioritizer.py              # HypothesisPrioritizer
│   ├── model/
│   │   ├── application_model.py         # ApplicationModel
│   │   └── schemas.py                   # Tous les Pydantic models domaine
│   ├── observation/
│   │   ├── active_crawler.py            # ActiveCrawler + extract_links
│   │   ├── engine.py                    # ObservationEngine
│   │   ├── header_inspector.py          # HeaderInspector
│   │   └── normalizer.py               # normalize_request / normalize_response
│   ├── oracle/
│   │   ├── confidence.py                # compute_confidence (5D)
│   │   ├── semantic_diff.py             # compute_semantic_diff
│   │   └── violation_oracle.py          # assess_violation (mutation-aware)
│   └── property_engine/
│       ├── engine.py                    # SecurityPropertyEngine
│       ├── property_types.py            # InferenceModule protocol
│       └── inference/
│           ├── authorization.py         # 3 règles BOLA/AuthZ/séparation
│           ├── confidentiality.py       # 1 règle ownership
│           ├── state.py                 # stub (Phase 6)
│           ├── integrity.py             # stub (Phase 6)
│           ├── coherence.py             # stub (Phase 6)
│           ├── temporal.py              # stub (Phase 6)
│           └── concurrency.py           # stub (Phase 6)
├── plugins/
│   ├── base.py                          # HDWPPlugin ABC
│   ├── registry.py                      # PluginRegistry (entry_points)
│   └── core/
│       └── authorization/
│           ├── bola.py                  # BOLAPlugin
│           └── authz.py                 # AuthZPlugin
└── store/
    ├── credential_filter.py             # filter_credentials()
    ├── database.py                      # init_db(), get_session()
    ├── models.py                        # SQLModel tables
    └── repository.py                    # Repository async CRUD
```
