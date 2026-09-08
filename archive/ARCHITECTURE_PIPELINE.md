# HDWP — Architecture du Pipeline et des Engines

> Document destiné à un agent d'intelligence pour comprendre le cœur décisionnel
> du moteur et identifier les points d'amélioration.

---

## Vue d'ensemble : le cycle PDWST

HDWP implémente un cycle scientifique de pentesting automatisé inspiré du modèle
**Property-Driven Security Testing (PDWST)**. Le pipeline est **event-driven** :
aucun engine n'appelle directement un autre — tout passe par un **AsyncEventBus**.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          HDWPEngine (orchestrateur)                        │
│                                                                           │
│  Phase 1: OBSERVER        Phase 2: RAISONNER         Phase 3: AGIR       │
│  ┌──────────────────┐    ┌───────────────────────┐   ┌────────────────┐  │
│  │ ObservationEngine │───▶│ ApplicationModel      │──▶│ ExperimentEng. │  │
│  │ (crawl, proxy,   │    │ (graphe comportemental)│   │ (HTTP mutés)   │  │
│  │  OpenAPI, SPA)    │    │         │              │   └───────┬────────┘  │
│  └──────────────────┘    │         ▼              │           │           │
│                          │ SecurityPropertyEngine │           ▼           │
│                          │ (propriétés formelles)  │   ┌────────────────┐  │
│                          │         │              │   │ SemanticOracle  │  │
│                          │         ▼              │   │ (verdict +      │  │
│                          │ HypothesisEngine       │   │  confiance)     │  │
│                          │ (hypothèses testables) │   └───────┬────────┘  │
│                          └───────────────────────┘           │           │
│                                                              ▼           │
│  Phase 4: CORRÉLER       Phase 5: APPRENDRE       Phase 6: RAPPORTER   │
│  ┌──────────────────┐    ┌───────────────────┐    ┌────────────────┐    │
│  │ ChainEngine      │    │ KnowledgeBase     │    │ ReportEngine   │    │
│  │ (attaques multi- │    │ (apprentissage    │    │ (MD, JSON, HAR)│    │
│  │  étapes)          │    │  inter-sessions)  │    └────────────────┘    │
│  └──────────────────┘    └───────────────────┘                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. AsyncEventBus — le système nerveux

**Fichier** : `core/bus/event_bus.py`

Pub/sub async. Chaque engine publie et souscrit à des événements typés.
`bus.drain()` garantit que tous les handlers ont terminé avant de passer
à la phase suivante.

### Les 21 types d'événements

| Événement | Producteur | Consommateur(s) |
|---|---|---|
| `observation.raw` | ObservationEngine, ProxyCapture | ApplicationModel, StateMachineLearner, PassiveFindingEngine |
| `model.updated` | ApplicationModel | SecurityPropertyEngine |
| `property.inferred` | SecurityPropertyEngine | HypothesisEngine |
| `hypothesis.generated` | HypothesisEngine, AmbiguityResolver | (buffer interne) |
| `experiment.result` | ExperimentEngine | SemanticOracle |
| `hypothesis.experiments_ready` | ExperimentEngine | SemanticOracle |
| `diff.computed` | SemanticOracle | (stocké) |
| `hypothesis.status_changed` | SemanticOracle | (UI, logs) |
| `finding.confirmed` | SemanticOracle | ChainEngine, ReportEngine, KnowledgeBase |
| `finding.refuted` | SemanticOracle | ApplicationModel (rétro-feedback) |
| `hypothesis.ambiguous` | SemanticOracle | AmbiguityResolver |
| `findings.correlated` | ChainEngine | (UI) |
| `fsm.updated` | StateMachineLearner | ApplicationModel |
| `flow.updated` | FlowMapBuilder | (ChainEngine) |
| `tech_stack.updated` | ErrorIntel, VersionScanner | ApplicationModel |
| `credentials.captured` | ProxyCapture | SessionManager |
| `auth.required` | ApplicationModel | (UI, auto-registrar) |
| `scan.completed` | HDWPEngine | (UI) |
| `scan.error` | HDWPEngine | (UI) |
| `report.generated` | ReportEngine | (UI) |
| `property.invalidated` | SecurityPropertyEngine | (interne) |

---

## 2. ObservationEngine — les yeux

**Fichier** : `core/observation/engine.py`

Collecte les données brutes sur la cible. Ne prend aucune décision.

### Sous-composants

| Composant | Rôle |
|---|---|
| **ActiveCrawler** | Crawl HTTP récursif avec rate-limiting. Émet `observation.raw` par page. Extrait les liens, formulaires, scripts JS. |
| **SPACrawler** | Crawl Playwright (headless browser) pour les SPA. Trafic routé via le proxy MITM. |
| **OpenAPI Seeder** | Découverte automatique de spec OpenAPI (/.well-known, /docs, /swagger.json). Pré-alimente le modèle sans crawl. |
| **ProxyCapture** | Proxy MITM (mitmproxy) pour observer le trafic réel. Capture les credentials en transit → `credentials.captured`. |
| **JS Extractor** | Parse le JavaScript crawlé : endpoints API, tokens hardcodés, routes SPA. |
| **Version Scanner** | Identifie les versions de bibliothèques JS/CSS → détection de composants vulnérables (OWASP A06). |
| **Header Inspector** | Analyse les headers de sécurité (HSTS, CSP, XFO, cookies) → tags passifs. |

### Données produites
- `RawObservation` : (request, response, tags, session_id) → publiées sur le bus

---

## 3. ApplicationModel — le cerveau cartographique

**Fichier** : `core/model/application_model.py`

Graphe comportemental incrémental de l'application cible. S'enrichit à
chaque `observation.raw`. **C'est le modèle mental que HDWP a de la cible.**

### Structure du graphe

```
EndpointNode ──────┐
  - path (pattern)  │     ParameterNode
  - methods[]       ├────▶  - name, location (query/body/path/header/cookie)
  - parameters[]    │       - observed_values[]
  - status_by_role  │       - inferred_type (int/uuid/string/email...)
                    │
RoleNode            │     DataObjectNode
  - name            │       - schema_def
  - auth_type       │       - sensitivity (public/sensitive)
  - observed_endpoints      - owner_role
```

### Mécanismes intelligents

| Mécanisme | Description |
|---|---|
| **URL normalization** | `/api/users/42` → `/api/users/{id_0}` pour grouper les endpoints |
| **Behavioral profiling** | Distribution statistique des tailles de réponse par endpoint → Z-score pour détecter les anomalies |
| **Status-by-role** | Matrice endpoint × role → status code. Détecte quels endpoints nécessitent quelle auth. |
| **Response corpus** | Bodies JSON stockés par (endpoint, role) pour le cross-role diffing |
| **Data identity fields** | Extraction récursive des champs d'identité (id, user_id, email...) pour détecter les IDOR |
| **Tech stack detection** | Tags framework:/db:/waf: extraits des headers et erreurs |
| **Model confidence** | Score [0,1] pondéré : couverture endpoints × rôles × BOLA testabilité |

### Événement publié
- `model.updated` → snapshot complet `ApplicationModelData`

---

## 4. SecurityPropertyEngine — le raisonnement formel

**Fichier** : `core/property_engine/engine.py`

Souscrit à `model.updated`. Infère des **propriétés de sécurité formelles**
à partir du graphe applicatif. Ce sont des assertions testables, pas des vulnérabilités.

### Types de propriétés (PropertyType)

| Type | Exemple de propriété formelle |
|---|---|
| `AUTHORIZATION` | "GET /api/users/{id} doit retourner 403 si le role n'est pas owner" |
| `CONFIDENTIALITY` | "Le champ 'email' dans /api/users/{id} ne doit pas fuiter vers un autre rôle" |
| `INTEGRITY` | "Le paramètre 'price' de POST /api/orders ne doit pas accepter de valeurs négatives" |
| `STATE` | "Le token de session doit être invalidé après POST /logout" |
| `COHERENCE` | "L'endpoint doit avoir un header HSTS" / "Business invariant : prix ≥ 0" |
| `TEMPORAL` | "POST /api/transfer ne doit pas être exploitable en race condition" |
| `CONCURRENCY` | "POST /api/coupons/redeem doit être idempotent sous charge concurrente" |

### Sources d'inférence

1. **InferenceRegistry** (modules built-in) : authorization, integrity, confidentiality, state...
2. **Plugin-contributed** : chaque plugin peut inférer des propriétés spécialisées
3. **CompositeInference** : croisement de propriétés (BOLA + data_leak → haute priorité)
4. **KB-calibrated confidence** : la KnowledgeBase ajuste la confiance initiale des inférences selon l'historique

### Événement publié
- `property.inferred` → `SecurityProperty`

---

## 5. HypothesisEngine — la formulation d'hypothèses

**Fichier** : `core/hypothesis/engine.py`

Souscrit à `property.inferred`. Transforme chaque propriété en **hypothèses testables**
avec des `ExperimentSpec` concrets.

### Logique de génération

```
SecurityProperty("INTEGRITY: param 'username' rejects injection")
    ↓
Hypothesis("Le paramètre 'username' est vulnérable à une injection")
    ├── ExperimentSpec(mutation_type="field_injection", payload="' OR '1'='1", payload_type="sqli")
    ├── ExperimentSpec(mutation_type="field_injection", payload="<script>alert(1)</script>", payload_type="xss")
    └── ExperimentSpec(mutation_type="field_injection", payload="{{7*7}}", payload_type="ssti")
```

### Mécanismes

| Mécanisme | Description |
|---|---|
| **Prioritizer** | Score HIGH/MEDIUM/LOW basé sur le type de propriété, le nombre de nœuds affectés, et les poids KB |
| **Expansion per-endpoint** | Chaque hypothèse est dupliquée pour chaque endpoint possédant le paramètre cible |
| **Plugin hypotheses** | Les plugins génèrent des hypothèses spécialisées (NoSQLi, path traversal, open redirect...) |
| **LLM suggestions** | Le LLM peut proposer des hypothèses complémentaires (si configuré) |
| **Strategy pivot** | Après un REFUTED, pivot vers un type de mutation alternatif (ex: SQLi refuté → tenter NoSQLi si MongoDB détecté) |
| **Dedup + refutation tracking** | Historique (endpoint × mutation_type × payload_type) → évite de re-tester les surfaces déjà réfutées |
| **Shuffle** | `get_pending()` mélange les hypothèses de même priorité pour couvrir uniformément la surface |

### Événement publié
- `hypothesis.generated` → `Hypothesis` (avec liste de `ExperimentSpec`)

---

## 6. ExperimentEngine — l'exécuteur

**Fichier** : `core/experiment/engine.py`

Exécute les hypothèses en envoyant des requêtes HTTP mutées à la cible.

### Pipeline d'exécution par hypothèse

```
Hypothesis
  │
  ▼
RequestSelector.select_for_hypothesis()
  → Résout chaque ExperimentSpec en ConcreteExperimentPlan
  → Trouve la requête baseline dans le corpus
  │
  ▼ (pour chaque plan)
  │
  ├── 1. BASELINE : exécuter la requête légitime (skip si 404/500)
  │
  ├── 2. MUTATION : MutationModule.apply() → requête mutée
  │   │   (identity_swap, object_ref_change, field_injection, jwt_manipulation,
  │   │    origin_test, race_condition, path_traversal, nosqli, open_redirect,
  │   │    type_confusion, boundary_value, parameter_pollution, method_override,
  │   │    http_method_fuzzing, token_reuse)
  │   │
  │   ├── ScopeGuard.check() → bloque si hors scope
  │   └── Exécution HTTP via SessionManager (auth par rôle, CSRF, OAuth2 refresh)
  │
  ├── 3. FOLLOW-UP ADAPTATIF : si trigger_condition match → ajouter des specs à la queue
  │
  ├── 4. WAF BYPASS : si 403 + WAF connu → générer des variantes d'encodage
  │
  └── 5. REPLAY : ré-exécuter la même mutation pour vérifier la reproductibilité
```

### Sous-composants

| Composant | Rôle |
|---|---|
| **RequestSelector** | Bridge abstract spec → concrete HTTP. Fonctions `plan_*` par mutation_type. |
| **MutationModule** | Applique la mutation minimale : swap headers, change ID, injecte payload. Fonctions `apply_*`. |
| **SessionManager** | Pool de clients httpx par rôle. Gère cookies, CSRF tokens, OAuth2 refresh. |
| **TokenBucket** | Rate limiter basé sur le RPM configuré. |
| **TemporalModule** | Race conditions : N requêtes concurrentes via asyncio.gather. |
| **EncodingPipeline** | WAF bypass : double-encoding, Unicode normalization, case switching. |
| **JWTMutator** | Forge de tokens JWT : alg:none, expired, weak secrets. |

### Événements publiés
- `experiment.result` → `ExperimentResult` (pour chaque baseline, mutation, replay)
- `hypothesis.experiments_ready` → signal de batch complet pour l'oracle

---

## 7. SemanticOracle — le juge

**Fichier** : `core/oracle/engine.py`

Souscrit à `experiment.result` (buffer) et `hypothesis.experiments_ready` (évaluation).
**C'est le cœur d'intelligence du moteur.**

### Pipeline d'évaluation

```
  ExperimentResults (baseline + mutations + replays)
       │
       ▼
  ┌─────────────────────┐
  │  SemanticDiff        │   Compare baseline vs mutation :
  │  compute_semantic_diff()│   - status_difference
  │                       │   - structural_difference (JSON keys)
  │                       │   - behavioral_difference (values differ, same keys)
  │                       │   - leaked_fields (new keys in experiment)
  │                       │   - body_similarity (Jaccard)
  │                       │   - data_identity_score (same user's data?)
  │                       │   - response_size_ratio (data extraction?)
  │                       │   - response_zscore (anomalie statistique)
  │                       │   - suspicious_fields (JWT, hashes, emails)
  │                       │   - security_headers_delta
  └──────────┬────────────┘
             │
             ▼
  ┌─────────────────────┐
  │  ViolationOracle     │   Verdict par mutation_type :
  │  assess_violation()  │   CONFIRMED | REFUTED | AMBIGUOUS | INSUFFICIENT
  │                       │
  │  Pour field_injection │   → InjectionOracle (SQLi, XSS, SSTI, CMDi,
  │  délègue à :          │      path traversal, NoSQLi, SSRF, open redirect,
  │                       │      mass assignment, business boundary)
  └──────────┬────────────┘
             │
             ▼
  ┌─────────────────────┐
  │  Reproducibility     │   Replay → même verdict que mutation?
  │  _verdict_matches()  │   reprodutibilité = confirming / total_replays
  └──────────┬────────────┘
             │
             ▼
  ┌─────────────────────┐
  │  ConfidenceScore     │   5 dimensions pondérées :
  │  compute_confidence()│
  │                       │   oracle_strength     (0.25) — force du verdict
  │                       │   reproducibility     (0.30) — replay confirme
  │                       │   observation_quality  (0.15) — n observations endpoint
  │                       │   behavioral_specificity(0.15) — diff spécifique au type
  │                       │   experiment_coverage  (0.15) — n experiments / n requis
  │                       │
  │                       │   overall >= 0.85 + any_confirmed → FINDING
  └──────────┬────────────┘
             │
             ├── CONFIRMED → Finding + finding.confirmed
             ├── REFUTED → finding.refuted
             └── AMBIGUOUS → hypothesis.ambiguous → AmbiguityResolver
```

### Sous-composants oracle

| Composant | Rôle |
|---|---|
| **SemanticDiff** | Comparaison sémantique (pas textuelle) des réponses. Jaccard sur les clés JSON, data_identity_score, Z-score. |
| **ViolationOracle** | Verdict mutation-aware via MutationRegistry. Chaque mutation_type a son assesseur spécialisé. |
| **InjectionOracle** | Détection fine : patterns SQL error, payload XSS reflété, template évalué, fichiers /etc/passwd, MongoDB errors, timing blind. |
| **ConfidenceModel** | Modèle 5D calibrable via TuningConfig YAML. Seuils configurables (confirmed_threshold, severity thresholds). |
| **AmbiguityResolver** | Souscrit à `hypothesis.ambiguous` → génère des expériences de désambiguïsation ciblées (max 2 tentatives). |
| **LLM Disambiguator** | Si LLM configuré, tente de désambiguïser les diffs ambigus. Ne peut jamais retourner CONFIRMED (ADR-002). |

---

## 8. PassiveFindingEngine — détection sans attaque

**Fichier** : `core/oracle/passive_engine.py`

Souscrit à `observation.raw`. Détecte directement les problèmes observables :
- Headers de sécurité manquants (HSTS, CSP, XFO, XCTO)
- Cookies sans flags (HttpOnly, Secure, SameSite)
- Informations serveur exposées (Server:, X-Powered-By:)
- Stack traces dans les réponses

Pas d'expérimentation nécessaire → publie directement `finding.confirmed`.

---

## 9. ChainEngine — corrélation d'attaques

**Fichier** : `core/chain/engine.py`

Souscrit à `finding.confirmed`. Quand 2+ findings existent, évalue des **règles
de corrélation** et génère des **chaînes d'attaque multi-étapes**.

### Règles de chaîne (par priorité)

| Règle | Scénario |
|---|---|
| `rule_bola_escalation` | BOLA confirmé → énumérer d'autres objets via l'ID exposé |
| `rule_sqli_exfil` | SQLi confirmé → UNION SELECT pour extraire information_schema |
| `rule_jwt_privesc` | JWT faible + BOLA → forger un token admin et accéder aux objets |
| `rule_cors_xss` | CORS misconfiguration + XSS → exfiltration cross-origin |
| `rule_generic_active_chain` | Fallback : combiner 2 findings en séquence d'exploitation |
| `rule_active_pivot` | Pivoting : utiliser un finding pour atteindre une surface cachée |
| `rule_precondition_chain` | Chaînes théoriques : identifier les préconditions manquantes |

### Exécution

Chaque `ChainSpec` contient des `ChainStep` ordonnés. Chaque step :
1. Injecte le contexte des steps précédents (`context_extractors`)
2. Exécute via `ExperimentEngine.execute_single()` ou `httpx` direct (session reprise)
3. Extrait des valeurs du résultat pour le step suivant

---

## 10. KnowledgeBase — mémoire inter-sessions

**Fichier** : `core/knowledge/base.py`

Base SQLite persistante (`~/.hdwp/knowledge.db`). Accumule les résultats
à travers les sessions de pentest.

### Données stockées

| Table | Contenu |
|---|---|
| `session_meta` | URL cible, type (api/spa/cms/graphql), date, n_findings |
| `pattern_stats` | Taux de confirmation par (property_type, mutation_type, target_type) |

### Influence sur le pipeline

| Point d'injection | Effet |
|---|---|
| **HypothesisPrioritizer** | Les poids sont adaptés selon l'historique. Si SQLi a un taux élevé sur les APIs → priorité augmentée. |
| **InferenceRegistry** | La confiance initiale des propriétés inférées est modulée par les stats KB. |
| **ApplicationModel** | Les poids de confidence du modèle sont ajustés. |
| **TuningConfig** | Override final via YAML (l'utilisateur garde le contrôle). |

### Apprentissage

```
Après chaque session :
  Pour chaque finding confirmé :
    new_weight = alpha * current + (1-alpha) * (1 + confirmed_rate)
    clamped to [0.2, 2.0]
```

Conservateur (`alpha=0.5`) : aucun type de vulnérabilité n'est jamais
complètement abandonné, même avec 0 confirmations historiques.

---

## 11. StateMachineLearner — apprentissage de flux

**Fichier** : `core/state_machine/learner.py`

Souscrit à `observation.raw`. Construit une FSM (automate fini) des flux
applicatifs observés (login → dashboard → actions → logout).

### Algorithme

1. Chaque observation → symbole `(path_pattern, method, status_bucket)`
2. États = symboles uniques
3. Transitions = passages consécutifs entre états
4. Publie `fsm.updated` quand la FSM change significativement

Utilisé par le ChainEngine pour comprendre les dépendances entre endpoints.

---

## 12. Composants transversaux

### LLMLayer (optionnel)

**Fichier** : `core/llm/layer.py`

Couche interprétative Claude. **Contrainte ADR-002** : ne peut jamais
retourner CONFIRMED seul. Utilisations :
1. Désambiguïser les SemanticDiff AMBIGUOUS
2. Proposer des hypothèses complémentaires
3. Interpréter du JavaScript obfusqué
4. Générer les remediation hints contextuels
5. Générer le résumé exécutif du rapport

### MutationRegistry

**Fichier** : `core/mutation_registry.py`

Registre centralisé de tous les types de mutation. Chaque entrée :
- `assess_violation` : (baseline, experiment, diff) → ViolationAssessment
- `compute_specificity` : → float [0,1]
- `plan_experiment` : (hypothesis, spec, model, corpus) → [ConcreteExperimentPlan]
- `apply_mutation` : (plan, session_manager) → NormalizedRequest
- Métadonnées OWASP/CWE + conseil de remédiation

### PluginRegistry

**Fichier** : `plugins/registry.py`

Système de plugins extensible. Chaque plugin peut :
- Inférer des propriétés de sécurité (`infer_properties`)
- Générer des hypothèses (`generate_hypotheses`)
- Enregistrer des mutations custom (`register_mutations`)
- Filtrer par tech_stack (ex: plugin NoSQLi actif uniquement si MongoDB détecté)

### Catégories de plugins existants

| Catégorie | Plugins |
|---|---|
| `authorization` | BOLA, privilege escalation, access control |
| `injection` | SQLi, XSS, SSTI, NoSQLi, path traversal, mass assignment, anomaly probing |
| `configuration` | Headers, CORS, cookies, information disclosure |
| `information_flow` | Open redirect, SSRF, data leaks |
| `session_property` | JWT manipulation, token reuse, session fixation |
| `temporal` | Race conditions |
| `concurrency` | Idempotency |
| `business_invariant` | Business logic (prix négatifs, overflow) |
| `file_operations` | File upload, LFI |
| `state_transition` | State machine violations |

### ScopeGuard

**Fichier** : `core/context/scope_guard.py`

Vérifie que chaque URL/méthode est dans le scope autorisé avant exécution.
Appliqué à l'ObservationEngine ET à l'ExperimentEngine.

### ReportEngine

**Fichier** : `core/report/engine.py`

Génère les rapports finaux en Markdown, JSON et HAR. Souscrit à `finding.confirmed`.

---

## 13. Flux de données complet (un cycle)

```
[Cible HTTP]
     │
     ▼
ObservationEngine.start()
  → ActiveCrawler crawle toutes les pages
  → Pour chaque réponse HTTP :
       émet observation.raw { request, response, tags }
     │
     ▼
ApplicationModel._on_observation()
  → Crée/met à jour EndpointNode, ParameterNode, DataObjectNode, RoleNode
  → Calcule behavioral_profiles (Z-score), status_by_role
  → émet model.updated { snapshot complet }
     │
     ▼
SecurityPropertyEngine._on_model_updated()
  → InferenceModules + Plugins + CompositeInference
  → Pour chaque nouvelle propriété :
       émet property.inferred { SecurityProperty }
     │
     ▼
HypothesisEngine._on_property_inferred()
  → Génère des Hypothesis avec ExperimentSpec[]
  → Prioritize (HIGH/MEDIUM/LOW)
  → Stocke dans la queue interne
     │
     ▼
HDWPEngine.run() appelle exp_engine.run_pending(hyp_engine.get_pending())
     │
     ▼
ExperimentEngine._run_hypothesis()
  → RequestSelector : résout les specs en plans concrets
  → Pour chaque plan :
       1. Exécute baseline (légitime)
       2. MutationModule.apply() → requête mutée
       3. Exécute mutation + replay
       émet experiment.result × 3 (baseline, mutation, replay)
  → émet hypothesis.experiments_ready
     │
     ▼
SemanticOracle._on_experiments_ready()
  → compute_semantic_diff(baseline, mutation)
  → assess_violation(mutation_type, baseline, mutation, diff)
  → Calcule reproducibility via replay
  → compute_confidence(5 dimensions)
  → SI overall >= 0.85 ET verdict CONFIRMED :
       émet finding.confirmed { Finding }
  → SI AMBIGUOUS :
       émet hypothesis.ambiguous
     │
     ├──▶ AmbiguityResolver → nouvelles expériences de désambiguïsation
     ├──▶ ChainEngine → corrélation multi-findings → chaînes d'attaque
     └──▶ KnowledgeBase.record_session() → apprentissage pour la prochaine session
```

---

## 14. Points d'intelligence — où améliorer le raisonnement

### A. Décisions prises automatiquement (actuellement heuristiques)

| Décision | Qui décide | Mécanisme actuel | Amélioration possible |
|---|---|---|---|
| Quelles propriétés inférer | SecurityPropertyEngine | Modules rule-based | Inférence causale, graphe de dépendances |
| Quelle priorité donner aux hypothèses | HypothesisPrioritizer | Poids statiques + KB | Bandits contextuels (exploration/exploitation) |
| Quel payload choisir pour chaque injection | Plugins (listes statiques) | Payloads hardcodés par type | Génération adaptative basée sur la tech stack et les réponses précédentes |
| Comment interpréter un diff ambigu | SemanticOracle + LLM | Heuristiques + LLM fallback | Classifieur entraîné sur les diffs historiques |
| Quand arrêter de tester un endpoint | Refutation tracking (compteur) | Max 3 refutations par surface | Modèle de rendement décroissant |
| Quelle chaîne d'attaque tenter | ChainEngine (règles fixes) | Pattern matching sur CWE pairs | Planification par graphe d'attaque (attack graphs) |
| Comment adapter l'encodage au WAF | EncodingPipeline | Stratégies statiques | Feedback loop : analyser la réponse WAF, adapter le prochain essai |

### B. Données disponibles mais sous-exploitées

| Donnée | Où elle existe | Potentiel |
|---|---|---|
| **Behavioral profiles** (Z-score par endpoint) | ApplicationModel | Détection d'anomalies inconnues sans signature — zero-day heuristique |
| **FSM apprise** | StateMachineLearner | Tester les transitions invalides (état admin sans login), bypass de workflow |
| **Flow map** (graphe de flux de données) | FlowMapBuilder | Propagation de taint automatique, identification de chaînes d'exploitation |
| **Response corpus** (JSON bodies par rôle) | ApplicationModel | Cross-role diffing systématique pour détecter les fuites de données subtiles |
| **Tech stack tags** | ApplicationModel | Sélection de payloads spécifiques au framework (ex: Spring4Shell si spring détecté) |
| **KnowledgeBase historique** | KnowledgeBase | Transfer learning entre cibles similaires, prédiction de vulnérabilités |
| **Timing data** (ms par requête) | ExperimentResult | Side-channel timing attacks, détection de rate-limiting intelligent |

### C. Boucles de feedback manquantes

| Feedback souhaité | État actuel |
|---|---|
| Résultat d'un exploit → ajuster les futurs payloads | Pas de feedback exploit → hypothesis engine |
| WAF block → enrichir les encodages automatiquement | Basique (EncodingPipeline) mais pas de feedback loop |
| Refuted finding → invalider les propriétés parentes | Partiel (ApplicationModel reçoit finding.refuted) |
| Confidence trop basse → demander plus d'observations | Le mode continu re-scanne mais sans ciblage intelligent |
| Chain success → relancer le cycle avec le nouveau contexte | Pas de feedback chain → hypothesis |

---

## 15. Schéma des dépendances d'initialisation

```python
# HDWPEngine.create() → _init_components()

KnowledgeBase ──────────────┐
  │                         │
  ├─▶ HypothesisPrioritizer │ (poids adaptés)
  ├─▶ InferenceRegistry     │ (confiance calibrée)
  └─▶ ApplicationModel      │ (poids confidence)
                            │
LLMLayer (optionnel) ───────┤
  │                         │
  ├─▶ HypothesisEngine      │
  ├─▶ SemanticOracle        │
  └─▶ ObservationEngine     │ (JS interpretation)
                            │
PluginRegistry ─────────────┤
  │                         │
  ├─▶ MutationRegistry      │ (mutations custom)
  ├─▶ SecurityPropertyEngine│ (inférence plugin)
  └─▶ HypothesisEngine      │ (hypothèses plugin)
                            │
ScopeGuard ─────────────────┤
  │                         │
  ├─▶ ObservationEngine     │
  └─▶ ExperimentEngine      │
                            │
SessionManager ─────────────┤
  │                         │
  └─▶ ExperimentEngine      │
                            │
TuningConfig (YAML) ────────┤
  │                         │
  └─▶ SemanticOracle        │ (seuils, poids)
```
