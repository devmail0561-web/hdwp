# Changelog

Toutes les modifications notables sont documentées ici.
Format : [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/)
Versionnage : [SemVer](https://semver.org/lang/fr/)

---

## [2.0.0] — 2026-09-06 — Refonte majeure : moteur sémantique, couverture multi-méthodes, détection étendue

### Moteur d'hypothèses — Retour aux principes sémantiques

**Corrigés**
- Plugins : utilisent maintenant `ParameterNode.semantic` (signal du modèle) au lieu du keyword matching sur les noms de paramètres
- `BOLAPlugin` : filtre par `affects_object` + `auth_required` + inclut `endpoint_path` dans les plans
- `SQLiPlugin` : exclut les sémantiques `id_ref`, `file_path`, `url_redirect` (cibles d'autres plugins)
- `XSSPlugin` : filtre par `response_content_type` — évite les tests XSS sur des endpoints JSON purs
- `SSRFPlugin` / `PathTraversalPlugin` : utilisent `semantic == "url_redirect"` / `"file_path"` en priorité

### Inférence de propriétés — Surface complète

**Ajoutés**
- `IntegrityInference` : règle `_SEMANTIC_TO_PROPERTY` — génère des propriétés de sécurité depuis le champ `ParameterNode.semantic` (path_traversal, SSRF, SSTI, XXE, credential exposure)
- `ConcurrencyInference` : TOCTOU detection sur endpoints POST/PUT avec paramètres business-critiques (price, amount, balance…)
- `ApplicationModel._infer_sensitivity()` : élève automatiquement `DataObjectNode.sensitivity` à `"sensitive"` quand `schema_def` contient des champs PII (email, password, ssn…)
- `ApplicationModel` : parse le header `Allow:` des réponses OPTIONS pour peupler `EndpointNode.methods`

### Oracle — Réduction des faux positifs

**Corrigés**
- `assess_ssti` : détecte les config leaks Flask/Django (`SECRET_KEY`, `DEBUG`…) quand `expected_result` est vide
- `assess_nosqli` : suppression du faux positif systématique `"token" in body.lower()`
- `assess_identity_swap` : AMBIGUOUS quand `data_identity_score is None` sans diff comportemental
- `assess_privilege_escalation` : AMBIGUOUS si les deux rôles retournent le même contenu identique (endpoint public)
- `assess_sqli` : détection time-based blind via `experiment.timing_ms - baseline.timing_ms > 3000ms`
- `_compute_data_identity` : recherche récursive (3 niveaux) — supporte GraphQL et REST avec envelope JSON
- `PassiveFindingEngine` : `reproducibility = 0.65` (au lieu de 1.0 hardcodé), `overall = 0.77`
- `HypothesisPrioritizer` : plancher `surface = max(surface, 0.25)` — grandes APIs ne sont plus pénalisées

### Couverture multi-méthodes

**Ajoutés**
- `ActiveCrawler._probe_methods()` : sonde POST/PUT/PATCH sur chaque endpoint GET découvert → alimente le corpus avec des observations non-GET
- `ActiveCrawler._probe_options()` : parse le header `Allow:` → alimente `EndpointNode.methods`
- `JSExtractor.extract_endpoints()` : retourne `list[tuple[str, str]]` (url, method) — méthode HTTP préservée depuis fetch/axios/XHR
- `RequestSelector` priorité 3 : génère des baselines synthétiques POST/PUT pour les endpoints connus du modèle mais absents du corpus
- `ApplicationModel._store_in_corpus_by_url()` : méthode réelle de la requête source (au lieu de GET hardcodé)
- `request_selector.plan_privilege_escalation` : `method = baseline.method if baseline.method else "GET"` (au lieu de `or "GET"` toujours atteint)

### Détection étendue — 16 nouveaux plugins CWE

**Ajoutés** : `xxe` (CWE-611), `graphql` (CWE-200/284), `crlf` (CWE-113), `deserialization` (CWE-502), `ldap_injection` (CWE-90), `xpath_injection` (CWE-643), `el_injection` (CWE-917), `prototype_pollution` (CWE-1321), `bfla` (CWE-285), `csrf` (CWE-352), `session_fixation` (CWE-384), `file_upload` (CWE-434), `security_headers` (CWE-693), `cache_poisoning` (CWE-345), `http_smuggling` (CWE-444), `http_parameter_pollution` (CWE-235)

### Observation — Couverture HTML/JS/SPA

**Ajoutés**
- `_LinkExtractor` : support `<textarea>`, `<select>/<option>`, formulaires sans `action`
- `HeaderInspector` : `Permissions-Policy`, `COOP`, `COEP`, `CORP`
- `HDWPProxy` : injection snippet JS collecteur (console errors, window.onerror, sendBeacon) dans les réponses HTML
- `SPACrawler` : crawl SPA via Playwright routé à travers le proxy MITM HDWP
- `POST /__hdwp_console__` : route serveur recevant les erreurs JS capturées

### Réseau — Tor par défaut

**Ajoutés**
- `http_client.py` : module central `build_client()` — toutes les requêtes sortantes passent par Tor (`socks5h://127.0.0.1:9150`) par défaut
- `socksio>=1.0` : dépendance ajoutée pour SOCKS5 via httpx
- Configuration via `options.tor_proxy` dans `hdwp-context.yaml`
- Exploits : 2 tentatives (Tor d'abord, connexion directe en fallback si Tor bloque la cible)

### Infrastructure

**Corrigés** (bugs pré-existants)
- `hdwp_proxy.py:422` : `asyncio.StreamWriter` sans argument `loop` (Python 3.12)
- `hdwp_proxy.py:200` : `Transfer-Encoding: chunked` décodé correctement via `readexactly()`
- `hdwp_proxy.py:376` : scope check AVANT le tunnel HTTPS CONNECT
- `hdwp_proxy.py:183` : multiples `Set-Cookie` headers préservés
- `version_scanner.py:157` : parsing CVSS v3 vecteurs corrigé
- `experiment/engine.py:80` : ordonnancement HIGH-before-LOW préservé avec `asyncio.ensure_future`
- `exploit.py:236` : `await sm.get_client()` → `sm.get_client()` (méthode synchrone)
- `exploit.py:202` : `_extract_sensitive` limitée à 10 niveaux de récursion
- `chain/engine.py:283` : `HDWPEvent` ne peut plus être double-encapsulé dans bus.emit

---

## [0.6.0] — 2026-09-01

### TUI Hacker (Textual)

**Ajoutés**
- `src/hdwp/tui/` — TUI Textual complet (MIT, Python, async-native)
- `HDWPApp` : panneaux multiples — logo ASCII HDWP, statut engine avec barres de progression, feed d'événements temps réel, table de findings live
- Thème hacker : fond #0d0d0d, vert matrix (#00ff41) pour le statut, cyan (#00bfff) pour les events, rouge/jaune/vert par sévérité
- Raccourcis clavier : [R]un, [A]uth, [K]nowledge, [S]top, [L]ogs, [Q]uit
- `hdwp run` lance maintenant le TUI au lieu d'une sortie Rich statique
- `--no-tui` flag pour CI/headless

### Capture Automatique de Credentials

**Ajoutés**
- `CREDENTIALS_CAPTURED` event dans le bus
- `_extract_auth_token()` : détecte les tokens Bearer dans les réponses JSON (`token`, `access_token`, `jwt`, etc.) et les cookies de session — déduplication par valeur
- La capture se fait AVANT le scope check — les tokens de login sont capturés même si `/login` est exclu du scope
- `SessionManager.add_role()` : ajoute dynamiquement un rôle capturé avec `asyncio.Lock`
- `HDWPEngine._on_credentials_captured()` : crée un nouveau `RoleConfig` et l'injecte dans le `SessionManager`
- TUI affiche `[KEY] Token capturé : captured_1 (bearer)` en temps réel

**Tests**
- 404 tests, ruff clean, 65 fichiers source

---

## [1.0.0] — 2026-09-01 — Moteur robuste : 5 limitations fondamentales corrigées

### Limitation 1 — Découverte REST

**Ajoutés**
- `JSExtractor` (`core/observation/js_extractor.py`) : extraction d'endpoints depuis les fichiers JavaScript — regex fetch/axios/baseURL, normalisation `${id}→{param}`, filtrage faux positifs
- `ActiveCrawler` : télécharge et parse les scripts `<script src>` intégrés dans les pages HTML (profondeur ≤2)
- `ObservationEngine.start()` : auto-discovery OpenAPI AVANT le crawl HTML (tente /swagger.json, /openapi.json et 8 autres chemins)
- `auto_discover_spec()` dans `openapi_seeder.py` : discovery automatique sans configuration
- `_extract_links_from_body()` dans `ApplicationModel` : extraction d'URLs depuis les réponses JSON HATEOAS

### Limitation 2 — Compte unique / BOLA

**Ajoutés**
- `AutoRegistrar` (`core/observation/auto_registrar.py`) : crée automatiquement 2 comptes de test via `/register`, `/api/users`, etc. si `allow_write=True` et moins de 2 rôles configurés
- `cleanup()` : supprime les comptes créés en fin de session (best-effort)
- Intégré dans `HDWPEngine.run()` avant les expériences

### Limitation 3 — Race condition (double-spend)

**Ajoutés**
- `run_race_condition_with_verification()` dans `TemporalModule` : pattern avant/après — mesure `delta_per_op` (1 opération), puis N concurrent, puis compare `delta_race` vs `N × delta_per_op`
- `_analyze_state_change()` : détecte les opérations perdues dans les champs numériques (balance, counter, stock)
- `_read_state()` helper pour exécuter des requêtes de lecture/écriture standalone

### Limitation 4 — Logique métier

**Ajoutés**
- `CoherenceInference` rempli : 3 règles — paramètres business-critiques (price/amount/quantity → propriété INTEGRITY), CORS, headers sécurité
- `assess_business_boundary()` dans `injection_oracle.py` : détecte valeurs négatives dans champs financiers, valeurs limites acceptées
- `HypothesisEngine` : génère 5 probes boundary pour les propriétés COHERENCE (`0`, `-1`, `-9999`, `0.001`, `9999999`)
- `NEGATIVE_VALUE_IN_FINANCIAL_FIELD` regex pour détecter `"total": -9.99` dans les réponses

### Limitation 5 — OAuth2

**Ajoutés**
- `CredentialConfig` : 2 nouveaux types `oauth2_password` et `oauth2_client_credentials` + champs `token_endpoint`, `client_id`, `client_secret`, `scope`, `refresh_token`
- `OAuth2Client` (`core/experiment/oauth2_client.py`) : `get_token()` avec cache + expiration, `force_refresh()`, support des 2 grant types
- `SessionManager.resolve_auth_headers()` (async) : acquiert le token OAuth2 si nécessaire, fallback sync pour les autres types
- Refresh automatique sur 401 dans `ExperimentEngine._execute()`
- `hdwp-context.example.yaml` : exemples OAuth2 commentés

**Tests**
- 451 tests, ruff clean, 68 fichiers source

---

## [Unreleased]

---

## [0.5.0] — 2026-09-01

### Multi-LLM Provider

**Ajoutés**
- `LLMConfig` dans `config_schema.py` : `provider` (anthropic|openai|ollama), `model`, `base_url`
- `OpenAICompatibleLLMLayer` : couvre OpenAI, Ollama (local), LM Studio, vLLM, Together, Groq via SDK `openai`
- `create_llm_layer(config)` : factory multi-provider, résolution des clés par convention (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `HDWP_LLM_API_KEY`) — Ollama sans clé requise
- Rétrocompatibilité : sans section `llm:`, comportement inchangé
- `hdwp-context.example.yaml` : section `llm:` commentée avec exemples pour les 3 providers
- `pyproject.toml` : `openai>=1.0` dans `[llm]`

### KnowledgeBase — Apprentissage inter-sessions

**Ajoutés**
- `KnowledgeBase` (`core/knowledge/base.py`) : stockée dans `~/.hdwp/knowledge.db`, persiste entre pentests
- `record_session(findings, session_id, target_url)` : extrait les patterns de vulnérabilités confirmées/réfutées
- `get_adapted_weights()` : retourne les poids ajustés par l'historique. Bootstrap-safe : poids statiques inchangés si 0 session
- Formule : `weight = base * clamp(1 + 0.5*(confirmed_rate - 0.5), 0.2, 2.0)`
- `HypothesisPrioritizer.with_weights(weights)` : classmethod pour injecter les poids KB
- `HypothesisEngine` accepte `prioritizer=` injecté
- `HDWPEngine` : charge la KB avant la session, met à jour après les findings
- `mutation_type` stocké dans `Finding.proof["mutation_type"]` pour extraction par la KB
- `hdwp knowledge stats` : tableau des patterns appris (property_type, mutation_type, taux confirmation, confiance)
- `hdwp knowledge reset` : réinitialise les patterns (garde l'historique de sessions)

**Tests**
- 390 tests, ruff clean, 62 fichiers source

---

## [0.4.1] — 2026-09-01 — Audit v2 corrections

### Corrections (audit v2 post-Phase 7)

**HAUTE**
- `interpret_js` regex : `.*?` (non-greedy) → `.*` (greedy) pour capturer les tableaux JSON imbriqués
- OpenAPI seeder : filtre scope (`fnmatch`) sur tous les endpoints avant émission, plus d'URL hors-scope dans le modèle
- OpenAPI seeder : endpoints avec `security` requirement → observation 401 pour anonymous → `auth_required` auto-détecté
- `_on_fsm_updated` : guard FSM-changée avant d'émettre `model.updated` — élimine les cycles de re-calcul inutiles
- `test_crawler_discovers_api_endpoints_from_html` : utilise maintenant le vrai `ActiveCrawler.crawl()` via patch transport

**MOYENNE**
- Version hardcodée `v0.1.0` dans rapport Markdown → `hdwp.__version__` dynamique
- `target="cible"` → URL réelle passée depuis `ContextLoader` dans la CLI `hdwp run --report`
- CLI : version affichée dynamiquement (`hdwp.__version__`) au lieu de `v0.1.0` hardcodé

**Tests**
- 366 tests, ruff clean

---

## [0.4.0] — 2026-09-01

### Phase 7 — LLM complet

**Ajoutés**
- `generate_remediation_hint(finding)` : conseil de remédiation contextuel via LLM, enrichit les findings CONFIRMED
- `generate_executive_summary(findings, target)` : résumé exécutif LLM intégré dans `generate_markdown()`
- `interpret_js(source)` : extraction d'endpoints depuis JavaScript obfusqué
- `propose_hypotheses(model, existing_count)` : hypothèses complémentaires LLM pour patterns non couverts

### Phase 6 complète — Alembic + OpenAPI seeding

**Ajoutés**
- Alembic migrations : `alembic.ini`, `alembic/env.py` (async), `alembic/versions/001_initial_schema.py` (upgrade + downgrade)
- `DiscoveryConfig` dans `config_schema.py` : champs `openapi_spec` et `seed_endpoints`
- `OpenAPISeeder` (`core/observation/openapi_seeder.py`) : génère des observations synthétiques depuis une spec OpenAPI (JSON/YAML, local/URL) ou une liste d'endpoints
- `ObservationEngine.seed_from_spec()` + appel automatique dans `HDWPEngine.run()` avant le crawl

### Tests d'intégration améliorés

**Ajoutés**
- `tests/integration/test_crawler_discovery.py` : 3 tests validant la découverte autonome via crawler HTML — le crawler suit les liens `<a href>` de la page d'accueil vers les endpoints REST, construit le modèle et infère des propriétés BOLA sans injection manuelle d'observations
- Page d'accueil HTML ajoutée au mock server (`GET /`) avec liens vers tous les endpoints API

**Tests**
- 364 tests, ruff clean, 60 fichiers source

---

---

## [0.3.1] — 2026-09-01 — Audit corrections

### Corrections (audit rigoureux post-Phase 6)

**CRITIQUE**
- Hypothèses persistées en base : `HypothesisEngine` injecte `Repository`, `save_hypothesis()` appelé avant émission bus → `update_hypothesis_status()` n'est plus un no-op silencieux
- Race condition experiment.result / experiments_ready : `await self._bus.drain()` avant l'émission `hypothesis.experiments_ready` → l'oracle reçoit le buffer complet

**HAUTE**
- `UnboundLocalError` dans `ExperimentEngine._execute` : `timing_ms` et `norm_resp` initialisés avant le `try`, catch élargi à `Exception`
- FSM câblée : `ApplicationModel` souscrit à `fsm.updated`, stocke la FSM dans `_on_fsm_updated()`, `snapshot()` inclut `fsm=self._fsm`, `StateInference` l'utilise en priorité
- `__import__("httpx")` fragile remplacé par `import httpx` normal dans `engine.py`
- `PassiveFindingEngine` : déduplication sur path pattern normalisé (plus de flooding sur /api/users/1, /users/2, etc.)
- `field_injection` sur body non-dict : exception catch + log warning (pas de crash silencieux)

**MOYENNE**
- `asyncio.get_event_loop()` → `asyncio.get_running_loop()` dans `event_bus.py` et `proxy_capture.py`
- `auth_required` : si rôle authentifié (200) observé sans anonymous correspondant, inféré comme potentiellement auth_required
- `timing_ms` double calcul dans `TemporalModule` : utilise la variable `timing` déjà calculée
- Couplage ADR-001 : `StateMachineLearner` n'importe plus `ApplicationModel` → nouveau module `core/model/url_utils.py` avec `normalize_url_path()`

**BASSE**
- `_role_from_headers()` (code mort) supprimé de `ExperimentEngine`

**Tests**
- 336 tests, ruff clean, 59 fichiers source

---

---

## [0.3.0] — 2026-09-01

### Phase 5 — Rapports & CLI

**Ajoutés**
- `ReportEngine` : abonnement `finding.confirmed`, génère Markdown/JSON/HAR
- `render_markdown()` : rapport structuré par sévérité avec chaîne de preuve
- `compute_summary()` : totaux par sévérité, OWASP, confiance moyenne
- `build_har()` : HAR 1.2 par finding pour replay
- CLI complète : `hdwp run` (tableau rich), `hdwp model` (export JSON), `hdwp report` (md/json/har), `hdwp replay`, `hdwp plugin list/enable/disable`

### Phase 5.5 — LLM désambiguïsation

**Ajoutés**
- `LLMLayerProtocol` (ABC) + `AnthropicLLMLayer` : désambiguïsation des diffs AMBIGUOUS
- `_parse_llm_verdict` : retourne AMBIGUOUS ou REFUTED — jamais CONFIRMED (ADR-002 respecté)
- `create_llm_layer()` : factory depuis `ANTHROPIC_API_KEY`, silencieuse si absente
- `SemanticOracle` : branche LLM sur INSUFFICIENT_DATA si layer disponible

### Phase 6 — Plugins avancés, ProxyCapture, FSM

**Ajoutés**
- `CoherenceInference` : CORS sur endpoints authentifiés, headers sécurité sur données sensibles
- `TemporalInference` : détection token expiration requis
- `StateInference` : détection flux multi-étapes (step/stage/wizard)
- `InfoDisclosurePlugin` : exposition de données sensibles via erreurs
- `SSRFPlugin` : injection sur paramètres URL-like, oracle heuristique (pas de callback server)
- `RaceConditionPlugin` : endpoints critiques (payment/order/transfer)
- `InjectionOracle.assess_ssrf()` : root:x: → CONFIRMED, connection refused → AMBIGUOUS
- `ProxyCapture` : intégration mitmproxy optionnelle, graceful degradation si absent, `start_passive()` dans ObservationEngine
- `StateMachineLearner` : clustering de séquences (path_pattern, method, status_bucket), émet `fsm.updated` tous les 10 obs
- `fsm_to_dot()` + `fsm_summary()` : visualisation FSM
- 3 nouveaux entry points plugin dans `pyproject.toml`

**Tests**
- 333 tests, ruff clean, 58 fichiers source

---

### A venir
- ReportEngine : Markdown, JSON, HAR
- CLI `hdwp report`, `hdwp replay` complètes
- LLM minimaliste (disambiguate_diff)

---

## [0.2.0] — 2026-09-01

### Phase 4 — Expériences & Oracle (MVP fonctionnel)

**Ajoutés**
- `RequestSelector` + `ConcreteExperimentPlan` : résolution des ExperimentSpec abstraites en requêtes HTTP concrètes via le corpus
- `SessionManager` : sessions httpx per-rôle, injection CSRF, `TokenExpiredError`
- `MutationModule` : identity_swap, object_ref_change, privilege_escalation, field_injection, origin_test, jwt_manipulation
- `ExperimentEngine` : baseline + mutation + replay, injection credentials depuis SessionManager
- `SemanticDiff` : diff comportemental avec filtre champs volatils, Jaccard
- `ViolationOracle` : verdict conscient du type de mutation (identity_swap: similar=vuln, object_ref_change: 2xx=vuln, privilege_escalation: 2xx=vuln, field_injection: délègue à InjectionOracle, jwt_manipulation: 2xx=vuln, origin_test: ACAO=*=vuln)
- `SemanticOracle` : orchestration diff + violation + confiance, CONFIRMED/REFUTED/INSUFFICIENT_DATA
- `ConfidenceModel` 5D : oracle_strength, reproducibility, observation_quality, behavioral_specificity, experiment_coverage
- `HDWPEngine` : orchestration complète du pipeline, context manager
- `hdwp run` : CLI fonctionnelle avec tableau rich des findings

### Robustesse (corrections post-audit)

**Lacune : auth_required jamais détecté**
- `ApplicationModel._update_auth_required()` : détecte automatiquement depuis les codes de statut (anonymous 401/403 + authentifié 200 → auth_required=True)

**Lacune : object_ref_change fragile**
- `RequestSelector._fallback_probe_values()` : génère jusqu'à 3 valeurs candidates (N-1, N+1, petits entiers pour integers ; UUIDs aléatoires pour UUIDs)

**Lacune : findings passifs jamais émis**
- `PassiveFindingEngine` : détecte depuis les observations — headers manquants (HSTS/CSP/XFO/XCTO), server disclosure, cookies sans flags, stack traces exposées

**Lacune : zéro détection d'injection**
- `InjectionOracle` : patterns SQL (17 bases de données), détection XSS reflection, évaluation SSTI, mass assignment
- `IntegrityInference` : inférence de propriétés d'intégrité pour tous les paramètres user-controlled
- `HypothesisEngine` : génération d'hypothèses SQLi/XSS/SSTI/mass_assignment

**Lacune : JWT non testé**
- `JWTMutator` : forge alg:none, expire le token, brute-force secrets HS256 (sans dépendance externe)
- `JWTPlugin` : hypothèses JWT pour les endpoints Bearer

**Lacune : CORS non testé**
- `CORSPlugin` : mutation origin_test, détection Access-Control-Allow-Origin permissif
- `ViolationOracle` : assess_cors

**Lacune : TemporalModule absent**
- `TemporalModule` : run_race_condition (asyncio.gather), run_token_reuse, assess_race_condition

**Tests**
- 274 tests, `ruff check src/` : 0 erreurs

---

### A venir
- `ExperimentEngine` : exécution des mutations HTTP
- `MutationModule` : identity_swap, object_ref_change, privilege_escalation
- `SemanticOracle` : orchestration diff + confiance + statut
- `hdwp run` fonctionnel (pipeline complet)
- Test d'intégration end-to-end sur mock server

---

## [0.1.0] — 2026-09-01

### Fondations (Phase 0-1)

**Ajoutés**
- Scaffolding complet : `pyproject.toml` (hatchling), `.gitignore`, `LICENSE` (MIT, Copyright M. TENDENG)
- CLI `hdwp` avec 5 sous-commandes : `run`, `model`, `report`, `replay`, `plugin` (stubs)
- `AsyncEventBus` : wrapper pyee typé, 12 types d'événements HDWPEventMap, `drain()`, `wait_for()`, historique
- 20+ modèles Pydantic v2 : `RawObservation`, `SecurityProperty`, `Hypothesis`, `ExperimentSpec`, `ExperimentResult`, `SemanticDiff`, `ConfidenceScore`, `Finding`, tous les nœuds de modèle
- `ContextLoader` : parse YAML, résolution `${ENV_VAR}`, `EngineContext` frozen
- `ScopeGuard` : fnmatch, bloque méthodes destructives, non-débrayable au runtime
- `Repository` async : SQLite + SQLModel, 7 tables, credential filtering avant persistance
- `TokenBucket` async : rate limiting token bucket, `from_rpm()`

### Observation & Modélisation (Phase 2)

**Ajoutés**
- `normalize_request/normalize_response` : normalisation HTTP, redaction headers credential, extraction paramètres de chemin
- `HeaderInspector` : détection headers sécurité manquants (HSTS, CSP, XFO, XCTO), server disclosure, flags cookie
- `ActiveCrawler` : BFS httpx async, multi-rôle, respect scope + rate limit, extraction liens HTML, tag `role:` sur observations
- `ObservationEngine` : orchestrateur du cycle de vie du crawl
- `ApplicationModel` : graphe comportemental incrémental depuis `observation.raw` — endpoints, paramètres, objets de données, rôles, corpus de requêtes
- `model_confidence` et `is_ready` : signal quand le modèle a assez de couverture pour raisonner

**Corrections (audit)**
- Endpoint key : path seul comme clé (plus `METHOD:path`), méthodes accumulées dans un seul `EndpointNode`
- Role tracking : lecture du tag `role:` au lieu du header `Authorization` redacté
- Payloads event bus standardisés en `model_dump()` (dicts JSON)

### Propriétés & Hypothèses (Phase 3)

**Ajoutés**
- `SecurityPropertyEngine` : 7 modules d'inférence, déduplication par `formal_statement`, intégration `PluginRegistry`
- `AuthorizationInference` : 3 règles — BOLA (paramètre `affects_object` integer/uuid), endpoint auth (auth_required + roles), séparation de rôles
- `ConfidentialityInference` : objets avec `sensitivity=private/sensitive` et `owner_parameter`
- 5 stubs d'inférence (state, integrity, coherence, temporal, concurrency) pour Phase 6
- `HypothesisEngine` : génération d'hypothèses falsifiables depuis les propriétés, priorisation `HypothesisPrioritizer`, intégration plugins
- `HypothesisPrioritizer` : `f(impact_weight × surface_ratio × observation_factor)` avec paliers HIGH/MEDIUM/LOW
- `HDWPPlugin` ABC + `PluginRegistry` (découverte `importlib.metadata.entry_points`)
- `BOLAPlugin` : hypothèses `object_ref_change` sur paramètres `affects_object`
- `AuthZPlugin` : hypothèses `privilege_escalation` sur endpoints `auth_required`

### Pré-Phase 4 — Oracle & Sélection (corrections audit)

**Ajoutés**
- `RequestSelector` + `ConcreteExperimentPlan` : pont entre `ExperimentSpec` abstraite et requête HTTP concrète via le corpus `ApplicationModel`
- `SessionManager` : sessions httpx persistantes par rôle, injection CSRF dynamique, `TokenExpiredError` sur 401
- `SemanticDiff` : comparaison comportementale, filtre champs volatils (timestamps, nonces, CSRF), Jaccard sur clés JSON
- `ViolationOracle` : verdict conscient du type de mutation — `identity_swap` (similar=vuln), `object_ref_change` (2xx=vuln), `privilege_escalation` (2xx=vuln)
- `ConfidenceModel` : 5 dimensions avec définitions opérationnelles — `observation_quality` log-scale, `behavioral_specificity` mutation-aware
- `VulnerableAppTransport` (mock server) : BOLA délibérée sur `GET /api/users/{id}`, AuthZ bypass sur `GET /api/admin/users`

**Corrections (audit critique)**
- `ViolationOracle` : l'ancien oracle confondait "différence significative" avec "vulnérabilité" — inversé pour `identity_swap` (BOLA = réponses *similaires*, pas différentes)
- Plan : L* remplacé par clustering de séquences (L* = 2-4 semaines, hors portée)
- Plan : LLM avancé en Phase 5.5 pour débloquer les diffs AMBIGUOUS
- Plan : Alembic ajouté Phase 6 pour migrations de schéma SQLite

**Tests**
- 182 tests, `ruff check src/` : zéro erreur

---

[Unreleased]: https://github.com/mtendeng/hdwp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mtendeng/hdwp/releases/tag/v0.1.0
