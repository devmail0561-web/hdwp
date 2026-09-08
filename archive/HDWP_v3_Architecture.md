# HDWP v3 — Analyse Critique et Architecture Cible

> Auteur : analyse structurelle du moteur v1 et proposition d'architecture v2
> Statut : document de conception — Michel Tendeng

---

## Partie I — Diagnostic Rigoureux du Moteur v1

### 1.1 Ce que le moteur prétend faire vs ce qu'il fait réellement

Le document d'architecture v1 revendique un moteur "hypothesis-driven" fondé sur un
cycle scientifique PDWST. C'est vrai sur la forme. Sur le fond, chaque composant
est plus faible que ce que son nom suggère.

#### `SemanticOracle` — il n'y a pas de sémantique

Le nom est trompeur. `compute_semantic_diff()` calcule :
- un score Jaccard sur les **clés** JSON (structure, pas sens)
- un ratio de taille de réponse (métrique proxy)
- un Z-score sur la distribution des tailles par endpoint

Ce sont des métriques **syntaxiques et statistiques**, pas sémantiques. Le moteur
ne comprend pas que `{"user_id": 42, "email": "alice@x.com"}` retourné en réponse
à une requête authentifiée avec le token de `user_id=7` est une violation d'accès.
Il peut le détecter *si* les champs `user_id` sont enregistrés comme `data_identity_fields`
et si le `SemanticIdentityCheck` est implémenté — mais ce composant n'est pas décrit
dans l'architecture v1 comme un mécanisme explicite.

`data_identity_score` existe dans la liste des dimensions calculées, mais son algorithme
n'est pas spécifié. C'est soit une heuristique floue, soit une fonctionnalité planifiée
mais non implémentée. Dans les deux cas, ce n'est pas de la sémantique.

#### `HypothesisEngine` — les hypothèses sont des templates, pas des inférences

Une hypothèse HDWP v1 ressemble à :

```
SecurityProperty("INTEGRITY: param 'username' rejects injection")
  → Hypothesis("Le paramètre 'username' est vulnérable à une injection")
    → ExperimentSpec(payload="' OR '1'='1")
    → ExperimentSpec(payload="<script>alert(1)</script>")
    → ExperimentSpec(payload="{{7*7}}")
```

C'est une **expansion de template** : une propriété formelle active une liste
prédéfinie de payloads correspondant à sa catégorie. L'`ExperimentSpec` généré
ne dépend pas du contexte observé de l'endpoint — pas du type de paramètre inféré,
pas du framework détecté, pas des réponses passées sur cet endpoint.

Une vraie hypothèse en sécurité ressemblerait à :
> *"Ce paramètre accepte des valeurs numériques (observé : 3 entiers distincts).
> Le framework est Spring + PostgreSQL (tag détecté). Les entiers sont probablement
> utilisés dans une clause WHERE. Test : injecter `1 AND pg_sleep(3)=0` pour
> confirmer l'interprétation SQL via timing."*

Ce raisonnement contextuel n'existe pas dans v1.

#### `SecurityPropertyEngine` — inférence fermée, pas ouverte

Les propriétés sont inférées par un `InferenceRegistry` de modules rule-based.
La liste des types de propriétés (`AUTHORIZATION`, `CONFIDENTIALITY`, `INTEGRITY`,
`STATE`, `COHERENCE`, `TEMPORAL`, `CONCURRENCY`) est fixe. Aucun mécanisme ne permet
d'inférer une propriété dont le type n'est pas dans cette taxonomie.

Conséquence : le moteur est **borgne face aux vulnérabilités émergentes**. Une
Business Logic Vulnerability qui viole simultanément `INTEGRITY` et `STATE` de
façon non standard (ex : état de panier manipulable pour appliquer un coupon après
validation) ne peut être inférée que si une règle explicite la couvre.

#### `KnowledgeBase` — calibration, pas apprentissage

La formule d'apprentissage est :

```
new_weight = alpha * current + (1 - alpha) * (1 + confirmed_rate)
clamped to [0.2, 2.0]
```

C'est un **Exponential Moving Average** sur un scalaire par `(property_type,
mutation_type, target_type)`. Le moteur apprend que "SQLi sur les APIs a un taux de
confirmation élevé" et booste la priorité des hypothèses SQLi futures.

Ce qu'il n'apprend pas :
- La structure des endpoints vulnérables (patterns URL, nommage des paramètres)
- Les corrélations entre tech_stack et types de vulnérabilités
- Les patterns de réponse qui précèdent une vulnérabilité confirmée (early signals)
- Les chaînes d'attaque qui ont fonctionné sur des cibles similaires

L'apprentissage v1 calibre des scalaires. Il ne généralise pas.

#### `ChainEngine` — corrélation à sens unique, pas planification

Les règles de chaîne (`rule_bola_escalation`, `rule_sqli_exfil`, etc.) sont des
**patterns IF-THEN fixés** : si finding A et finding B sont tous deux confirmés,
alors tenter la chaîne C. C'est de la corrélation exhaustive sur un ensemble fini
de patterns.

Le moteur ne peut pas découvrir qu'une chaîne `SSRF → metadata leak → credentials →
account takeover` est possible sur une cible spécifique si cette séquence exacte
n'est pas encodée dans une règle. Il ne planifie pas vers un objectif.

#### `ApplicationModel` — graphe riche, mais sous-exploité

L'`ApplicationModel` accumule `EndpointNode`, `ParameterNode`, `DataObjectNode`,
`RoleNode` avec `behavioral_profiles`, `status_by_role`, `response_corpus`.
C'est la donnée la plus riche du système et la moins exploitée.

Le `behavioral_profile` (Z-score) est calculé mais sert seulement à l'`anomaly_response`
tag sur l'observation. Il n'alimente pas directement une propriété de sécurité ni
une hypothèse. Le `response_corpus` (JSON bodies par rôle) est stocké mais le
cross-role diffing systématique décrit en section 14.B est marqué comme "potentiel",
pas comme mécanisme implémenté.

---

### 1.2 Les défauts structurels profonds

#### Défaut 1 : absence de modèle de menace dynamique

HDWP v1 n'a pas de représentation explicite du **modèle de menace** de l'application
testée. Il accumule des observations et infère des propriétés, mais il n'a jamais
de vue d'ensemble du type :

> *"Sur cette application, les assets critiques sont [invoices, payment_methods].
> Les acteurs sont [anonymous, user, admin]. Les flux de données sensibles sont
> [user→invoice, user→payment]. Les surfaces d'attaque prioritaires sont [ces 3
> endpoints] parce qu'ils sont à l'intersection de ces flux et de ces assets."*

Sans modèle de menace dynamique, le moteur teste tout de façon uniforme. Il dépense
autant d'effort sur `GET /api/health` que sur `POST /api/payments`.

#### Défaut 2 : le bus d'événements crée une illusion de découplage

L'`AsyncEventBus` est architecturalement correct. Mais les 21 types d'événements
forment un **graphe de dépendances implicites** non documenté. Par exemple :
`model.updated` doit avoir été émis avant que `property.inferred` soit utile,
qui doit précéder `hypothesis.generated`, qui doit précéder `experiment.result`.

Ce couplage temporel implicite signifie que le pipeline est en réalité **séquentiel
déguisé en event-driven**. `bus.drain()` avant chaque phase confirme cela. Le
bénéfice réel du bus est l'extensibilité (plugins), pas la concurrence.

Le vrai problème : cette architecture ne supporte pas un **pipeline continu**
où une nouvelle observation en phase 1 pourrait déclencher une hypothèse haute
priorité pendant que d'autres expériences de phase 3 sont en cours. Le `drain()`
impose une barrière synchrone.

#### Défaut 3 : l'oracle ne peut pas apprendre à distinguer les vrais positifs

Le `ConfidenceModel` avec ses 5 dimensions (`oracle_strength`, `reproducibility`,
`observation_quality`, `behavioral_specificity`, `experiment_coverage`) est un
modèle linéaire fixe. Le seuil `>= 0.85` pour émettre un finding est configuré
dans `TuningConfig YAML`.

Ce modèle ne peut pas apprendre que sur une application REST moderne avec WAF
Cloudflare, un `behavioral_specificity` de 0.6 combiné à un timing > 3s est
plus prédictif d'un vrai positif qu'un `oracle_strength` de 0.9 sans timing
anomaly. Les poids sont statiques (sauf override YAML manuel).

#### Défaut 4 : la génération de payloads ignore la surface réelle

`MutationModule` applique des mutations "minimales". Les payloads d'injection
viennent de listes statiques dans les plugins. Ces listes sont découplées de :

- Le **type observé** du paramètre (int, uuid, email, JSON object, base64)
- Les **valeurs observées** passées (ex : si toutes les valeurs observées sont
  des UUIDs v4, `' OR '1'='1` sera probablement rejeté par validation côté client
  avant même d'atteindre la couche SQL)
- La **tech stack confirmée** (PostgreSQL vs MySQL vs SQLite → syntaxes différentes)
- La **réponse WAF** aux tentatives précédentes

#### Défaut 5 : absence de raisonnement inter-sessions exploitable

La `KnowledgeBase` stocke des statistiques par `(property_type, mutation_type,
target_type)`. Le `target_type` est une catégorie grossière (api/spa/cms/graphql).

Ce découpage perd toute l'information structurelle qui permettrait le transfer
learning : deux APIs e-commerce avec des patterns URL similaires et le même
stack technique auraient probablement des profils de vulnérabilité similaires.
HDWP v1 les traite comme deux entrées statistiques indépendantes dans le même
bucket `api`.

---

### 1.3 Ce que le moteur sait faire correctement

Il ne s'agit pas de tout refaire. Ces composants sont corrects et doivent être conservés :

- **AsyncEventBus** : le pattern pub/sub est le bon choix architectural. La limite
  n'est pas le bus mais l'utilisation synchrone qu'on en fait.
- **ScopeGuard** : robuste, appliqué aux deux points d'entrée critiques.
- **SessionManager** : gestion du pool de clients par rôle, CSRF, OAuth2 refresh —
  c'est du bon travail d'ingénierie.
- **PassiveFindingEngine** : détection sans attaque correctement découplée.
- **PluginRegistry** : l'extensibilité est bien pensée. Les filtres `tech_stack`
  sur les plugins sont une bonne décision.
- **StateMachineLearner** : l'idée est bonne, l'implémentation FSM par symboles
  est correcte. Le problème est l'exploitation en aval, pas la construction.
- **ReportEngine** : non critique pour l'intelligence du moteur.

---

## Partie II — Ce que "intelligent" signifie concrètement pour un moteur de pentest

Avant de concevoir l'architecture v2, il faut définir précisément ce que
"intelligence" signifie dans ce contexte. Trois capacités distinctes :

### 2.1 Raisonnement causal

Le moteur doit pouvoir répondre à : *"Pourquoi cet endpoint est-il prioritaire ?"*
avec une justification causale, pas une priorité numérique opaque. Un raisonneur
causal représente les dépendances entre composants de l'application et infère
les conséquences d'une violation sur un composant sur l'ensemble du graphe.

### 2.2 Adaptation contextuelle

Le comportement du moteur doit changer en fonction des observations en temps
réel, pas seulement entre les sessions. Si le premier payload SQLi retourne
une erreur PostgreSQL, les payloads suivants doivent être PostgreSQL-spécifiques.
Si un WAF bloque avec un pattern de réponse identifiable, les mutations suivantes
doivent intégrer des techniques de bypass adaptées à ce WAF.

### 2.3 Planification orientée objectif

Le moteur doit avoir un **objectif** (exfiltrer des données, élever les
privilèges, prendre le contrôle d'un compte) et travailler *vers* cet objectif,
pas tester exhaustivement la surface d'attaque. Cela implique de savoir quand
s'arrêter (objectif atteint ou surface épuisée) et de savoir comment chaîner
les findings pour progresser vers l'objectif.

---

## Partie III — Architecture HDWP v3

### 3.1 Vue d'ensemble

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                          HDWPEngine v2 (orchestrateur)                           │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐ │
│  │                       ThreatModelEngine [NOUVEAU]                           │ │
│  │   Asset Registry · Actor Graph · DataFlow Graph · Attack Surface Scorer     │ │
│  └─────────────────────────────────┬───────────────────────────────────────────┘ │
│                                    │ threat.model.updated                        │
│  ┌─────────────┐   observation.raw │                                             │
│  │ Observation │──────────────────▶│                                             │
│  │ Engine      │                   ▼                                             │
│  │ (inchangé)  │  ┌────────────────────────────────────────────────────────┐    │
│  └─────────────┘  │          ApplicationModel v2 (enrichi)                 │    │
│                   │  EndpointGraph · ParameterModel · BehavioralProfiles   │    │
│                   │  ResponseCorpus · InvariantStore [NOUVEAU]             │    │
│                   └──────────────────┬─────────────────────────────────────┘    │
│                                      │ model.updated                            │
│                                      ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                   ReasoningLayer [NOUVEAU — cœur v2]                      │  │
│  │                                                                           │  │
│  │   CausalInferenceEngine          ContextualHypothesisEngine               │  │
│  │   ├── DataFlowAnalyzer           ├── ContextBuilder                       │  │
│  │   ├── InvariantLearner           ├── PayloadSynthesizer                   │  │
│  │   ├── PrivilegeGraphAnalyzer     ├── AdaptiveSpecGenerator                │  │
│  │   └── AnomalySignalAggregator   └── StrategySelector                     │  │
│  │                                                                           │  │
│  └───────────────────┬───────────────────────────┬───────────────────────────┘  │
│                      │ property.inferred          │ hypothesis.generated         │
│                      ▼                            ▼                             │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │                      ExperimentEngine v2                                  │   │
│  │   RequestSelector · MutationModule · SessionManager · ScopeGuard         │   │
│  │   AdaptivePayloadEngine [NOUVEAU] · WAFDialogEngine [NOUVEAU]            │   │
│  └──────────────────────────────────┬───────────────────────────────────────┘   │
│                                     │ experiment.result                          │
│                                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │                      SemanticOracle v2                                    │   │
│  │   SemanticDiff · ViolationOracle · CrossRoleDiffEngine [NOUVEAU]         │   │
│  │   TemporalAnomalyDetector [NOUVEAU] · ConfidenceModel v2                 │   │
│  └──────────────────────────────────┬───────────────────────────────────────┘   │
│                                     │ finding.confirmed                          │
│                                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │                   AttackGraphPlanner [NOUVEAU]                            │   │
│  │   StateSpace · GoalManager · AStarPlanner · PreconditionSolver           │   │
│  └──────────────────────────────────┬───────────────────────────────────────┘   │
│                                     │ hypothesis.generated (rétroaction)         │
│                                     │ chain.executed                            │
│                                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │                     KnowledgeBase v2                                      │   │
│  │   PatternStore · StructuralIndex · TransferEngine · EvidenceGraph        │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

### 3.2 Nouveau bus d'événements : pipeline continu

**Fichier** : `core/bus/event_bus.py` (modifié)

Le `drain()` synchrone est conservé pour la compatibilité des phases mais le bus
expose maintenant deux modes :

| Mode | Comportement | Usage |
|---|---|---|
| `BATCH` (existant) | `drain()` → barrière synchrone entre phases | Phases 1→2→3 initiales |
| `STREAM` (nouveau) | Handlers déclenchés immédiatement, pas de barrière | Adaptation en cours d'expérimentation |

Le mode `STREAM` permet à l'`AdaptivePayloadEngine` de modifier la queue
d'expériences en cours d'exécution sans attendre la fin d'une phase.

**Nouveaux types d'événements** (en plus des 21 existants) :

| Événement | Producteur | Consommateur(s) |
|---|---|---|
| `threat.model.updated` | ThreatModelEngine | ReasoningLayer, HypothesisEngine |
| `invariant.violated` | InvariantLearner | ReasoningLayer, SecurityPropertyEngine |
| `dataflow.updated` | DataFlowAnalyzer | CausalInferenceEngine |
| `behavioral.anomaly` | AnomalySignalAggregator | ReasoningLayer |
| `payload.adapted` | AdaptivePayloadEngine | ExperimentEngine |
| `waf.signature.detected` | WAFDialogEngine | AdaptivePayloadEngine |
| `crossrole.diff.confirmed` | CrossRoleDiffEngine | SemanticOracle |
| `temporal.anomaly.detected` | TemporalAnomalyDetector | SemanticOracle |
| `attack.state.updated` | AttackGraphPlanner | (UI, KnowledgeBase) |
| `goal.reached` | AttackGraphPlanner | HDWPEngine (arrêt) |
| `precondition.missing` | AttackGraphPlanner | HypothesisEngine |
| `pattern.matched` | KnowledgeBase v2 | ReasoningLayer (early signal) |

---

### 3.3 ThreatModelEngine — ce qui manquait le plus

**Fichier** : `core/threat/engine.py`

Composant entièrement nouveau. Construit et maintient un **modèle de menace
dynamique** de l'application testée, mis à jour à chaque `observation.updated`
et `model.updated`. C'est le composant qui répond à : *"Qu'est-ce qui compte
sur cette application et pourquoi ?"*

#### 3.3.1 AssetRegistry

Identifie et classe les **assets** de l'application :

```python
@dataclass
class Asset:
    id: str
    endpoints: List[str]           # endpoints qui exposent cet asset
    data_fields: List[str]         # champs de données associés
    sensitivity: SensitivityLevel  # PUBLIC, INTERNAL, SENSITIVE, CRITICAL
    owner_role: Optional[str]      # rôle propriétaire si identifiable
    access_roles: List[str]        # rôles ayant accès légitime
```

**Heuristiques d'identification** :

- Endpoints avec des ID numériques ou UUID dans le path → objects possédés
- Champs `price`, `amount`, `balance` → assets financiers (CRITICAL)
- Champs `email`, `phone`, `address`, `password` → données personnelles (SENSITIVE)
- Endpoints sous `/admin/` ou accessibles uniquement par un rôle admin → assets internes
- Données apparaissant dans plusieurs endpoints → assets partagés, priorité élevée

#### 3.3.2 DataFlowGraph

Graphe orienté représentant les **flux de données** entre endpoints.

```
Nœuds : EndpointNode (existant dans ApplicationModel)
Arêtes : DataFlowEdge {
    source_endpoint: str
    target_endpoint: str
    field_name: str        # le champ qui transite
    flow_type: FlowType    # PRODUCES | CONSUMES | TRANSFORMS | LEAKS
}
```

**Construction** : pour chaque `ParameterNode` consommé par un endpoint B,
chercher dans le `ResponseCorpus` d'autres endpoints si ce même champ est
produit. Si oui → arête `PRODUCES→CONSUMES`.

**Exemple concret** :

```
GET /api/invoices/{id} → produit { invoice_id, amount, owner_id }
POST /api/payments     → consomme { invoice_id, amount }
→ DataFlowEdge(GET /api/invoices/{id}, POST /api/payments, "invoice_id", PRODUCES)
→ DataFlowEdge(GET /api/invoices/{id}, POST /api/payments, "amount", PRODUCES)
```

Cette arête signifie : *un attaquant qui contrôle `invoice_id` en lisant des
invoices arbitraires peut déclencher des paiements sur des invoices qui ne lui
appartiennent pas.* C'est une propriété `BOLA+BUSINESS_LOGIC` non inférable
par des règles endpoint-locales.

#### 3.3.3 AttackSurfaceScorer

Score chaque endpoint en fonction de son importance dans le modèle de menace :

```
score(endpoint) =
    asset_sensitivity_max(assets_produits ∪ assets_consommés)    [0.0–1.0]
  × role_boundary_factor(status_by_role)                          [1.0–3.0]
  × dataflow_centrality(endpoint, DataFlowGraph)                  [1.0–2.0]
  × behavioral_anomaly_factor(zscore_history)                     [1.0–1.5]
```

Ce score remplace le système de priorité `HIGH/MEDIUM/LOW` du `HypothesisPrioritizer`
v1 par un score continu justifié causalement.

---

### 3.4 ReasoningLayer — le raisonnement centralisé

**Fichier** : `core/reasoning/layer.py`

C'est le composant le plus structurellement différent de v1. Dans v1, le raisonnement
est distribué entre `SecurityPropertyEngine`, `HypothesisEngine`, et les plugins.
Dans v2, il est centralisé dans un `ReasoningLayer` qui a accès à toute
l'information contextuelle avant de prendre des décisions.

#### 3.4.1 CausalInferenceEngine

Souscrit à `model.updated`, `dataflow.updated`, `behavioral.anomaly`.
Infère des propriétés de sécurité **causalement justifiées**.

**Différence avec v1** : le `SecurityPropertyEngine` v1 inspecte chaque endpoint
localement via des modules rule-based. Le `CausalInferenceEngine` inspecte les
**relations entre endpoints** via le `DataFlowGraph` et les **invariants appris**.

```python
class CausalInferenceEngine:

    def infer_from_dataflow(self, graph: DataFlowGraph) -> List[SecurityProperty]:
        properties = []
        for edge in graph.edges:
            if edge.flow_type == FlowType.PRODUCES:
                # Si A produit un champ consommé par B,
                # et que A est accessible par un rôle R1,
                # et que B est sensible au rôle qui soumet,
                # → propriété BOLA inter-endpoints
                source_roles = self.model.get_accessible_roles(edge.source)
                target_sensitivity = self.model.get_asset_sensitivity(edge.target)
                if target_sensitivity >= SensitivityLevel.SENSITIVE:
                    properties.append(SecurityProperty(
                        type=PropertyType.AUTHORIZATION,
                        scope=CrossEndpointScope(edge.source, edge.target),
                        justification=CausalJustification(
                            dataflow_edge=edge,
                            accessible_by=source_roles,
                            controls=edge.field_name
                        ),
                        confidence=self._compute_causal_confidence(edge)
                    ))
        return properties
```

**InvariantLearner** : apprend par induction les invariants de l'application
à partir des `observation.raw`. Un invariant est une propriété qui est vraie
dans toutes les observations passées.

```python
# Invariants appris par exemple :
Invariant("owner_id in response == authenticated_user_id", endpoints=["/api/invoices/*"])
Invariant("price >= 0 always", endpoints=["/api/products/*", "/api/orders/*"])
Invariant("status progression: pending → confirmed → shipped", fsm=True)
```

Quand une expérimentation produit une réponse qui viole un invariant appris →
`invariant.violated` émis → propriété haute confiance générée sans règle
explicite.

#### 3.4.2 ContextualHypothesisEngine

Remplace l'`HypothesisEngine` v1. La différence fondamentale : les hypothèses
sont générées avec un **contexte complet** de l'endpoint, pas à partir d'une
propriété formelle seule.

```python
@dataclass
class HypothesisContext:
    endpoint: EndpointNode
    parameter: ParameterNode
    tech_stack: TechStack             # db_type, framework, waf, language
    observed_values: List[Any]        # valeurs observées du paramètre
    inferred_type: ParameterType      # INT, UUID, EMAIL, JSON, BASE64, STRING
    response_corpus: ResponseCorpus   # réponses historiques par rôle
    threat_score: float               # score AttackSurfaceScorer
    causal_property: SecurityProperty # propriété causale parente
    kb_signals: List[KBSignal]        # signaux early de la KnowledgeBase
```

Avec ce contexte, l'`AdaptiveSpecGenerator` génère des `ExperimentSpec`
contextuels :

```python
# Exemple : paramètre 'id' avec observed_values=[1,2,3], db_type=postgresql
ExperimentSpec(
    mutation_type="field_injection",
    payload="1 AND pg_sleep(3)=0",       # blind SQLi PostgreSQL
    payload_type="sqli_blind_timing",
    rationale="paramètre numérique + PostgreSQL détecté → timing blind",
    expected_signal="temporal.anomaly > 3s"
)

# vs v1 qui génèrerait :
ExperimentSpec(payload="' OR '1'='1")    # payload MySQL sans contexte
```

**StrategySelector** : choisit la stratégie de test en fonction du `threat_score`
et des ressources disponibles.

| threat_score | Stratégie | Description |
|---|---|---|
| > 0.8 | DEEP | Toutes les mutations, WAF bypass, réplication en charge |
| 0.5–0.8 | STANDARD | Mutations prioritaires, un round de WAF bypass |
| 0.2–0.5 | SHALLOW | Mutations haute confiance uniquement |
| < 0.2 | PASSIVE | Observation passive seulement |

---

### 3.5 AdaptivePayloadEngine — boucle de feedback payload

**Fichier** : `core/experiment/adaptive_payload.py`

Composant nouveau inséré dans le pipeline d'`ExperimentEngine`.
Souscrit à `experiment.result` en mode STREAM. Modifie la queue d'expériences
en temps réel.

#### Architecture interne

```
experiment.result (en cours de session)
        │
        ▼
ContextExtractor
  → PayloadContext {
      db_type: postgresql | mysql | sqlite | mongodb | ...
      framework: spring | django | rails | express | ...
      waf: cloudflare | aws_waf | modsecurity | f5 | none
      param_encoding: raw | base64 | url | json
      error_pattern: Optional[str]   # texte de l'erreur si présente
      timing_delta: float            # temps réponse vs baseline
    }
        │
        ▼
SignalClassifier
  Analyse la réponse de la dernière expérience :

  Cas 1 : BLOCKED (403 + WAF signature dans headers)
    → WAFDialogEngine.identify_waf(response)
    → EncodingPipeline.generate_bypasses(payload, waf_type)
    → Émet payload.adapted avec les variantes

  Cas 2 : ERROR (5xx avec stack trace ou message d'erreur)
    → ErrorParser.extract_db_info(error_message)
    → PayloadSynthesizer.refine_for_error(payload, error_context)
    → Exemple : "syntax error near 'OR'" → payload affiné sur le token fautif

  Cas 3 : TIMING_ANOMALY (response_time > baseline * 3)
    → TemporalAnomalyDetector confirme
    → PayloadSynthesizer.escalate_timing(payload)
    → Génère payloads UNION/extraction pour confirmer blind

  Cas 4 : UNEXPECTED_FIELD (nouveau champ dans réponse)
    → CrossRoleDiffEngine.check_field_ownership(field, auth_context)
    → Si champ appartient à un autre utilisateur → finding.confirmed direct

  Cas 5 : NORMAL (réponse similaire à baseline)
    → Refutation partielle, pas de modification de queue
```

#### WAFDialogEngine

Identifie le WAF en dialoguant avec lui de façon structurée :

```python
class WAFDialogEngine:
    """
    Séquence d'identification :
    1. Probe neutre (requête légère) → analyse headers de réponse
    2. Probe de signature (payload minimal connu) → pattern de réponse WAF
    3. Classification : Cloudflare (cf-ray header), AWS WAF (x-amzn-*),
       ModSecurity (ModSecurity: 2.x dans Server:), F5 (X-WA-Info:), etc.
    """
    def identify_waf(self, response: NormalizedResponse) -> WAFType:
        ...

    def generate_bypass_variants(self, payload: str, waf: WAFType) -> List[str]:
        """
        Techniques par WAF :
        - Cloudflare : Unicode normalization, case alternation, inline comments
        - ModSecurity : multipart boundary abuse, chunked encoding, HPP
        - AWS WAF : encoding mismatch, newline injection in headers
        - F5 : parameter fragmentation, HTTP verb tunneling
        """
        ...
```

---

### 3.6 SemanticOracle v3 — vérité sémantique réelle

**Fichier** : `core/oracle/engine.py` (modifié en profondeur)

#### CrossRoleDiffEngine (nouveau sous-composant)

Exploite le `response_corpus` multi-rôles stocké dans l'`ApplicationModel`.
Effectue un diff systématique des réponses par rôle pour chaque endpoint.

```python
class CrossRoleDiffEngine:
    """
    Pour chaque endpoint avec N rôles observés :

    1. Structural diff : quels champs sont présents pour role_A mais absents pour role_B ?
       → Si champ sensible (détecté par AssetRegistry) présent pour admin mais
         absent pour user → propriété CONFIDENTIALITY haute confiance

    2. Value diff : mêmes champs, valeurs différentes ?
       → Si 'balance' retourne 0 pour user mais la vraie valeur pour admin
         → confirme que le champ existe mais est masqué → test d'énumération

    3. Identity diff : les champs d'identité pointent-ils vers le bon owner ?
       → GET /api/orders/{id} avec token user_42 retourne order.owner_id = 7
         → BOLA confirmed sans besoin d'autre signal
    """
    def diff_cross_role(
        self,
        endpoint: str,
        role_responses: Dict[str, NormalizedResponse]
    ) -> List[CrossRoleDiffResult]:
        ...
```

#### TemporalAnomalyDetector (nouveau sous-composant)

```python
class TemporalAnomalyDetector:
    """
    Baseline : P95 des temps de réponse par endpoint sur les observations légitimes
    Détection : response_time > baseline_p95 + 2σ → temporal.anomaly.detected
    Corrélation : si temporal_anomaly coïncide avec field_injection → blind_injection_candidate
    Escalade automatique : génère ExperimentSpec de confirmation (timing avec sleep(1), sleep(3), sleep(7))
    """
```

#### ConfidenceModel v3 — apprenant

Le modèle de confiance v1 est linéaire fixe. Le v2 est un **modèle logistique
calibré par l'historique des findings** dans la `KnowledgeBase v2`.

```
Dimensions d'entrée (conservées de v1) :
  oracle_strength, reproducibility, observation_quality,
  behavioral_specificity, experiment_coverage

Dimensions ajoutées :
  temporal_signal        : anomalie timing détectée (0/1)
  crossrole_signal       : diff cross-rôle confirmé (0/1)
  invariant_violated     : invariant appris violé (0/1)
  waf_bypass_success     : WAF bypassé pour obtenir ce résultat (0/1)
  causal_depth           : profondeur de la justification causale [0,1]

Modèle : régression logistique
  P(true_positive) = σ(w·x + b)
  Poids initiaux : calibrés sur les valeurs v1 + prior KnowledgeBase
  Mise à jour : après chaque session confirmée (validation manuelle)
                gradient descent partiel → mise à jour incrémentale des poids
```

---

### 3.7 AttackGraphPlanner — planification orientée objectif

**Fichier** : `core/attack_graph/planner.py`

Remplace le `ChainEngine` à règles fixes. Traite la découverte d'attaques comme
un problème de planification dans un espace d'états.

#### 3.7.1 AttackStateSpace

```python
@dataclass
class AttackState:
    """
    L'état courant de l'attaquant dans l'espace de possibilités.
    Mis à jour à chaque finding.confirmed.
    """
    assets_readable: Set[str]       # assets dont le contenu est accessible
    assets_writable: Set[str]       # assets que l'attaquant peut modifier
    credentials_held: Set[Credential]  # credentials capturés ou forgés
    knowledge: Set[str]             # informations structurelles acquises
                                    # (ex: "db_schema.users.columns")
    privileges: Dict[str, Role]     # rôles effectivement détenus par endpoint
    session_tokens: Dict[str, str]  # tokens valides par rôle

@dataclass
class AttackTransition:
    """
    Un finding confirmé est un opérateur qui transforme l'état.
    """
    finding: Finding
    preconditions: List[StateCondition]   # conditions requises pour appliquer
    effects: List[StateEffect]            # modifications de l'état résultantes

# Exemples de transitions :
AttackTransition(
    finding=bola_on_invoices,
    preconditions=[HasRole("user")],
    effects=[
        AddReadable("invoices.*"),
        AddKnowledge("invoice_ids_enumerable")
    ]
)

AttackTransition(
    finding=sqli_on_search,
    preconditions=[],
    effects=[
        AddKnowledge("db_schema.*"),
        AddReadable("database_content")
    ]
)
```

#### 3.7.2 GoalManager

```python
class GoalDefinition:
    ACCOUNT_TAKEOVER = AttackGoal(
        required_state=AttackState(
            credentials_held={AnyCredential(role="admin")},
            ...
        )
    )
    DATA_EXFIL = AttackGoal(
        required_state=AttackState(
            assets_readable={SensitiveAsset(sensitivity=CRITICAL)},
            ...
        )
    )
    PRIVILEGE_ESCALATION = AttackGoal(
        required_state=AttackState(
            privileges={"any_endpoint": Role("admin")},
            ...
        )
    )
```

#### 3.7.3 A\* Planner

```
Algorithme A* sur AttackStateSpace :

État initial  : AttackState(credentials_held={Credential(role="user")})
État cible    : GoalDefinition.ACCOUNT_TAKEOVER (ou autre)

Coût d'une arête : 1 - finding.confidence
  (finding de haute confiance = transition peu coûteuse)

Heuristique h : distance de l'état courant à l'état cible
  (nombre de StateEffects manquants pour atteindre le goal)

Résultat : séquence ordonnée d'AttackTransitions
  → traduite en ChainSpec pour exécution par ExperimentEngine

Comportement sur précondition manquante :
  Si aucun chemin n'atteint le goal avec les findings actuels :
    → PreconditionSolver identifie la précondition bloquante
    → Émet precondition.missing { endpoint, required_condition }
    → HypothesisEngine génère des hypothèses ciblées sur cette précondition
    → Cycle redémarre
```

#### 3.7.4 Boucle de rétroaction

```
finding.confirmed
      │
      ▼
AttackGraphPlanner.update_state(finding)
      │
      ├── État mis à jour → relance A* → nouveau plan
      │
      ├── Si goal atteint → goal.reached → arrêt ou nouveau goal
      │
      └── Si précondition manquante → precondition.missing
                │
                ▼
          HypothesisEngine.inject_targeted(precondition)
                │
                ▼
          [réintègre le pipeline normal]
```

---

### 3.8 KnowledgeBase v3 — mémoire structurelle

**Fichier** : `core/knowledge/base.py` (refonte)

#### Données supplémentaires stockées

| Table | Contenu v1 | Ajout v3 |
|---|---|---|
| `session_meta` | URL, type, date, n_findings | + `attack_graph_snapshot`, `goal_reached`, `final_state` |
| `pattern_stats` | taux par (property, mutation, target_type) | + `stack_signature` (hash structurel du tech_stack) |
| `structural_patterns` | — | Patterns URL + paramètres qui ont prédit une vulnérabilité |
| `invariants` | — | Invariants appris persistés entre sessions |
| `payload_effectiveness` | — | Efficacité de chaque payload par (waf_type, db_type, param_type) |
| `confidence_model_weights` | — | Poids du ConfidenceModel v2 mis à jour après chaque session |
| `evidence_graph` | — | Graphe de relations entre findings à travers les sessions |

#### StructuralIndex — transfer learning inter-sessions

```python
class StructuralIndex:
    """
    Indexe les sessions passées par similarité structurelle de la cible.

    Signature structurelle d'une cible :
      - Distribution des méthodes HTTP par endpoint
      - Présence de patterns d'authentification (JWT, session cookie, OAuth2)
      - Profondeur moyenne des paths
      - Types de paramètres dominants (UUID, int, string)
      - Tech stack hash

    Requête : trouver les N sessions les plus similaires à la session courante
    → Extraire les patterns de vulnérabilités confirmées sur ces sessions
    → Émettre pattern.matched { pattern, confidence, source_session }
    → ReasoningLayer utilise ce signal comme prior pour la génération d'hypothèses
    """

    def find_similar_sessions(self, current_signature: TargetSignature) -> List[Session]:
        # cosine similarity sur les vecteurs de signature
        ...
```

#### EvidenceGraph

Graphe de type `(Finding) → ENABLES → (Finding)` persisté entre sessions.
Représente les chaînes d'attaque qui ont fonctionné historiquement.

```
(BOLA sur /api/invoices) → ENABLES → (Payment fraud sur /api/payments)
(JWT weak secret)        → ENABLES → (Privilege escalation via admin token)
(SQLi sur /api/search)   → ENABLES → (Credential dump depuis DB)
```

Utilisé par l'`AttackGraphPlanner` pour pondérer les transitions connues.

---

### 3.9 ApplicationModel v3 — enrichi

**Fichier** : `core/model/application_model.py` (modifié)

Deux ajouts structurels au modèle existant (tout le reste est conservé) :

#### InvariantStore

```python
class InvariantStore:
    """
    Stocke les invariants appris par observation.

    Invariant format :
      field_condition: str       # ex: "owner_id == auth_user_id"
      endpoints: List[str]       # où cet invariant est observé
      observation_count: int     # nombre d'observations confirmant l'invariant
      confidence: float          # proportion d'observations conformes
      last_violated: Optional[datetime]  # dernière violation (si testée)
    """

    def observe(self, observation: RawObservation) -> List[InvariantUpdate]:
        """
        Met à jour les invariants existants et en propose de nouveaux
        à partir d'une observation. Un invariant est proposé quand une
        propriété est vraie dans > 95% des observations d'un endpoint.
        """
        ...

    def check_violation(self, response: NormalizedResponse, endpoint: str) -> List[InvariantViolation]:
        """
        Vérifie si une réponse expérimentale viole les invariants appris
        pour cet endpoint. Si oui → émet invariant.violated.
        """
        ...
```

#### ParameterModel enrichi

```python
@dataclass
class ParameterNode:  # v3
    name: str
    location: ParameterLocation
    observed_values: List[Any]
    inferred_type: ParameterType        # existant
    # Ajouts v2 :
    value_distribution: Distribution    # uniforme / gaussienne / catégorielle
    validation_constraints: List[Constraint]  # déduits des erreurs observées
    linked_assets: List[str]            # assets que ce paramètre contrôle
    mutation_history: MutationHistory   # historique des mutations et résultats
```

`mutation_history` permet à l'`AdaptivePayloadEngine` de savoir ce qui a déjà
été testé sur ce paramètre sans consulter la queue d'hypothèses complète.

---

### 3.10 LLMLayer v2 — rôle redéfini

**Fichier** : `core/llm/layer.py` (modifié)

La contrainte ADR-002 (le LLM ne peut jamais retourner CONFIRMED seul) est maintenue
et étendue.

Nouveaux rôles du LLM dans v3 :

| Rôle | Input | Output | Contrainte |
|---|---|---|---|
| Désambiguïsation (existant) | SemanticDiff AMBIGUOUS | Verdict orienté | Jamais CONFIRMED seul |
| JS Interpretation (existant) | JavaScript obfusqué | Endpoints extraits | Output structuré validé |
| Invariant Proposal | ResponseCorpus multi-rôles | Invariants candidats | Validés par InvariantLearner avant usage |
| Attack Narrative | AttackGraphPlanner output | Description de la chaîne | Rapport uniquement |
| Payload Context Inference | Tech stack + erreurs observées | PayloadContext enrichi | Suggestions, pas décisions |
| Precondition Analysis | Blocage dans AttackGraph | Hypothèses de déblocage | Soumises au pipeline normal |

Le LLM reste **consultatif** dans tous les cas. Aucune de ses sorties ne modifie
l'état du moteur sans passer par un validateur déterministe.

---

### 3.11 Flux de données complet v3

```
[Cible HTTP]
      │
      ▼
ObservationEngine.start()
  → ActiveCrawler, SPACrawler, ProxyCapture, JS Extractor (inchangés)
  → émet observation.raw
      │
      ├──▶ ApplicationModel v2._on_observation()
      │       → met à jour EndpointGraph, ParameterModel, ResponseCorpus
      │       → InvariantStore.observe() → met à jour les invariants
      │       → émet model.updated
      │
      └──▶ ThreatModelEngine._on_observation()
              → AssetRegistry.update()
              → DataFlowGraph.update()
              → AttackSurfaceScorer.recompute()
              → émet threat.model.updated
      │
      ▼
ReasoningLayer._on_model_updated() + _on_threat_model_updated()
      │
      ├── CausalInferenceEngine.infer_from_dataflow(DataFlowGraph)
      │     → émet property.inferred (causalement justifiée)
      │
      ├── CausalInferenceEngine.infer_from_invariants(InvariantStore)
      │     → pour chaque invariant à haute confiance → propriété INTEGRITY/AUTH
      │
      └── AnomalySignalAggregator.aggregate(behavioral_profiles)
            → émet behavioral.anomaly si Z-score anormal
      │
      ▼
ContextualHypothesisEngine._on_property_inferred(property, context)
      → ContextBuilder assemble HypothesisContext complet
      → AdaptiveSpecGenerator génère ExperimentSpec contextuels
      → StrategySelector choisit la profondeur de test
      → émet hypothesis.generated (avec contexte enrichi)
      │
      ▼
ExperimentEngine._run_hypothesis() (modifié)
  → RequestSelector + MutationModule (conservés)
  → SessionManager (conservé)
  → Pour chaque expérience :
       1. Baseline + mutation + replay (conservé)
       2. En parallèle, AdaptivePayloadEngine souscrit à experiment.result (STREAM)
          → SignalClassifier.classify(result)
          → Si signal → payload.adapted → injecté dans la queue courante
       → émet experiment.result
  → émet hypothesis.experiments_ready
      │
      ▼
SemanticOracle v2._on_experiments_ready()
  → compute_semantic_diff (conservé + amélioré)
  → CrossRoleDiffEngine.diff_cross_role() → crossrole.diff.confirmed ?
  → TemporalAnomalyDetector.check() → temporal.anomaly.detected ?
  → InvariantStore.check_violation() → invariant.violated ?
  → ViolationOracle.assess_violation() (conservé)
  → ConfidenceModel v2.compute(10 dimensions)
  → Si P(true_positive) >= threshold → finding.confirmed
      │
      ▼
AttackGraphPlanner._on_finding_confirmed(finding)
  → AttackTransition.from_finding(finding)
  → StateSpace.apply_transition(transition)
  → GoalManager.check_goal_reached(current_state)
  │
  ├── Si goal atteint → goal.reached → arrêt + rapport
  │
  ├── Si plan A* existe → chain.executed (ExperimentEngine direct)
  │
  └── Si précondition manquante :
        → PreconditionSolver.identify_blocker()
        → émet precondition.missing
        → HypothesisEngine.inject_targeted() [rétroaction]
      │
      ▼
KnowledgeBase v2.record()
  → PatternStore.update(structural_pattern)
  → payload_effectiveness.update(payload, result)
  → confidence_model_weights.update(gradient)
  → EvidenceGraph.add_edge(finding_a, finding_b) si chaîne
  → StructuralIndex.reindex()
```

---

### 3.12 Schéma des dépendances d'initialisation v3

```python
# HDWPEngine.create() v3

KnowledgeBase v3
  ├─▶ ConfidenceModel v3    (poids chargés)
  ├─▶ HypothesisPrioritizer (poids adaptés — conservé)
  ├─▶ InvariantStore        (invariants persistés rechargés)
  └─▶ StructuralIndex       (index inter-sessions chargé)

ThreatModelEngine
  ├─▶ AssetRegistry
  ├─▶ DataFlowGraph
  └─▶ AttackSurfaceScorer

ReasoningLayer
  ├─▶ CausalInferenceEngine  (dépend de ThreatModelEngine + ApplicationModel)
  ├─▶ ContextualHypothesisEngine (dépend de CausalInferenceEngine)
  └─▶ AnomalySignalAggregator

LLMLayer (optionnel, inchangé dans ses dépendances)
  ├─▶ ContextualHypothesisEngine
  ├─▶ SemanticOracle v3
  └─▶ ObservationEngine

PluginRegistry (conservé)
  ├─▶ MutationRegistry
  ├─▶ ReasoningLayer (inférence plugin → CausalInferenceEngine)
  └─▶ ContextualHypothesisEngine

AdaptivePayloadEngine
  ├─▶ WAFDialogEngine
  └─▶ ExperimentEngine (injection dans la queue en STREAM)

AttackGraphPlanner
  ├─▶ GoalManager
  ├─▶ StateSpace (initialisé depuis KnowledgeBase v2 EvidenceGraph)
  └─▶ PreconditionSolver → ContextualHypothesisEngine

ScopeGuard, SessionManager, TokenBucket (inchangés)
TuningConfig YAML (conservé, override final)
```

---

## Partie IV — Matrice de décision : v2 vs v3

| Capacité | v2 | v3 |
|---|---|---|
| Détection de vulnérabilités isolées | ✅ Pattern matching | ✅ Conservé + inférence causale |
| Prioritisation des endpoints | Heuristique H/M/L | Score causal continu (ThreatModelEngine) |
| Génération de payloads | Listes statiques par type | Contextuelle : type + stack + réponses passées |
| Adaptation en cours d'expérimentation | ❌ | ✅ AdaptivePayloadEngine (STREAM) |
| Détection de vulnérabilités inter-endpoints | ❌ | ✅ DataFlowGraph + CausalInferenceEngine |
| Apprentissage d'invariants | ❌ | ✅ InvariantStore (inductif) |
| Diffing cross-rôle | "Potentiel" (non implémenté) | ✅ CrossRoleDiffEngine |
| Détection temporelle (blind injection) | Signal timing basique | ✅ TemporalAnomalyDetector corrélé |
| Contournement WAF adaptatif | EncodingPipeline statique | ✅ WAFDialogEngine + feedback loop |
| Planification d'attaque | Règles IF-THEN fixes | ✅ A* sur AttackStateSpace |
| Rétroaction chaîne → hypothèses | ❌ | ✅ PreconditionSolver |
| Transfer learning inter-sessions | EMA scalaire par bucket | ✅ StructuralIndex + cosine similarity |
| Modèle de confiance | Linéaire fixe (5D) | Logistique calibré (10D + mise à jour incrémentale) |
| Modèle de menace dynamique | ❌ | ✅ ThreatModelEngine |
| Rôle du LLM | Désambiguïsation + rapport | + Invariants candidats + Payload context |

---

## Partie V — Ordre d'implémentation recommandé

L'ordre est contraint par les dépendances entre composants et le ratio
impact/effort.

### Sprint 1 — Fondation du raisonnement (6–8 semaines)

**Objectif** : avoir un moteur qui sait ce qui compte sur la cible avant de tester.

1. `DataFlowGraph` dans `ApplicationModel v3`
   — dépend de : `ResponseCorpus` (déjà stocké), `ParameterModel` (déjà existant)
   — débloque : `CausalInferenceEngine`, `ThreatModelEngine`

2. `ThreatModelEngine` (AssetRegistry + AttackSurfaceScorer)
   — dépend de : `DataFlowGraph`
   — débloque : prioritisation causale, StrategySelector

3. `InvariantStore` dans `ApplicationModel v3`
   — dépend de : `observation.raw` (déjà produit)
   — débloque : inférence sans règles, signal haute confiance

### Sprint 2 — Oracle enrichi (4–6 semaines)

**Objectif** : détecter ce que v2 manque avec les données déjà collectées.

4. `CrossRoleDiffEngine`
   — dépend de : `ResponseCorpus` (déjà stocké), `AssetRegistry`
   — impact immédiat sur BOLA et data leaks

5. `TemporalAnomalyDetector`
   — dépend de : `ExperimentResult.timing` (déjà collecté), baseline P95
   — impact immédiat sur blind injections

6. `ConfidenceModel v2` (logistique, 10D)
   — dépend de : CrossRoleDiffEngine, TemporalAnomalyDetector (nouveaux signaux)
   — poids initiaux calibrés manuellement sur des sessions de référence

### Sprint 3 — Payloads adaptatifs (4–5 semaines)

**Objectif** : ne plus envoyer des payloads génériques.

7. `AdaptivePayloadEngine` + `WAFDialogEngine`
   — dépend de : `PayloadContext` (ContextExtractor), bus en mode STREAM
   — débloque la boucle de feedback payload

8. `ContextualHypothesisEngine` (remplace HypothesisEngine)
   — dépend de : `HypothesisContext`, `ThreatModelEngine`, `InvariantStore`
   — remplace le template expansion par la génération contextuelle

### Sprint 4 — Planification (6–8 semaines)

**Objectif** : raisonner vers un objectif, pas tester exhaustivement.

9. `AttackStateSpace` + `AttackTransition`
   — dépend de : findings confirmés de v2 (qualité suffisante requise)

10. `A* Planner` + `GoalManager`
    — dépend de : `AttackStateSpace`, `EvidenceGraph` (KnowledgeBase v2)

11. `PreconditionSolver` + boucle de rétroaction
    — dépend de : A* Planner, ContextualHypothesisEngine

### Sprint 5 — Mémoire structurelle (3–4 semaines)

**Objectif** : que chaque session améliore les suivantes.

12. `StructuralIndex` + `EvidenceGraph` dans `KnowledgeBase v2`
    — dépend de : sessions v2 complètes pour alimenter l'index
    — impact visible après 5–10 sessions accumulées

13. Mise à jour incrémentale des poids du `ConfidenceModel v2`
    — dépend de : `EvidenceGraph`, validation manuelle des findings

---

## Annexe — ADRs impactés

| ADR | Décision originale | Impact v3 |
|---|---|---|
| ADR-002 | LLM ne peut jamais retourner CONFIRMED seul | Maintenu et étendu : LLM reste consultatif dans tous les nouveaux rôles |
| ADR-NEW-001 | `InvariantViolation` peut déclencher un finding haute confiance sans LLM | L'`InvariantStore` est un oracle déterministe, pas probabiliste |
| ADR-NEW-002 | `AdaptivePayloadEngine` opère en mode STREAM, pas BATCH | Le bus doit supporter les deux modes sans régression |
| ADR-NEW-003 | `AttackGraphPlanner` est le seul émetteur de `goal.reached` | Aucun autre composant n'interrompt le scan sur objectif atteint |
| ADR-NEW-004 | Les poids du `ConfidenceModel v2` ne sont mis à jour qu'après validation manuelle | Pas de mise à jour automatique non supervisée des seuils de détection |
