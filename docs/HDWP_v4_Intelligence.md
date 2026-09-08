# HDWP v4 — Modèle de Raisonnement et d'Apprentissage

> Document de conception — Intelligence réelle, pas énumération adaptative
> Michel Tendeng — HDWP v4

---

## Partie I — Diagnostic Définitif

### Le plafond des v1-v3

Les versions précédentes partagent une limite architecturale commune :
**l'espace de recherche est fermé à la conception**.

Un composant comme `ContextualHypothesisEngine` choisit *plus intelligemment*
dans un ensemble de templates pré-définis. Il ne peut pas proposer un vecteur
d'attaque qu'aucun plugin n'a encodé. Il ne comprend pas pourquoi un vecteur
devrait fonctionner — il sait que dans son répertoire, ce type de paramètre
est associé à ce type de mutation.

La différence entre un scanner et un raisonneur n'est pas la sophistication
du scoring. C'est la capacité à **généraliser à partir de principes**, pas
à **énumérer à partir de règles**.

### Ce que "intelligence" signifie concrètement ici

Trois capacités, trois niveaux de difficulté :

| Capacité | Description | Faisabilité ML/DL |
|---|---|---|
| **Généralisation** | Prédire qu'un endpoint inconnu a probablement une classe de vulnérabilité | ✅ Directement |
| **Compréhension causale** | Savoir *pourquoi* un vecteur devrait fonctionner | ✅ Partiellement (représentations latentes) |
| **Découverte** | Proposer des vecteurs jamais programmés | ⚠️ LLM décisionnel requis (lever ADR-002) |

Cette architecture adresse les trois, avec des garde-fous différents pour chacun.

### La décision sur ADR-002

ADR-002 interdisait au LLM de retourner CONFIRMED seul — décision défensive
correcte pour éviter les faux positifs non vérifiables. Mais appliquée globalement,
elle bridait aussi la génération d'hypothèses.

**ADR-002 révisé** : le LLM reste non-décisionnel sur les **verdicts** (CONFIRMED/REFUTED).
Il devient décisionnel sur la **génération d'hypothèses** — avec validation
déterministe obligatoire avant exécution. Un LLM peut proposer un vecteur
d'attaque sans que sa proposition constitue un finding.

---

## Partie II — Les trois couches d'intelligence ML/DL

L'intelligence est décomposée en trois couches indépendantes, empilées :

```
┌─────────────────────────────────────────────────────────────┐
│  Couche 3 — Raisonnement (LLM décisionnel sur hypothèses)   │
│  VulnerabilityReasoningLLM                                   │
│  Entrée : schéma endpoint + comportement observé + context   │
│  Sortie : hypothèses libres, validées par garde-fous         │
└─────────────────────────────────┬───────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────┐
│  Couche 2 — Apprentissage (ML supervisé + RL)               │
│  VulnPredictionModel · PayloadOptimizer · OracleModel       │
│  Entrée : features structurelles de l'endpoint              │
│  Sortie : probabilités de vulnérabilité, payloads optimaux  │
└─────────────────────────────────┬───────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────┐
│  Couche 1 — Représentation (Embeddings)                     │
│  EndpointEmbedder · ResponseEmbedder · PayloadEmbedder      │
│  Entrée : données brutes (URL, paramètres, réponses HTTP)   │
│  Sortie : vecteurs denses en espace sémantique              │
└─────────────────────────────────────────────────────────────┘
```

---

## Partie III — Couche 1 : Représentations

### 3.1 Pourquoi des embeddings

Les modèles ML ne peuvent pas opérer directement sur des chaînes comme
`/api/v1/users/{id}/orders` ou `{"error": "syntax error near 'OR'"}`.
Il faut une représentation numérique qui **préserve la similarité sémantique**.

Deux endpoints `/api/users/{id}` et `/api/accounts/{uuid}` sont structurellement
similaires — même pattern d'accès à une ressource par identifiant. Dans un espace
d'embedding bien entraîné, leurs vecteurs sont proches. Un modèle entraîné à
détecter BOLA sur le premier généralise au second **sans règle explicite**.

### 3.2 EndpointEmbedder

**Fichier** : `core/ml/embedders/endpoint_embedder.py`

Produit un vecteur dense représentant un endpoint et ses paramètres.

#### Architecture

```python
class EndpointEmbedder:
    """
    Transforme un EndpointNode en vecteur R^d représentant ses propriétés
    structurelles et comportementales.
    """

    def embed(self, endpoint: EndpointNode) -> np.ndarray:
        # Concaténation de features hétérogènes → vecteur unifié
        features = [
            self._embed_path(endpoint.path),        # path tokenisé
            self._embed_methods(endpoint.methods),  # one-hot HTTP methods
            self._embed_params(endpoint.parameters),# features des paramètres
            self._embed_auth(endpoint.auth_config), # type d'auth requis
            self._embed_behavior(endpoint.behavioral_profile), # Z-score, distributions
            self._embed_roles(endpoint.status_by_role),        # matrice rôle×status
        ]
        return np.concatenate(features)
```

**Path tokenization** : le path est segmenté en tokens avec un vocabulaire
appris sur un corpus d'APIs REST :

```
/api/v1/users/{id}/orders/active
→ ["api", "v1", "users", "{id}", "orders", "active"]
→ embedding par Byte-Pair Encoding (BPE) entraîné sur 50k paths d'API
→ vecteur R^128 par token → mean pooling → R^128
```

**Parameter features** :

```python
@dataclass
class ParameterFeatures:
    type_onehot: np.ndarray       # [int, uuid, email, string, json, base64, bool]
    location_onehot: np.ndarray   # [query, body, path, header, cookie]
    value_entropy: float          # entropie des valeurs observées
    uniqueness_ratio: float       # prop de valeurs uniques dans observed_values
    name_embedding: np.ndarray    # embedding du nom du paramètre (R^64)
    appears_in_response: bool     # ce paramètre est-il reflété dans la réponse ?
```

`name_embedding` utilise un modèle de mots pré-entraîné sur le vocabulaire
des APIs (noms de champs courants : `user_id`, `owner`, `account`, `token`...).
Des noms sémantiquement liés à l'autorisation auront des embeddings proches.

#### Modèle pré-entraîné vs fine-tuning

L'`EndpointEmbedder` est **pré-entraîné** sur un corpus de specs OpenAPI publiques
(API Guru : 2000+ specs, 50k+ endpoints). La tâche de pré-entraînement est une
tâche de reconstruction : prédire les paramètres d'un endpoint à partir de son path,
et vice-versa. Le résultat est un espace latent où des endpoints fonctionnellement
similaires sont proches.

Fine-tuning : sur les données accumulées par HDWP lui-même (sessions passées).

### 3.3 ResponseEmbedder

**Fichier** : `core/ml/embedders/response_embedder.py`

Encode une réponse HTTP (headers + body) en vecteur.

```python
class ResponseEmbedder:

    def embed(self, response: NormalizedResponse) -> np.ndarray:
        return np.concatenate([
            self._embed_status(response.status_code),    # one-hot étendu
            self._embed_headers(response.headers),       # présence de security headers
            self._embed_body_structure(response.body),   # structure JSON (sans valeurs)
            self._embed_body_values(response.body),      # distribution des valeurs
            self._embed_timing(response.elapsed_ms),     # timing normalisé
            self._embed_error_signals(response.body),    # présence de patterns d'erreur
        ])
```

**Body structure encoding** : le body JSON est représenté par son **schéma
structurel** (clés récursives, profondeur, présence de champs d'identité)
indépendamment des valeurs. Deux réponses avec des structures identiques mais
des valeurs différentes ont le même embedding structurel.

**Error signal detection** : dictionnaire de patterns d'erreur par catégorie :
```python
ERROR_PATTERNS = {
    "sql_error":    [r"syntax error", r"ORA-\d+", r"MySQL.*Error", r"pg_exception"],
    "stack_trace":  [r"at\s+\w+\.\w+\(", r"Traceback\s+\(most recent"],
    "disclosure":   [r"root:", r"/etc/passwd", r"Windows\System32"],
    "template":     [r"\{\{.*\}\}", r"\$\{.*\}", r"<%.*%>"],
}
```
Ces patterns sont encodés en vecteur binaire (présent/absent), pas en texte.

### 3.4 DiffEmbedder

**Fichier** : `core/ml/embedders/diff_embedder.py`

Encode la **différence** entre une réponse baseline et une réponse expérimentale.
C'est le vecteur d'entrée principal de l'`OracleModel`.

```python
class DiffEmbedder:

    def embed(self, baseline: NormalizedResponse, experiment: NormalizedResponse) -> np.ndarray:
        b = self.response_embedder.embed(baseline)
        e = self.response_embedder.embed(experiment)

        return np.concatenate([
            e - b,              # différence directe (direction du changement)
            np.abs(e - b),      # magnitude du changement
            e * b,              # interaction (produit élément par élément)
            self._structural_diff(baseline.body, experiment.body),
            self._identity_diff(baseline, experiment),  # data_identity fields
            self._timing_diff(baseline.elapsed_ms, experiment.elapsed_ms),
        ])
```

Ce vecteur de diff capture non seulement *ce qui a changé* mais *comment* et
*dans quelle direction*, ce qui permet à l'`OracleModel` d'apprendre des patterns
de diff associés à des classes de vulnérabilités.

---

## Partie IV — Couche 2 : Apprentissage

### 4.1 VulnPredictionModel — prédiction avant test

**Fichier** : `core/ml/models/vuln_prediction.py`

**Objectif** : prédire la probabilité qu'un endpoint soit vulnérable à chaque
classe de vulnérabilité, **avant** de lancer les expériences. C'est le composant
qui permet la **généralisation** — tester en priorité ce qui a des chances d'être
vulnérable, pas ce que les règles désignent.

#### Architecture du modèle

```
Input : EndpointEmbedding (R^d)
          + ThreatContextEmbedding (R^64) [assets contrôlés, rôles, dataflow]

Hidden layers :
  Dense(512, ReLU) → BatchNorm → Dropout(0.3)
  Dense(256, ReLU) → BatchNorm → Dropout(0.3)
  Dense(128, ReLU)

Output :
  Multi-label classification — une probabilité par classe :
  P(BOLA) | P(SQLi) | P(XSS) | P(SSTI) | P(SSRF) | P(IDOR) |
  P(AuthBypass) | P(RaceCondition) | P(BusinessLogic) | P(InfoDisclosure)
```

**Fonction de perte** : Binary Cross-Entropy multi-label avec class weights
(les classes rares — SSRF, RaceCondition — reçoivent un poids plus élevé
pour éviter que le modèle les ignore).

#### Données d'entraînement

Deux sources :

1. **Corpus public** : CVE enrichis avec les specs OpenAPI des APIs vulnérables
   quand disponibles. HackerOne disclosed reports avec structures d'endpoints.
   OWASP API Security Top 10 avec exemples annotés.

2. **Données propres HDWP** : chaque session produit des `(endpoint_embedding,
   finding_confirmed)` paires. Après validation manuelle des findings, ces paires
   alimentent le fine-tuning du modèle.

#### Utilisation dans le pipeline

```python
# Dans ContextualHypothesisEngine, avant génération d'hypothèses :
vuln_probs = vuln_prediction_model.predict(endpoint_embedding)

# Seuillage adaptatif par classe :
high_priority_vulns = [cls for cls, p in vuln_probs.items() if p > 0.6]
medium_priority_vulns = [cls for cls, p in vuln_probs.items() if 0.3 < p <= 0.6]

# La StrategySelector utilise ces probabilités pour allouer les ressources :
# P(BOLA) = 0.85 → DEEP sur les mutations d'identité
# P(XSS) = 0.12 → SKIP ou PASSIVE seulement
```

Le moteur n'énumère plus les 10 classes sur chaque endpoint. Il investit
les ressources proportionnellement aux probabilités prédites.

#### Interprétabilité

Le `VulnPredictionModel` expose des **feature importances** via SHAP
(SHapley Additive exPlanations) :

```python
explanation = vuln_model.explain(endpoint_embedding)
# → "P(BOLA) = 0.85 principalement dû à :
#    - paramètre 'user_id' dans path (+0.32)
#    - endpoint accessible par multiple rôles (+0.28)
#    - valeurs numériques séquentielles observées (+0.19)"
```

Cette explication alimente le `CausalInferenceEngine` comme justification
de la propriété inférée — remplaçant les règles hard-codées par une
justification apprise.

### 4.2 PayloadOptimizer — génération de payloads par RL

**Fichier** : `core/ml/models/payload_optimizer.py`

**Objectif** : apprendre à générer et sélectionner des payloads optimaux pour
chaque contexte. C'est l'adresse directe au problème des listes statiques.

#### Formulation Reinforcement Learning

```
État s_t :
  EndpointEmbedding             # représentation de l'endpoint cible
  + ParameterEmbedding          # représentation du paramètre ciblé
  + TechStackEmbedding          # stack technique détecté
  + MutationHistory             # ce qui a déjà été tenté sur cet endpoint
  + WAFEmbedding                # WAF détecté et ses caractéristiques

Action a_t :
  Sélection d'un payload dans un espace discret étendu
  OU génération d'un payload par un modèle génératif (voir 4.2.2)

Récompense r_t :
  +1.0  si experiment.result → finding.confirmed (vrai positif)
  +0.3  si signal détecté sans confirmation (ambiguous → à investiguer)
  -0.1  si refuted (surface épuisée sans signal)
  -0.5  si WAF block (payload inefficace)
  -0.3  si baseline_match (pas de différence détectable)
  -0.01 par requête (coût de ressources — encourage l'efficacité)
```

#### Architecture de l'agent RL

**Algorithme** : Proximal Policy Optimization (PPO) — stable, adapté aux
espaces d'action discrets étendus.

```python
class PayloadOptimizerAgent(PPOAgent):

    def __init__(self):
        self.policy_network = PolicyNetwork(
            input_dim=state_embedding_dim,
            hidden_dims=[512, 256],
            output_dim=payload_vocab_size  # ~5000 payloads indexés
        )
        self.value_network = ValueNetwork(
            input_dim=state_embedding_dim,
            hidden_dims=[256, 128],
            output_dim=1  # estimation de valeur d'état
        )
```

**Espace d'action** : vocabulaire de ~5000 payloads indexés, organisés
hiérarchiquement (classe → sous-type → variant). L'agent apprend une
**politique** : P(payload | état), pas une lookup table fixe.

**Entraînement** :
- Phase initiale (offline) : imitation learning sur les payloads confirmés
  des sessions passées — initialise la politique avec un comportement raisonnable
- Phase continue (online) : PPO en session réelle — chaque expérience produit
  une transition (s, a, r, s') mise en mémoire de replay

**Ce que l'agent apprend** :

```
Après N sessions sur des APIs Spring + PostgreSQL :
  État : {param_type=int, tech=postgresql, waf=none, history=[payload_A refuted]}
  Politique apprise :
    P("1 AND pg_sleep(3)=0") = 0.42    # timing blind postgres
    P("1::text ILIKE '%") = 0.31       # casting postgres
    P("1 UNION SELECT ...") = 0.18     # union-based
    P("' OR '1'='1") = 0.02            # payloads génériques → déprioritisés
```

L'agent a appris que les payloads PostgreSQL-spécifiques fonctionnent mieux
que les payloads génériques sur ce contexte — **sans qu'on lui ait dit de le faire**.

#### 4.2.2 PayloadGenerator — génération par séquence

Pour les cas où aucun payload du vocabulaire ne correspond, un modèle génératif
produit des payloads nouveaux.

```python
class PayloadGenerator:
    """
    Modèle seq2seq fine-tuné pour la génération de payloads.

    Architecture : Transformer (encoder-decoder)
    Input (encoder) : contexte encodé en tokens
      → [PARAM_TYPE:int] [DB:postgresql] [WAF:cloudflare] [PREV:refuted] [TARGET:blind_sqli]
    Output (decoder) : payload généré token par token

    Entraînement :
      - Corpus de payloads annotés avec leur contexte d'efficacité
      - Fine-tuning sur les payloads confirmés de la KnowledgeBase
    """

    def generate(self, context: PayloadContext, n_samples: int = 5) -> List[str]:
        """
        Génère N payloads candidats via beam search.
        Les candidats sont filtrés par ScopeGuard avant usage.
        """
        ...
```

**Contrainte** : les payloads générés passent obligatoirement par :
1. `ScopeGuard.validate()` — dans le scope autorisé
2. `SafetyFilter.check()` — pas de payloads destructeurs (DROP TABLE, rm -rf)
3. `DeduplicationFilter.check()` — pas déjà tenté sur cet endpoint

### 4.3 OracleModel — verdict par apprentissage

**Fichier** : `core/ml/models/oracle_model.py`

**Objectif** : remplacer le `ConfidenceModel` linéaire fixe par un modèle
appris sur les diffs (baseline, experiment) réels. C'est la réponse directe
au problème du `SemanticOracle` qui fait de la statistique syntaxique.

#### Architecture

```
Input :
  DiffEmbedding(baseline, experiment)    # vecteur de diff R^d
  + MutationType (one-hot)              # type de mutation appliqué
  + HypothesisContext embedding         # contexte de l'hypothèse
  + ReplayConsistency                   # les replays confirment-ils ?

Architecture :
  Attention layer sur les composantes du DiffEmbedding
    (le modèle apprend quelles dimensions du diff sont pertinentes
     pour chaque type de mutation)
  Dense(256, ReLU) → Dropout(0.2)
  Dense(128, ReLU)
  Dense(64, ReLU)

Output :
  P(true_positive)     # probabilité de vrai positif
  P(false_positive)    # probabilité de faux positif
  P(ambiguous)         # insuffisamment discriminant
  severity_score       # sévérité estimée [0,1]
  confidence_score     # confiance du verdict [0,1]
```

**Ce que le modèle apprend** : sur un corpus de diffs annotés (vrais positifs
et faux positifs confirmés par des pentesters), le modèle apprend quelles
*combinaisons* de changements dans la réponse signalent une vraie vulnérabilité.

Exemple de ce qu'il ne peut pas exprimer avec des règles mais peut apprendre :

> *"Un changement de status 200→200 avec un body 15% plus grand ET la présence
> d'un nouveau champ `user_id` différent de l'identité authentifiée ET un timing
> stable → P(BOLA) = 0.94"*

Cette combinaison est trop fine pour être une règle, mais parfaitement learnable
par un classifieur sur des données annotées.

#### Données d'entraînement

```python
@dataclass
class OracleTrainingSample:
    diff_embedding: np.ndarray          # DiffEmbedder.embed(baseline, experiment)
    mutation_type: MutationType         # le type de mutation appliqué
    hypothesis_context: np.ndarray      # contexte encodé
    replay_consistency: float           # proportion de replays confirmant
    label: VerdictLabel                 # TRUE_POSITIVE | FALSE_POSITIVE | AMBIGUOUS
    # labellé par : finding confirmé manuellement OU refuté après investigation
```

**Bootstrapping** : le modèle v4 est initialisé avec les seuils v3 traduits
en paramètres. Les premières sessions alimentent le réentraînement.

**Mise à jour** : réentraînement incrémental après chaque `N` sessions validées
(pas de mise à jour online non supervisée — ADR-NEW-004 étendu).

### 4.4 VulnerabilityEmbeddingSpace — espace latent des vulnérabilités

**Fichier** : `core/ml/models/vuln_embedding_space.py`

Composant transversal. Apprend un **espace sémantique des vulnérabilités**
où des vulnérabilités similaires sont proches.

```
Entraînement : triplet loss
  Anchor   : finding confirmé F_A (endpoint A, vuln X)
  Positive : finding confirmé F_B similaire (endpoint B similaire, même vuln X)
  Negative : finding confirmé F_C différent (endpoint C, vuln Y ≠ X)

  L = max(0, d(A,P) - d(A,N) + margin)

Résultat : espace R^128 où :
  - BOLA sur /api/users/{id} ≈ BOLA sur /api/accounts/{uuid}  (proches)
  - BOLA sur /api/users/{id} ≠ SQLi sur /api/search           (éloignés)
```

**Utilisation** : quand un nouvel endpoint est observé, son embedding est
comparé à ceux du corpus de findings par similarité cosine. Les findings
les plus proches sont des **prédictions de vulnérabilités probables** —
c'est le mécanisme de transfer learning inter-sessions le plus direct.

```python
similar_findings = vuln_space.find_similar(endpoint_embedding, k=5)
# → [
#   (Finding(BOLA, /api/invoices/{id}), similarity=0.91),
#   (Finding(BOLA, /api/orders/{uuid}), similarity=0.87),
#   (Finding(IDOR, /api/users/{id}),    similarity=0.79),
# ]
# → émet pattern.matched vers ReasoningLayer avec confidence=0.91
```

---

## Partie V — Couche 3 : Raisonnement (LLM décisionnel sur hypothèses)

### 5.1 Le changement par rapport à ADR-002

ADR-002 original : *"LLM ne peut jamais retourner CONFIRMED"*
ADR-002 révisé v4 : *"LLM ne peut jamais retourner CONFIRMED. LLM peut retourner
des hypothèses qui entrent dans le pipeline de validation normal."*

La distinction est précise : le LLM ne juge pas les résultats des expériences.
Il propose des vecteurs d'attaque. Ces vecteurs sont traités exactement comme
des hypothèses d'un plugin — ils passent par `ExperimentEngine` et `OracleModel`
avant tout verdict.

### 5.2 VulnerabilityReasoningLLM

**Fichier** : `core/llm/reasoning.py`

```python
class VulnerabilityReasoningLLM:
    """
    LLM utilisé pour générer des hypothèses d'attaque libres.
    Contraintes strictes sur les inputs et outputs.
    """

    SYSTEM_PROMPT = """
    Tu es un expert en sécurité web analysant le comportement d'une API.
    
    Tu reçois :
    - Le schéma observé d'un endpoint (méthode, path, paramètres, réponse)
    - Le comportement observé (status par rôle, valeurs typiques, timing)
    - Les invariants appris sur cet endpoint
    - Le contexte de la cible (tech stack, assets exposés)
    
    Tu dois générer des HYPOTHÈSES D'ATTAQUE sous forme structurée.
    Une hypothèse est :
    - Une classe de vulnérabilité que tu suspectes
    - Un raisonnement en une phrase expliquant pourquoi
    - Un vecteur de test concret
    
    Tu ne peux pas : affirmer qu'une vulnérabilité existe. Tu ne peux que proposer
    des vecteurs à tester. Ton output est toujours du JSON structuré.
    """

    def generate_hypotheses(
        self,
        endpoint: EndpointNode,
        context: HypothesisContext,
        existing_hypotheses: List[Hypothesis]
    ) -> List[LLMHypothesis]:
        """
        Génère des hypothèses que le moteur n'aurait pas générées.
        
        Inputs sérialisés en JSON, PAS de réponses brutes incluses.
        Outputs validés par LLMHypothesisValidator avant injection.
        """
        ...

    def reason_about_chain(
        self,
        confirmed_findings: List[Finding],
        current_attack_state: AttackState
    ) -> List[ChainHypothesis]:
        """
        Raisonne sur des chaînes d'attaque possibles à partir des findings.
        Propose des séquences que l'AttackGraphPlanner n'a pas calculées.
        """
        ...
```

#### LLMHypothesisValidator

Toute hypothèse LLM passe par un validateur déterministe avant injection :

```python
class LLMHypothesisValidator:

    def validate(self, hypothesis: LLMHypothesis) -> ValidationResult:
        checks = [
            self._check_scope(hypothesis),          # dans le scope autorisé
            self._check_safety(hypothesis),          # pas destructeur
            self._check_parseable(hypothesis),       # spec interprétable
            self._check_not_duplicate(hypothesis),   # pas déjà tenté
            self._check_budget(hypothesis),          # n'épuise pas le budget
        ]
        return ValidationResult(
            valid=all(c.passed for c in checks),
            filtered_spec=self._sanitize(hypothesis) if any_failed else hypothesis
        )
```

**Ce que le LLM apporte concrètement** :

```
Endpoint observé : POST /api/graphql
Context : GraphQL détecté, aucun rate limit observé, introspection non désactivée

LLM génère :
  Hypothesis("introspection query pour énumérer le schéma complet")
    → ExperimentSpec(payload='{"query": "{ __schema { types { name } } }"}')
  
  Hypothesis("batch queries pour contourner le rate limiting")
    → ExperimentSpec(payload='[{"query":"..."},{"query":"..."}×50]')
  
  Hypothesis("field duplication attack sur les resolvers")
    → ExperimentSpec(payload='{"query":"{ user { id id id id id } }"}')
```

Ces trois vecteurs sont spécifiques à GraphQL. Aucun plugin générique ne les
couvre. Le LLM les génère parce qu'il comprend que GraphQL a ces propriétés —
c'est de la connaissance sur les **principes** du protocole, pas des règles.

---

## Partie VI — Architecture Complète v4

### 6.1 Vue d'ensemble

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            HDWPEngine v4                                         │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐ │
│  │                        ML Foundation Layer                                  │ │
│  │  EndpointEmbedder · ResponseEmbedder · DiffEmbedder · VulnEmbeddingSpace   │ │
│  └──────────────────────────────┬──────────────────────────────────────────────┘ │
│                                 │ embeddings                                     │
│  ┌──────────────────────────────▼──────────────────────────────────────────────┐ │
│  │                      Intelligence Layer                                      │ │
│  │                                                                              │ │
│  │  VulnPredictionModel          OracleModel           PayloadOptimizer        │ │
│  │  (P(vuln) par endpoint)       (verdict ML)          (PPO agent RL)          │ │
│  │                                                                              │ │
│  │  VulnerabilityReasoningLLM    AttackGraphPlanner                            │ │
│  │  (hypothèses libres)          (A* planification)                            │ │
│  └──────────────────────────────┬──────────────────────────────────────────────┘ │
│                                 │                                                │
│  ┌──────────────────────────────▼──────────────────────────────────────────────┐ │
│  │                       Pipeline Opérationnel                                  │ │
│  │                                                                              │ │
│  │  ObservationEngine → ApplicationModel → ThreatModelEngine                   │ │
│  │  → ContextualHypothesisEngine → ExperimentEngine → SemanticOracle v4       │ │
│  │  → KnowledgeBase v4                                                         │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Flux de décision complet

```
[Endpoint observé]
      │
      ▼
EndpointEmbedder.embed(endpoint) → R^d
      │
      ├──▶ VulnPredictionModel.predict()
      │       → {P(BOLA)=0.85, P(SQLi)=0.12, P(XSS)=0.03, ...}
      │       → SHAP explanation → justification causale
      │       → StrategySelector : DEEP sur BOLA, SKIP sur XSS
      │
      ├──▶ VulnEmbeddingSpace.find_similar()
      │       → [Finding(BOLA, sim=0.91), Finding(IDOR, sim=0.79)]
      │       → émet pattern.matched → ReasoningLayer
      │
      └──▶ VulnerabilityReasoningLLM.generate_hypotheses() [si P(unknown) > 0.4]
              → hypothèses libres validées par LLMHypothesisValidator
              → injectées dans la queue d'hypothèses
      │
      ▼
ContextualHypothesisEngine
  → reçoit : VulnPredictionModel output + pattern.matched + LLM hypothèses
  → génère HypothesisContext complet
  → prioritise selon P(vuln) prédit, pas selon règles H/M/L
      │
      ▼
ExperimentEngine
  → PayloadOptimizer.select_payload(état_courant)
      → Agent PPO : action = payload optimal selon politique apprise
      → PayloadGenerator si aucun payload du vocabulaire ne convient
      │
      ├── ScopeGuard + SafetyFilter (inchangés)
      ├── exécution HTTP (inchangé)
      │
      └── Résultat → AdaptivePayloadEngine (mode STREAM)
                → r_t = récompense calculée
                → (s_t, a_t, r_t, s_{t+1}) → mémoire de replay PPO
                → mise à jour politique (batch async, pas online)
      │
      ▼
SemanticOracle v4
  → DiffEmbedder.embed(baseline, experiment)
  → OracleModel.predict(diff_embedding, mutation_type, context)
      → P(true_positive), P(false_positive), severity
  → CrossRoleDiffEngine (v3, conservé)
  → TemporalAnomalyDetector (v3, conservé)
  → InvariantStore.check_violation() (v3, conservé)
  → Verdict final : max(OracleModel output, règles déterministes)
      │
      ▼
AttackGraphPlanner (v3, conservé + enrichi)
  → VulnerabilityReasoningLLM.reason_about_chain(findings)
      → chaînes d'attaque que A* n'aurait pas calculées
      │
      ▼
KnowledgeBase v4
  → Stocke (endpoint_embedding, vuln_class, confirmed) → réentraînement VulnPredictionModel
  → Stocke (diff_embedding, verdict) → réentraînement OracleModel
  → Stocke (s, a, r, s') → réentraînement PayloadOptimizer
  → StructuralIndex.reindex() → transfer learning inter-sessions
```

### 6.3 Nouveaux événements bus

| Événement | Producteur | Consommateur |
|---|---|---|
| `ml.vuln_prediction` | VulnPredictionModel | ContextualHypothesisEngine, StrategySelector |
| `ml.pattern_matched` | VulnEmbeddingSpace | ReasoningLayer |
| `ml.oracle_verdict` | OracleModel | SemanticOracle v4 |
| `rl.transition` | ExperimentEngine | PayloadOptimizer (replay buffer) |
| `llm.hypothesis_proposed` | VulnerabilityReasoningLLM | LLMHypothesisValidator |
| `llm.hypothesis_validated` | LLMHypothesisValidator | ContextualHypothesisEngine |
| `ml.model_retrained` | KnowledgeBase v4 | (UI, logs) |

---

## Partie VII — KnowledgeBase v4 : mémoire apprenante

**Fichier** : `core/knowledge/base.py` (refonte complète)

### 7.1 Stockage des données d'entraînement

```python
class KnowledgeBase_v4:

    # Tables existantes (v3) conservées

    # Nouvelles tables ML :
    training_samples_vuln:     # (endpoint_embedding, vuln_labels, session_id)
    training_samples_oracle:   # (diff_embedding, mutation_type, verdict, session_id)
    rl_transitions:            # (state, action, reward, next_state, session_id)
    payload_effectiveness:     # (payload_hash, context_embedding, reward, session_id)
    finding_embeddings:        # (finding_id, embedding, vuln_class, session_id)
```

### 7.2 Cycle de réentraînement

```
Après chaque N sessions (N configurable, défaut = 10) :

1. VulnPredictionModel :
   → Extraire les training_samples_vuln validés manuellement
   → Fine-tuning par mini-batch gradient descent (lr=1e-4, 5 epochs)
   → Validation sur held-out set de sessions précédentes
   → Si val_loss améliore → déployer, sinon → conserver le modèle précédent

2. OracleModel :
   → Même protocole sur training_samples_oracle
   → Attention : ne réentraîner que sur les verdicts confirmés par un humain

3. PayloadOptimizer :
   → PPO update sur le buffer rl_transitions
   → Peut être mis à jour plus fréquemment (pas de label humain requis)

4. VulnEmbeddingSpace :
   → Réentraînement triplet loss sur les nouveaux findings
   → StructuralIndex.reindex() après
```

### 7.3 Validation obligatoire avant réentraînement

Le réentraînement ne se fait jamais sur des données non validées.
Un finding auto-confirmé par l'`OracleModel` ne peut pas alimenter
le réentraînement de l'`OracleModel` — ce serait un boucle de
confirmation circulaire.

```python
class TrainingDataValidator:
    """
    Un sample est validé si :
    - Finding marqué comme vrai positif par un pentexter humain (via UI)
    - OU finding correspondant à un CVE connu sur la cible (vérifiable)
    - OU finding reproduit avec un outil indépendant (Burp, sqlmap)
    """
    def is_valid_for_training(self, sample: TrainingSample) -> bool:
        return (
            sample.human_validated
            or sample.cve_matched
            or sample.independent_tool_confirmed
        )
```

---

## Partie VIII — Ce que v4 change réellement

### 8.1 Ce qui est fondamentalement différent

**Généralisation sans règles** : `VulnPredictionModel` prédit P(BOLA) = 0.85
sur un endpoint qu'il n'a jamais vu, parce qu'il partage des features
structurelles avec des endpoints BOLA confirmés dans son espace d'embedding.
Aucune règle n'est traversée.

**Payloads appris, pas listés** : `PayloadOptimizer` sélectionne un payload
PostgreSQL-spécifique sur un endpoint PostgreSQL parce que la politique PPO
a appris que cette combinaison est récompensée — sans qu'on lui ait dit de
préférer les payloads PostgreSQL.

**Oracle appris, pas calculé** : `OracleModel` détecte qu'une réponse avec
body +15% + nouveau champ `owner_id` différent + timing stable = BOLA avec
P=0.94, parce qu'il a vu des centaines de diffs similaires labellés BOLA.

**Hypothèses libres** : `VulnerabilityReasoningLLM` génère un vecteur
d'introspection GraphQL parce qu'il comprend le protocole, pas parce qu'un
plugin l'encode.

### 8.2 Ce qui reste borné (honnêteté requise)

**Le corpus d'entraînement borne la généralisation** : le `VulnPredictionModel`
ne prédit bien que les classes de vulnérabilités représentées dans ses données
d'entraînement. Une classe entièrement nouvelle (zero-day conceptuel) restera
dans P(unknown) et sera déléguée au LLM ou aux plugins.

**La récompense RL est sparse** : les vrais positifs sont rares. Le `PayloadOptimizer`
apprend lentement, surtout sur des cibles sans vulnérabilités évidentes.
Un mécanisme de récompense shaped (récompenses intermédiaires sur les signaux
ambigus) atténue ce problème mais ne le résout pas.

**Le LLM hallucine** : `VulnerabilityReasoningLLM` peut proposer des vecteurs
plausibles mais incorrects. Le `LLMHypothesisValidator` filtre les propositions
invalides, mais des faux positifs supplémentaires sont attendus. C'est le prix
de l'espace de recherche ouvert.

**La validation humaine est un goulot** : le réentraînement est conditionné
à la validation humaine des findings. Sans validation régulière, les modèles
stagnent. C'est intentionnel (ADR-NEW-004) mais contraignant.

---

## Partie IX — Ordre d'implémentation v4

### Phase 0 — Infrastructure ML (4–6 semaines)

**Objectif** : infrastructure de données et de modèles avant toute intelligence.

- Pipeline de collecte de données structurées depuis les sessions existantes
- `EndpointEmbedder` + `ResponseEmbedder` + `DiffEmbedder`
- Base de données d'entraînement (`KnowledgeBase v4` tables ML)
- Interface de validation humaine (UI simple pour labelliser les findings)
- Scripts de réentraînement périodique

### Phase 1 — OracleModel (4–5 semaines)

**Objectif** : premier modèle ML en production, sur le composant à plus fort impact.

- Corpus initial : sessions HDWP annotées (même peu nombreuses au départ)
- Architecture simple (MLP sur DiffEmbedding) → augmenter la complexité si besoin
- Déploiement en parallèle du ConfidenceModel v3 (A/B test)
- Validation : comparer le taux de vrais positifs entre les deux oracles

### Phase 2 — VulnPredictionModel (5–6 semaines)

**Objectif** : prédire avant de tester.

- Corpus : API Guru specs + CVE enrichis + sessions HDWP
- Fine-tuning sur données propres après quelques sessions
- Intégration dans `ContextualHypothesisEngine` pour la priorisation
- SHAP explanations pour alimenter `CausalInferenceEngine`

### Phase 3 — PayloadOptimizer (6–8 semaines)

**Objectif** : apprendre à choisir les payloads.

- Imitation learning initial sur les payloads confirmés des sessions passées
- Environnement RL : session HDWP comme environnement, récompenses définies
- Déploiement progressif : d'abord en suggestion, puis en remplacement des listes

### Phase 4 — VulnerabilityReasoningLLM (3–4 semaines)

**Objectif** : ouvrir l'espace de recherche.

- Prompt engineering + validation des outputs LLM
- `LLMHypothesisValidator` avec tous les garde-fous
- Intégration dans la queue d'hypothèses avec priorité configurable

### Phase 5 — VulnEmbeddingSpace (4–5 semaines)

**Objectif** : transfer learning cross-sessions mature.

- Nécessite un corpus de findings suffisant (> 200 findings labellés)
- Triplet loss training
- Intégration dans `ReasoningLayer` pour les early signals

---

## Partie X — ADRs v4

| ADR | Décision | Justification |
|---|---|---|
| ADR-002 révisé | LLM non-décisionnel sur les verdicts. LLM décisionnel sur les hypothèses, avec validation déterministe obligatoire. | Ouvre l'espace de recherche sans risque sur les verdicts |
| ADR-ML-001 | Aucun modèle ML ne peut confirmer seul un finding sans signal déterministe corroborant | Évite les boucles de confirmation circulaires |
| ADR-ML-002 | Les modèles ML ne sont réentraînés que sur des données validées humainement ou par outil indépendant | Évite la dérive par auto-confirmation |
| ADR-ML-003 | `PayloadOptimizer` est le seul composant autorisé à faire des mises à jour online (buffer replay) | Les autres modèles sont batch-only pour la stabilité |
| ADR-ML-004 | `VulnPredictionModel` expose obligatoirement des SHAP explanations pour chaque prédiction | Interprétabilité requise pour l'audit et la confiance |
| ADR-ML-005 | `PayloadGenerator` ne génère jamais de payloads destructeurs (DDL SQL, commandes système) | SafetyFilter est non-contournable |
