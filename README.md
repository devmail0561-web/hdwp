# HDWP Engine

**Hypothesis-Driven Web Pentesting Engine**

Un moteur de test de sécurité web qui raisonne en falsifiant des propriétés de sécurité formelles, pas par signatures ou payloads.

## Philosophie

Les scanners traditionnels (ZAP, Nikto, Burp Scanner) fonctionnent en mode *fire-and-detect* : injecter des payloads depuis une liste, chercher des patterns d'erreur.

HDWP fonctionne différemment — il **falsifie des propriétés** :

```
ApplicationModel (graphe sémantique)
  → SecurityPropertyEngine (théorèmes sur le graphe)
    → HypothesisEngine (hypothèses falsifiables)
      → ExperimentEngine (baseline + mutation)
        → SemanticOracle (verdict comportemental)
```

Les classifications OWASP/CWE sont appliquées *a posteriori* sur les findings — jamais comme point de départ.

## Features

### Détection
- **40 plugins sémantiques** — OWASP Web Top 10, OWASP API Security Top 10, CWEs web critiques
- **Détection d'anomalies inconnues** — Z-score comportemental, ratio de taille, entropie des champs — détecte sans signature
- **36 types de mutation** — identity_swap, field_injection, type_confusion, cache_poisoning, http_smuggling, info_disclosure, etc.
- **Boucle de feedback** — findings confirmés → nouvelles hypothèses d'approfondissement automatiques
- **Couverture multi-méthodes** — sonde POST/PUT/PATCH sur chaque endpoint GET découvert

### Exploitation data-driven
- **1040 stratégies d'exploitation YAML** — 100 par catégorie OWASP (A01–A10), extensibles sans code
- **PayloadDatabase** — payloads externalisés en YAML (14 fichiers), fallback legacy automatique
- **Encoding pipeline** — encodeurs chaînés (URL, Unicode, Base64, null bytes, etc.)
- **WAF bypass** — `BypassRegistry` avec 15 stratégies transport/protocol, 7 signatures WAF reconnues
- **Chaînes adaptatives** — SQLi/XSS ADAPTIVE_CHAINS : escalade automatique selon détection

### Intelligence
- **ML confidence model** — ConfidenceModelV2 (10 dimensions logistiques), ExplainabilityLayer (transparence verdict)
- **MetaLearner** — façade ML unifiée, apprentissage inter-sessions via KnowledgeBase
- **Oracle comportemental** — compare baseline vs mutation avec `data_identity_score`
- **Threat scoring** — `ThreatModelEngine` score de menace dynamique par endpoint
- **Invariant learning** — `InvariantStore` apprend inductivement les invariants et détecte les violations
- **CrossRole diff** — compare les réponses inter-rôles (STRUCTURAL/VALUE/IDENTITY)
- **Temporal anomaly** — détection d'injection blind via timing (baseline p95 + escalade)
- **Attack graph** — `AttackGraphPlanner` planifie des chaînes multi-étapes via A* sur `AttackState`

### Infrastructure
- **Onglet INTEL** — tableau de bord temps réel des signaux v3 dans l'interface web
- **Tor opt-in** — connexion directe par défaut ; Tor activé via `tor_proxy` dans le contexte ou `--proxy` CLI
- **SPA support** — crawl Playwright routé à travers le proxy MITM
- **Proxy MITM intégré** — CA auto-généré, installation automatique navigateurs
- **Adaptive learning** — poids adaptés par type de cible (API, CMS, SPA, GraphQL)
- **Version scanning** — CVE via OSV.dev

## Install

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Pour le support SPA (Playwright)
pip install -e ".[spa]"
.venv/bin/playwright install chromium
```

## Configuration

```yaml
# hdwp-context.yaml
target:
  base_url: "https://target.example.com"
  name: "Target API"

scope:
  include: ["https://target.example.com/*"]

options:
  tor_proxy: "socks5h://127.0.0.1:9150"  # Tor par défaut
  max_requests_per_minute: 60

plugins:
  disabled: []  # vide = tous les plugins actifs
```

## Usage

```bash
# Lancer l'interface
hdwp

# Scan direct
hdwp --target https://target.example.com

# Avec un fichier de contexte
hdwp --context hdwp-context.yaml
```

## Pipeline

```
OBSERVE     → crawl GET + probe POST/PUT/PATCH + proxy MITM + OpenAPI seed
MODEL       → EndpointNode, ParameterNode (semantic), DataObjectNode (sensitivity)
              + ThreatModelEngine (score/classification par endpoint)
              + InvariantStore (apprentissage inductif des invariants)
INFER       → SecurityProperty depuis le graphe sémantique (40 plugins)
HYPOTHESIZE → ContextualHypothesisEngine (profondeur SHALLOW/MEDIUM/DEEP selon threat score)
EXPERIMENT  → baseline + mutation (36 types, payloads YAML, encoding pipeline)
              + AdaptivePayloadEngine (WAF detection + bypass strategy)
              + BypassRegistry (15 stratégies transport/protocol)
ORACLE      → SemanticDiff + data_identity_score + anomaly detection (Z-score, size ratio, entropy)
              + CrossRoleDiffEngine (STRUCTURAL/VALUE/IDENTITY)
              + TemporalAnomalyDetector (blind injection via timing)
              + ConfidenceModelV2 (10 dimensions) + ExplainabilityLayer
EXPLOIT     → 1040 stratégies YAML (A01–A10) + moteur réseau multi-phases
              + 15+ inject types + PoC HTML auto-générés
CHAIN       → AttackGraphPlanner (A* multi-étapes sur AttackState) + corrélations multi-findings
REPORT      → Findings avec impact, scénarios d'attaque, remédiations, explainability
```

## License

MIT — Copyright (c) 2026 M. TENDENG
