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

- **34 vecteurs de détection** — plugins sémantiques couvrant OWASP Web Top 10, OWASP API Security Top 10, et CWEs web critiques
- **Couverture multi-méthodes** — sonde POST/PUT/PATCH sur chaque endpoint GET découvert
- **Oracle comportemental** — compare baseline vs mutation avec `data_identity_score` (pas seulement les patterns)
- **Tor par défaut** — tout le trafic passe par `socks5h://127.0.0.1:9150`
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
INFER       → SecurityProperty depuis le graphe sémantique (34 modules)
HYPOTHESIZE → Hypothèses falsifiables par (endpoint × mutation × param)
EXPERIMENT  → baseline + mutation (méthode réelle du corpus)
ORACLE      → SemanticDiff + data_identity_score + violation assessors
CHAIN       → Corrélation multi-findings (BOLA+SQLi, CORS+XSS…)
REPORT      → Findings avec impact, scénarios d'attaque, remédiations
```

## License

MIT — Copyright (c) 2026 M. TENDENG
