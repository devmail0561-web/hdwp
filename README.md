# HDWP Engine

**Hypothesis-Driven Web Pentesting Engine**

A web application security testing engine that reasons by falsifying security properties, not by signatures or payloads.

## Features

- **Hypothesis-driven analysis** — tests security properties, not signatures
- **Adaptive learning** — adapte les priorités, la confiance et les poids par type de cible (API, CMS, SPA, GraphQL) au fil des sessions
- **Proxy MITM intégré** — capture des credentials HTTP/HTTPS sans dépendance externe (certificat CA auto-généré, installation automatique dans Chrome/Firefox/système)
- **Version scanning** — détection de bibliothèques JS/CSS vulnérables (CVE via OSV.dev)
- **Flow visualization** — graphe animé des flux de données entre endpoints
- **Plugin system** — créez vos propres modules de détection

## Core Loop

```
OBSERVE -> MODEL -> INFER PROPERTIES -> HYPOTHESIZE -> EXPERIMENT -> ORACLE -> FINDING
```

## Install

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# Run the engine
hdwp run --context hdwp-context.yaml

# Export the application model
hdwp model --context hdwp-context.yaml --export model.json

# Generate a report
hdwp report --session SESSION_ID --format md

# Replay an experiment
hdwp replay --experiment EXP-xxxx

# Manage plugins
hdwp plugin list
```

## License

MIT -- Copyright (c) 2026 M. TENDENG
