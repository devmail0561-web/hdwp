# HDWP Engine

**Hypothesis-Driven Web Pentesting Engine**

A web application security testing engine that reasons by falsifying security properties, not by signatures or payloads.

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
