<div align="center">

# HDWP

**Hypothesis-Driven Web Pentesting Engine**

*A semantic security testing engine that falsifies formal security properties — not signatures, not payloads.*

<br/>

[![License](https://img.shields.io/badge/License-MIT-4b5563?style=flat-square)](LICENSE)
[![Engine](https://img.shields.io/badge/Engine-Python_3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![UI](https://img.shields.io/badge/UI-React_19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![Build](https://img.shields.io/badge/Build-Vite_8-646CFF?style=flat-square&logo=vite&logoColor=white)](https://vite.dev)
[![Database](https://img.shields.io/badge/Database-SQLite_async-003B57?style=flat-square&logo=sqlite&logoColor=white)]()
[![ML](https://img.shields.io/badge/ML-scikit--learn-F7931E?style=flat-square&logo=scikitlearn&logoColor=white)]()

[![Plugins](https://img.shields.io/badge/Plugins-38_semantic-8b5cf6?style=flat-square)]()
[![Strategies](https://img.shields.io/badge/Strategies-1040_YAML-06b6d4?style=flat-square)]()
[![Tests](https://img.shields.io/badge/Tests-1301_passing-22c55e?style=flat-square)]()
[![Release](https://img.shields.io/github/v/release/devmail0561-web/hdwp?include_prereleases&style=flat-square&color=f97316)](https://github.com/devmail0561-web/hdwp/releases/latest)
[![Binary](https://img.shields.io/badge/Binary-standalone_230_MB-1d4ed8?style=flat-square)](https://github.com/devmail0561-web/hdwp/releases/latest)

</div>

---

> [!WARNING]
> **Legal notice — Authorized use only.**
>
> HDWP is designed exclusively for **authorized security testing** — penetration testing engagements with written permission, bug bounty programs within scope, CTF competitions, and controlled lab environments.
>
> Running HDWP against systems you do not own or do not have **explicit written authorization** to test is illegal in most jurisdictions (CFAA, Computer Misuse Act, and equivalents worldwide). Unauthorized use may result in criminal prosecution and civil liability.
>
> **The authors and contributors of HDWP accept no responsibility for misuse, damage, or legal consequences arising from unauthorized or malicious use of this software.** By downloading or using HDWP you agree that you are solely responsible for ensuring your use is lawful and authorized.

---

## Philosophy

Traditional scanners (ZAP, Nikto, Burp Scanner) work in *fire-and-detect* mode: inject payloads from a list, look for error patterns. HDWP works differently — it **falsifies security properties**:

```
ApplicationModel  (semantic graph)
  → SecurityPropertyEngine  (theorems over the graph)
    → HypothesisEngine      (falsifiable hypotheses)
      → ExperimentEngine    (baseline + mutation)
        → SemanticOracle    (behavioral verdict)
```

OWASP/CWE classifications are applied *a posteriori* on findings — never as a starting point.

---

## Features

### Detection
- **38 semantic plugins** — OWASP Web Top 10, OWASP API Security Top 10, critical web CWEs
- **Unknown anomaly detection** — behavioral Z-score, size ratio, field entropy — detects without signatures
- **36 mutation types** — `identity_swap`, `field_injection`, `type_confusion`, `cache_poisoning`, `http_smuggling`, `info_disclosure`, etc.
- **Feedback loop** — confirmed findings automatically generate deeper follow-up hypotheses
- **Multi-method coverage** — probes POST/PUT/PATCH on every discovered GET endpoint

### Data-driven exploitation
- **1 040 YAML exploit strategies** — 100 per OWASP category (A01–A10), extensible without code
- **PayloadDatabase** — externalized payloads in YAML (14 files), automatic legacy fallback
- **Encoding pipeline** — chained encoders (URL, Unicode, Base64, null bytes, …)
- **WAF bypass** — `BypassRegistry` with 15 transport/protocol strategies, 7 recognized WAF signatures
- **Adaptive chains** — SQLi/XSS `ADAPTIVE_CHAINS`: automatic escalation based on WAF detection

### Intelligence
- **ML confidence model** — `ConfidenceModelV2` (10 logistic dimensions), `ExplainabilityLayer` (transparent verdicts)
- **MetaLearner** — unified ML facade, cross-session learning via `KnowledgeBase`
- **Behavioral oracle** — baseline vs. mutation comparison with `data_identity_score`
- **Threat scoring** — `ThreatModelEngine` dynamic threat score per endpoint
- **Invariant learning** — `InvariantStore` inductively learns invariants and flags violations
- **CrossRole diff** — compares inter-role responses (`STRUCTURAL` / `VALUE` / `IDENTITY`)
- **Temporal anomaly** — blind injection detection via timing (baseline p95 + escalation)
- **Attack graph** — `AttackGraphPlanner` plans multi-step chains via A\* on `AttackState`

### Infrastructure
- **INTEL dashboard** — real-time v3 signal dashboard in the web UI
- **Tor opt-in** — direct connection by default; Tor enabled via `tor_proxy` in context or `--proxy` CLI
- **SPA support** — Playwright crawl routed through the MITM proxy
- **Integrated MITM proxy** — auto-generated CA, automatic browser installation
- **Adaptive learning** — weights tuned per target type (API, CMS, SPA, GraphQL)
- **Version scanning** — CVE lookup via OSV.dev

---

## Installation

### Option 1 — Standalone binary (recommended)

Download the pre-built binary from the [latest release](https://github.com/devmail0561-web/hdwp/releases/latest). No Python required.

```bash
# Download
curl -LO https://github.com/devmail0561-web/hdwp/releases/latest/download/hdwp
chmod +x hdwp

# Verify checksum (see release page for current SHA-256)
sha256sum hdwp

# Run
./hdwp --help
```

> The binary is a self-contained Linux x86-64 ELF executable (~230 MB) built with PyInstaller. It bundles Python 3.12, all dependencies, 1 040 YAML strategies, and the React frontend.

### Option 2 — From source (Python 3.12)

```bash
git clone https://github.com/devmail0561-web/hdwp.git
cd hdwp

python3.12 -m venv .venv
source .venv/bin/activate

# Core engine
pip install -e .

# With dev tools (tests, linting)
pip install -e ".[dev]"

# With SPA crawling support
pip install -e ".[spa]"
.venv/bin/playwright install chromium

# With ML extras (confidence model training)
pip install -e ".[ml]"

# With LLM-assisted analysis
pip install -e ".[llm]"
```

### Option 3 — Rebuild the binary yourself

```bash
pip install pyinstaller
pyinstaller hdwp.spec --distpath dist/bin --noconfirm
# Output: dist/bin/hdwp
```

---

## Configuration

Create a `hdwp-context.yaml` file:

```yaml
target:
  base_url: "https://target.example.com"
  name: "Target API"

scope:
  include: ["https://target.example.com/*"]

options:
  max_requests_per_minute: 60
  # Tor routing (optional)
  tor_proxy: "socks5h://127.0.0.1:9150"

plugins:
  disabled: []   # empty = all plugins active
```

A minimal example is provided in [`hdwp-context.example.yaml`](hdwp-context.example.yaml).

---

## Usage

```bash
# Open the web interface (auto-opens browser)
hdwp

# Direct scan — creates a minimal context automatically
hdwp --target https://target.example.com

# Scan from a context file
hdwp --context hdwp-context.yaml

# Crawl and export the application model
hdwp model --context hdwp-context.yaml

# List available plugins
hdwp plugin list

# Generate a report from an evidence store
hdwp report --db hdwp.db

# Replay a specific experiment
hdwp replay --db hdwp.db --id <experiment-id>
```

---

## Pipeline

```
OBSERVE     → GET crawl + POST/PUT/PATCH probe + MITM proxy + OpenAPI seed
MODEL       → EndpointNode, ParameterNode (semantic), DataObjectNode (sensitivity)
              + ThreatModelEngine (score/classification per endpoint)
              + InvariantStore (inductive invariant learning)
INFER       → SecurityProperty from semantic graph (38 plugins)
HYPOTHESIZE → ContextualHypothesisEngine (depth SHALLOW/MEDIUM/DEEP by threat score)
EXPERIMENT  → baseline + mutation (36 types, YAML payloads, encoding pipeline)
              + AdaptivePayloadEngine (WAF detection + bypass strategy)
              + BypassRegistry (15 transport/protocol strategies)
ORACLE      → SemanticDiff + data_identity_score + anomaly detection (Z-score, size ratio, entropy)
              + CrossRoleDiffEngine (STRUCTURAL/VALUE/IDENTITY)
              + TemporalAnomalyDetector (blind injection via timing)
              + ConfidenceModelV2 (10 dimensions) + ExplainabilityLayer
EXPLOIT     → 1 040 YAML strategies (A01–A10) + multi-phase network engine
              + 15+ inject types + auto-generated HTML PoCs
CHAIN       → AttackGraphPlanner (A* multi-step on AttackState) + multi-finding correlations
REPORT      → Findings with impact, attack scenarios, remediations, explainability
```

---

## License

MIT — Copyright (c) 2026 M. TENDENG

See [LICENSE](LICENSE) for details.
