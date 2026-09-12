<div align="center">

# HDWP

**Semantic Web Security Scanner — ML-Optimized**

*Builds a semantic model of the application, derives formal security properties, and falsifies them through behavioral experiments. No signatures. No exploit layer.*

<br/>

[![License](https://img.shields.io/badge/License-MIT-4b5563?style=flat-square)](LICENSE)
[![Engine](https://img.shields.io/badge/Engine-Python_3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![UI](https://img.shields.io/badge/UI-React_19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![Build](https://img.shields.io/badge/Build-Vite_8-646CFF?style=flat-square&logo=vite&logoColor=white)](https://vite.dev)
[![ML](https://img.shields.io/badge/ML-scikit--learn-F7931E?style=flat-square&logo=scikitlearn&logoColor=white)]()

[![Plugins](https://img.shields.io/badge/Plugins-38_semantic-8b5cf6?style=flat-square)]()
[![Mutations](https://img.shields.io/badge/Mutations-31_types-06b6d4?style=flat-square)]()
[![Tests](https://img.shields.io/badge/Tests-1309_passing-22c55e?style=flat-square)]()
[![Release](https://img.shields.io/github/v/release/devmail0561-web/hdwp?include_prereleases&style=flat-square&color=f97316)](https://github.com/devmail0561-web/hdwp/releases/latest)
[![Binary](https://img.shields.io/badge/Binary-standalone-1d4ed8?style=flat-square)](https://github.com/devmail0561-web/hdwp/releases/latest)

</div>

---

> [!WARNING]
> **Legal notice — Authorized use only.**
>
> HDWP is designed exclusively for **authorized security testing**: penetration testing engagements with explicit written permission, bug bounty programs within defined scope, CTF competitions, and controlled lab environments.
>
> Running HDWP against systems you do not own or do not have **explicit written authorization** to test is illegal in most jurisdictions (U.S. Computer Fraud and Abuse Act, UK Computer Misuse Act, and equivalent laws worldwide). Unauthorized use may result in criminal prosecution and civil liability.
>
> **The authors and contributors of HDWP bear no responsibility whatsoever for misuse, damage, data loss, or legal consequences arising from unauthorized or malicious use of this software.** By downloading, installing, or running HDWP you agree that you are solely responsible for ensuring your use is lawful and properly authorized.

---

## Table of Contents

- [Philosophy](#philosophy)
- [How It Compares](#how-it-compares)
- [ML Pipeline](#ml-pipeline)
- [What HDWP Analyzes](#what-hdwp-analyzes)
- [Features](#features)
- [Plugins](#plugins)
- [Mutations](#mutations)
- [Attack Chains](#attack-chains)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Server](#api-server)
- [Report Formats](#report-formats)
- [Pipeline](#pipeline)
- [License](#license)

---

## Philosophy

Traditional scanners (OWASP ZAP, Nikto, Burp Scanner) work in *fire-and-detect* mode: iterate over a payload list, inject it, match the response against an error pattern. They are bounded by their signature databases — they can only find what they already know how to look for.

HDWP operates on a different premise. It **models the application semantically**, derives **formal security properties** from that model, then **falsifies** those properties through controlled behavioral experiments. OWASP and CWE classifications are applied *a posteriori* on the findings — never as a starting point.

```
ApplicationModel  (semantic graph — endpoints, parameters, roles, data sensitivity)
  → SecurityPropertyEngine  (formal theorems: "this endpoint must be access-controlled")
    → HypothesisEngine      (falsifiable hypotheses from each property)
      → ExperimentEngine    (baseline request + mutation, encoding pipeline)
        → SemanticOracle    (behavioral diff: is the mutation distinguishable from baseline?)
          → MetaLearner     (8 ML models — score, explain, learn, adapt across sessions)
            → Finding       (confirmed vulnerability with confidence breakdown)
              → AttackGraph (A* multi-step chain planning from confirmed findings)
```

The result: HDWP detects **unknown vulnerability classes** through behavioral anomaly detection, not just the 38 named CWEs it covers explicitly. And it learns.

---

## How It Compares

| Capability | HDWP | Burp Suite Pro | OWASP ZAP | Nikto | Nuclei |
|---|:---:|:---:|:---:|:---:|:---:|
| Semantic application model | ✅ | ❌ | ❌ | ❌ | ❌ |
| Property-based hypothesis engine | ✅ | ❌ | ❌ | ❌ | ❌ |
| Unknown anomaly detection (no signatures) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Multi-role behavioral diff (BOLA/AuthZ) | ✅ | Partial | Partial | ❌ | ❌ |
| ML confidence scoring with explainability | ✅ | ❌ | ❌ | ❌ | ❌ |
| Cross-session ML learning (persistent KB) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Thompson Sampling mutation prioritization | ✅ | ❌ | ❌ | ❌ | ❌ |
| A\* multi-step attack chain planning | ✅ | ❌ | ❌ | ❌ | ❌ |
| CVE scanning (JS + backend) | ✅ | Partial | Partial | Partial | ✅ |
| MITM proxy + SPA browser crawl | ✅ | ✅ | ✅ | ❌ | ❌ |
| JS dynamic API extraction (fetch/axios/XHR) | ✅ | Partial | Partial | ❌ | ❌ |
| WebSocket + gRPC protocol coverage | ✅ | Partial | Partial | ❌ | Partial |
| Fully open-source | ✅ | ❌ | ✅ | ✅ | ✅ |

**Key differentiators:**
- **Burp Suite Pro** is a powerful manual proxy with an active scanner and its own CVE database. It requires a browser, a license, and significant manual effort. It has no semantic model and cannot plan multi-step attack chains.
- **OWASP ZAP** is a good free alternative to Burp with WebSocket support and an Access Control Testing add-on for multi-role AuthZ. Its scanner relies on signature-based detection and its automation framework requires scripting effort to customize.
- **Nikto** is a fast but shallow banner/header/path scanner with no semantic understanding.
- **Nuclei** has a large template library (including WebSocket protocol support since v2.8) but templates are static signatures, not behavioral hypotheses. No application model, no cross-role diff, no ML.
- **HDWP** is the only tool in this list that builds a semantic graph of the application, derives security properties from it, uses behavioral comparison to detect violations, and improves across sessions through machine learning.

---

## ML Pipeline

HDWP embeds 9 ML components coordinated by a unified `MetaLearner` facade. All models persist their state in a cross-session `KnowledgeBase` (SQLite). They learn from every scan and improve over time.

### ConfidenceModelV2

A **10-dimensional logistic regression** that produces the final `[0,1]` confidence score for each finding. Dimensions:

| Dimension | What it measures |
|---|---|
| `oracle_strength` | How clearly the behavioral diff signals a violation |
| `reproducibility` | Fraction of experiment replays that confirm the violation |
| `observation_quality` | Completeness and diversity of the observation corpus |
| `behavioral_specificity` | How specific the mutation is to the suspected CWE class |
| `experiment_coverage` | Breadth of parameter locations and mutation variants tested |
| `temporal_signal` | Timing anomaly escalation level (blind injection detection) |
| `crossrole_signal` | Cross-role differential confidence |
| `invariant_violated` | Whether a learned invariant was violated |
| `waf_bypass_success` | WAF bypass success indicator |
| `causal_depth` | Causal reasoning depth (replay confirmation chains) |

Weights are updated cross-session by `FeedbackLoop` from confirmed vs. false-positive findings.

### OracleModel

A **scikit-learn logistic classifier** trained on the raw 10D feature vectors from `SemanticOracle` verdicts. Provides an independent probability estimate that reinforces (or weakens) the `ConfidenceModelV2` score.

Trains automatically when ≥ 50 labeled examples are available in the `KnowledgeBase`. Stored as a joblib-serialized model, reloaded at each session startup.

### VulnClassifier

A **per-endpoint vulnerability type predictor**. Takes the endpoint profile (method, path pattern, content type, observed parameter names) and predicts which mutation types are likely to yield findings on that endpoint.

Fed into `MetaLearner.sort_hypotheses()` to prioritize the hypothesis queue before scanning begins.

### PayloadOptimizer

A **Thompson Sampling contextual bandit** with arms keyed by `(endpoint_fingerprint, mutation_type)`.

- **Fingerprint** encodes `{method}:{has_auth}:{has_path_params}:{content_type_bucket}` — 6×2×2×3 = 72 possible values.
- **Reward signal**: `+1.0` for CONFIRMED, `-0.5` for REFUTED, `0.0` for AMBIGUOUS.
- The bandit reorders hypotheses so that (fingerprint, mutation) pairs with a high historical success rate on similar endpoints are tried first.
- Persisted in `KnowledgeBase.payload_optimizer_stats` between sessions.

### HypothesisBandit

A **Thompson Sampling bandit** with arms keyed by `(property_type, mutation_type)`, using `Beta(alpha, beta)` posteriors.

Complements `PayloadOptimizer`: while `PayloadOptimizer` optimizes by endpoint profile, `HypothesisBandit` optimizes by abstract property × mutation type — a higher-level signal that generalizes across endpoint types.

### ActiveLearner

An **active learning component** that identifies the hypotheses where the model is most uncertain (`score ≈ 0.5`) and promotes them for testing. Ensures the bandit models receive informative training examples, not just easy positives/negatives.

### ExplainabilityLayer

Built into `ConfidenceModelV2.explain()`, the explainability layer produces a **per-dimension contribution breakdown** for each confirmed finding:

```json
{
  "oracle_strength":        { "score": 0.91, "contribution": "HIGH" },
  "reproducibility":        { "score": 0.88, "contribution": "HIGH" },
  "temporal_signal":        { "score": 0.00, "contribution": "NONE" },
  "crossrole_signal":       { "score": 0.75, "contribution": "MEDIUM" },
  "causal_depth":           { "score": 0.82, "contribution": "HIGH" },
  "overall":                0.87,
  "top_contributors":       ["oracle_strength", "causal_depth", "reproducibility"]
}
```

Displayed in the FINDINGS tab and included in JSON/Markdown reports.

### MetaLearner (facade)

Orchestrates all ML components. Exposes a single API to `engine.py`:

| Method | What it does |
|---|---|
| `await load(kb)` | Loads all models from `KnowledgeBase` at session start |
| `wire(bus, oracle)` | Subscribes to bus events to feed the feedback loop |
| `sort_hypotheses(hypotheses)` | Reorders the hypothesis queue using `HypothesisBandit` + `PayloadOptimizer` + `ActiveLearner` |
| `await save_session(kb, target_hash, target_type)` | Saves updated model weights to `KnowledgeBase` at session end |
| `stats()` | Returns a snapshot of all model states for the `/api/state` endpoint |

---

## What HDWP Analyzes

HDWP performs deep multi-source discovery. It leaves nothing unexamined.

### Crawl sources

**Standard HTML parsing**
- Navigation links (`<a href>`)
- Forms: action URL, HTTP method, field names and types — realistic synthetic values submitted (email, password, number defaults)
- `<button formaction>` alternate submission targets
- `<link rel="prefetch|preload|canonical|alternate">` resource hints
- Data attributes: `data-url`, `data-href`, `data-action`, `data-api`, `data-api-url`, `data-endpoint`, `data-src`

**JavaScript static analysis** — without executing the browser
- `fetch()` and `window.fetch()` calls (URL + method extracted from options object)
- `axios.get/post/put/delete/patch()` and `axios.create({ baseURL })`
- `XMLHttpRequest.open("METHOD", "/path")`
- jQuery: `$.ajax`, `$.get`, `$.post`, `$.getJSON`
- WebSocket connections: `new WebSocket("wss://...")` — URL discovered and queued
- Config object properties: `url`, `path`, `endpoint`, `href`, `baseURL`, `apiUrl`
- API-like bare strings: paths starting with `/api/`, `/v1/`, `/graphql/`, `/rest/`, `/rpc/`
- **DOM sink detection**: inline scripts scanned for dangerous sinks (`innerHTML`, `eval`, `document.write`, `outerHTML`) — feeds XSS hypotheses

**API schemas & specs**
- OpenAPI/Swagger auto-discovery at 10 standard paths: `/swagger.json`, `/openapi.json`, `/api-docs`, `/v1/api-docs`, `/v2/api-docs`, `/v3/api-docs`, `/.well-known/openapi.json`, etc.
- Local file or remote URL via `discovery.openapi_spec` in context config (JSON or YAML)
- GraphQL introspection queries on detected GraphQL endpoints
- Manual seed list via `discovery.seed_endpoints`

**HTTP response mining**
- HATEOAS JSON fields: `href`, `url`, `uri`, `_url`, `link`, `location`, `next`, `prev`, `self`
- `Link:` response header (RFC 5988) for pagination and related resources
- `robots.txt`: `Disallow`, `Allow`, and `Sitemap` directives
- `sitemap.xml`: all `<loc>` URL entries

**Active probing**
- OPTIONS request per unique normalized path — discovers the `Allow` header and CORS `Access-Control-*` headers
- POST/PUT/PATCH probing on every discovered GET endpoint — builds multi-method corpus without needing an OpenAPI spec

**SPA and browser traffic** (optional)
- Playwright-based crawler routes a real browser through the HDWP MITM proxy — captures all XHR and fetch calls from rendered JavaScript applications
- Passive proxy capture mode (mitmproxy) — records real user browser traffic as an additional seed

**Protocol coverage**
- **WebSocket** — `ws://` and `wss://` endpoints observed and injected via `WebSocketObserver` + `WebSocketInjector`
- **gRPC** — `GrpcObserver` enumerates services via server reflection; `GrpcInjector` injects mutations into unary calls

### Version fingerprinting and CVE scanning

HDWP fingerprints every library and framework it encounters and queries the **OSV.dev vulnerability database**:

**Frontend JavaScript libraries** (detected from CDN URLs and in-page content):
- jQuery, React, Angular, Bootstrap, Vue.js, Lodash
- Generic JS comment headers: `/* LibraryName vX.Y.Z */`
- CDN URL version tokens (cdnjs, jsdelivr, unpkg)
- Queries OSV.dev `npm` ecosystem; findings tagged **OWASP A06:2021 / CWE-1395**

**Backend frameworks** (detected from HTTP headers and error pages):
- Django, Flask, FastAPI (Python / PyPI)
- Ruby on Rails (RubyGems)
- Laravel (Packagist)
- Spring Boot / spring-core (Maven)
- Express.js, Next.js (npm)
- ASP.NET Core (NuGet)
- Version extracted from `X-Powered-By`, `Server` headers, and error page HTML

Offline mode supported — query a local JSON database instead of the live OSV.dev API.

---

## Features

### Behavioral oracle
- **Semantic diff** — compares baseline vs. mutation response using `data_identity_score`, structural diff, value diff, and identity diff
- **Z-score anomaly detection** — flags responses that statistically deviate from baseline without a known signature
- **Size ratio anomaly** — detects information disclosure via response size changes
- **Field entropy analysis** — detects randomness changes in fields that should be stable
- **CrossRole diff** (`STRUCTURAL` / `VALUE` / `IDENTITY`) — compares the same request across different authenticated roles to detect BOLA and AuthZ issues

### ML intelligence (9 components)
- **ConfidenceModelV2** — 10-dimensional logistic model; produces the final `[0,1]` confidence score per finding, with built-in explainability (`explain()`)
- **OracleModel** — scikit-learn classifier trained on confirmed vs. false-positive verdicts
- **VulnClassifier** — per-endpoint vulnerability type prediction to focus the hypothesis queue
- **PayloadOptimizer** — Thompson Sampling bandit over `(endpoint_fingerprint × mutation_type)`
- **HypothesisBandit** — Thompson Sampling bandit over `(property_type × mutation_type)`
- **ActiveLearner** — promotes uncertain hypotheses to maximize training signal
- **SimilarityIndex** — cross-endpoint similarity for transfer learning
- **EndpointClusterer** — endpoint grouping for vulnerability type prediction
- **FeedbackLoop** — updates ConfidenceModelV2 weights from confirmed vs. false-positive findings
- **MetaLearner** — unified facade; all models persist cross-session in `KnowledgeBase` (SQLite)

### Detection intelligence
- **ThreatModelEngine** — per-endpoint threat score drives hypothesis depth (`SHALLOW` / `MEDIUM` / `DEEP`)
- **InvariantStore** — inductively learns invariants from baseline traffic; flags any violation
- **TemporalAnomalyDetector** — detects blind injection (SQLi, SSTI, CMDI) purely via response time (baseline p95 + automatic escalation)
- **AmbiguityResolver** — uses LLM context (when configured) to resolve inconclusive verdicts

### Infrastructure
- **Integrated MITM proxy** — auto-generated CA certificate, one-command browser installation (`hdwp install-ca`)
- **Native desktop UI** — pywebview window (React 19 dashboard), INTEL tab (live signal stream over WebSocket), one-click JSON export to disk
- **REST API server** — FastAPI; full programmatic control of scans, plugins, reports, and the proxy
- **Tor opt-in** — direct connection by default; Tor enabled via `tor_proxy` in context or `--proxy` CLI flag
- **HAR, Markdown, and JSON reports** — machine-readable and human-readable output formats

---

## Plugins

38 semantic plugins across 8 categories. Each plugin derives a formal security property from the application model and generates falsifiable hypotheses for the experiment engine.

### Authorization (6)

| Plugin | Tests |
|---|---|
| `core.authorization.authz` | Horizontal and vertical access control — swaps role credentials on every endpoint |
| `core.authorization.bfla` | Broken Function Level Authorization — tests admin-level functions with low-privilege credentials |
| `core.authorization.bola` | BOLA / IDOR — enumerates integer and UUID path parameters for cross-user object access |
| `core.authorization.csrf` | CSRF — tests missing or bypassable token protection on state-changing endpoints |
| `core.authorization.laravel_mass_assign` | Laravel Eloquent mass assignment — injects `is_admin`, `role` fields via `$request->all()` |
| `core.authorization.method_override` | HTTP Method Override — `X-HTTP-Method-Override` bypass of method-based access control |

### Business Invariants (2)

| Plugin | Tests |
|---|---|
| `core.business_invariant.business_boundary` | Invalid state transitions, balance/limit overflow, business rule bypass |
| `core.business_invariant.race_condition` | TOCTOU / double-spend via concurrent request flooding |

### Configuration (5)

| Plugin | Tests |
|---|---|
| `core.configuration.cache_poisoning` | `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL` injection to poison shared caches |
| `core.configuration.cors` | CORS misconfiguration — wildcard or reflected-origin policies |
| `core.configuration.http_smuggling` | CL.TE desync — conflicting `Content-Length` + `Transfer-Encoding: chunked` |
| `core.configuration.security_headers` | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| `core.configuration.spring_actuator` | Exposed Spring Boot Actuator endpoints (`/env`, `/heapdump`, `/beans`, …) |

### File Operations (1)

| Plugin | Tests |
|---|---|
| `core.file_operations.file_upload` | Unrestricted file upload — missing MIME type and extension validation |

### Information Flow (4)

| Plugin | Tests |
|---|---|
| `core.information_flow.http_parameter_pollution` | HPP — duplicate parameter values to detect inconsistent server-side parsing |
| `core.information_flow.info_disclosure` | Verbose error messages, stack traces, debug info via error-triggering character injection |
| `core.information_flow.open_redirect` | `redirect`, `next`, `url` parameter injection with evil absolute URLs |
| `core.information_flow.ssrf` | SSRF — URL parameters pointing to `169.254.169.254`, `localhost`, internal ranges |

### Injection (16)

| Plugin | CWE | Tests |
|---|---|---|
| `core.injection.anomaly_probing` | CWE-843 | Type confusion + boundary values — wrong types and edge cases without a named payload |
| `core.injection.cmdi` | CWE-78 | OS command injection: `; id`, `\| whoami`, backtick sequences |
| `core.injection.crlf` | CWE-113 | `%0d%0a` CRLF / header injection |
| `core.injection.deserialization` | CWE-502 | Python, Java, PHP deserialization payloads |
| `core.injection.django_debug` | CWE-215 | Django `DEBUG=True` stack trace pages |
| `core.injection.el_injection` | CWE-917 | Spring/JSP EL injection: `${7*7}`, `#{7*7}` |
| `core.injection.graphql` | CWE-89 | GraphQL introspection, query batching, variable injection |
| `core.injection.ldap_injection` | CWE-90 | LDAP filter injection: `)(cn=*`, `*)(|` |
| `core.injection.mass_assignment` | CWE-915 | Generic mass assignment: `admin`, `role`, `__proto__`, `_debug` fields |
| `core.injection.nosqli` | CWE-943 | MongoDB operator injection: `{"$gt":""}`, `{"$regex":".*"}` |
| `core.injection.path_traversal` | CWE-22 | Path traversal/LFI — plain, URL-encoded, mixed, double-dot variants |
| `core.injection.prototype_pollution` | CWE-1321 | `__proto__`, `constructor`, `prototype` key injection in JSON |
| `core.injection.sqli` | CWE-89 | Boolean-blind, time-based (MySQL/MSSQL/PostgreSQL), union, comment bypass — adaptive chains |
| `core.injection.ssti` | CWE-94 | `{{7*7}}`, `${7*7}}`, `<%= 7*7 %>` — Jinja2, Twig, ERB, Freemarker |
| `core.injection.xpath_injection` | CWE-643 | `' or '1'='1`, `] \| //` XPath injection |
| `core.injection.xss` | CWE-79 | `<script>`, `<img onerror>`, SVG, attribute breakout — adaptive chains with encoding/obfuscation |
| `core.injection.xxe` | CWE-611 | XML External Entity — external entity declarations in XML request bodies |

### Session (2)

| Plugin | Tests |
|---|---|
| `core.session_property.jwt` | JWT `alg:none` bypass, expired token acceptance, weak HMAC secret brute-force |
| `core.session_property.session_fixation` | Session ID unchanged after authentication |

### Temporal (1)

| Plugin | Tests |
|---|---|
| `core.temporal.session_replay` | Tokens remain valid after logout (post-logout replay) |

---

## Mutations

31 mutation types define *how* HDWP transforms a baseline request into an experiment. Mutations target every parameter location: path, query string, request body, headers, cookies, JSON keys, XML attributes, GraphQL variables.

| Mutation | OWASP | What it does |
|---|---|---|
| `identity_swap` | A01 | Replaces auth credentials with a different role's — tests horizontal access control |
| `object_ref_change` | A01 | Changes an ID parameter to another object's reference — tests BOLA/IDOR |
| `privilege_escalation` | A01 | Accesses a restricted endpoint with low-privilege credentials |
| `field_injection` | A03 | Injects a probe string into any parameter location |
| `jwt_manipulation` | A02 | Forges JWT with `alg:none`, expired timestamp, or weak secret |
| `origin_test` | A05 | Adds `Origin: https://evil.hdwp-test.invalid` to test CORS policy |
| `race_condition` | A04 | TemporalModule fires concurrent copies of the request |
| `token_reuse` | A07 | TemporalModule replays the token after logout |
| `path_traversal` | A01 | Injects `../../etc/passwd` — plain, URL-encoded, mixed, double-dot |
| `nosqli` | A03 | Replaces string values with MongoDB operator objects |
| `open_redirect` | A01 | Injects evil absolute URL into redirect parameters |
| `method_override` | A01 | Adds `X-HTTP-Method-Override`; switches method to GET |
| `http_method_fuzzing` | A01 | Changes the HTTP method of the baseline request |
| `type_confusion` | A03 | Sends wrong-type values to detect missing validation |
| `boundary_value` | A04 | Null, negative, overflow, empty — integer and boundary handling |
| `parameter_pollution` | A01 | Injects `is_admin`, `role`, `__proto__`, `_debug` for mass assignment |
| `xxe_injection` | A05 | XML with external entity declarations |
| `crlf_injection` | A03 | `\r\n` sequences in header values |
| `ldap_injection` | A03 | LDAP special characters in filter parameters |
| `xpath_injection` | A03 | XPath special characters in parameters |
| `el_injection` | A03 | EL expressions (`${...}`) in parameters |
| `prototype_pollution` | A08 | `__proto__`, `constructor`, `prototype` as JSON keys |
| `csrf_test` | A01 | Removes or tampers CSRF tokens |
| `cache_poisoning` | A05 | Injects `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL` |
| `http_smuggling` | A05 | CL.TE probe with conflicting `Content-Length` + `Transfer-Encoding: chunked` |
| `file_upload` | A08 | Files with dangerous extensions or MIME types |
| `hpp` | A01 | Duplicate parameter values (HTTP Parameter Pollution) |
| `info_disclosure` | A05 | `'"<>%00` injection to provoke verbose error responses |
| `django_debug` | A05 | Probes Django `DEBUG=True` stack trace pages |
| `spring_actuator` | A05 | Probes Spring Boot Actuator management endpoints |
| `laravel_mass_assign` | A04 | Tests Laravel Eloquent mass assignment via `$request->all()` |

---

## Attack Chains

The `AttackGraphPlanner` runs an A\* search over confirmed findings to plan multi-step attack chains. It activates automatically when two or more findings are confirmed.

**How it works:**
1. Each confirmed `Finding` is converted to an `AttackTransition` encoding its effects (credentials obtained, objects readable/writable, privileges granted, tokens held)
2. Backward-reachability pruning eliminates transitions irrelevant to the target goal
3. A\* search (max 2000 nodes, max chain length 5 steps) finds the minimum-cost path from the current attacker state to the goal
4. A successful chain produces a `HIGH` severity finding with 0.85 confidence and emits `GOAL_REACHED`

**Three built-in goals:**

| Goal | What it achieves |
|---|---|
| `ACCOUNT_TAKEOVER` | Obtain another user's credentials and impersonate them |
| `DATA_EXFILTRATION` | Read sensitive data not accessible to the attacker |
| `PRIVILEGE_ESCALATION` | Escalate from a low-privilege role to admin or higher |

---

## Installation

### Option 1 — Standalone binary (recommended)

Download the pre-built binary from the [latest release](https://github.com/devmail0561-web/hdwp/releases/latest). No Python required. Works on any Linux x86-64 system.

```bash
curl -LO https://github.com/devmail0561-web/hdwp/releases/latest/download/hdwp
chmod +x hdwp
sha256sum hdwp  # verify against the release page
./hdwp --help
```

### Option 2 — From source

Requires Python 3.12.

```bash
git clone https://github.com/devmail0561-web/hdwp.git
cd hdwp

python3.12 -m venv .venv
source .venv/bin/activate

# Core engine
pip install -e .

# With dev tools (tests, linting, type-checking)
pip install -e ".[dev]"

# With SPA crawling (Playwright headless browser)
pip install -e ".[spa]"
.venv/bin/playwright install chromium

# With ML extras (confidence model training and cross-session learning)
pip install -e ".[ml]"

# With LLM-assisted analysis and executive summary generation
pip install -e ".[llm]"

# With MITM proxy (mitmproxy backend)
pip install -e ".[proxy]"

# With gRPC support
pip install -e ".[grpc]"
```

### Option 3 — Rebuild the binary yourself

```bash
pip install pyinstaller
pyinstaller hdwp.spec --distpath dist/bin --noconfirm
# Output: dist/bin/hdwp
```

---

## Configuration

Create a `hdwp-context.yaml` file. A minimal example is provided in [`hdwp-context.example.yaml`](hdwp-context.example.yaml).

```yaml
target:
  base_url: "https://target.example.com"
  name: "Target API"

# Define the crawl boundary
scope:
  include:
    - "https://target.example.com/*"
  exclude:
    - "https://target.example.com/logout"

# Provide authenticated sessions for multi-role testing
sessions:
  - name: admin
    headers:
      Authorization: "Bearer eyJhbGc..."
  - name: user
    headers:
      Authorization: "Bearer eyJhbGc..."
  - name: anonymous

options:
  max_requests_per_minute: 60
  # Optional: route traffic through Tor
  tor_proxy: "socks5h://127.0.0.1:9150"
  # Optional: point to a local OpenAPI spec
  # discovery:
  #   openapi_spec: "./openapi.json"

plugins:
  disabled: []   # empty = all 38 plugins active
```

---

## Usage

```bash
# Open the web dashboard (auto-opens browser)
hdwp

# Direct scan — creates a minimal context automatically
hdwp --target https://target.example.com

# Full scan from a context file
hdwp --context hdwp-context.yaml

# Headless/CI mode — prints findings table, no browser
hdwp run --context hdwp-context.yaml --no-tui

# Crawl and export the application model as JSON
hdwp model --context hdwp-context.yaml --export model.json

# List all available plugins
hdwp plugin list

# Enable or disable a specific plugin
hdwp plugin enable core.injection.sqli
hdwp plugin disable core.configuration.spring_actuator

# Generate a report from an evidence database
hdwp report --db evidence_store.db --format md --output ./report
hdwp report --db evidence_store.db --format json
hdwp report --db evidence_store.db --format har

# Replay a specific experiment (inspect request/response pair)
hdwp replay --experiment <experiment-id> --db evidence_store.db

# Inspect the adaptive knowledge base
hdwp knowledge stats
hdwp knowledge export-cves
hdwp knowledge refresh-cves
hdwp knowledge reset

# Install the MITM CA certificate in all detected browsers
hdwp install-ca --verbose
```

---

## API Server

When launched, HDWP starts a FastAPI server with REST endpoints and a WebSocket event stream. The full interactive API documentation is available at [`/api/docs`](http://127.0.0.1:7007/api/docs) once the engine is running.

| Group | Endpoints |
|---|---|
| **State** | `GET /api/health` · `GET /api/state` |
| **Sessions** | `POST /api/session/new` · `GET /api/sessions` · `POST /api/session/{id}/resume` · `DELETE /api/session/{id}` |
| **Scan** | `POST /api/scan/start` · `POST /api/scan/stop` |
| **Findings** | `GET /api/findings` · `POST /api/findings/export` |
| **Plugins** | `GET /api/plugins` · `POST /api/plugins/toggle` · `POST /api/plugins/scaffold` · `POST /api/plugins/reload` |
| **Attack chains** | `GET /api/chain/findings` · `GET /api/chain/candidates` |
| **Report** | `POST /api/report/generate` · `GET /api/report/default-dir` |
| **Proxy** | `POST /api/proxy/start` · `POST /api/proxy/stop` · `GET /api/proxy/ca-cert` · `POST /api/proxy/install-ca` |
| **Knowledge** | `GET /api/knowledge/stats` · `GET /api/knowledge/learning-health` · `POST /api/knowledge/reset` |
| **LLM** | `GET /api/llm/config` · `POST /api/llm/api-key` · `GET /api/llm/models` |
| **WebSocket** | `WS /ws/events` — real-time engine event stream to the dashboard |

---

## Report Formats

| Format | Flag | Output | Use case |
|---|---|---|---|
| **Markdown** | `--format md` | Single `.md` file | Human-readable penetration test report — findings grouped by severity, OWASP/CWE references, reproduction steps, confidence breakdown, remediations. Optional LLM-generated executive summary. |
| **JSON** | `--format json` | `findings.json` + `summary.json` | Machine-readable output for SIEM integration, ticketing systems, or custom dashboards. Also available from the UI via the `[ EXPORTER JSON ]` button (saves to `~/Bureau/`). |
| **HAR** | `--format har` | One `.har` per finding | HTTP Archive format — import directly into Burp Suite or browser DevTools for manual verification and replay. |

---

## Pipeline

```
OBSERVE     → BFS crawl (HTML, forms, JS fetch/axios/XHR/WebSocket, HATEOAS JSON,
              Link header, robots.txt, sitemap.xml, data-* attributes, DOM sinks)
              + OpenAPI/GraphQL spec import
              + OPTIONS probing per path
              + POST/PUT/PATCH probing per GET endpoint
              + SPA browser crawl (Playwright via MITM proxy)
              + WebSocketObserver (WebSocket endpoint discovery + traffic capture)
              + GrpcObserver (service reflection + method enumeration)
              + Version fingerprinting → OSV.dev CVE lookup (JS + 9 backend frameworks)

MODEL       → EndpointNode, ParameterNode (semantic type, sensitivity)
              DataObjectNode (data classification)
              + ThreatModelEngine (per-endpoint threat score → hypothesis depth)
              + InvariantStore (inductive invariant learning from baseline)

INFER       → 38 SecurityProperty derivations from the semantic graph

PRIORITIZE  → MetaLearner.sort_hypotheses()
              PayloadOptimizer (Thompson Sampling: fingerprint × mutation_type)
              HypothesisBandit (Thompson Sampling: property_type × mutation_type)
              ActiveLearner (promotes uncertain hypotheses)
              VulnClassifier (per-endpoint mutation focus)

EXPERIMENT  → baseline request + 31 mutation types
              + Encoding pipeline (URL, Unicode, Base64, null bytes, …)
              + BypassRegistry (15 transport/protocol bypass strategies, 7 WAF signatures)
              + WebSocketInjector / GrpcInjector for non-HTTP protocols

ORACLE      → SemanticDiff (data_identity_score, structural diff, value diff)
              + Z-score anomaly, size ratio, field entropy
              + CrossRoleDiffEngine (STRUCTURAL / VALUE / IDENTITY)
              + TemporalAnomalyDetector (blind injection via response time)
              + InjectionOracle (XSS reflection, SSTI evaluation, SQLi pattern)
              + ConfidenceModelV2 (10 dimensions)
              + OracleModel (scikit-learn classifier)
              + ConfidenceModelV2.explain() (per-finding contribution breakdown)
              → Finding (CONFIRMED / REFUTED / AMBIGUOUS → AmbiguityResolver)

LEARN       → FeedbackLoop updates ConfidenceModelV2 weights
              MetaLearner.save_session() saves all model states to KnowledgeBase

CHAIN       → AttackGraphPlanner (A* multi-step on AttackState)
              goals: ACCOUNT_TAKEOVER, DATA_EXFILTRATION, PRIVILEGE_ESCALATION
              + multi-finding correlation (FINDINGS_CORRELATED events)

REPORT      → Markdown / JSON / HAR
              + optional LLM executive summary
```

---

## License

MIT — Copyright (c) 2026 M. TENDENG
