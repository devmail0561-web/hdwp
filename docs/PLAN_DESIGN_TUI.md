# Plan — Refonte TUI : logique de navigation, design, bugs, LLM/plugins

## 0. Contexte projet

### Qu'est-ce que HDWP ?

HDWP Engine est un moteur de pentest web **piloté par hypothèses** (Hypothesis-Driven Web
Pentesting). Contrairement aux scanners classiques qui injectent des payloads sur des listes
d'URLs et comparent aux signatures, HDWP observe l'application, reconstruit son modèle
comportemental, en déduit les propriétés de sécurité qui *devraient* être vraies, puis génère
des expériences minimales pour les **falsifier**.

```
OBSERVE → MODEL → INFER PROPERTIES → HYPOTHESIZE → EXPERIMENT → ORACLE → FINDING
```

Les classifications OWASP/CWE sont appliquées *a posteriori* sur les findings confirmés —
elles ne sont jamais le point de départ du raisonnement (ADR-006).

**Auteur :** M. TENDENG — **Licence :** MIT — **Python :** 3.12 — **Version :** 0.1.0

### Pipeline complet

```
HDWPApp (TUI)
  └─► HDWPEngine._init_components()
        ├─► ContextLoader          → charge hdwp-context.yaml
        ├─► ObservationEngine
        │     └─► ActiveCrawler    → BFS par rôle, émet observation.raw
        │     └─► ProxyCapture     → MITM passif (mitmproxy, optionnel)
        ├─► ApplicationModel       → graphe comportemental incrémental
        ├─► SecurityPropertyEngine → infère 7 types de propriétés
        ├─► HypothesisEngine       → génère hypothèses falsifiables + priorise
        ├─► ExperimentEngine
        │     ├─► RequestSelector  → ExperimentSpec → ConcreteExperimentPlan
        │     ├─► MutationModule   → 6 mutations (identity_swap, object_ref_change,
        │     │                       privilege_escalation, field_injection,
        │     │                       jwt_manipulation, origin_test)
        │     └─► SessionManager   → credentials par rôle, tokens CSRF
        ├─► SemanticOracle         → diff + ViolationOracle + ConfidenceScore 5D
        │     └─► LLMLayer         → désambiguïse les diffs AMBIGUOUS (ADR-002)
        ├─► PassiveFindingEngine   → findings depuis headers/cookies/disclosure
        ├─► PluginRegistry         → plugins via entry_points + ~/.hdwp/plugins/
        ├─► ReportEngine           → Markdown, JSON, HAR
        └─► Repository             → SQLite (~/,hdwp/workspaces/SESSION/evidence.db)
```

### Contrainte ADR-002 (LLM non-décisionnel)

Le LLM intervient uniquement pour :
1. Désambiguïser un diff AMBIGUOUS → max `confidence_hint = 0.55` (seuil CONFIRMED = 0.85)
2. Proposer des hypothèses complémentaires (non exécutées seules)
3. Interpréter du JavaScript obfusqué (enrichissement crawl)
4. Générer des `remediation_hint` contextuels
5. Générer le résumé exécutif du rapport Markdown

Le LLM ne peut **jamais** déclencher seul un `ViolationVerdict.CONFIRMED`.

### Interactions TUI ↔ Engine

Le TUI est l'interface principale. `ScanScreen` instancie `HDWPEngine` et partage son
`AsyncEventBus` pour recevoir les événements en temps réel :

| Événement bus | Widget TUI |
|---|---|
| `observation.raw` | `EventLogPanel` (`OBS`) |
| `hypothesis.generated` | `EventLogPanel` (`HYP`) |
| `experiment.result` | `EventLogPanel` (`EXP`) |
| `finding.confirmed` | `FindingsTable` + `EventLogPanel` (`V`) |
| `credentials.captured` | `EventLogPanel` (`KEY`) + notification toast |

### Structure `~/.hdwp/`

```
~/.hdwp/
├── knowledge.db              ← KnowledgeBase (apprentissage inter-sessions)
├── plugins.state.json        ← état enabled/disabled des plugins (à créer)
├── llm.config.json           ← config LLM persistée depuis le TUI (à créer)
├── contexts/                 ← contextes YAML générés automatiquement par URL
├── plugins/                  ← plugins utilisateur (PLUGIN_CLASS = MonPlugin)
└── workspaces/
    └── SESSION-xxxx/
        ├── evidence.db       ← SQLite findings, experiments, diffs
        ├── context.yaml      ← contexte de la session
        ├── model.json        ← export du modèle applicatif
        └── reports/          ← rapports générés (report.md, findings.json, har/)
```

---

## 1. Graphe de navigation complet

```
HDWPApp(context_path, db_url, auto_start_url)
         │ on_mount
         ├─ auto_start_url ──────────────────────────────────► ScanScreen
         └─ (interactif) ─────────────────────────────────────► TargetScreen
                                                                      │
                              ┌───────────────────────────────────────┤
                              │ radio[2]="Tokens manuels"             │
                              ▼                                       │
                         TokensScreen                                  │
                         dismiss(list[RoleConfig])                     │
                              │ callback _on_tokens                   │
                              └───────────────────────────────────────┤
                                                                      │ [ENTER]
                                              ┌───────────────────────┼──────────────────────┐
                                              │ mode="auto"           │ mode="yaml"          │ mode="manual"
                                              ▼                       ▼                      ▼
                                         ScanScreen(url,          ScanScreen(url,       ScanScreen(url,
                                           mode="auto",             mode="yaml",          mode="manual",
                                           db_url)                  context_path,         manual_tokens,
                                                                    db_url)               db_url)
                                              │
                          ┌───────────────────┼───────────────────┬───────────────┐
                          │ [F]               │ [R]               │ [P]           │ [ESC]
                          ▼                   ▼                   ▼               ▼
                   FindingsScreen       ReportScreen        SettingsScreen   TargetScreen
                   (db_url, findings)   (db_url,            (registry)       (ou exit si
                          │             llm_config)              │            auto_start)
                          │ [ESC]            │ [ESC]             │ [ESC]
                          └──────────────────┴───────────────────┘
                                             ▼
                                         ScanScreen
```

---

## 2. Données qui transitent entre écrans

| De → Vers | Données transmises |
|---|---|
| `HDWPApp` → `TargetScreen` | `db_url` |
| `HDWPApp` → `ScanScreen` (auto-start) | `target_url`, `context_path`, `mode="auto"`, `db_url` |
| `TargetScreen` → `TokensScreen` | rien (retour via `dismiss(list[RoleConfig])`) |
| `TargetScreen` → `ScanScreen` | `target_url`, `mode`, `context_path`\|`manual_tokens`, `db_url` |
| `ScanScreen` → `FindingsScreen` | `db_url` (calculé), `findings` (list[dict] accumulés en live) |
| `ScanScreen` → `ReportScreen` | `db_url` (calculé), `llm_config` (depuis `ctx.config.llm`) |
| `ScanScreen` → `SettingsScreen` | rien |
| Tous retours → `ScanScreen` | rien (pop_screen sans données) |

**Gap critique :** `HDWPApp._context_path` n'est transmis à `ScanScreen` que dans le path `auto_start`. Si l'utilisateur passe `--context foo.yaml` sans `--target`, le contexte est perdu après `TargetScreen`.

---

## 3. Bugs identifiés

| # | Fichier | Bug | Sévérité |
|---|---|---|---|
| B1 | `tokens.py:22` | `Binding("escape", "pop_screen")` bypasse `dismiss()` → callback jamais appelé → `_manual_tokens` reste vide | **CRITIQUE** |
| B2 | `settings.py:31` | `self._selected_plugin` déclaré mais jamais lu ni écrit | Mineure |
| B3 | `messages.py:66` | `ProxyStarted` défini, jamais émis ni consommé | Mineure |
| B4 | `report.py:49` | `"Active (claude-sonnet)"` hardcodé, ne reflète pas `llm_config.model` | Majeure |
| B5 | `scan.py:294` | Si `_ctx` non chargé, `llm_config=None` → LLM silencieusement désactivé | Majeure |
| B6 | `scan.py:113` | Proxy et moteur démarrent simultanément sans synchronisation | Majeure |
| B7 | `target.py:154` | `radio._nodes[1].toggle()` — accès privé Textual fragile | Mineure |
| B8 | `app.py` | `context_path` transmis à ScanScreen uniquement en auto-start, pas en flux interactif | Majeure |

---

## 4. Trou fonctionnel : configuration LLM absente du TUI

**Constat :** le modèle LLM se configure **uniquement** via `hdwp-context.yaml`.
Il n'existe aucune interface TUI pour choisir le provider, le modèle, ou l'URL Ollama.

**Solution :** ajouter un 4ème onglet **LLM** dans `SettingsScreen` :

```
[ Plugins ]  [ Knowledge ]  [ Sessions ]  [ LLM ]

── CONFIGURATION LLM ─────────────────────────────────────────

  Statut     ◉ Activé      ○ Désactivé
  Provider   ◉ Anthropic   ○ OpenAI   ○ Ollama
  Modèle     ┌─────────────────────────────────┐
             │  claude-sonnet-4-6               │
             └─────────────────────────────────┘
  Base URL   ┌─────────────────────────────────┐  (Ollama seulement)
             │  http://localhost:11434/v1        │
             └─────────────────────────────────┘

  Clé API    ● ANTHROPIC_API_KEY détectée        ← indicateur env var

  [ SAUVEGARDER ]
```

`SettingsScreen` reçoit un paramètre optionnel `llm_config: LLMConfig | None = None`
(passé par `ScanScreen` comme il le fait déjà pour `ReportScreen`).
Sauvegarder écrit dans `~/.hdwp/llm.config.json` (persist entre sessions).

---

## 5. Logo

`HdwpHeader` (widget partagé dans `app.py`) est présent sur **tous** les écrans :

```
 ██╗  ██╗██████╗ ██╗    ██╗██████╗
 ██║  ██║██╔══██╗██║    ██║██╔══██╗
 ███████║██║  ██║██║ █╗ ██║██████╔╝
 ██╔══██║██║  ██║██║███╗██║██╔═══╝
 ██║  ██║██████╔╝╚███╔███╔╝██║
 ╚═╝  ╚═╝╚═════╝  ╚══╝╚══╝╚═╝
   v0.1.0  |  SESSION-a1b2c3d4
```

`TargetScreen` avait un logo `##` ASCII redondant — déjà supprimé. Le logo unicode
suffit et reste présent via `HdwpHeader`.

---

## 6. Design des interfaces

### 6.0 Éléments communs

| Élément | Spécification |
|---|---|
| Logo | `HdwpHeader` fixe en haut (unicode bloc art, vert `#00ff41`, hauteur 8) |
| Fond global | `#080808` |
| Panneaux | fond `#0d0d0d`, bordure `solid #1a3a1a` (vert sombre) |
| Boutons | `[ TEXT ]` — fond transparent, inversion couleur au hover/focus |
| Labels section | `── TITRE ──` en `#445566` (muted) |
| Texte normal | `#d8d8e8` |
| Séparateurs | `─────────` en `#1a1a1a` |

---

### TargetScreen

```
┌──────────────────────────────────────────────────────────────────┐
│  ██╗  ██╗██████╗ ██╗    ██╗██████╗                              │  #00ff41
│  ██║  ██║██╔══██╗██║    ██║██╔══██╗  HYPOTHESIS-DRIVEN          │
│  ███████║██║  ██║██║ █╗ ██║██████╔╝  WEB PENTESTING ENGINE      │
│  ██╔══██║██║  ██║██║███╗██║██╔═══╝                              │
│  ██║  ██║██████╔╝╚███╔███╔╝██║        v0.1.0                    │
│  ╚═╝  ╚═╝╚═════╝  ╚══╝╚══╝╚═╝                                  │
├──────────────────────────────────────────────────────────────────┤  #1a3a1a
│                                                                  │
│  ── TARGET URL ─────────────────────────────────────────────    │  #445566
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  https://                                                │   │  #d8d8e8 / #0d0d0d
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ── CREDENTIALS ────────────────────────────────────────────    │
│  ◉  Auto — proxy MITM  (configurez Firefox sur 127.0.0.1:8080)  │  #00ff41 (sélectionné)
│  ○  Fichier de contexte YAML                                     │  #445566 (non sélectionné)
│  ○  Tokens manuels                                               │
│                                                                  │
│  ── [si YAML sélectionné] ──────────────────────────────────    │  (masqué sinon)
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  /chemin/vers/context.yaml                               │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ── [si TOKENS sélectionné] ────────────────────────────────    │  (masqué sinon)
│  2 token(s) saisi(s)                                             │  #44ff88
│                                                                  │
│  [ LANCER ]          [ CHARGER YAML ]          [ QUITTER ]      │  vert / cyan / rouge
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

### TokensScreen

```
┌──────────────────────────────────────────────────────────────────┐
│  ██╗  ██╗██████╗ ██╗    ██╗██████╗  …  v0.1.0  │  no session   │  header
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ── AJOUTER UN TOKEN ───────────────────────────────────────    │
│                                                                  │
│  Role      ┌───────────────────────────────┐                    │
│            │  user_a                       │                    │
│            └───────────────────────────────┘                    │
│                                                                  │
│  Type      ◉  Bearer    ○  Cookie    ○  API Key                 │
│                                                                  │
│  Token     ┌──────────────────────────────────────────────┐     │
│            │  Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVC…  │     │
│            └──────────────────────────────────────────────┘     │
│                                                                  │
│  ─────────────────────────────────────────────────────────      │
│  2 token(s) ajouté(s)                                            │  #44ff88
│                                                                  │
│  [ + AJOUTER ]                           [ → CONTINUER ]        │  vert / vert vif
│                                                                  │
│  (ESC → retour sans tokens)                                      │  #445566
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

*Fix B1 : ESC appelle `dismiss(None)` — le callback reçoit None et conserve les tokens déjà saisis.*

---

### ScanScreen

```
┌──────────────────────────────────────────────────────────────────┐
│  ██╗  ██╗██████╗ ██╗    ██╗██████╗   v0.1.0  │  SESSION-a1b2   │  header
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌── STATUS ───────────────────┐  ┌── LIVE FEED ─────────────┐  │
│  │                             │  │                          │  │
│  │  ● CRAWLING          #00d4ff│  │  14:32  OBS  /api/users  │  │  cyan
│  │    PROXY  :8080 ▲    #ffd700│  │  14:32  KEY  user_a      │  │  or
│  │    TARGET /api/…     #d8d8e8│  │  14:32  PROP BOLA        │  │  violet
│  │                             │  │  14:33  HYP  id_swap     │  │  orange
│  │  Crawl  [████████░░]  78%   │  │  14:33  EXP  en cours…   │  │  bleu
│  │                             │  │  14:33   V   BOLA 97%    │  │  #44ff88
│  │  HYP   7   H:3  M:4         │  │                          │  │
│  │  EXP  12 / 15               │  │                          │  │
│  │                             │  │                          │  │
│  └─────────────────────────────┘  └──────────────────────────┘  │
│                                                                  │
│  ┌── FINDINGS ──────────────────────────────────────────────┐   │
│  │  FIND-a1b2  ████ HIGH   BOLA    A01:2021  CWE-639   97%  │   │
│  │  FIND-c3d4  ███░ HIGH   SQLi    A03:2021  CWE-89    92%  │   │
│  │  FIND-e5f6  ██░░ MED    CORS    A05:2021  CWE-942   86%  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  [ STOP ]    [ FINDINGS ]    [ REPORT ]    [ PLUGINS ]           │
└──────────────────────────────────────────────────────────────────┘
```

*`●` pulse toutes les 500ms entre `PHASE_COLORS[phase]` et `#1a1a1a`.*

---

### FindingsScreen

```
┌──────────────────────────────────────────────────────────────────┐
│  ██╗  ██╗██████╗ …   v0.1.0  │  SESSION-a1b2  │  FINDINGS       │  header
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌── LISTE (3) ───────────────┐  ┌── DÉTAIL ─────────────────┐  │
│  │                            │  │                           │  │
│  │  ▶ FIND-a1b2               │  │  ID       FIND-a1b2       │  │
│  │    ████ HIGH   BOLA  97%   │  │  TYPE     BOLA (CWE-639)  │  │
│  │                            │  │  OWASP    A01:2021        │  │
│  │    FIND-c3d4               │  │  ENDPOINT /api/users/{id} │  │
│  │    ████ HIGH   SQLi  92%   │  │  CONF     97%             │  │
│  │                            │  │                           │  │
│  │    FIND-e5f6               │  │  REPRODUCTIONS            │  │  #445566 section
│  │    ██░░ MED    CORS  86%   │  │  1. GET /api/users/42     │  │
│  │                            │  │     Auth: Bearer userA    │  │
│  │                            │  │  2. Données de userB      │  │
│  │                            │  │                           │  │
│  │                            │  │  REMEDIATION              │  │
│  │                            │  │  Vérifier ownership       │  │
│  │                            │  │  côté serveur.            │  │
│  └────────────────────────────┘  └───────────────────────────┘  │
│                                                                  │
│  [ EXPORTER JSON ]                               [ RETOUR ]     │
└──────────────────────────────────────────────────────────────────┘
```

---

### ReportScreen

```
┌──────────────────────────────────────────────────────────────────┐
│  ██╗  ██╗██████╗ …   v0.1.0  │  SESSION-a1b2  │  RAPPORT        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ── FORMAT ─────────────────────────────────────────────────    │
│  ◉  Markdown     ○  JSON     ○  HAR                              │
│                                                                  │
│  ── FICHIER ────────────────────────────────────────────────    │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  ~/.hdwp/workspaces/SESSION-a1b2/reports/report.md       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ── RÉSUMÉ IA ──────────────────────────────────────────────    │
│  ◉  Activé (claude-sonnet-4-6)    ← dynamique depuis config     │  #d8d8e8
│  ○  Désactivé                                                    │
│                                                                  │
│  ── CLÉ API ────────────────────────────────────────────────    │
│  ● ANTHROPIC_API_KEY   détectée                                  │  #44ff88 si présente
│  ○ OPENAI_API_KEY      absente                                   │  #445566 si absente
│                                                                  │
│  [ GÉNÉRER ]                                    [ RETOUR ]      │
└──────────────────────────────────────────────────────────────────┘
```

*Fix B4 : label construit depuis `self._llm_config.model` — jamais hardcodé.*
*Indicateur clé API : `os.getenv("ANTHROPIC_API_KEY")` vérifié au `on_mount`.*

---

### SettingsScreen

```
┌──────────────────────────────────────────────────────────────────┐
│  ██╗  ██╗██████╗ …   v0.1.0  │  SESSION-a1b2  │  PARAMÈTRES     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [ Plugins ]   [ Knowledge ]   [ Sessions ]   [ LLM ]            │  ← onglet actif = inversion
│  ─────────────────────────────────────────────────────────────  │
│                                                                  │
│  ── onglet PLUGINS ─────────────────────────────────────────    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  PLUGIN                      CAT      VER   STATUT  SOURCE │ │  #445566 en-tête
│  │ ────────────────────────────────────────────────────────── │ │
│  │  ▶ core.authorization.bola   authz    1.0   ● on    builtin│ │  #00ff41 enabled
│  │    core.configuration.cors   config   1.0   ○ off   builtin│ │  #445566 disabled
│  │    user.mon-plugin           custom   0.2   ● on    user   │ │  #ffd700 user plugin
│  └────────────────────────────────────────────────────────────┘ │
│  SPACE pour toggle                                               │  #445566
│                                                                  │
│  ── onglet LLM ─────────────────────────────────────────────    │
│  Statut    ◉  Activé          ○  Désactivé                       │
│  Provider  ◉  Anthropic       ○  OpenAI    ○  Ollama             │
│  Modèle    ┌──────────────────────────────────────┐             │
│            │  claude-sonnet-4-6                    │             │
│            └──────────────────────────────────────┘             │
│  Base URL  ┌──────────────────────────────────────┐  (Ollama)   │
│            │  http://localhost:11434/v1             │             │
│            └──────────────────────────────────────┘             │
│  Clé API   ● ANTHROPIC_API_KEY  détectée                         │  #44ff88
│                                                                  │
│  [ SAUVEGARDER ]                               [ RETOUR ]       │
└──────────────────────────────────────────────────────────────────┘
```

*Sauvegarder écrit dans `~/.hdwp/llm.config.json` et met à jour `LLMConfig` en mémoire.*
*Source des plugins : `"builtin"` (entry_point) vs `"user"` (~/.hdwp/plugins/).*

---

### 6.2 Changements de logique par écran

**TargetScreen**
- Supprimer `radio._nodes[1].toggle()` → utiliser l'API publique Textual
- Corriger la propagation de `context_path` depuis `HDWPApp`

**TokensScreen** (Bug B1)
- Remplacer `Binding("escape", "pop_screen")` par action qui appelle `self.dismiss(None)`
- ESC = retour sans tokens (dismiss avec None, pas bypass du callback)

**ScanScreen**
- Corriger Bug B5 : notifier si `_ctx` non chargé avant d'ouvrir ReportScreen
- Corriger Bug B6 : proxy démarre en premier, moteur attend `ProxyStarted`
- Ajouter `SettingsScreen(llm_config=self._ctx.config.llm if self._ctx else None)`

**ReportScreen** (Bug B4)
- Label dynamique : `f"Activé ({self._llm_config.model})"` au lieu de `"Active (claude-sonnet)"`
- Si `llm_config` absent : afficher `"Activé (LLM non configuré)"` en muted

**SettingsScreen**
- Ajouter onglet LLM (voir section 4)
- Supprimer `_selected_plugin` inutilisé (Bug B2)
- Recevoir `llm_config: LLMConfig | None = None`

**messages.py**
- Supprimer `ProxyStarted` ou le câbler : émettre depuis `_start_proxy_worker` et
  écouter dans `_start_engine_worker` pour synchronisation (fix Bug B6)

---

## 7. Ordre d'implémentation

```
Phase 1 — Bugs critiques (avant tout design)
  B1  TokensScreen ESC → dismiss(None)
  B4  ReportScreen label dynamique
  B8  HDWPApp._context_path propagé en flux interactif

Phase 2 — Design TUI (après validation mockups HTML)
  CSS/TCSS refonte complète
  Layout de chaque écran

Phase 3 — LLM dans SettingsScreen
  Onglet LLM + persistance ~/.hdwp/llm.config.json
  Câblage depuis ScanScreen

Phase 4 — Synchronisation proxy/moteur (Bug B6)
  ProxyStarted émis depuis proxy_worker
  engine_worker attend ProxyStarted avant de démarrer

Phase 5 — Nettoyage
  B2 _selected_plugin supprimé
  B3 ProxyStarted utilisé ou supprimé
  B7 _nodes remplacé
```

---

## 8. Fichiers à modifier

| Fichier | Raison |
|---|---|
| `src/hdwp/tui/screens/tokens.py` | B1 : ESC → dismiss(None) |
| `src/hdwp/tui/screens/report.py` | B4 : label dynamique |
| `src/hdwp/tui/screens/scan.py` | B5, B6 : ctx guard, sync proxy |
| `src/hdwp/tui/screens/settings.py` | Onglet LLM, suppr _selected_plugin |
| `src/hdwp/tui/screens/target.py` | B7 : remplacer _nodes, B8 : context_path |
| `src/hdwp/tui/app.py` | B8 : propager context_path |
| `src/hdwp/tui/messages.py` | B3 : ProxyStarted câblé ou supprimé |
| `src/hdwp/tui/hdwp.tcss` | Refonte CSS complète (après mockups) |
| `src/hdwp/core/context/config_schema.py` | Aucun changement |
