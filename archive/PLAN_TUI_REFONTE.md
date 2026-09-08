# Plan — Refonte TUI : Interface Hacker Interactive Complete

> **Status** : Approuve apres 6+ cycles de critique/correction + revue complete (limites corrigees, points flous completes).
> **Date** : 2026-09-01
> **Auteur** : M. TENDENG
> **Revue** : 21 corrections Textual 8.x, factorisation engine, flux inter-screens, tests, backward compat

## Contexte

Le TUI actuel est un affichage passif avec des raccourcis clavier. L'utilisateur ne peut rien configurer depuis le terminal. Le proxy doit etre demarre APRES le moteur (flux inverse). Toutes les fonctions utiles (rapport, plugins, findings, knowledge) ne sont accessibles que via des commandes CLI separees.

**Objectifs :**
1. TUI entierement interactif -- entree URL directe, zero YAML obligatoire
2. Proxy demarre AUTOMATIQUEMENT et AVANT le moteur
3. Toutes les fonctions accessibles depuis le TUI (screens navigables)
4. Design hacker dark : neon sur fond noir, animations, couleurs impactantes
5. Structure `~/.hdwp/` centralisee pour tous les fichiers

---

## Architecture : Screens Textual

Textual 8.x supporte `App.push_screen()` / `pop_screen()`. Chaque "mode" est une `Screen` distincte.

```
HDWPApp
+-- TargetScreen     <-- ecran de demarrage (URL input, mode credentials)
+-- ScanScreen       <-- ecran principal du scan (proxy + engine + live events)
+-- FindingsScreen   <-- browser interactif des findings
+-- ReportScreen     <-- generation rapport depuis le TUI
+-- SettingsScreen   <-- plugins, knowledge base
+-- TokensScreen     <-- saisie manuelle de credentials
```

**Navigation :**
- `TargetScreen` -> `[ENTER]` -> `ScanScreen`
- `ScanScreen` -> `[F]` -> `FindingsScreen` -> `[ESC]` retour
- `ScanScreen` -> `[R]` -> `ReportScreen` -> `[ESC]` retour
- `ScanScreen` -> `[P]` -> `SettingsScreen` -> `[ESC]` retour

---

## Ecran 1 -- TargetScreen (demarrage)

```
+---------------------------------------------------------------------+
|   ##  ## #####  ##   ## #####                                       |
|   ##  ## ##  ## ##   ## ##  ##  HYPOTHESIS-DRIVEN                   |
|   ###### ##  ## ## # ## #####   WEB PENTESTING ENGINE               |
|   ##  ## ##  ## ##### ## ##                                         |
|   ##  ## #####  ###  ### ##      v1.0.0                             |
+---------------------------------------------------------------------+
|                                                                     |
|   TARGET URL                                                        |
|   +-----------------------------------------------------------+    |
|   | https://                                              [->] |    |
|   +-----------------------------------------------------------+    |
|                                                                     |
|   CREDENTIALS MODE                                                  |
|   * Auto -- proxy MITM (naviguez et connectez-vous dans Firefox)    |
|   o Fichier de contexte YAML                                        |
|   o Saisir les tokens manuellement                                  |
|                                                                     |
|   [ENTER] Lancer l'analyse    [C] Charger YAML   [Q] Quitter       |
+---------------------------------------------------------------------+
```

**Widgets :** `Input` (URL), `RadioSet` (mode credentials), `Button`

**Comportement :**
- `[ENTER]` ou bouton -> `push_screen(ScanScreen(target_url, mode, ...))`

```python
class ScanScreen(Screen):
    """Ecran principal du scan."""

    def __init__(
        self,
        target_url: str,
        mode: str = "auto",               # "auto" | "yaml" | "manual"
        context_path: Path | None = None,  # None si mode URL directe
        manual_tokens: list[RoleConfig] | None = None,
    ) -> None:
        super().__init__()
        self._target_url = target_url
        self._mode = mode
        self._context_path = context_path
        self._manual_tokens = manual_tokens or []
        self._engine: HDWPEngine | None = None
        self._proxy_capture: ProxyCapture | None = None
```
- Mode "Auto" : `ScanScreen` demarre le proxy immediatement + affiche `"Proxy 127.0.0.1:8080 actif"`
- Mode YAML : `Input` (Textual n'a pas de FilePicker) avec validation du chemin dans `on_input_submitted`. Si chemin inexistant -> message d'erreur rouge. Si valide -> `push_screen(ScanScreen(...))`
- Mode manuel : `push_screen(TokensScreen)` pour saisir tokens, retour via `dismiss(tokens)` (voir section TokensScreen)
- Deux containers `Vertical` (un pour URL, un pour chemin YAML), visibilite geree par `display = True/False` selon le choix RadioSet

```python
class TargetScreen(Screen):
    """Ecran de demarrage : saisie URL + choix du mode credentials."""

    def __init__(self) -> None:
        super().__init__()
        self._manual_tokens: list[RoleConfig] = []

    def _action_launch(self) -> None:
        """[ENTER] -- valider et lancer le scan."""
        url = self.query_one("#url-input", Input).value.strip()
        if not url.startswith(("http://", "https://")):
            self.notify("URL invalide (doit commencer par http:// ou https://)",
                        severity="error", timeout=3.0)
            return

        mode = self._get_selected_mode()  # "auto" | "yaml" | "manual"

        if mode == "yaml":
            yaml_path = Path(self.query_one("#yaml-input", Input).value.strip())
            if not yaml_path.exists():
                self.notify(f"Fichier introuvable : {yaml_path}",
                            severity="error", timeout=3.0)
                return
            self.app.push_screen(ScanScreen(
                target_url=url, mode="yaml", context_path=yaml_path,
            ))
        elif mode == "manual":
            if not self._manual_tokens:
                self.notify("Aucun token saisi. Cliquez d'abord sur le mode manuel.",
                            severity="warning", timeout=3.0)
                return
            self.app.push_screen(ScanScreen(
                target_url=url, mode="manual", manual_tokens=self._manual_tokens,
            ))
        else:
            # mode "auto" : proxy MITM
            self.app.push_screen(ScanScreen(target_url=url, mode="auto"))

    def _on_radio_changed(self, event: RadioSet.Changed) -> None:
        """Affiche/masque le champ YAML selon le mode selectionne."""
        yaml_container = self.query_one("#yaml-container")
        yaml_container.display = (event.index == 1)  # index 1 = "Fichier YAML"
```

---

## Ecran 2 -- ScanScreen (principal)

```
+-- HDWP -- SCAN --- https://target.com ----------- SESSION-a1b2 -----+
| +---- STATUS ----------------+ +---- LIVE FEED ----------------+    |
| | * PROXY ACTIF 127.0.0.1:80 | | 14:32:01 [OBS] GET /api/users|    |
| | * CRAWLING                 | | 14:32:02 [KEY] Bearer capture |    |
| |                            | |          -> user_a ajoute     |    |
| | Crawl   [########--] 78%  | | 14:32:03 [PROP] BOLA infere  |    |
| | Props   [######----] 58%  | | 14:32:04 [HYP] identity_swap |    |
| | Hypo    7  HIGH:3  MED:4  | | 14:32:05 [EXP] mutation...   |    |
| | Exps   12/15               | | 14:32:06 [V]  BOLA conf:97% |    |
| +----------------------------+ +--------------------------------+    |
| +---- FINDINGS --------------------------------------------------+  |
| |  FIND-a1b2 | #### HIGH  | BOLA    | A01:2021 | CWE-639 | 97%  |  |
| |  FIND-c3d4 | #### HIGH  | SQLi    | A03:2021 | CWE-89  | 92%  |  |
| |  FIND-e5f6 | ##-- MED   | CORS    | A05:2021 | CWE-942 | 96%  |  |
| +----------------------------------------------------------------+  |
+---------------------------------------------------------------------+
|  [S]top  [F]indings  [R]eport  [P]lugins  [K]nowledge  [Q]uit      |
+---------------------------------------------------------------------+
```

**Flux proxy AVANT moteur (correction critique) :**

```python
# ScanScreen.on_mount() -- bus cree ICI (sync), avant tout worker
def on_mount(self) -> None:
    self._bus = AsyncEventBus()
    self._proxy_capture: ProxyCapture | None = None

    # Charger le contexte (sync OK -- lecture YAML)
    if self._context_path:
        self._ctx = ContextLoader.load(self._context_path)
    else:
        from hdwp.core.paths import build_context_from_url
        ctx_path = build_context_from_url(self._target_url)
        self._ctx = ContextLoader.load(ctx_path)

    self._scope_guard = ScopeGuard(self._ctx)
    self._session_id = self._ctx.session_id

    # Injecter les tokens manuels dans le contexte si fournis
    if self._manual_tokens:
        self._ctx.config.roles.extend(self._manual_tokens)

    # Bridge bus -> TUI pour le live feed
    self._subscribe_to_bus(self._bus)

    # Demarrer proxy puis moteur
    if self._mode == "auto":
        self._start_proxy_worker()
    self._start_engine_worker()

@work(exclusive=False, name="proxy_worker")
async def _start_proxy_worker(self) -> None:
    """Proxy demarre en parallele, INDEPENDAMMENT du moteur."""
    try:
        self._proxy_capture = ProxyCapture(
            self._bus, self._scope_guard, self._session_id, port=8080,
        )
        self.post_message(StatusUpdate("proxy", 0.0, "Proxy MITM 127.0.0.1:8080 actif"))
        await self._proxy_capture.start()  # bloque jusqu'a stop
    except (RuntimeError, ImportError):
        self._proxy_capture = None
        self.post_message(ProxyUnavailable())

@work(exclusive=True, name="engine_worker")
async def _start_engine_worker(self) -> None:
    """Moteur demarre avec le meme bus que le proxy."""
    try:
        self._engine = await HDWPEngine.create_from_context(
            self._ctx, bus=self._bus,
        )
        findings = await self._engine.run()
        self.post_message(EngineComplete(len(findings)))
    except Exception as exc:
        self.post_message(EngineError(str(exc)))
    finally:
        if self._engine:
            await self._engine.close()
            self._engine = None
        # Arreter le proxy quand le moteur termine
        if self._proxy_capture:
            await self._proxy_capture.stop()
```

### Gestion de `ProxyUnavailable`

```python
class ProxyUnavailable(Message):
    """mitmproxy absent ou port occupe."""

def on_proxy_unavailable(self, message: ProxyUnavailable) -> None:
    """Le proxy n'a pas pu demarrer -- le scan continue sans."""
    status = self.query_one(StatusPanel)
    status.set_proxy_status(active=False)  # affiche "PROXY ---" en gris
    self.query_one(EventLogPanel).add_event(
        "ERR", "Proxy indisponible (mitmproxy absent ou port occupe)"
    )
    self.notify(
        "Le scan continue sans proxy. Installez mitmproxy pour capturer les credentials.",
        title="PROXY OFF",
        severity="warning",
        timeout=5.0,
    )
```

`StatusPanel.set_proxy_status(active: bool)` : si `False`, la ligne proxy dans le
StatusPanel affiche `"  PROXY ---"` en couleur `#445566` (muted) au lieu de vert.

### Coordination workers : arret propre

```python
async def action_stop(self) -> None:
    """[S] -- arrete proxy ET moteur."""
    for w in self.workers:
        w.cancel()
    if self._proxy_capture:
        await self._proxy_capture.stop()
        self._proxy_capture = None
    if self._engine:
        await self._engine.close()
        self._engine = None
    self.query_one(EventLogPanel).add_event("ERR", "Scan arrete par l'utilisateur")
    self.query_one(StatusPanel).update_status("error", 0.0, "Arrete")
```

**Le scan demarre automatiquement quand ScanScreen s'ouvre -- pas besoin de [R] redondant.**

Les tokens captures via proxy ne sont PAS utilises par le crawl. Ils alimentent le `SessionManager` via `credentials.captured` -> `add_role()` et sont utilises par les EXPERIENCES (phase apres le crawl).

**Couleurs severity dans la table :**
```python
SEV_BARS = {
    "CRITICAL": "[red]####[/red]",
    "HIGH":     "[red]###-[/red]",
    "MEDIUM":   "[yellow]##--[/yellow]",
    "LOW":      "[green]#---[/green]",
    "INFO":     "[blue]----[/blue]",
}
```

---

## Ecran 3 -- FindingsScreen (browser interactif)

```
+-- HDWP -- FINDINGS -- 3 confirmes -----------------------------------+
| +---- LISTE ----------------+ +---- DETAIL ----------------------+   |
| |                           | |                                  |   |
| | > FIND-a1b2 HIGH BOLA    | | ID       : FIND-a1b2             |   |
| |   FIND-c3d4 HIGH SQLi    | | TYPE     : BOLA (CWE-639)        |   |
| |   FIND-e5f6 MED  CORS    | | OWASP    : A01:2021              |   |
| |                           | | ENDPOINT : /api/users/{id}       |   |
| |                           | | CONF     : 97%                   |   |
| |                           | |                                  |   |
| |                           | | REPRODUCTIONS :                  |   |
| |                           | | 1. GET /api/users/42             |   |
| |                           | |    Authorization: Bearer A       |   |
| |                           | | 2. Resultat : donnees User B     |   |
| |                           | |                                  |   |
| |                           | | REMEDIATION :                    |   |
| |                           | | Verifier ownership cote srv      |   |
| +---------------------------+ +----------------------------------+   |
+----------------------------------------------------------------------+
|  [UP/DOWN] Naviguer  [ENTER] Selectionner  [X] Exporter  [ESC] Retour|
+----------------------------------------------------------------------+
```

**Widgets :** `ListView` pour la liste, `Static`/`Markdown` pour le detail.

`FindingsScreen` recoit `db_url` en parametre -> charge depuis `Repository`.

---

## Ecran 4 -- ReportScreen

```
+-- HDWP -- RAPPORT ---------------------------------------------------+
|                                                                      |
|   GENERER UN RAPPORT                                                 |
|                                                                      |
|   Format   * Markdown  o JSON  o HAR                                 |
|                                                                      |
|   Fichier  +-----------------------------------------------+        |
|            | ~/.hdwp/workspaces/SESSION-xxx/reports/report.md|        |
|            +-----------------------------------------------+        |
|                                                                      |
|   Resume IA  * Active (claude-sonnet)  o Desactive                   |
|                                                                      |
|            [ENTER] Generer   [ESC] Retour                            |
+----------------------------------------------------------------------+
```

`ScanScreen` passe `self._db_url` et `self._engine._context.config.llm` a `ReportScreen`.

---

## Ecran 5 -- SettingsScreen (plugins + knowledge + sessions)

Trois onglets (`TabbedContent`) :
- **Plugins** : `DataTable` des plugins avec statut enabled/disabled, toggle avec `[SPACE]`
- **Knowledge** : statistiques d'apprentissage, bouton reset
- **Sessions** : liste des workspaces dans `~/.hdwp/workspaces/`, bouton "Ouvrir"

```python
class SettingsScreen(Screen):
    BINDINGS = [Binding("escape", "pop_screen", "Retour")]

    def __init__(self, registry: PluginRegistry | None = None) -> None:
        super().__init__()
        self._registry = registry or PluginRegistry()

    def compose(self) -> ComposeResult:
        with TabbedContent("Plugins", "Knowledge", "Sessions"):
            yield self._build_plugins_tab()
            yield self._build_knowledge_tab()
            yield self._build_sessions_tab()

    def _build_sessions_tab(self) -> Widget:
        """Liste les workspaces existants dans ~/.hdwp/workspaces/."""
        from hdwp.core.paths import WORKSPACES_DIR
        table = DataTable()
        table.add_columns("Session", "Date", "DB Size")
        if WORKSPACES_DIR.exists():
            for ws in sorted(WORKSPACES_DIR.iterdir(), reverse=True):
                db_file = ws / "evidence.db"
                size = f"{db_file.stat().st_size // 1024}KB" if db_file.exists() else "—"
                table.add_row(ws.name, ws.stat().st_mtime, size)
        return table
```

---

## Ecran 6 -- TokensScreen (saisie manuelle)

```
AJOUTER CREDENTIALS
Role name : [ user_a      ]
Type      : * Bearer  o Cookie  o API Key
Token     : [ Bearer eyJ...   ]
            [+ Ajouter]  [-> Continuer]
```

**Flux de donnees TokensScreen → TargetScreen → ScanScreen :**

```python
# TokensScreen stocke les tokens dans une liste interne
# et les retourne via dismiss() quand l'utilisateur clique [Continuer]

class TokensScreen(Screen):
    def __init__(self) -> None:
        super().__init__()
        self._tokens: list[RoleConfig] = []

    def _action_add(self) -> None:
        """Ajoute le token courant a la liste."""
        from hdwp.core.context.config_schema import CredentialConfig, RoleConfig
        role = RoleConfig(
            name=self.query_one("#role-input", Input).value,
            credentials=CredentialConfig(
                type=self._get_selected_type(),
                token=self.query_one("#token-input", Input).value,
            ),
        )
        self._tokens.append(role)
        self.query_one("#role-input", Input).value = ""
        self.query_one("#token-input", Input).value = ""
        self.notify(f"Token ajoute : {role.name}", severity="information", timeout=2.0)

    def _action_continue(self) -> None:
        """Retourne les tokens a TargetScreen."""
        self.dismiss(self._tokens)

# TargetScreen recupere les tokens via callback :
def _on_manual_mode(self) -> None:
    def _on_tokens(tokens: list[RoleConfig] | None) -> None:
        if tokens:
            self._manual_tokens = tokens
    self.app.push_screen(TokensScreen(), callback=_on_tokens)

# Quand TargetScreen lance le scan, les tokens manuels sont passes :
# push_screen(ScanScreen(target_url, mode, manual_tokens=self._manual_tokens))
# ScanScreen les injecte dans le SessionManager via add_role()
```

---

## CSS -- Palette de couleurs diversifiee et dynamique

### IMPORTANT : Textual 8.x ne supporte PAS `var(--color)`

Toutes les couleurs sont HARDCODEES dans le TCSS. La palette ci-dessous est donnee en commentaire, pas comme variables.

### Palette (chaque type d'info a sa propre couleur)

```
Fond principal    : #080808
Fond panneaux     : #0d0d0d
Selection/hover   : #1a1a2a

Vert matrix       : #00ff41   (statut OK, success, titre)
Cyan obs          : #00d4ff   (observations HTTP, URLs)
Violet prop       : #cc44ff   (proprietes inferees, IA)
Orange exp        : #ff6b35   (experiences en cours)
Bleu hyp          : #4488ff   (hypotheses generees)
Or key            : #ffd700   (credentials captures, tokens)
Rouge err         : #ff2244   (erreurs, stop)
Texte normal      : #d8d8e8
Muted             : #445566   (timestamps, metadata)

Severite CRITICAL : #ff0000 sur #2a0000
Severite HIGH     : #ff4444 sur #1a0000
Severite MEDIUM   : #ffaa00 sur #1a0a00
Severite LOW      : #44ff88 sur #001a00
Severite INFO     : #4488ff sur #00001a
```

### Couleurs par type d'evenement dans le live feed

```python
_EVENT_COLORS: ClassVar[dict[str, str]] = {
    "OBS":  "#00d4ff",   # cyan -- observations HTTP
    "PROP": "#cc44ff",   # violet -- proprietes inferees
    "HYP":  "#ff6b35",   # orange -- hypotheses
    "EXP":  "#4488ff",   # bleu -- experiences
    "V":    "#44ff88",   # vert vif -- CONFIRMED (bold)
    "X":    "#ff2244",   # rouge -- refute/erreur
    "KEY":  "#ffd700",   # or -- credentials captures
    "ERR":  "#ff0000",   # rouge vif -- erreur
}
```

### Effets dynamiques via Timer Python

```python
# StatusPanel : indicateur * qui pulse en changeant de couleur
PHASE_COLORS = {
    "crawl":       "#00d4ff",  # cyan
    "properties":  "#cc44ff",  # violet
    "experiments": "#ff6b35",  # orange
    "done":        "#44ff88",  # vert vif
    "error":       "#ff2244",  # rouge
}
# Alterne entre PHASE_COLORS[phase] et version foncee toutes les 500ms
# Phase stockee dans self._phase: str (PAS dans label.renderable)
```

### Nouveaux findings -- flash visuel

Quand un finding est confirme, la ligne dans `FindingsTable` est surlignee 2 secondes :
```python
self.set_timer(2.0, lambda: row_key.remove_class("new-finding"))
```

CSS (changement abrupt, pas de transition -- Textual 8.x ne supporte pas les transitions CSS) :
```css
.new-finding {
    background: #2a0a00;
    text-style: bold;
}
```

### Capture de credentials -- notification gold

```python
self.notify(
    f"Token capture : {role} ({token_type})",
    title="CREDENTIAL CAPTURED",
    severity="information",   # string, pas enum (Textual 8.x)
    timeout=3.0,
)
```

CSS pour les toasts (pas `.notification`, c'est `.toast` dans Textual 8.x) :
```css
.toast { background: #2a2000; border: solid #ffd700; }
```

### Barres de progression par phase

Selector correct = `.bar--bar` (pas `> .bar`) :
```css
#crawl-bar .bar--bar       { background: #00d4ff; }
#props-bar .bar--bar       { background: #cc44ff; }
#experiments-bar .bar--bar { background: #ff6b35; }
```

---

## Repertoires par defaut -- Structure `~/.hdwp/`

```
~/.hdwp/
+-- knowledge.db              <-- KnowledgeBase (deja la)
+-- contexts/                 <-- Fichiers de contexte sauvegardes
|   +-- auto_a1b2c3d4.yaml   <-- Genere par URL (hash-based, reutilise)
|   +-- mon-pentest.yaml
+-- plugins/                  <-- Plugins installes par l'utilisateur
|   +-- mon-plugin/
|       +-- hdwp_plugin.py    <-- Doit exposer PLUGIN_CLASS = MonPlugin
+-- workspaces/               <-- Un repertoire par session de pentest
    +-- SESSION-a1b2c3d4/
        +-- evidence.db       <-- SQLite evidence store de la session
        +-- context.yaml      <-- Contexte utilise (copie)
        +-- model.json        <-- Modele applicatif exporte
        +-- reports/          <-- Rapports generes
            +-- report.md
            +-- findings.json
            +-- har/
                +-- FIND-xxxx.har
```

### `src/hdwp/core/paths.py` -- module centralise

```python
"""Chemins par defaut HDWP -- tous les fichiers vont dans ~/.hdwp/"""
from __future__ import annotations

import hashlib
from pathlib import Path
from urllib.parse import urlparse

HDWP_HOME = Path.home() / ".hdwp"
KNOWLEDGE_DB = HDWP_HOME / "knowledge.db"
CONTEXTS_DIR = HDWP_HOME / "contexts"
PLUGINS_DIR = HDWP_HOME / "plugins"
WORKSPACES_DIR = HDWP_HOME / "workspaces"

def workspace_dir(session_id: str) -> Path:
    return WORKSPACES_DIR / session_id

def evidence_db_url(session_id: str) -> str:
    d = workspace_dir(session_id)
    d.mkdir(parents=True, exist_ok=True)
    return f"sqlite+aiosqlite:///{d}/evidence.db"

def evidence_db_url_with_fallback(session_id: str) -> str:
    """Backward compat : si evidence_store.db existe dans le cwd, l'utiliser."""
    legacy = Path("evidence_store.db")
    if legacy.exists():
        return f"sqlite+aiosqlite:///{legacy.resolve()}"
    return evidence_db_url(session_id)

def reports_dir(session_id: str) -> Path:
    d = workspace_dir(session_id) / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d

def model_path(session_id: str) -> Path:
    return workspace_dir(session_id) / "model.json"

def context_path_for_url(target_url: str) -> Path:
    """Retourne un chemin de contexte YAML deterministe pour une URL.
    Hash-based : meme URL -> meme fichier -> reutilise entre sessions."""
    parsed = urlparse(target_url)
    slug = parsed.netloc.replace(":", "_")
    url_hash = hashlib.sha256(target_url.encode()).hexdigest()[:8]
    CONTEXTS_DIR.mkdir(parents=True, exist_ok=True)
    return CONTEXTS_DIR / f"auto_{slug}_{url_hash}.yaml"

def build_context_from_url(target_url: str) -> Path:
    """Cree un fichier hdwp-context.yaml minimal pour une URL cible.
    Si le fichier existe deja (meme hash), le reutilise sans reecrire."""
    path = context_path_for_url(target_url)
    if path.exists():
        return path
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    content = f"""# Contexte genere automatiquement par HDWP
target:
  base_url: "{base}"
  name: "Pentest {parsed.netloc}"

scope:
  include:
    - "{base}/*"

roles:
  - name: "anonymous"

options:
  allow_write: false
  max_requests_per_minute: 30
"""
    path.write_text(content, encoding="utf-8")
    return path
```

**Factorisation :** `_create_minimal_context()` de `cli/main.py` est remplacee par
`paths.build_context_from_url()`. Le CLI et `TargetScreen` appellent la meme fonction.
Les fichiers temporaires dans `/tmp` sont elimines -- tout va dans `~/.hdwp/contexts/`.

### Integration dans le moteur

- `HDWPEngine.create()` : `db_url` par defaut = `evidence_db_url(context.session_id)`
- `ReportEngine.generate_markdown()` : output par defaut = `reports_dir(session_id) / "report.md"`
- `hdwp model --export` : defaut = `model_path(session_id)`
- `PluginRegistry.discover()` : cherche aussi dans `~/.hdwp/plugins/` via `sys.path.insert(0, str(plugin_subdir))` pour chaque sous-dossier + `importlib.util.spec_from_file_location("hdwp_plugin", plugin_subdir / "hdwp_plugin.py")`

### Backward compatibility

Si `evidence_store.db` existe dans le repertoire courant (anciens scans), le moteur le trouve en priorite.

---

## CLI -- `hdwp` sans args lance le TUI

```python
# src/hdwp/cli/main.py
app = typer.Typer(invoke_without_command=True)  # AVANT : no_args_is_help=True

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        from hdwp.tui.app import HDWPApp
        HDWPApp().run()
```

### Auto-start mode (`hdwp run --target URL`)

Quand `hdwp run --target URL` est appele, le TUI doit skip `TargetScreen` et aller
directement au scan. Implementation :

```python
# src/hdwp/tui/app.py
class HDWPApp(App):
    def __init__(
        self,
        context_path: Path | None = None,
        db_url: str | None = None,
        auto_start_url: str | None = None,
    ) -> None:
        super().__init__()
        self._context_path = context_path
        self._db_url = db_url
        self._auto_start_url = auto_start_url

    def on_mount(self) -> None:
        if self._auto_start_url:
            # Skip TargetScreen, aller directement au scan
            self.switch_screen(ScanScreen(
                target_url=self._auto_start_url,
                context_path=self._context_path,
                mode="auto",
            ))
        else:
            self.push_screen(TargetScreen())

# src/hdwp/cli/main.py -- dans run()
# Mode TUI (defaut) :
from hdwp.tui.app import HDWPApp
HDWPApp(
    context_path=context,
    db_url=db_url,
    auto_start_url=target,     # None si pas de --target
).run()
```

**Pourquoi `switch_screen` au lieu de `push_screen` en auto-start :**
`push_screen` empile TargetScreen (default) PUIS ScanScreen -> ESC reviendrait
a un TargetScreen inutile. `switch_screen` remplace directement.

---

## `HDWPEngine` -- factorisation `create()` / `create_from_context()`

Le `create()` actuel fait ~100 lignes d'init. Pour eviter la duplication,
on extrait la logique commune dans `_init_components()` (methode privee),
et `create_from_context()` l'appelle avec un bus externe.

```python
# src/hdwp/core/engine.py

@classmethod
async def _init_components(
    cls,
    context: EngineContext,
    bus: AsyncEventBus,
    db_url: str | None = None,
    plugin_ids: list[str] | None = None,
) -> HDWPEngine:
    """Logique commune : initialise tous les composants depuis un context + bus."""
    from hdwp.core.paths import evidence_db_url

    scope_guard = ScopeGuard(context)

    effective_db_url = db_url or evidence_db_url(context.session_id)
    engine_db = await init_db(effective_db_url)
    repository = Repository(engine_db)

    app_model = ApplicationModel(bus)

    # Plugin registry
    registry = PluginRegistry()
    registry.discover()
    enabled = plugin_ids or context.config.plugins.enabled
    for pid in enabled:
        registry.enable(pid)

    # KnowledgeBase
    from hdwp.core.hypothesis.prioritizer import HypothesisPrioritizer
    from hdwp.core.knowledge.base import DEFAULT_KB_PATH, KnowledgeBase
    kb_path = context.config.options.knowledge_db or DEFAULT_KB_PATH
    kb = KnowledgeBase(db_path=kb_path)
    adapted_weights = await kb.get_adapted_weights()
    prioritizer = HypothesisPrioritizer.with_weights(adapted_weights)

    # Composants de raisonnement
    SecurityPropertyEngine(bus, plugin_registry=registry)
    hyp_engine = HypothesisEngine(
        bus, model_accessor=app_model.snapshot,
        plugin_registry=registry, repository=repository,
        prioritizer=prioritizer,
    )
    from hdwp.core.llm.layer import create_llm_layer
    llm_layer = create_llm_layer(context.config.llm)
    oracle = SemanticOracle(bus, repository, llm_layer=llm_layer)
    PassiveFindingEngine(bus, repository)
    report_engine = ReportEngine(bus, repository)
    from hdwp.core.state_machine.learner import StateMachineLearner
    StateMachineLearner(bus)

    obs_engine = ObservationEngine(bus, context, scope_guard)

    rate_limiter = TokenBucket.from_rpm(context.config.options.max_requests_per_minute)
    session_manager = SessionManager(context.config.roles)
    session_manager._clients = {
        role.name: httpx.AsyncClient(follow_redirects=True, timeout=httpx.Timeout(15.0))
        for role in context.config.roles
    }

    # Pre-acquire OAuth2 tokens
    for role_name, oauth_client in session_manager._oauth_clients.items():
        try:
            token = await oauth_client.get_token()
            role = session_manager._roles.get(role_name)
            if role and role.credentials:
                role.credentials.token = token
        except Exception:
            pass

    # Wire credential capture
    from hdwp.core.bus.events import CREDENTIALS_CAPTURED
    from hdwp.core.bus.events import HDWPEvent as _HDWPEvent

    def _cred_handler(event: _HDWPEvent) -> None:
        asyncio.create_task(_on_credentials_captured(event, session_manager))

    bus.on(CREDENTIALS_CAPTURED, _cred_handler)

    exp_engine = ExperimentEngine(
        bus=bus, scope_guard=scope_guard, session_manager=session_manager,
        rate_limiter=rate_limiter, model_accessor=app_model.snapshot,
        corpus_accessor=app_model.get_all_corpus,
    )

    return cls(
        context=context, bus=bus, app_model=app_model,
        obs_engine=obs_engine, hyp_engine=hyp_engine, exp_engine=exp_engine,
        oracle=oracle, session_manager=session_manager,
        repository=repository, report_engine=report_engine,
        knowledge_base=kb,
    )

@classmethod
async def create(
    cls, context_path: Path,
    db_url: str | None = None, plugin_ids: list[str] | None = None,
) -> HDWPEngine:
    """Charge un fichier YAML puis delegue a _init_components."""
    context = ContextLoader.load(context_path)
    bus = AsyncEventBus()
    return await cls._init_components(context, bus, db_url, plugin_ids)

@classmethod
async def create_from_context(
    cls,
    context: EngineContext,
    bus: AsyncEventBus,
    db_url: str | None = None,
    plugin_ids: list[str] | None = None,
) -> HDWPEngine:
    """Variante pour le TUI : accepte un bus et un context deja crees.
    Le bus est celui du proxy, partage avec le moteur."""
    return await cls._init_components(context, bus, db_url, plugin_ids)
```

**Impact :** `create()` passe de ~100 lignes a 3. Aucune duplication.

---

## Corrections Textual 8.x (lacunes identifiees et resolues)

| # | Probleme | Solution |
|---|----------|----------|
| 0 | CSS custom properties `var(--x)` | Couleurs hardcodees |
| 1 | `FilePicker` inexistant | `Input` avec validation de chemin |
| 2 | Proxy timing (tokens pas pour le crawl) | Documente : tokens pour les experiments |
| 3 | `_build_context_from_url` indefini | Defini avec hash-based filename |
| 4 | ProgressBar CSS `.bar` | Selector correct : `.bar--bar` |
| 5 | `~/.hdwp/plugins/` + entry_points | `sys.path` + `hdwp_plugin.py` convention |
| 6 | Workspace sans continuite | Meme URL reutilise meme context file |
| 7 | `App.notify()` severity enum | String `"information"` / CSS `.toast` |
| 8 | CSS transitions impossibles | Changement abrupt de classe |
| 9 | `app.auto_start` depuis Screen | `cast(HDWPApp, self.app)` |
| 10 | `push_screen` empile en auto-start | `switch_screen` remplace |
| 11 | Bus pas initialise avant workers | Bus cree dans `on_mount()` sync |
| 12 | Scan n'auto-demarre pas | `on_mount()` lance proxy + engine |
| 13 | `label.renderable` pas une string | Phase stockee dans `self._phase: str` |
| 14 | RadioSet switch URL/YAML | Deux `Vertical` containers, `display` toggle |
| 15 | ReportEngine bus ferme apres scan | Bus vide (stub) |
| 16 | `_create_minimal_context()` duplique dans CLI et TUI | Factorise dans `paths.build_context_from_url()` |
| 17 | `evidence_store.db` legacy dans le cwd ignore | `evidence_db_url_with_fallback()` verifie le cwd d'abord |
| 18 | `TokensScreen` ne retourne pas les tokens | `dismiss(self._tokens)` + callback sur `TargetScreen` |
| 19 | Auto-start empile TargetScreen inutilement | `switch_screen(ScanScreen)` au lieu de `push_screen` |
| 20 | Proxy absent = crash | `ProxyUnavailable` message + scan continue sans proxy |

---

## Fichiers a creer / modifier

| Fichier | Action | Complexite |
|---|---|---|
| `src/hdwp/core/paths.py` | **Nouveau** : chemins `~/.hdwp/`, `build_context_from_url()`, `evidence_db_url_with_fallback()` | Faible |
| `src/hdwp/core/engine.py` | Factoriser `create()` en `_init_components()` + `create_from_context()` | **Elevee** |
| `src/hdwp/tui/app.py` | Refonte : HDWPApp + Screen routing + `auto_start_url` | Moyenne |
| `src/hdwp/tui/screens/__init__.py` | **Nouveau** package | Faible |
| `src/hdwp/tui/screens/target.py` | **Nouveau** : TargetScreen (Input, RadioSet, validation, callback tokens) | Moyenne |
| `src/hdwp/tui/screens/scan.py` | **Nouveau** : ScanScreen (proxy auto, bus partage, workers, ProxyUnavailable) | **Elevee** |
| `src/hdwp/tui/screens/findings.py` | **Nouveau** : FindingsScreen (db_url, Repository, ListView+detail) | Moyenne |
| `src/hdwp/tui/screens/report.py` | **Nouveau** : ReportScreen (db_url, llm config, RadioSet format) | Moyenne |
| `src/hdwp/tui/screens/settings.py` | **Nouveau** : SettingsScreen (TabbedContent, plugins/knowledge/sessions) | Moyenne |
| `src/hdwp/tui/screens/tokens.py` | **Nouveau** : TokensScreen (saisie manuelle, `dismiss(tokens)`) | Faible |
| `src/hdwp/tui/widgets.py` | Etendre : `StatusPanel.set_proxy_status()`, pulse Timer | Moyenne |
| `src/hdwp/tui/hdwp.tcss` | Refonte CSS complet (palette hardcodee, couleurs severity) | Moyenne |
| `src/hdwp/tui/messages.py` | + `ProxyUnavailable`, `ProxyStarted` | Faible |
| `src/hdwp/cli/main.py` | `invoke_without_command=True`, callback, remplacer `_create_minimal_context` | Faible |
| `src/hdwp/store/database.py` | `init_db()` utilise `paths.evidence_db_url()` si pas de db_url | Faible |
| `src/hdwp/core/report/engine.py` | Output par defaut dans `paths.reports_dir()` | Faible |
| `src/hdwp/plugins/registry.py` | Discover aussi `~/.hdwp/plugins/` via `sys.path` + `importlib` | Faible |
| `tests/tui/test_screens.py` | **Nouveau** : tests Textual `App.run_test()` pour chaque screen | Moyenne |
| `tests/core/test_paths.py` | **Nouveau** : tests unitaires `paths.py` | Faible |
| `tests/core/test_engine_create.py` | **Nouveau** : tests `create_from_context()` bus partage | Faible |

---

## Correction proxy (flux correct)

**Avant (casse) :**
```
[R] -> Engine demarre -> [A] -> Proxy demarre (trop tard)
```

**Apres (correct) :**
```
TargetScreen -> [ENTER] -> ScanScreen monte
  +-- Proxy demarre en background worker (immediatement)
  +-- TUI affiche "Proxy MITM 127.0.0.1:8080 -- configurez Firefox"
  +-- Engine demarre (crawl en parallele avec le proxy)
  +-- Tokens captures via proxy -> injectes dans le moteur en temps reel
```

Le proxy fonctionne MEME sans mitmproxy (juste absent du layout) -- pas de crash.

---

## Tests a ecrire

Utiliser `App.run_test()` de Textual pour les tests de screens.
Les tests existants (451+) ne doivent PAS casser.

### Tests unitaires paths.py

| Test | Assertion |
|---|---|
| `test_evidence_db_url` | Cree `~/.hdwp/workspaces/SESSION-x/evidence.db` |
| `test_evidence_db_url_with_fallback_legacy` | Si `evidence_store.db` dans cwd -> l'utilise |
| `test_evidence_db_url_with_fallback_no_legacy` | Sinon -> `~/.hdwp/workspaces/` |
| `test_build_context_from_url` | Cree YAML valide dans `~/.hdwp/contexts/` |
| `test_build_context_from_url_idempotent` | Meme URL -> meme fichier, pas de reecriture |
| `test_context_path_for_url_deterministic` | Meme URL -> meme hash |

### Tests screens (via `App.run_test()`)

```python
async def test_target_screen_invalid_url():
    """URL sans schema -> notification d'erreur, pas de push_screen."""
    async with HDWPApp().run_test() as pilot:
        app = pilot.app
        app.push_screen(TargetScreen())
        await pilot.click("#url-input")
        await pilot.press("b", "a", "d", "enter")
        # Pas de ScanScreen empile
        assert not isinstance(app.screen, ScanScreen)

async def test_target_screen_yaml_not_found():
    """Chemin YAML inexistant -> notification d'erreur."""
    async with HDWPApp().run_test() as pilot:
        # selectionner mode YAML, entrer un chemin bidon, ENTER
        # -> pas de ScanScreen, notification affichee
        ...

async def test_scan_screen_proxy_unavailable():
    """Si mitmproxy absent -> ProxyUnavailable emis, scan continue."""
    async with HDWPApp().run_test() as pilot:
        # Monkeypatch import mitmproxy -> ImportError
        # ScanScreen doit afficher "PROXY ---" et continuer le moteur
        ...

async def test_scan_screen_engine_complete():
    """Moteur termine -> EngineComplete emis, StatusPanel a 'COMPLETE'."""
    ...

async def test_findings_screen_loads_from_db():
    """FindingsScreen charge les findings depuis le Repository."""
    ...

async def test_tokens_screen_dismiss():
    """TokensScreen retourne les tokens via dismiss()."""
    ...
```

### Tests integration engine

| Test | Assertion |
|---|---|
| `test_create_from_context_shares_bus` | `engine._bus is bus` (meme instance) |
| `test_create_from_context_no_duplication` | `create()` et `create_from_context()` produisent le meme engine |
| `test_create_uses_paths_evidence_db_url` | DB par defaut dans `~/.hdwp/workspaces/` |

### Tests CLI

| Test | Assertion |
|---|---|
| `test_hdwp_no_args_launches_tui` | `hdwp` sans args -> `HDWPApp().run()` appele |
| `test_hdwp_run_target_auto_start` | `hdwp run --target URL` -> `auto_start_url` passe |

---

## Verification manuelle

1. `hdwp` (sans args) -> TargetScreen s'affiche avec le logo + input URL
2. Entrer `https://exemple.com` + ENTER -> ScanScreen s'ouvre, proxy demarre
3. `[F]` -> FindingsScreen avec liste/detail
4. `[R]` -> ReportScreen, choisir format, ENTER -> fichier cree
5. `[P]` -> SettingsScreen, SPACE -> toggle plugin
6. `451+` tests verts + nouveaux tests ci-dessus
7. `~/.hdwp/workspaces/SESSION-xxx/` cree avec evidence.db + reports/
8. `hdwp run --target URL` -> skip TargetScreen, ScanScreen directement
9. Proxy absent (pas de mitmproxy) -> scan continue, "PROXY ---" affiche
10. Mode YAML avec fichier inexistant -> erreur rouge, pas de crash
