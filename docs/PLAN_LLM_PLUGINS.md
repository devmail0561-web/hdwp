# Plan — LLM + Plugin/Mutation : complétion et expérience développeur

## Contexte

Deux lacunes critiques identifiées après analyse approfondie :

1. **LLM** : `LLMLayerProtocol` expose 5 méthodes, 3 seulement sont câblées dans le pipeline.
   `propose_hypotheses` et `interpret_js` sont entièrement implémentées mais jamais appelées.
   De plus, le TUI `ReportScreen` a un bug silencieux : si `llm_config.enabled=False` dans le YAML,
   sélectionner "Active" dans l'UI ne fait rien (double guard).

2. **Plugins/Mutations** : l'architecture est extensible en théorie (interface complète,
   `register_mutations()` câblé dans l'engine) mais incomplet en pratique :
   le cycle de vie (`on_load/on_model_ready/on_unload`) n'est jamais appelé,
   l'état enabled/disabled n'est pas persisté entre sessions, et `register_mutations()`
   ne reçoit pas le modèle observé.

---

## Axe A — LLM : câbler les 2 méthodes manquantes

### État actuel du LLM

```
LLMLayerProtocol (5 méthodes)
  ├── disambiguate_diff()          → CÂBLÉ  dans SemanticOracle (diffs AMBIGUOUS)
  ├── generate_remediation_hint()  → CÂBLÉ  dans SemanticOracle (findings CONFIRMED)
  ├── generate_executive_summary() → CÂBLÉ  dans ReportEngine.generate_markdown()
  ├── propose_hypotheses()         → ✗ PAS CÂBLÉ (HypothesisEngine n'a pas llm_layer)
  └── interpret_js()               → ✗ PAS CÂBLÉ (ObservationEngine n'a pas llm_layer)

Contrainte ADR-002 : le LLM ne peut jamais déclencher seul CONFIRMED.
Max confidence_hint = 0.55 (seuil CONFIRMED = 0.85).
```

**Configuration YAML :**
```yaml
llm:
  enabled: true
  provider: anthropic        # anthropic | openai | ollama
  model: claude-sonnet-4-6   # gpt-4o-mini | llama3.2 | mistral | ...
  base_url: null             # pour ollama: http://localhost:11434/v1

# Clé API dans l'environnement (jamais dans le YAML) :
# Anthropic : export ANTHROPIC_API_KEY=sk-ant-...
# OpenAI    : export OPENAI_API_KEY=sk-...
# Ollama    : aucune clé requise
```

### A3 — Fix TUI double guard (priorité haute, indépendant)

**Fichier :** `src/hdwp/tui/screens/report.py`, lignes 88–92

Remplacer la condition `if self._is_llm_active() and self._llm_config and self._llm_config.enabled:` par :

```python
if self._is_llm_active():
    config = self._llm_config
    if config is None:
        config = LLMConfig(enabled=True)
    elif not config.enabled:
        config = config.model_copy(update={"enabled": True})
    llm_layer = create_llm_layer(config)
```

`LLMConfig` est déjà importé. `create_llm_layer` retourne `None` si la clé API est absente — comportement correct.

### A1 — `propose_hypotheses` → HypothesisEngine

**Fichier :** `src/hdwp/core/hypothesis/engine.py`

1. Ajouter `llm_layer: LLMLayerProtocol | None = None` à `__init__`, stocker dans `self._llm_layer`.
   Import en `TYPE_CHECKING` : `from hdwp.core.llm.layer import LLMLayerProtocol`.

2. Dans `_on_property_inferred`, après le bloc plugins (ligne ~73), avant `for hyp in hypotheses:` :

```python
if self._llm_layer is not None and self._model_accessor is not None:
    model = self._model_accessor()
    if model is not None:
        try:
            statements = await self._llm_layer.propose_hypotheses(model, len(self._hypotheses))
            for stmt in statements:
                hypotheses.append(self._statement_to_hypothesis(stmt, prop))
        except Exception as exc:  # noqa: BLE001
            logger.warning("llm.propose_hypotheses_skipped", error=str(exc))
```

3. Ajouter méthode statique `_statement_to_hypothesis(stmt, prop) -> Hypothesis` :
   détecte le `mutation_type` par mots-clés dans le texte (idor/sql → `field_injection`,
   privilege/admin → `privilege_escalation`, race → `identity_swap`, sinon `field_injection`).
   Crée `Hypothesis(source_plugin="llm", priority="MEDIUM", required_experiments=[ExperimentSpec(mutation_type=..., mutation_params={"llm_generated": True})])`.

**Fichier :** `src/hdwp/core/engine.py`, `_init_components()`

Déplacer `create_llm_layer(context.config.llm)` AVANT la construction de `HypothesisEngine`,
puis passer `llm_layer=llm_layer` à `HypothesisEngine(...)`.
(Pas d'import circulaire : `engine → llm.layer → oracle.violation_oracle`, pas de retour.)

### A2 — `interpret_js` → ActiveCrawler (mode complémentaire)

**Fichier :** `src/hdwp/core/observation/active_crawler.py`

1. Ajouter `llm_layer: LLMLayerProtocol | None = None` à `__init__`.

2. Dans `_crawl_as_role`, dans le bloc JS (après `api_urls = js_extractor.extract_endpoints(...)`),
   appeler le LLM **uniquement si `api_urls` est vide** (mode complémentaire, pas systématique) :

```python
if not api_urls and self._llm_layer is not None:
    try:
        llm_paths = await self._llm_layer.interpret_js(js_resp.text)
        for path in llm_paths:
            llm_url = f"{origin}{path}" if path.startswith("/") else path
            if self._scope_guard.check(llm_url, "GET") == ScopeVerdict.ALLOWED:
                if llm_url not in visited:
                    queue.append((llm_url, depth + 1))
    except Exception:  # noqa: BLE001, S110
        pass
```

**Fichier :** `src/hdwp/core/observation/engine.py`

Ajouter `llm_layer: LLMLayerProtocol | None = None` à `ObservationEngine.__init__`,
passer `llm_layer=self._llm_layer` à `ActiveCrawler(...)` dans `start()`.

**Fichier :** `src/hdwp/core/engine.py`

Passer `llm_layer=llm_layer` à `ObservationEngine(bus, context, scope_guard, llm_layer=llm_layer)`.

---

## Axe B — Plugins : compléter l'expérience développeur

### Cycle de détection complet d'un plugin custom

```
Plugin.infer_properties(model)       → détecte une propriété de sécurité
Plugin.generate_hypotheses(model)    → crée Hypothesis avec ExperimentSpec(mutation_type="ma_mutation")
Plugin.register_mutations(model)     → enregistre plan_function + apply_function pour "ma_mutation"
  → mutation_registry.plan("ma_mutation", ...)   → ConcreteExperimentPlan
  → mutation_registry.apply("ma_mutation", ...)  → NormalizedRequest mutée
SemanticOracle                       → évalue le résultat, confirme ou réfute
```

### B2 — Persistance de l'état enabled/disabled

**Fichier :** `src/hdwp/plugins/registry.py`

Ajouter à `PluginRegistry` :
- `self._sources: dict[str, str] = {}` (valeurs : `"entry_point"` | `"user"`)
- `_load_state(path=HDWP_HOME / "plugins.state.json")` : lit JSON `{"enabled": [...], "disabled": [...]}`
- `_save_state(path=...)` : écrit ce JSON
- `get_source(plugin_id: str) -> str` : retourne `self._sources.get(plugin_id, "entry_point")`

Modifier `enable(plugin_id, persist=True)` et `disable(plugin_id, persist=True)` pour appeler `_save_state()` si `persist=True`.

`discover()` appelle `_load_state()` en fin de méthode.

Dans `_discover_entry_points` : `self._sources[plugin.id] = "entry_point"`.
Dans `_discover_user_plugins` : `self._sources[plugin.id] = "user"`.

**Fichier :** `src/hdwp/core/engine.py`, `_init_components()`

Changer `registry.enable(pid)` → `registry.enable(pid, persist=False)` pour les plugins
issus du YAML (ne pas polluer le state file avec des configs temporaires).

### B1 — Cycle de vie plugins (dépend de B2)

**Fichier :** `src/hdwp/core/engine.py`

1. `HDWPEngine.__init__` : ajouter `registry: PluginRegistry | None = None`, stocker `self._registry`.

2. `_init_components()` : juste avant `return engine`, appeler `on_load()` avec timeout :

```python
for plugin in registry.list_enabled():
    try:
        await asyncio.wait_for(plugin.on_load(), timeout=5.0)
    except asyncio.TimeoutError:
        log.warning("plugin.on_load_timeout", plugin_id=plugin.id)
    except Exception as exc:  # noqa: BLE001
        log.warning("plugin.on_load_failed", plugin_id=plugin.id, error=str(exc))
```

3. `run()`, après la Phase 1c (auto-registration) :

```python
if self._registry is not None:
    snap = self._app_model.snapshot()
    for plugin in self._registry.list_enabled():
        try:
            await asyncio.wait_for(plugin.on_model_ready(snap), timeout=5.0)
        except asyncio.TimeoutError:
            log.warning("plugin.on_model_ready_timeout", plugin_id=plugin.id)
        except Exception as exc:  # noqa: BLE001
            log.warning("plugin.on_model_ready_failed", plugin_id=plugin.id, error=str(exc))
```

4. `close()` : avant `self._session_manager.close_all()`, appeler `on_unload()` avec même pattern.

### B4 — `register_mutations()` avec contexte modèle (dépend de B1)

**Fichier :** `src/hdwp/plugins/base.py`

Changer la signature :
```python
def register_mutations(self, model: ApplicationModelData | None = None) -> list[dict]:
    """
    Retourne une liste de dicts pour mutation_registry.register().
    model : snapshot du modèle applicatif après observation (None à l'init).
    Chaque dict : name, owasp_category, cwe_id, remediation,
                  + optionnel : plan_experiment, apply_mutation,
                                assess_violation, compute_specificity
    """
    return []
```

**Fichier :** `src/hdwp/core/engine.py`, `run()`, après `on_model_ready` (Phase 1e)

```python
if self._registry is not None and snap is not None:
    for plugin in self._registry.list_enabled():
        try:
            try:
                specs = plugin.register_mutations(snap)
            except TypeError:
                specs = plugin.register_mutations()   # backward compat
            for mut_spec in specs:
                mutation_registry.register(**mut_spec)
        except Exception as exc:  # noqa: BLE001
            log.warning("plugin.register_mutations_model_failed",
                        plugin_id=plugin.id, error=str(exc))
```

### B3 — `hdwp plugin list` amélioré (dépend de B2)

**Fichier :** `src/hdwp/cli/main.py`

Dans le `case "list":` du subcommand `plugin`, ajouter 2 colonnes :
- `"Statut"` : `[green]enabled[/green]` ou `[dim]disabled[/dim]`
- `"Source"` : `registry.get_source(p.id)` → `"entry_point"` ou `"user"`

---

## Ordre d'implémentation recommandé

```
1. A3  — Fix TUI (3 lignes, indépendant, valeur immédiate)
2. B2  — Persistance registry (prérequis pour B1, B3)
3. B3  — CLI plugin list colonnes (dépend de B2)
4. B1  — Lifecycle plugins (refactor engine, dépend de B2)
5. B4  — register_mutations(model) (dépend de B1, engine refactorisé)
6. A1  — propose_hypotheses (dépend du déplacement llm_layer dans engine)
7. A2  — interpret_js (quasi-indépendant, peut aller avec A1)
```

---

## Fichiers critiques à modifier

| Fichier | Axes | Nature |
|---|---|---|
| `src/hdwp/tui/screens/report.py` | A3 | 4 lignes, double guard |
| `src/hdwp/core/hypothesis/engine.py` | A1 | `__init__` + `_on_property_inferred` + nouvelle méthode |
| `src/hdwp/core/observation/active_crawler.py` | A2 | `__init__` + bloc JS |
| `src/hdwp/core/observation/engine.py` | A2 | `__init__` + `start()` |
| `src/hdwp/plugins/registry.py` | B2, B3 | `_sources`, `_load_state`, `_save_state`, `enable`/`disable` |
| `src/hdwp/plugins/base.py` | B4 | Signature `register_mutations` |
| `src/hdwp/cli/main.py` | B3 | Colonnes tableau plugin list |
| `src/hdwp/core/engine.py` | A1, A2, B1, B4 | Déplacer `create_llm_layer`, lifecycle, passer `registry` |

---

## Vérification

```bash
# Tests existants ne doivent pas casser
.venv/bin/python -m pytest tests/ -q --tb=short

# Nouveaux tests à écrire
tests/unit/test_hypothesis_engine.py        # propose_hypotheses: appel LLM, fallback erreur
tests/unit/test_plugin_registry.py          # enable/disable persist, load_state, get_source
tests/unit/test_engine_plugin_lifecycle.py  # on_load timeout, register_mutations(model)
tests/unit/test_report_screen_llm.py        # model_copy avec enabled=True

# Smoke test imports
.venv/bin/python -c "
from hdwp.core.hypothesis.engine import HypothesisEngine
from hdwp.plugins.registry import PluginRegistry
print('OK')
"
```

---

## Risques

| Risque | Mitigation |
|---|---|
| Coût LLM élevé sur A2 (1 appel par fichier JS) | Mode complémentaire : `if not api_urls` — LLM uniquement si le crawleur standard n'a rien trouvé |
| A1 : 1 appel LLM par propriété inférée | Acceptable MVP, pas de deduplication nécessaire pour l'instant |
| B2 : `_save_state` écrit dans `~/.hdwp/` dans les tests | Tests passent `path=tmp_path/...` au paramètre explicite |
| B4 : `TypeError` comme signal de backward compat masque de vrais bugs | Log `plugin.register_mutations_model_failed` — acceptable |
