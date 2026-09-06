# Plan : Corriger le scan tab (vitesse, metriques temps reel, pipelines bloques)

## Context

Le scan tab a 3 problemes rapportes :
1. **Les metriques (status, phase, etc.) ne se mettent pas a jour** pendant le scan
2. **Le scan est trop lent** : ~12 minutes avant de voir quoi que ce soit
3. **Seul le pipeline d'observation affiche quelque chose**, les autres sont bloques

L'analyse approfondie revele des causes a 3 niveaux : timing backend, pipeline sequentiel, et lacunes UI.

## Analyse des causes racines

### A. Bottlenecks timing (11 identifies, 3 critiques)

| # | Bottleneck | Temps estime | Severite |
|---|-----------|-------------|----------|
| 1 | **OpenAPI discovery** : `discovery_delay = 59s` x 10 chemins = 590s | ~10 min | CRITIQUE |
| 2 | **Rate limiter** : 60 RPM = 1 req/s apres burst de 6 | ~94s pour 100 pages | MOYEN |
| 3 | **Crawl sequentiel par role** : les roles ne sont pas crawles en parallele | x N roles | MOYEN |
| 4 | **JS downloads sequentiels** dans le BFS (chaque JS = acquire + HTTP) | ~20s pour 20 fichiers | FAIBLE |
| 5 | **Auto-registration** : 10 paths x 4 templates, sequentiel | jusqu'a 400s | MOYEN (conditionnel) |

Le bottleneck #1 est le probleme dominant. La formule dans `observation/engine.py:52` :
```python
discovery_delay = max(0.0, 60.0 / rate_limiter.max_rate - 1.0)
# Avec 60 RPM default : 60.0 / 1.0 - 1.0 = 59 secondes entre chaque probe
```
Ce delai est aberrant : la decouverte OpenAPI utilise deja un httpx.AsyncClient avec timeout 5s. Le rate limiter global n'a pas besoin de proteger ces probes internes.

### B. Pipeline sequentiel

`HDWPEngine.run()` execute tout dans l'ordre strict :
```
seed_from_spec -> obs_engine.start() -> drain -> version_scan -> drain -> auto_registration -> drain -> exp_engine.run_pending() -> drain
```
Les experiments ne demarrent qu'apres la fin COMPLETE de l'observation + version scan + auto-registration.
Pendant ce temps, le pipeline reactif (model -> properties -> hypotheses) fonctionne mais ses sorties s'accumulent sans etre exploitees.

L'ExperimentEngine n'a pas d'API publique `run_single()`, mais `run_pending([single_hyp])` fonctionne car internalement chaque hypothese est traitee independamment via `_run_hypothesis()`.

### C. Lacunes UI (13 gaps identifies, 5 directement lies au probleme)

| # | Gap | Impact |
|---|-----|--------|
| 1 | **9/16 types d'evenements WS ignores** : hypothesis.generated, experiment.result, property.inferred, etc. | Aucune mise a jour temps reel sauf endpoints et findings |
| 2 | **Pipeline visualization statique** : StatusPanel affiche les 7 phases en dur sans indiquer la phase active | L'utilisateur ne voit pas quelle phase est en cours |
| 3 | **Compteur PROPRIETES hardcode a "---"** : ni StateResponse ni scanStore ne trackent le nombre de proprietes | Impossible de voir l'activite INFER |
| 4 | **error_message jamais affiche** : present dans StateResponse mais pas extrait par updateFromState() | L'utilisateur ne voit pas pourquoi un scan echoue |
| 5 | **Pas d'evenement bus "scan.done"** : la transition done depend du polling (jusqu'a 1.5s de latence) | Transition finale retardee |
| 6 | **proxy.started/proxy.failed sont du dead code** : ces types ne sont pas dans ALL_EVENT_TYPES | Le proxy status ne vient que du polling |
| 7 | **Findings: double ingestion sans deduplication** (WS addFinding + fetch replace) | Doublons ou perte de findings |
| 8 | **Experiment count et property count absents de StateResponse** | Pas de metriques de progression pour INFER/EXPERIMENT |

## Approche

### Phase 1 : Eliminer les bottlenecks critiques (Backend)

**1a. Supprimer le delai OpenAPI discovery**

**Fichier** : `src/hdwp/core/observation/engine.py:52`

La decouverte OpenAPI n'est pas du trafic de crawl -- ce sont des probes internes avec leur propre httpx client et timeout de 5s. Le rate limiter global ne devrait pas s'appliquer.

```python
# Avant :
discovery_delay = max(0.0, 60.0 / rate_limiter.max_rate - 1.0)

# Apres :
discovery_delay = min(1.0, max(0.0, 60.0 / rate_limiter.max_rate - 1.0))
```

Effet : 10 chemins x 1s = 10 secondes au lieu de 590 secondes. Chaque probe a deja un timeout de 5s en cas d'echec.

**1b. Ajouter property_count et experiment_count a StateResponse**

**Fichier** : `src/hdwp/server/models/state.py`

Ajouter `property_count: int = 0` et `experiment_count: int = 0` au modele StateResponse.

**Fichier** : `src/hdwp/server/routes/state_route.py`

Extraire depuis le moteur :
- `property_count` depuis `session.engine._prop_engine` (compter les proprietes inferees)
- `experiment_count` depuis `session.engine._exp_engine` (compter les resultats)

Il faut verifier que `_prop_engine` expose un compteur ou une liste accessible. Sinon, tracker le compte dans `ScanSession` via un handler bus sur `property.inferred`.

### Phase 2 : Mise a jour temps reel via WebSocket (Frontend)

**2a. Enrichir useWebSocket.ts avec les dispatches manquants**

**Fichier** : `src/hdwp/app/src/hooks/useWebSocket.ts`

Ajouter dans `ws.onmessage` :
```
hypothesis.generated  -> setPhase("HYPOTHESIZE") + incrementHypothesisCount()
property.inferred     -> setPhase("INFER") + incrementPropertyCount()
experiment.result     -> setPhase("EXPERIMENT") + incrementExperimentCount()
finding.confirmed     -> setPhase("FINDING") (deja addFinding)
```

**2b. Etendre scanStore avec les setters manquants**

**Fichier** : `src/hdwp/app/src/stores/scanStore.ts`

Ajouter :
- `propertyCount: number` + `incrementPropertyCount()`
- `experimentCount: number` + `incrementExperimentCount()`
- `incrementHypothesisCount()`
- `incrementFindingsCount()`
- `setPhase(phase: string)`
- `errorMessage: string` + extraction dans `updateFromState()`

Le polling (updateFromState) reste comme fallback et corrige les derives eventuelles entre les compteurs incrementaux WS et les valeurs reelles.

**2c. Rendre la pipeline visualization dynamique**

**Fichier** : `src/hdwp/app/src/components/StatusPanel.tsx`

Actuellement les 7 etapes de pipeline sont affichees statiquement. Modifier pour :
- Highlight la phase active (basee sur `scanStore.phase`)
- Griser les phases non atteintes
- Animer la phase en cours

Utiliser le mapping phase -> etape :
```
OBSERVE -> step 0, MODEL -> step 1, INFER -> step 2,
HYPOTHESIZE -> step 3, EXPERIMENT -> step 4, ORACLE -> step 5, FINDING -> step 6
```

**2d. Afficher error_message**

**Fichier** : `src/hdwp/app/src/stores/scanStore.ts`

Ajouter `errorMessage: string` au store et l'extraire dans `updateFromState()`.

**Fichier** : `src/hdwp/app/src/components/StatusPanel.tsx`

Afficher le message d'erreur quand `phase === 'ERROR'`.

**2e. Remplacer le compteur PROPRIETES hardcode**

**Fichier** : `src/hdwp/app/src/components/StatusPanel.tsx`

Remplacer la valeur `'---'` par `propertyCount` du scanStore (alimente par le WS + polling).

### Phase 3 : Streamer les experiments pendant l'observation (Backend)

**Fichier** : `src/hdwp/core/engine.py`

Transformer `run()` pour lancer les experiments incrementalement :

```python
async def run(self) -> list[Finding]:
    # ... Phase 1a : seed_from_spec (inchange) ...

    # Demarrer un consumer d'hypotheses en arriere-plan
    hyp_queue: asyncio.Queue[Hypothesis | None] = asyncio.Queue()

    async def _on_new_hypothesis(event: HDWPEvent) -> None:
        hyp = Hypothesis.model_validate(event.payload)
        if hyp.status == HypothesisStatus.PENDING:
            await hyp_queue.put(hyp)

    self._bus.on(HYPOTHESIS_GENERATED, _on_new_hypothesis)

    experiment_task = asyncio.create_task(
        self._consume_experiments(hyp_queue)
    )

    # Phase 1b : crawl (hypotheses arrivent via bus -> queue -> experiments)
    await self._obs_engine.start()
    await self._bus.drain()

    # ... version scan, auto-registration (inchange) ...

    # Signaler la fin et attendre les experiments restants
    await hyp_queue.put(None)  # sentinel
    await experiment_task
    await self._bus.drain()

    # ... findings, KB update (inchange) ...
```

Nouvelle methode `_consume_experiments()` :
```python
async def _consume_experiments(self, queue: asyncio.Queue) -> None:
    while True:
        hyp = await queue.get()
        if hyp is None:
            break
        await self._exp_engine.run_pending([hyp])
```

**Risque** : le corpus est incomplet pour les hypotheses generees tot. Attenuation : les hypotheses sont generees en reaction aux endpoints decouverts, donc le corpus contient deja les requetes necessaires pour ces endpoints specifiques. `RequestSelector` accede au corpus via `corpus_accessor` (bind a `app_model.get_all_corpus`) qui retourne l'etat courant du modele, pas un snapshot fige.

### Phase 4 : Correctifs secondaires

**4a. Emettre un evenement bus scan.done/scan.error**

**Fichier** : `src/hdwp/core/bus/events.py`

Ajouter `SCAN_COMPLETED = "scan.completed"` et `SCAN_ERROR = "scan.error"` a `ALL_EVENT_TYPES`.

**Fichier** : `src/hdwp/server/routes/scan.py`

Emettre ces evenements dans `_run()` quand le scan termine ou echoue. L'EventBridge les broadcastera automatiquement.

**Fichier** : `src/hdwp/app/src/hooks/useWebSocket.ts`

Handler `scan.completed` -> setStatus("done"), setPhase("DONE").
Handler `scan.error` -> setStatus("error"), setPhase("ERROR").

**4b. Supprimer le dead code proxy.started/proxy.failed**

**Fichier** : `src/hdwp/app/src/hooks/useWebSocket.ts`

Retirer les handlers pour `proxy.started` et `proxy.failed` (ces types n'existent pas dans ALL_EVENT_TYPES, ils ne sont jamais emis).

## Fichiers critiques

| Fichier | Phase | Modification |
|---------|-------|-------------|
| `src/hdwp/core/observation/engine.py` | 1a | Cap discovery_delay a 1s |
| `src/hdwp/server/models/state.py` | 1b | Ajouter property_count, experiment_count |
| `src/hdwp/server/routes/state_route.py` | 1b | Extraire les nouveaux compteurs |
| `src/hdwp/app/src/hooks/useWebSocket.ts` | 2a, 4a, 4b | Dispatches WS enrichis |
| `src/hdwp/app/src/stores/scanStore.ts` | 2b, 2d | Nouveaux champs et setters |
| `src/hdwp/app/src/components/StatusPanel.tsx` | 2c, 2d, 2e | Pipeline dynamique, erreur, proprietes |
| `src/hdwp/core/engine.py` | 3 | Streaming experiments |
| `src/hdwp/core/bus/events.py` | 4a | Nouveaux types scan.completed, scan.error |
| `src/hdwp/server/routes/scan.py` | 4a | Emettre scan.completed/scan.error |

## Fonctions existantes a reutiliser

- `EventBridge.attach()` -- broadcast deja tous les ALL_EVENT_TYPES, les nouveaux types seront automatiquement bridges
- `ExperimentEngine.run_pending([hyp])` -- fonctionne avec une liste d'un seul element
- `ApplicationModel.get_all_corpus()` -- bind comme corpus_accessor, retourne l'etat courant (pas un snapshot fige)
- `HypothesisEngine._on_property_inferred()` -- chaine reactif deja en place pendant le crawl
- `scanStore.updateFromState()` -- reste comme fallback de correction pour les compteurs incrementaux

## Ce qui est hors scope (a noter pour plus tard)

- Findings deduplication (GAP 5) -- risque de doublons mais impact faible
- auth.required banner never clears (GAP 11) -- UX mineure
- credentials.captured counter (GAP 12) -- informatif seulement
- finding.refuted store update (GAP 10) -- edge case rare
- Crawl parallele par role (bottleneck #3) -- amelioration future significative
- cancelled vs completed distinction (GAP 9) -- UX mineure

## Verification

1. **Timing** : lancer un scan, verifier dans les logs que la decouverte OpenAPI complete en <15s
2. **Metriques WS** : ouvrir le scan tab, verifier que endpointCount, hypothesisCount, propertyCount changent pendant le crawl (pas seulement a la fin)
3. **Pipeline dynamique** : verifier que StatusPanel highlight la phase active et progresse visuellement
4. **Experiments streaming** : verifier que des experiment.result apparaissent AVANT la fin du crawl
5. **Error display** : forcer une erreur (URL invalide) et verifier que le message s'affiche
6. **Tests** : `pytest tests/ -k "not integration" --tb=short` -- tous les tests doivent passer
7. **Build frontend** : `cd src/hdwp/app && npm run build` sans erreurs TypeScript
8. **Scan complet** : verifier la transition scan.completed instant (pas 1.5s de latence)
