# Plan : Apprentissage adaptatif complet pour le moteur HDWP

**Statut : IMPLÉMENTÉ** — 2026-09-03

## Contexte

L'audit du moteur révèle un apprentissage **partiel** : seule `KnowledgeBase.get_adapted_weights()` adapte réellement les poids du `HypothesisPrioritizer`. Tout le reste est hardcodé ou inerte. L'apprentissage est aussi **global** (cross-targets sans discrimination). Ce plan corrige les deux problèmes.

**État actuel :**

| Couche | Portée | Problème |
|--------|--------|----------|
| `ApplicationModel.model_confidence` | Session uniquement | Poids `0.4/0.4/0.2` hardcodés (L420-437 `application_model.py`) |
| `KnowledgeBase.PatternStatsRecord` | Cross-sessions + cross-targets | Clé = `(property_type, mutation_type)` — pas de distinction par type de cible |
| `SessionMetaRecord.target_hash` | Stocké, jamais utilisé | SHA-256 présent mais inerte (L21 `models.py`) |
| `AuthorizationInference._infer_bola` | Hardcodé | Confiance 0.5/0.8 fixe (L36 `authorization.py`) |
| `SecurityPropertyEngine` | Hardcodé | Aucun stats KB injectées — modules créés sans paramètres |

---

## Étape 1 — Enrichir les modèles de données

**Fichier :** `src/hdwp/core/knowledge/models.py`

### 1a. `SessionMetaRecord` — 4 nouveaux champs

```python
class SessionMetaRecord(SQLModel, table=True):
    __tablename__ = "session_meta"
    session_id: str = Field(primary_key=True)
    target_hash: str = ""
    findings_count: int = 0
    ended_at: str = ""
    endpoint_count: int = 0        # NOUVEAU
    role_count: int = 0            # NOUVEAU
    bola_param_count: int = 0      # NOUVEAU
    target_type: str = ""          # NOUVEAU : "api", "cms", "spa", "graphql", "unknown"
```

### 1b. `PatternStatsRecord` — ajouter `target_type` à la PK

```python
class PatternStatsRecord(SQLModel, table=True):
    __tablename__ = "pattern_stats"
    property_type: str = Field(primary_key=True)
    mutation_type: str = Field(primary_key=True)
    target_type: str = Field(default="unknown", primary_key=True)  # NOUVEAU
    ...
```

**Problème SQLite :** ALTER TABLE ne peut pas modifier une PK. Solution : migration par recréation de table (voir Étape 2).

**Convention `target_type` :** valeurs possibles = `"api"`, `"cms"`, `"spa"`, `"graphql"`, `"unknown"`. La valeur `"unknown"` est le défaut universel — y compris pour les anciens records migrés. Pas de `""` vide : la migration mappe `""` → `"unknown"` pour éviter la fragmentation.

---

## Étape 2 — Migration backward-compatible de la KB

**Fichier :** `src/hdwp/core/knowledge/base.py`

Ajouter `_migrate_schema()` appelé dans `_get_engine()` après `create_all` :

```python
async def _migrate_schema(self, engine: AsyncEngine) -> None:
    """Ajoute les colonnes manquantes et migre la PK de pattern_stats si nécessaire."""
    from sqlalchemy import text
    async with engine.begin() as conn:
        # session_meta : simples ADD COLUMN (pas de changement PK)
        for col, col_type in [
            ("endpoint_count", "INTEGER DEFAULT 0"),
            ("role_count", "INTEGER DEFAULT 0"),
            ("bola_param_count", "INTEGER DEFAULT 0"),
            ("target_type", "TEXT DEFAULT ''"),
        ]:
            try:
                await conn.execute(text(f"ALTER TABLE session_meta ADD COLUMN {col} {col_type}"))
            except Exception:
                pass  # colonne existe déjà

        # pattern_stats : migration PK 2→3 colonnes
        # Vérifier si target_type existe déjà dans pattern_stats
        try:
            await conn.execute(text("SELECT target_type FROM pattern_stats LIMIT 1"))
        except Exception:
            # Migration nécessaire : recréer la table avec la nouvelle PK
            try:
                await conn.execute(text("""
                    CREATE TABLE pattern_stats_new (
                        property_type TEXT NOT NULL,
                        mutation_type TEXT NOT NULL,
                        target_type TEXT NOT NULL DEFAULT '',
                        confirmed_count INTEGER DEFAULT 0,
                        refuted_count INTEGER DEFAULT 0,
                        total_count INTEGER DEFAULT 0,
                        avg_confidence REAL DEFAULT 0.0,
                        last_updated TEXT DEFAULT '',
                        PRIMARY KEY (property_type, mutation_type, target_type)
                    )
                """))
                await conn.execute(text("""
                    INSERT INTO pattern_stats_new 
                        (property_type, mutation_type, target_type, confirmed_count, 
                         refuted_count, total_count, avg_confidence, last_updated)
                    SELECT property_type, mutation_type, 'unknown', confirmed_count, 
                           refuted_count, total_count, avg_confidence, last_updated
                    FROM pattern_stats
                """))
                await conn.execute(text("DROP TABLE pattern_stats"))
                await conn.execute(text("ALTER TABLE pattern_stats_new RENAME TO pattern_stats"))
            except Exception:
                pass  # table n'existe pas encore (première exécution) → create_all la créera
```

**Idempotent et safe :** fonctionne sur nouvelle DB (create_all) ET sur ancienne DB (migration).

---

## Étape 3 — Classification de cible + `record_session()` enrichi

**Fichier :** `src/hdwp/core/knowledge/base.py`

### 3a. `classify_target()` (fonction publique)

```python
def classify_target(target_url: str, model_snapshot: ApplicationModelData | None = None) -> str:
    url = target_url.lower()
    # Classification par URL (disponible au démarrage)
    if "/graphql" in url:
        return "graphql"
    if any(seg in url for seg in ("/api/", "/v1/", "/v2/", "/v3/", "/rest/")):
        return "api"
    if not model_snapshot:
        return "unknown"
    # Classification enrichie par le modèle (disponible en fin de scan)
    paths = [ep.path.lower() for ep in model_snapshot.endpoints]
    if any("wp-" in p or "/admin/" in p or "/cms/" in p for p in paths):
        return "cms"
    json_count = sum(1 for ep in model_snapshot.endpoints if "api" in ep.path.lower())
    if json_count > len(paths) * 0.5:
        return "spa"
    return "unknown"
```

**Deux phases de classification :**
- **Au démarrage** (`_init_components`) : URL-only → `classify_target(url, None)` → pour `get_adapted_weights(target_type=...)`
- **En fin de scan** (`record_session()`) : URL + modèle → classification plus fiable stockée en DB

### 3b. `record_session()` — nouveau paramètre `model_snapshot`

Signature :
```python
async def record_session(
    self, findings, session_id, target_url,
    model_snapshot: ApplicationModelData | None = None,  # NOUVEAU, backward-compat
) -> None:
```

Dans le corps, lors de l'upsert de `SessionMetaRecord` :
```python
target_type = classify_target(target_url, model_snapshot)
endpoint_count = len(model_snapshot.endpoints) if model_snapshot else 0
role_count = len(model_snapshot.roles) if model_snapshot else 0
bola_param_count = sum(1 for p in model_snapshot.parameters if p.affects_object) if model_snapshot else 0
```

**CRITIQUE — `PatternStatsRecord` SELECT/INSERT avec 3 colonnes PK :**

Le SELECT dans `record_session()` (actuellement L85-89) DOIT inclure `target_type` dans le WHERE :
```python
result = await session.exec(
    select(PatternStatsRecord).where(
        PatternStatsRecord.property_type == property_type,
        PatternStatsRecord.mutation_type == mutation_type,
        PatternStatsRecord.target_type == target_type,  # OBLIGATOIRE
    )
)
```
Sans cette 3ème condition, `.first()` retourne un record arbitraire parmi les target_types possibles → corruption des stats du mauvais type de cible.

Pour les INSERT de nouveaux records :
```python
record = PatternStatsRecord(
    property_type=property_type,
    mutation_type=mutation_type,
    target_type=target_type,
)
```

### 3c. Appel dans `engine.py:run()`

Modifier L352-358 :
```python
await self._kb.record_session(
    findings=findings,
    session_id=self._context.session_id,
    target_url=self._context.base_url,
    model_snapshot=self._app_model.snapshot(),  # NOUVEAU
)
```

---

## Étape 4 — `get_adapted_weights()` avec conscience du type de cible

**Fichier :** `src/hdwp/core/knowledge/base.py`

Ajouter paramètre optionnel :
```python
async def get_adapted_weights(self, target_type: str | None = None) -> dict[str, float]:
```

Logique :
1. Si `target_type` fourni → SELECT WHERE `target_type = ?` 
2. Si aucun record pour ce type OU < 3 total → fallback sur tous les records (comportement actuel)
3. Agrégation et formule inchangées

Dans `_init_components` (L159) :
```python
url_target_type = classify_target(context.base_url)
adapted_weights = await kb.get_adapted_weights(target_type=url_target_type)
```

---

## Étape 5 — `model_confidence` adaptatif

**Fichier :** `src/hdwp/core/model/application_model.py`

### 5a. Nouveau champ + setter

```python
def __init__(self, bus: AsyncEventBus) -> None:
    ...
    self._confidence_weights: dict[str, float] = {"ep": 0.4, "role": 0.4, "bola": 0.2}

def set_confidence_weights(self, weights: dict[str, float]) -> None:
    self._confidence_weights = weights
```

### 5b. `model_confidence` utilise les poids injectés

```python
@property
def model_confidence(self) -> float:
    ...
    w = self._confidence_weights
    total = w["ep"] + w["role"] + w["bola"]
    if total == 0:
        total = 1.0
    return (w["ep"] * ep_cov + w["role"] * role_cov + w["bola"] * bola_cov) / total
```

### 5c. `get_confidence_weights()` dans KnowledgeBase

**Fichier :** `src/hdwp/core/knowledge/base.py`

Utilise des agrégations SQL (pas de chargement en mémoire) :
```python
async def get_confidence_weights(self) -> dict[str, float]:
    engine = await self._get_engine()
    async with AsyncSession(engine) as session:
        result = await session.execute(text("""
            SELECT 
                COUNT(*) as n,
                AVG(CASE WHEN endpoint_count > 0 
                    THEN CAST(findings_count AS REAL) / endpoint_count ELSE NULL END) as ep_ratio,
                AVG(CASE WHEN role_count > 0 
                    THEN CAST(findings_count AS REAL) / role_count ELSE NULL END) as role_ratio,
                AVG(CASE WHEN bola_param_count > 0 
                    THEN CAST(findings_count AS REAL) / bola_param_count ELSE NULL END) as bola_ratio
            FROM session_meta
            WHERE findings_count > 0 AND endpoint_count > 0
        """))
        row = result.one()
    
    if row.n < 5:
        return {"ep": 0.4, "role": 0.4, "bola": 0.2}
    
    ep = row.ep_ratio or 0
    role = row.role_ratio or 0
    bola = row.bola_ratio or 0
    total = ep + role + bola
    if total == 0:
        return {"ep": 0.4, "role": 0.4, "bola": 0.2}
    
    raw = {"ep": ep / total, "role": role / total, "bola": bola / total}
    return {k: round(max(0.1, min(0.7, v)), 4) for k, v in raw.items()}
```

### 5d. Injection dans `_init_components`

Après la création de `app_model` (L138) et du KB :
```python
confidence_weights = await kb.get_confidence_weights()
app_model.set_confidence_weights(confidence_weights)
```

---

## Étape 6 — BOLA inference avec confiance adaptative

### 6a. `AuthorizationInference` — accepter `kb_stats`

**Fichier :** `src/hdwp/core/property_engine/inference/authorization.py`

```python
class AuthorizationInference:
    def __init__(self, kb_stats: dict[tuple[str, str], dict[str, float]] | None = None):
        self._kb_stats = kb_stats or {}
```

Dans `_infer_bola`, remplacer L36 :
```python
base_confidence = 0.8 if len(model.roles) >= 2 else 0.5
bola_stats = self._kb_stats.get(("authorization", "object_ref_change"), {})
if bola_stats.get("total", 0) >= 3:
    historical_rate = bola_stats.get("confirmed_rate", 0.5)
    confidence = 0.3 * base_confidence + 0.7 * historical_rate
    confidence = max(0.3, min(0.95, confidence))
else:
    confidence = base_confidence
```

### 6b. `InferenceRegistry.default_with_kb_stats()`

**Fichier :** `src/hdwp/core/property_engine/inference_registry.py`

Ajouter un classmethod qui passe `kb_stats` aux modules qui l'acceptent :
```python
@classmethod
def default_with_kb_stats(cls, kb_stats: dict) -> InferenceRegistry:
    reg = cls()
    for name, module_cls in _BUILTIN_MODULES:
        try:
            mod = module_cls(kb_stats=kb_stats)
        except TypeError:
            mod = module_cls()  # Module n'accepte pas kb_stats
        reg.register(name, mod)
    reg.discover()  # plugins tiers : sans kb_stats (backward-compat)
    return reg
```

**Nécessite de refactorer `_BUILTIN_MODULES`** : extraire la liste des modules depuis le corps de `default()` vers une constante de module pour la réutiliser dans `default_with_kb_stats()`.

### 6c. Propagation dans `_init_components`

**Fichier :** `src/hdwp/core/engine.py`

Après le chargement KB (L159), construire `kb_stats` depuis `kb.get_stats()` :
```python
raw_stats = await kb.get_stats()
kb_stats: dict[tuple[str, str], dict[str, float]] = {}
for s in raw_stats:
    key = (s["property_type"], s["mutation_type"])
    kb_stats[key] = {"confirmed_rate": s["confirmed_rate"], "total": s["total"]}

# Utiliser le registry avec stats KB injectées
from hdwp.core.property_engine.inference_registry import InferenceRegistry
inference_reg = InferenceRegistry.default_with_kb_stats(kb_stats)
SecurityPropertyEngine(bus, plugin_registry=registry, inference_registry=inference_reg)
```

Le paramètre `inference_registry` de `SecurityPropertyEngine.__init__` existe déjà (L32) — aucun changement nécessaire dans ce constructeur.

---

## Étape 6bis — Imports et `get_stats()` mis à jour

**Fichier :** `src/hdwp/core/knowledge/base.py`

**Import manquant :** Ajouter `from sqlalchemy import text` en tête de fichier (utilisé par `_migrate_schema()` et `get_confidence_weights()`).

**`get_stats()` — inclure `target_type` dans la sortie :**
```python
return [
    {
        "property_type": r.property_type,
        "mutation_type": r.mutation_type,
        "target_type": r.target_type,  # NOUVEAU
        ...
    }
    for r in records
]
```

Sans ce champ, le frontend affichera des doublons (même property_type + mutation_type mais target_types différents) sans moyen de les distinguer.

**Frontend `KBPattern` interface** (`SettingsTab.tsx`) — ajouter `target_type: string` :
```typescript
interface KBPattern {
    property_type: string;
    mutation_type: string;
    target_type: string;  // NOUVEAU
    confirmed: number;
    total: number;
    avg_confidence: number;
}
```

---

## Étape 7 — API `/knowledge/learning-health`

**Fichier :** `src/hdwp/server/routes/knowledge.py`

```python
@router.get("/knowledge/learning-health")
async def get_learning_health(request: Request) -> dict:
    kb = request.app.state.knowledge_base
    patterns = await kb.get_stats()
    confidence_weights = await kb.get_confidence_weights()
    adapted_weights = await kb.get_adapted_weights()
    
    from hdwp.core.knowledge.base import BASE_WEIGHTS
    divergences = {}
    for key, base in BASE_WEIGHTS.items():
        adapted = adapted_weights.get(key, base)
        div_pct = abs(adapted - base) / base * 100
        divergences[key] = {
            "base": base, "adapted": round(adapted, 4),
            "divergence_pct": round(div_pct, 1), "is_adapted": div_pct > 10,
        }
    
    return {
        "confidence_weights": confidence_weights,
        "adapted_weights": adapted_weights,
        "divergences": divergences,
        "patterns": patterns,
    }
```

---

## Étape 8 — Frontend : section "Santé de l'apprentissage"

**Fichier :** `src/hdwp/app/src/components/SettingsTab.tsx`

Dans `KnowledgeSettings` (après les stats existantes) :

1. Fetch `GET /api/knowledge/learning-health` au mount
2. Section "QUALITÉ DE L'APPRENTISSAGE" :
   - 3 barres pour `confidence_weights` : ep/role/bola (label + pourcentage)
   - Pour chaque pattern : barre `confirmed_rate` colorée (vert > 60%, jaune 30-60%, rouge < 30%)
   - Pour chaque divergence : badge "ADAPTÉ" si `is_adapted` avec `base → adapted`
   - Message "5 sessions minimum pour adaptation" si < 5 sessions

---

## Risques et mitigations

| Risque | Impact | Mitigation |
|--------|--------|------------|
| Migration PK SQLite échoue | Perte de stats historiques | `try/except` autour de la migration ; si échec, `create_all` recrée la table vide |
| Classification URL-only incorrecte au démarrage | Poids sous-optimaux pour la 1ère session | Fallback sur global si < 3 sessions pour le `target_type` détecté |
| `get_confidence_weights()` avec < 5 sessions | Division instable | Retourne les défauts `0.4/0.4/0.2` |
| Plugins tiers sans `kb_stats` | TypeError au constructeur | `try/except TypeError` dans `default_with_kb_stats()` |
| Concurrence : 2 sessions démarrent simultanément | Double migration | Migration idempotente (SELECT pour vérifier, try/except pour chaque ALTER) |
| `record_session()` oublie `target_type` dans WHERE | Corruption stats cross-target | Marqué CRITIQUE dans le plan — 3 colonnes PK = 3 colonnes WHERE obligatoires |
| `get_stats()` sans `target_type` | Doublons confus dans le frontend | `target_type` ajouté à la sortie + interface `KBPattern` mise à jour |

---

## Ce qui reste hardcodé (accepté)

- **Formule de priorité** (`impact * surface * obs_factor`) — structure, pas paramètres
- **Seuils `affects_object`** (numérique/UUID) — convention REST
- **Règles CORS/JWT/SSRF** — fondées sur RFC/OWASP
- **`is_ready` threshold** (0.3) — seuil minimal de couverture
- **Confiance `_infer_endpoint_auth`** (0.7) et `_infer_role_separation` (0.75) — pas assez de données historiques pour adapter ces sous-cas

---

## Ordre d'exécution

| # | Quoi | Fichiers |
|---|------|----------|
| 1 | Modèles de données + migration schema | `knowledge/models.py`, `knowledge/base.py` |
| 2 | `classify_target()` + `record_session()` enrichi | `knowledge/base.py`, `engine.py` |
| 3 | `get_adapted_weights(target_type=)` per-target | `knowledge/base.py`, `engine.py` |
| 4 | `get_confidence_weights()` + injection `ApplicationModel` | `knowledge/base.py`, `application_model.py`, `engine.py` |
| 5 | BOLA adaptatif + propagation via registry | `authorization.py`, `inference_registry.py`, `engine.py` |
| 6 | API `/knowledge/learning-health` | `server/routes/knowledge.py` |
| 7 | Frontend section apprentissage | `SettingsTab.tsx` |
| 8 | Tests | `tests/unit/test_knowledge_base.py` |

---

## Vérification

1. **Migration :** supprimer `~/.hdwp/knowledge.db`, relancer → pas d'erreur. Garder une ancienne KB → colonnes ajoutées, PK migrée, données conservées.
2. **Unitaire :** `test_knowledge_base.py` — tests pour `get_confidence_weights()`, `get_adapted_weights(target_type="api")`, `classify_target()`, `_migrate_schema()`.
3. **Intégration :** Après 5+ sessions mockées → `model_confidence` utilise poids KB ≠ 0.4/0.4/0.2.
4. **BOLA adaptatif :** 3+ findings BOLA → confiance `_infer_bola` > 0.8.
5. **Frontend :** Settings → Knowledge → barres de progression et badges visibles.
6. **Backward compat :** `record_session()` sans `model_snapshot` → fonctionne (défaut None).
