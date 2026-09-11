# Skill : HDWP — Creer un plugin externe

## Quand utiliser ce skill
Invoquer avec `/hdwp-plugin` quand l'utilisateur demande de creer un nouveau plugin HDWP. Le plugin est genere dans `~/.hdwp/plugins/` (externe au code source) et immediatement importable par le PluginRegistry.

---

## Ce que tu dois faire

Tu crees un plugin conforme a `hdwp.plugins.base.HDWPPlugin` et tu le places dans le repertoire utilisateur pour import automatique.

### Etape 1 — Recueillir les informations

Si non fournies par l'utilisateur, demander via AskUserQuestion :
- **Nom du plugin** : identifiant unique (ex: `custom.injection.graphql_deep`)
- **Categorie** : `injection` | `authorization` | `configuration` | `information_flow` | `session_property` | `business_invariant` | `temporal` | `file_operations` | `state_transition` | `concurrency`
- **Type de vuln ciblee** : ex: sqli, xss, bola, ssrf, jwt...
- **OWASP mapping** : ex: A03:2021
- **CWE mapping** : ex: CWE-89
- **Tech stack requise** (optionnel) : ex: `{'framework:spring'}` — vide = universel

### Etape 2 — Generer le plugin

Creer le dossier et fichier :
```
~/.hdwp/plugins/<plugin_slug>/hdwp_plugin.py
```

Le fichier DOIT respecter cette structure exacte :

```python
from __future__ import annotations

from hdwp.plugins.base import HDWPPlugin
from hdwp.core.model.schemas import (
    ApplicationModelData,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
    PropertyType,
    SecurityProperty,
    generate_id,
)


class MyPlugin(HDWPPlugin):

    @property
    def id(self) -> str:
        return "<PLUGIN_ID>"  # ex: custom.injection.graphql_deep

    @property
    def name(self) -> str:
        return "<NOM_LISIBLE>"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "<CATEGORIE>"

    @property
    def description(self) -> str:
        return "<DESCRIPTION>"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["<OWASP>"]  # ex: ["A03:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["<CWE>"]  # ex: ["CWE-89"]

    def tech_stack_required(self) -> set[str]:
        return set()  # ou {"framework:django"} etc.

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        """Infere des proprietes de securite depuis le modele applicatif."""
        properties = []
        # Filtrer les parametres/endpoints pertinents dans model
        # Creer des SecurityProperty avec PropertyType.INTEGRITY / CONFIDENTIALITY / AVAILABILITY
        return properties

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        """Genere des hypotheses a tester pour la vuln ciblee."""
        hypotheses = []
        # Pour chaque parametre/endpoint candidat :
        #   - Construire des ExperimentSpec avec mutation_type, payloads, etc.
        #   - Creer une Hypothesis avec required_experiments
        return hypotheses


# OBLIGATOIRE — le registry cherche cette variable
PLUGIN_CLASS = MyPlugin
```

### Regles

- `PLUGIN_CLASS` en variable module-level est **obligatoire** — sans ca le registry ignore le fichier
- L'id doit commencer par `custom.` pour eviter les collisions avec les builtins
- Si le plugin accepte `payload_db` en `__init__`, le registry l'injecte automatiquement
- `infer_properties()` et `generate_hypotheses()` sont les 2 methodes abstraites obligatoires
- `register_mutations()` est optionnel — retourner une liste de dicts pour ajouter des mutations custom

### Etape 3 — Valider

```bash
.venv/bin/python -c "
from hdwp.plugins.registry import PluginRegistry
r = PluginRegistry()
r.discover()
p = r.get('<PLUGIN_ID>')
print(f'OK: {p.name} v{p.version}' if p else 'ERREUR: plugin non trouve')
"
```

### Etape 4 — Informer l'utilisateur

Afficher :
- Chemin du fichier cree
- Commande de validation
- Comment desactiver : `~/.hdwp/plugins_config.json` → retirer l'id de la liste `enabled`
- Rappel : le plugin est charge automatiquement au prochain demarrage HDWP
