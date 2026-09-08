# HDWP Engine — Guide d'authoring de plugins

**Version :** 0.1.0  
**Auteur :** M. TENDENG

---

## 1. Rôle d'un plugin

Un plugin HDWP contribue au raisonnement du moteur de deux façons :

1. **Inférence de propriétés** : depuis le modèle applicatif, produire des `SecurityProperty` que les règles built-in n'ont pas détectées.
2. **Génération d'hypothèses** : depuis le modèle applicatif, produire des `Hypothesis` avec des `ExperimentSpec` concrètes.

Un plugin ne peut pas :
- Émettre des requêtes réseau directement (interdiction absolue — toutes les requêtes passent par l'ExperimentEngine)
- Écrire dans le modèle applicatif (accès lecture seule)
- Statuer sur une hypothèse (réservé au SemanticOracle)
- Dépasser 5 secondes dans `infer_properties()` ou `generate_hypotheses()`

---

## 2. Contrat du plugin

Chaque plugin hérite de `HDWPPlugin` (`src/hdwp/plugins/base.py`) :

```python
from hdwp.plugins.base import HDWPPlugin
from hdwp.core.model.schemas import ApplicationModelData, SecurityProperty, Hypothesis

class MonPlugin(HDWPPlugin):
    # --- Métadonnées obligatoires ---

    @property
    def id(self) -> str:
        # Identifiant unique : "<scope>.<category>.<nom>"
        # ex: "community.authorization.my_bola_variant"
        return "community.authorization.my_bola_variant"

    @property
    def name(self) -> str:
        return "Mon plugin BOLA personnalisé"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        # Voir Section 3 pour les catégories valides
        return "authorization"

    # --- Métadonnées optionnelles ---

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A01:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-639"]

    # --- Cycle de vie ---

    async def on_load(self) -> None:
        # Appelé au chargement du plugin (initialisation optionnelle)
        pass

    async def on_model_ready(self, model: ApplicationModelData) -> None:
        # Appelé quand le modèle est prêt pour la première fois
        pass

    async def on_unload(self) -> None:
        pass

    # --- Logique principale ---

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        # Analyser le modèle, retourner des propriétés de sécurité
        # Doit retourner en moins de 5 secondes
        ...

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        # Générer des hypothèses falsifiables avec ExperimentSpec
        # Doit retourner en moins de 5 secondes
        ...
```

---

## 3. Catégories de plugins

Les plugins sont classés par **type de propriété de sécurité**, pas par nom de vulnérabilité.

| Catégorie | Types de propriétés ciblés | Exemples |
|---|---|---|
| `authorization` | AUTHORIZATION, CONFIDENTIALITY | BOLA, IDOR, AuthZ bypass, escalade de privilèges |
| `state_transition` | STATE | Bypass d'étapes de workflow, skip de validation |
| `information_flow` | CONFIDENTIALITY | SSRF, information disclosure dans les réponses |
| `business_invariant` | INTEGRITY, COHERENCE | Conditions de course, double-spend |
| `injection` | INTEGRITY | SQLi, XSS, SSTI, injection de templates |
| `configuration` | COHERENCE | CORS permissif, headers de sécurité manquants |
| `session_property` | TEMPORAL | JWT faible, non-invalidation post-logout |

---

## 4. Exemple complet

Plugin qui détecte une information disclosure dans les headers de réponse (ex : `X-Powered-By` révèle la version du framework).

```python
# Copyright (c) 2026 M. TENDENG  # ou votre nom
# Licensed under the MIT License.

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


DISCLOSURE_HEADERS = frozenset({
    "x-powered-by",
    "server",
    "x-aspnet-version",
    "x-aspnetmvc-version",
})


class HeaderDisclosurePlugin(HDWPPlugin):
    @property
    def id(self) -> str:
        return "community.information_flow.header_disclosure"

    @property
    def name(self) -> str:
        return "Header Information Disclosure"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "information_flow"

    @property
    def owasp_mapping(self) -> list[str]:
        return ["A05:2021"]

    @property
    def cwe_mapping(self) -> list[str]:
        return ["CWE-200"]

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        properties = []
        # Chercher des endpoints dont les observations ont des tags "server:..."
        disclosed_servers: set[str] = set()
        for ep in model.endpoints:
            for tag in []:  # les tags sont dans les observations, pas les endpoints
                # Note : les tags sont dans RawObservation.tags
                # Le modèle n'expose pas directement les tags par endpoint
                # Un plugin plus avancé lirait les observations depuis le corpus
                pass

        # Exemple simplifié : infère la propriété si des endpoints sont présents
        if model.endpoints:
            properties.append(
                SecurityProperty(
                    id=generate_id("PROP"),
                    type=PropertyType.CONFIDENTIALITY,
                    formal_statement=(
                        "Les réponses HTTP ne doivent pas révéler "
                        "d'informations sur l'infrastructure technique."
                    ),
                    model_nodes=[ep.id for ep in model.endpoints[:3]],
                    inference_confidence=0.6,
                    source_observations=[],
                )
            )
        return properties

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        hypotheses = []
        for ep in model.endpoints:
            hypotheses.append(
                Hypothesis(
                    source_plugin=self.id,
                    property_id="",  # lié dynamiquement par l'HypothesisEngine
                    statement=(
                        f"L'endpoint '{ep.path}' révèle des informations "
                        "d'infrastructure dans ses headers de réponse."
                    ),
                    priority="LOW",
                    priority_rationale="Information disclosure sans impact direct sur l'accès",
                    required_experiments=[
                        ExperimentSpec(
                            mutation_type="identity_swap",
                            base_request=NormalizedRequest(
                                method=ep.methods[0] if ep.methods else "GET",
                                url="",  # résolu par RequestSelector depuis le corpus
                            ),
                            mutation_params={
                                "check_headers": list(DISCLOSURE_HEADERS),
                                "endpoint_path": ep.path,
                            },
                            description=f"Vérifier les headers révélateurs sur {ep.path}",
                        )
                    ],
                )
            )
        return hypotheses
```

---

## 5. Packaging

### 5.1 Structure du package

```
mon-plugin-hdwp/
├── src/
│   └── hdwp_header_disclosure/
│       ├── __init__.py
│       └── plugin.py          # contient HeaderDisclosurePlugin
├── tests/
│   └── test_plugin.py
└── pyproject.toml
```

### 5.2 `pyproject.toml`

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "hdwp-header-disclosure"
version = "1.0.0"
requires-python = ">=3.12"
dependencies = ["hdwp>=0.1.0"]

[project.entry-points."hdwp.plugins"]
"community.information_flow.header_disclosure" = "hdwp_header_disclosure.plugin:HeaderDisclosurePlugin"
```

La clé de l'entry point doit correspondre exactement à la valeur retournée par `plugin.id`.

### 5.3 Installation

```bash
# Développement local
pip install -e ./mon-plugin-hdwp

# Depuis PyPI
pip install hdwp-header-disclosure

# Vérification
hdwp plugin list
```

---

## 6. Activation dans le contexte

Dans `hdwp-context.yaml` :

```yaml
plugins:
  enabled:
    - "community.information_flow.header_disclosure"
  config:
    "community.information_flow.header_disclosure":
      # paramètres spécifiques au plugin (optionnel)
```

---

## 7. Tests d'un plugin

Un plugin doit être testable en isolation, sans infrastructure :

```python
# tests/test_plugin.py

from hdwp.core.model.schemas import (
    ApplicationModelData, EndpointNode, ParameterNode, RoleNode
)
from hdwp_header_disclosure.plugin import HeaderDisclosurePlugin


def make_model_with_endpoints():
    ep = EndpointNode(path="/api/users", methods=["GET"])
    return ApplicationModelData(endpoints=[ep], roles=[], parameters=[], objects=[])


def test_generates_hypotheses():
    plugin = HeaderDisclosurePlugin()
    model = make_model_with_endpoints()
    hypotheses = plugin.generate_hypotheses(model)
    assert len(hypotheses) == 1
    assert hypotheses[0].source_plugin == plugin.id


def test_no_hypotheses_empty_model():
    plugin = HeaderDisclosurePlugin()
    model = ApplicationModelData()
    assert plugin.generate_hypotheses(model) == []
```
