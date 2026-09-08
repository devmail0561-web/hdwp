# HDWP Engine — Guide de démarrage

**Version :** 0.1.0  
**Auteur :** M. TENDENG

---

## Prérequis

- Python 3.12 ou supérieur
- Linux (testé sur Ubuntu/Debian)
- Git

---

## 1. Installation

```bash
# Cloner le dépôt
git clone <url-du-depot>
cd project_hdwp

# Créer l'environnement virtuel
python3.12 -m venv .venv
source .venv/bin/activate

# Installer en mode développement avec les dépendances de test
pip install -e ".[dev]"

# Vérifier l'installation
hdwp --help
```

Sortie attendue :
```
Usage: hdwp [OPTIONS] COMMAND [ARGS]...

 HDWP Engine -- Hypothesis-Driven Web Pentesting Engine

Commands:
  run      Run the HDWP engine against a target.
  model    Export the application model.
  report   Generate a report from a session.
  replay   Replay an experiment.
  plugin   Manage plugins.
```

---

## 2. Configuration

Copier l'exemple de contexte et l'adapter :

```bash
cp hdwp-context.example.yaml hdwp-context.yaml
```

Structure minimale :

```yaml
target:
  base_url: "https://target.example.com"
  name: "Application cible"

scope:
  include:
    - "https://target.example.com/*"
  exclude:
    - "https://target.example.com/logout"

roles:
  - name: "anonymous"
    credentials: null
  - name: "user_a"
    credentials:
      type: "bearer"
      token: "${USER_A_TOKEN}"   # chargé depuis la variable d'environnement

options:
  allow_write: false             # bloque POST/PUT/PATCH/DELETE par défaut
  max_requests_per_minute: 60

plugins:
  enabled:
    - "core.authorization.bola"
    - "core.authorization.authz"
```

### Credentials

Les tokens ne sont jamais écrits en clair dans le fichier de contexte. Utiliser la syntaxe `${NOM_VAR}` :

```bash
export USER_A_TOKEN="votre-token-ici"
export USER_B_TOKEN="token-utilisateur-b"
hdwp run --context hdwp-context.yaml
```

### Types de credentials supportés

| Type | Champs | Header généré |
|---|---|---|
| `bearer` | `token` | `Authorization: Bearer <token>` |
| `basic` | `username`, `password` | `Authorization: Basic <base64>` |
| `api_key` | `token` (ou `header_name` + `header_value`) | `X-Api-Key: <token>` |
| `cookie` | `token` | `Cookie: <token>` |

---

## 3. Vérifier la configuration

Avant de lancer une analyse, vérifier que le scope est correct avec une inspection du modèle seul :

```bash
hdwp model --context hdwp-context.yaml --export model.json
```

Cette commande crawle la cible et exporte le modèle comportemental inféré. Inspecter `model.json` pour vérifier que les endpoints, paramètres et rôles sont correctement détectés.

---

## 4. Lancer une analyse

```bash
hdwp run --context hdwp-context.yaml
```

### Options disponibles

```bash
# Mode passif uniquement (sans exécution d'expériences actives)
hdwp run --context hdwp-context.yaml --passive-only

# Tester une seule hypothèse
hdwp run --context hdwp-context.yaml --hypothesis HYP-a1b2c3d4
```

### État d'implémentation actuel

| Fonctionnalité | Statut |
|---|---|
| Crawl actif multi-rôle | Disponible |
| Construction du modèle applicatif | Disponible |
| Inférence de propriétés (7 types) | Disponible |
| Génération d'hypothèses | Disponible |
| Exécution d'expériences (ExperimentEngine) | Disponible |
| Oracle sémantique (findings) | Disponible |
| Apprentissage adaptatif inter-sessions | Disponible |
| Rapports (Markdown, JSON, HAR) | Disponible |
| LLM (désambiguïsation, hypothèses) | Disponible |
| Mode proxy MITM intégré | Disponible |
| Version scanning (CVE via OSV.dev) | Disponible |

---

## 5. Gérer les plugins

```bash
# Lister les plugins disponibles
hdwp plugin list

# Activer un plugin
hdwp plugin enable core.authorization.bola

# Installer un plugin externe
hdwp plugin install ./mon-plugin-hdwp
```

Les plugins découvrables via `hdwp plugin list` sont ceux déclarés dans `pyproject.toml` avec l'entry point `hdwp.plugins`.

---

## 6. Rejouer une expérience

Une fois des expériences exécutées (Phase 4+), chaque expérience est identifiée par un ID `EXP-XXXX` et stockée dans l'Evidence Store. Pour rejouer :

```bash
hdwp replay --experiment EXP-a1b2c3d4
```

---

## 7. Générer un rapport (Phase 5)

```bash
# Rapport Markdown
hdwp report --session SESSION_ID --format md

# Export JSON pour CI/CD
hdwp report --session SESSION_ID --format json

# Export HAR pour rejouer dans Burp/ZAP
hdwp report --session SESSION_ID --format har
```

---

## 8. Lancer les tests

```bash
# Tous les tests
pytest tests/

# Tests unitaires uniquement
pytest tests/unit/

# Tests d'intégration (nécessite le mock server)
pytest tests/integration/

# Avec couverture
pytest tests/ --cov=hdwp --cov-report=html
```

---

## 9. Vérification de la qualité du code

```bash
# Linting
ruff check src/

# Typage strict
mypy src/hdwp --strict
```

---

## 10. Configuration du Proxy MITM

HDWP embarque un proxy MITM natif qui capture le trafic HTTP/HTTPS de votre navigateur pour récupérer les credentials et enrichir l'analyse. Il démarre automatiquement à chaque scan en mode **DÉCOUVERTE** (port `127.0.0.1:8080`).

### Installation du certificat CA (une seule fois)

Pour intercepter le HTTPS, les navigateurs doivent faire confiance au CA HDWP (`~/.hdwp/ca.crt`).

**Installation automatique :**
```bash
# Depuis la CLI
hdwp proxy install-ca

# Ou depuis l'interface web — bouton "INSTALLER CERTIFICAT CA"
# dans le panneau STATUS pendant un scan
```

Cette commande installe automatiquement le certificat dans :
- Chrome (NSS `~/.pki/nssdb/`)
- Firefox (profils snap et non-snap)
- Store système Linux (`update-ca-certificates`)
- Keychain macOS
- Windows Certificate Store

Elle nécessite `libnss3-tools` pour les profils NSS :
```bash
sudo apt install libnss3-tools   # Ubuntu/Debian
```

**Installation manuelle :**

| Navigateur | Méthode |
|-----------|---------|
| Firefox | Paramètres → Vie privée → Certificats → Importer `~/.hdwp/ca.crt` |
| Chrome | `chrome://settings/security` → Gérer les certificats → Autorités → Importer |
| Système (Linux) | `sudo cp ~/.hdwp/ca.crt /usr/local/share/ca-certificates/hdwp.crt && sudo update-ca-certificates` |
| macOS | `security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db ~/.hdwp/ca.crt` |

### Configuration du navigateur

Configurez `127.0.0.1:8080` comme proxy HTTP/HTTPS dans votre navigateur avant de naviguer sur la cible.

**Firefox** : Paramètres → Réseau → Paramètres de connexion → Proxy manuel  
**Chrome/Chromium** : Utilise les paramètres proxy du système

---

## 11. Pour aller plus loin

- [ARCHITECTURE.md](ARCHITECTURE.md) — architecture détaillée, composants, Event Bus, oracle de violation, modèle de confiance
- [PLUGIN_AUTHORING.md](PLUGIN_AUTHORING.md) — créer et packager un plugin HDWP
- `hdwp-context.example.yaml` — exemple de fichier de contexte complet avec commentaires
