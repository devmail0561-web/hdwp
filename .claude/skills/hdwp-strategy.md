# Skill : HDWP — Creer une strategie d'exploitation YAML

## Quand utiliser ce skill
Invoquer avec `/hdwp-strategy` quand l'utilisateur demande de creer une strategie d'exploitation YAML. La strategie est generee dans `~/.hdwp/exploit_strategies/` (externe au code source) et immediatement importable par le StrategyRegistry.

---

## Ce que tu dois faire

Tu crees un fichier YAML conforme au schema `ExploitStrategy` et tu le places dans le repertoire utilisateur.

### Etape 1 — Recueillir les informations

Si non fournies par l'utilisateur, demander via AskUserQuestion :
- **Type de vuln** : sqli, xss, ssrf, bola, bfla, jwt, cmdi, ssti, lfi, nosqli, cors, race_condition, business_boundary, deserialization, etc.
- **Nom** : description courte de la strategie
- **Tech stack** (optionnel) : mysql, postgresql, php, java, nodejs, spring, django... vide = universel
- **Mode** : `sequential` (phases en serie) | `exhaustive` (toutes les phases) | `parallel`
- **Payloads** : les payloads a injecter
- **Critere de succes** : comment determiner que l'exploit a marche

### Etape 2 — Generer le YAML

Creer le fichier dans :
```
~/.hdwp/exploit_strategies/<id_en_snake_case>.yaml
```

Le fichier DOIT respecter ce schema exact :

```yaml
id: custom.<categorie>.<nom_unique>
vuln_type: <TYPE_VULN>
name: "<NOM_LISIBLE>"
description: "<DESCRIPTION>"
proof_type: network          # network | passive | contextual
mode: sequential             # sequential | exhaustive | parallel
tech_stack: []               # [mysql, php, spring] ou [] = universel
params: {}                   # cles arbitraires accessibles via {params.key} dans les payloads

phases:
  - name: <NOM_PHASE>
    inject: <TYPE_INJECTION>
    payloads:
      - "<PAYLOAD_1>"
      - "<PAYLOAD_2>"
    success:
      type: <TYPE_SUCCES>
      # + champs specifiques au type
    output: <NOM_OUTPUT>
```

### Types d'injection disponibles

| inject | Description |
|---|---|
| `param_from_winning_request` | Remplace la valeur du parametre gagnant |
| `header` | Injecte dans un header HTTP |
| `path_param` | Remplace un segment du path |
| `url_transform` | Transforme l'URL entiere |
| `url_id_replace` | Remplace un ID numerique dans l'URL |
| `body_merge` | Merge dans le body JSON |
| `jwt_header` | Modifie le header JWT |
| `jwt_resign_hs256` | Re-signe le JWT avec un secret teste |
| `jwt_payload_modify` | Modifie le payload JWT |
| `winning_request_replay` | Rejoue la requete gagnante telle quelle |
| `winning_request_mutation` | Mute la requete gagnante |
| `get_verification` | GET sur l'URL pour verifier |
| `none` | Pas d'injection (verification passive) |

### Types de succes disponibles

| success.type | Champs supplementaires |
|---|---|
| `status_2xx` | — |
| `status_not_5xx` | — |
| `status_code` | `status: 200` |
| `status_not_redirect` | — |
| `body_contains` | `value: "texte"` |
| `body_contains_any` | `keywords: ["k1", "k2"]` |
| `header_present` | `header: "X-Header"` |
| `header_reflects_payload` | `header: "X-Header"` |
| `header_equals` | `header: "X-Header"`, `value: "val"` |
| `location_header_contains_payload` | — |
| `regex` | `pattern: "re_pattern"` |
| `any_response` | — |
| `status_not_5xx_and_length_gt_10` | — |

### Chainages entre phases

Utiliser `depends_on` pour creer des phases conditionnelles :

```yaml
phases:
  - name: probe
    inject: param_from_winning_request
    payloads: ["1' OR '1'='1"]
    success:
      type: body_contains_any
      keywords: ["error", "SQL", "syntax"]
    output: probe_result

  - name: extract
    depends_on: probe_result       # ne s'execute que si probe reussit
    inject: param_from_winning_request
    payloads: ["1 UNION SELECT table_name FROM information_schema.tables--"]
    success:
      type: body_contains_any
      keywords: [users, admin, accounts]
    output: extract_result
```

### Champs speciaux optionnels

```yaml
phases:
  - name: phase_name
    # ...
    limit: "{params.max_results}"         # limiter les resultats
    extract_aws_creds: true               # extraction auto credentials AWS
    payload_mutations:                     # pour jwt_payload_modify
      role: "admin"
      is_admin: true
```

### Regles

- L'id doit commencer par `custom.` pour eviter les collisions avec les 1040+ builtins
- Les payloads contenant des caracteres speciaux YAML doivent etre quotes : `"payload"`
- Les strategies user ont **priorite** sur les builtins si meme `id`
- Un fichier YAML = une strategie = un `id` unique

### Etape 3 — Valider

```bash
.venv/bin/python -c "
import yaml
from pathlib import Path
f = Path.home() / '.hdwp/exploit_strategies/<FICHIER>.yaml'
data = yaml.safe_load(f.read_text())
print(f'OK: {data[\"id\"]} — {len(data.get(\"phases\", []))} phases')
"
```

Et verifier le chargement dans le registry :

```bash
.venv/bin/python -c "
from hdwp.core.exploit.strategy_registry import StrategyRegistry
r = StrategyRegistry()
r.discover()
s = [x for x in r.list_all() if x.id == '<STRATEGY_ID>']
print(f'OK: {s[0].name} (source={s[0].source})' if s else 'ERREUR: strategie non trouvee')
"
```

### Etape 4 — Informer l'utilisateur

Afficher :
- Chemin du fichier cree
- Commandes de validation
- Comment desactiver : `~/.hdwp/exploit_strategies_config.json`
- Rappel : la strategie est chargee automatiquement au prochain demarrage HDWP
