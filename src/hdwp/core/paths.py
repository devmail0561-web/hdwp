# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

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
        content = path.read_text(encoding="utf-8")
        # Régénérer si c'est un contexte auto-généré avec l'ancien défaut allow_write: false
        if "# Contexte genere automatiquement" in content and "allow_write: false" in content:
            path.unlink()
        else:
            return path
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    content = f"""# Contexte genere automatiquement par HDWP
# ATTENTION : ce fichier est genere une seule fois. Modifiez-le pour ajouter des tokens.
target:
  base_url: "{base}"
  name: "Pentest {parsed.netloc}"

scope:
  include:
    - "{base}"
    - "{base}/*"

# Ajoutez des roles avec credentials pour les tests d'autorisation (BOLA, privilege escalation)
# Exemple :
#   - name: "user_a"
#     credentials:
#       type: bearer
#       token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
roles:
  - name: "anonymous"

options:
  # allow_write: true permet les requetes POST/PUT/DELETE dans les experiences
  allow_write: true
  max_requests_per_minute: 60
"""
    path.write_text(content, encoding="utf-8")
    return path
