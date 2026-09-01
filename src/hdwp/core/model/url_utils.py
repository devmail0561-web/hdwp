# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Utilitaires de normalisation d'URL partagés entre composants."""
from __future__ import annotations

import re
from urllib.parse import urlparse

_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def normalize_url_path(url: str) -> str:
    """
    Normalise un chemin URL en remplaçant les segments numériques/UUID
    par des placeholders {id_N} / {uuid_N}.

    Exemples :
      /api/users/42        → /api/users/{id_0}
      /api/items/some-slug → /api/items/some-slug  (inchangé)
    """
    path = urlparse(url).path.strip("/")
    parts = path.split("/") if path else []
    normalized: list[str] = []
    param_idx = 0
    for part in parts:
        if _NUMERIC_RE.match(part):
            normalized.append(f"{{id_{param_idx}}}")
            param_idx += 1
        elif _UUID_RE.match(part):
            normalized.append(f"{{uuid_{param_idx}}}")
            param_idx += 1
        else:
            normalized.append(part)
    return "/" + "/".join(normalized) if normalized else "/"
