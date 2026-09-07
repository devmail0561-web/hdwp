# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
ErrorIntel : extrait des informations structurées depuis les erreurs HTTP.

Quand injection_oracle.py détecte une erreur (SQL error, stack trace, etc.),
ErrorIntel parse le contenu pour extraire des infos exploitables :
  - Type de DB (mysql, postgresql, oracle, sqlite, mssql, mongodb)
  - Framework backend (django, rails, spring, flask)
  - Chemins de fichiers révélés dans les stack traces
  - Noms de tables/colonnes dans les erreurs SQL
  - Version du serveur

Ces informations alimentent _detected_versions et tech_stack du modèle,
ce qui active les plugins tech-adaptatifs (SQLi Oracle vs MySQL, etc.).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ErrorIntel:
    db_type: str | None = None
    framework: str | None = None
    file_paths: list[str] = field(default_factory=list)
    table_names: list[str] = field(default_factory=list)
    column_names: list[str] = field(default_factory=list)
    server_version: str | None = None
    tech_tags: list[str] = field(default_factory=list)  # tags pour ApplicationModel._tech_stack


_DB_PATTERNS: dict[str, list[re.Pattern]] = {
    "db:mysql": [
        re.compile(r"You have an error in your SQL syntax", re.I),
        re.compile(r"MySQL server version", re.I),
        re.compile(r"mysql_fetch_array\(\)", re.I),
        re.compile(r"SQLSTATE\[HY\d+\].*MySQL", re.I),
    ],
    "db:postgresql": [
        re.compile(r"PG::", re.I),
        re.compile(r"PostgreSQL.*ERROR", re.I),
        re.compile(r'ERROR:.*syntax error at or near "', re.I),
        re.compile(r"relation .* does not exist", re.I),
    ],
    "db:oracle": [
        re.compile(r"ORA-\d{4,}", re.I),
        re.compile(r"Oracle.*Database.*Error", re.I),
    ],
    "db:mssql": [
        re.compile(r"Microsoft SQL Server", re.I),
        re.compile(r"Incorrect syntax near", re.I),
        re.compile(r"Unclosed quotation mark after the character string", re.I),
    ],
    "db:sqlite": [
        re.compile(r"SQLiteException", re.I),
        re.compile(r"sqlite3\.OperationalError", re.I),
        re.compile(r"no such table", re.I),
    ],
    "db:mongodb": [
        re.compile(r"MongoError", re.I),
        re.compile(r"BSONTypeError", re.I),
        re.compile(r"E11000 duplicate key", re.I),
    ],
}

_FRAMEWORK_PATTERNS: dict[str, list[re.Pattern]] = {
    "framework:django": [
        re.compile(r"Django.*Exception|Django.*Error", re.I),
        re.compile(r"DJANGO_SETTINGS_MODULE", re.I),
        re.compile(r'File ".*django.*\.py", line \d+', re.I),
    ],
    "framework:rails": [
        re.compile(r"ActionController.*Error", re.I),
        re.compile(r"ActiveRecord.*Error", re.I),
        re.compile(r'\.rb:\d+:in `', re.I),
    ],
    "framework:spring": [
        re.compile(r"org\.springframework\.", re.I),
        re.compile(r"HibernateException", re.I),
        re.compile(r"at org\.spring", re.I),
    ],
    "framework:flask": [
        re.compile(r"werkzeug\.exceptions\.", re.I),
        re.compile(r"flask\.exceptions\.", re.I),
        re.compile(r'File ".*flask.*\.py", line \d+', re.I),
    ],
    "framework:laravel": [
        re.compile(r"Illuminate\\", re.I),
        re.compile(r"Laravel.*Whoops", re.I),
    ],
    "framework:php": [
        re.compile(r"Fatal error:.*on line \d+", re.I),
        re.compile(r"Parse error:.*PHP", re.I),
        re.compile(r"Warning:.*PHP", re.I),
    ],
    "framework:java": [
        re.compile(r"java\.lang\.(RuntimeException|NullPointerException|Exception)", re.I),
        re.compile(r"at [\w\.]+\([\w]+\.java:\d+\)"),
    ],
}

_FILE_PATH_RE = re.compile(
    r'(?:File|in)\s+"?(/[^\s"\'<>]+\.(?:py|rb|java|php|js|ts|cs|go))"?',
    re.I
)
_TABLE_RE = re.compile(
    r"(?:table|relation|column)\s+['\"`]?([\w_]+)['\"`]?\s+(?:doesn't exist|does not exist|not found|no such)",
    re.I
)
_COLUMN_RE = re.compile(
    r"Unknown column '([\w_]+)' in|column \"([\w_]+)\" of relation",
    re.I
)
_SERVER_VERSION_RE = re.compile(
    r"(?:Server|MySQL|PostgreSQL|Oracle)\s+[Vv]ersion[:\s]+(\d+[\.\d]+)",
    re.I
)


def extract(response_body: object, status_code: int = 500) -> ErrorIntel | None:
    """Extrait des informations depuis un corps de réponse d'erreur.

    Retourne None si aucun signal d'erreur exploitable n'est trouvé.
    """
    if status_code < 400:
        return None
    body_str = str(response_body) if response_body is not None else ""
    if not body_str or len(body_str) < 10:
        return None

    intel = ErrorIntel()
    found_something = False

    # Détecter le type de DB
    for db_tag, patterns in _DB_PATTERNS.items():
        if any(p.search(body_str) for p in patterns):
            intel.db_type = db_tag.split(":")[1]
            intel.tech_tags.append(db_tag)
            found_something = True
            break

    # Détecter le framework
    for fw_tag, patterns in _FRAMEWORK_PATTERNS.items():
        if any(p.search(body_str) for p in patterns):
            intel.framework = fw_tag.split(":")[1]
            intel.tech_tags.append(fw_tag)
            found_something = True
            break

    # Extraire les chemins de fichiers
    for m in _FILE_PATH_RE.finditer(body_str):
        path = m.group(1)
        if path not in intel.file_paths:
            intel.file_paths.append(path)
            found_something = True

    # Extraire les noms de tables/colonnes
    for m in _TABLE_RE.finditer(body_str):
        tbl = m.group(1)
        if tbl and tbl not in intel.table_names:
            intel.table_names.append(tbl)
            found_something = True

    for m in _COLUMN_RE.finditer(body_str):
        col = m.group(1) or m.group(2)
        if col and col not in intel.column_names:
            intel.column_names.append(col)
            found_something = True

    # Version serveur
    sv = _SERVER_VERSION_RE.search(body_str)
    if sv:
        intel.server_version = sv.group(1)
        found_something = True

    return intel if found_something else None
