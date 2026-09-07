# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Encoding Pipeline : transformations de payloads adaptées au WAF détecté.

Quand ExperimentEngine reçoit un 403 avec un tag waf:* dans tech_stack,
il génère des follow-up specs avec les encodages les plus susceptibles de
contourner CE WAF spécifique.

Intégré dans ExperimentEngine via le mécanisme trigger_condition déjà en place :
  mutation → 403 avec waf:cloudflare → encoding_pipeline sélectionne html_entities
  → follow_up ExperimentSpec avec payload encodé
"""
from __future__ import annotations

import html
import random
import re
import string
import urllib.parse
from dataclasses import dataclass
from typing import Callable


@dataclass
class EncodingStrategy:
    name: str
    transform: Callable[[str], str]
    waf_effective_against: set[str]   # waf tags pour lesquels efficace (vide = tous)
    description: str = ""


def _double_url_encode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def _html_entities(s: str) -> str:
    return html.escape(s, quote=True)


def _unicode_escape(s: str) -> str:
    result = []
    for ch in s:
        if ch in string.printable and ch not in "<>\"'&;":
            result.append(ch)
        else:
            result.append(f"\\u{ord(ch):04x}")
    return "".join(result)


def _case_variation(s: str) -> str:
    """Alterne majuscules/minuscules sur les mots-clés SQL/HTML."""
    keywords = re.compile(r'\b(select|union|insert|update|delete|from|where|'
                          r'script|alert|onerror|onload|href|src)\b', re.I)
    def vary(m: re.Match) -> str:
        word = m.group(0)
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))
    return keywords.sub(vary, s)


def _null_byte(s: str) -> str:
    return s + "\x00"


def _comment_insert_sql(s: str) -> str:
    """Insère des commentaires SQL /* */ entre les espaces."""
    return s.replace(" ", "/**/")


def _hex_encode(s: str) -> str:
    """Encode chaque caractère en hex \x41 format."""
    return "".join(f"\\x{ord(c):02x}" if ord(c) > 32 else c for c in s)


def _html_char_ref(s: str) -> str:
    """Encode les caractères dangereux en entités numériques HTML."""
    result = []
    for ch in s:
        if ch in "<>\"'&":
            result.append(f"&#{ord(ch)};")
        else:
            result.append(ch)
    return "".join(result)


ENCODING_STRATEGIES: list[EncodingStrategy] = [
    EncodingStrategy(
        name="url_encode",
        transform=urllib.parse.quote,
        waf_effective_against={"waf:generic", "waf:nginx_limit"},
        description="URL encoding simple",
    ),
    EncodingStrategy(
        name="double_url",
        transform=_double_url_encode,
        waf_effective_against={"waf:modsecurity", "waf:generic"},
        description="Double URL encoding — contourne les filtres qui décodent une fois",
    ),
    EncodingStrategy(
        name="html_entities",
        transform=_html_entities,
        waf_effective_against={"waf:cloudflare", "waf:sucuri", "waf:barracuda"},
        description="Entités HTML — contourne les filtres regex sur les balises brutes",
    ),
    EncodingStrategy(
        name="html_char_ref",
        transform=_html_char_ref,
        waf_effective_against={"waf:cloudflare", "waf:akamai"},
        description="Références de caractères HTML numériques",
    ),
    EncodingStrategy(
        name="unicode_escape",
        transform=_unicode_escape,
        waf_effective_against={"waf:akamai", "waf:imperva"},
        description="Escape Unicode — contourne les filtres non-Unicode-aware",
    ),
    EncodingStrategy(
        name="case_variation",
        transform=_case_variation,
        waf_effective_against={"waf:modsecurity", "waf:f5_bigip"},
        description="Variation de casse sur les mots-clés",
    ),
    EncodingStrategy(
        name="null_byte",
        transform=_null_byte,
        waf_effective_against={"waf:generic", "waf:modsecurity"},
        description="Null byte en fin de payload — tronque certains filtres C-style",
    ),
    EncodingStrategy(
        name="comment_insert",
        transform=_comment_insert_sql,
        waf_effective_against={"waf:modsecurity", "waf:barracuda"},
        description="Commentaires SQL entre les espaces — contourne les regex linéaires",
    ),
    EncodingStrategy(
        name="hex_encode",
        transform=_hex_encode,
        waf_effective_against={"waf:generic"},
        description="Hex escape des caractères non-ASCII",
    ),
]


def get_bypass_strategies(waf_tag: str) -> list[EncodingStrategy]:
    """Retourne les stratégies d'encodage efficaces contre un WAF donné, triées par priorité."""
    specific = [s for s in ENCODING_STRATEGIES if waf_tag in s.waf_effective_against]
    generic = [s for s in ENCODING_STRATEGIES if "waf:generic" in s.waf_effective_against and s not in specific]
    # Spécifiques en premier, puis génériques
    return specific + generic


def build_bypass_experiment_specs(
    original_payload: str,
    mutation_params: dict,
    waf_tag: str,
    max_strategies: int = 3,
) -> list[dict]:
    """Construit des mutation_params avec payloads encodés pour le WAF détecté.

    Retourne des dicts de mutation_params (pas des ExperimentSpec — pour éviter
    les imports circulaires ; l'appelant construit les ExperimentSpec).
    """
    strategies = get_bypass_strategies(waf_tag)[:max_strategies]
    bypass_specs = []
    for strategy in strategies:
        try:
            encoded = strategy.transform(original_payload)
            if encoded == original_payload:
                continue  # l'encodage n'a rien changé — inutile
            new_params = {
                **mutation_params,
                "payload": encoded,
                "payload_type": f"{mutation_params.get('payload_type', 'injection')}_bypass_{strategy.name}",
                "_bypass_strategy": strategy.name,
                "_waf_target": waf_tag,
            }
            bypass_specs.append(new_params)
        except Exception:
            continue
    return bypass_specs
