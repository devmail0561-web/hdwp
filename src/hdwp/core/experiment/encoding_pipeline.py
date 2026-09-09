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

import base64
import codecs
import html
import random
import re
import string
import unicodedata
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass


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
                          r'script|alert|onerror|onload|href|src)\b', re.IGNORECASE)
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


# ── Phase 1: 16 nouveaux encoders ─────────────────────────────────────────────

# Haute priorité (8 encoders) - WAF bypass critique

def _base64_encode(s: str) -> str:
    """Base64 encoding standard."""
    return base64.b64encode(s.encode()).decode()


def _octal_encode(s: str) -> str:
    """Octal encoding — contourne filtres MySQL CHAR()."""
    return "".join(f"\\{ord(c):03o}" if ord(c) > 32 else c for c in s)


def _whitespace_obfuscation(s: str) -> str:
    """Tab/newline/space variation — contourne regex linéaires."""
    ws_chars = [" ", "\t", "\n"]
    return re.sub(r'\s+', lambda m: random.choice(ws_chars), s)


def _json_unicode(s: str) -> str:
    """JSON \\uXXXX escaping — contourne filtres API."""
    return s.encode('unicode_escape').decode('ascii')


def _xml_entities(s: str) -> str:
    """XML numeric entities — contourne filtres XML."""
    return "".join(f"&#{ord(c)};" if c in "&<>\"'" else c for c in s)


def _js_unicode(s: str) -> str:
    """JavaScript \\uXXXX escaping — contourne filtres XSS."""
    return "".join(f"\\u{ord(c):04x}" for c in s)


def _backtick_unicode(s: str) -> str:
    """Backtick/dollar hex encoding — CMDi bypass."""
    return s.replace("`", "\\x60").replace("$", "\\x24")


def _mixed_encoding(s: str) -> str:
    """Encoding mixte aléatoire — bypass filtres multi-couches."""
    result = []
    for c in s:
        choice = random.randint(0, 2)
        if choice == 0:
            result.append(urllib.parse.quote(c, safe=""))
        elif choice == 1:
            result.append(f"\\u{ord(c):04x}")
        else:
            result.append(f"\\x{ord(c):02x}")
    return "".join(result)


# Moyenne priorité (5 encoders) - Scénarios spécialisés

def _utf7_encode(s: str) -> str:
    """UTF-7 encoding — contourne anciens WAF."""
    try:
        return s.encode('utf-7').decode('ascii')
    except Exception:
        return s


def _utf16_encode(s: str) -> str:
    """UTF-16 with BOM — contourne détection charset."""
    try:
        encoded = s.encode('utf-16')
        return encoded.decode('utf-16')
    except Exception:
        return s


def _utf32_encode(s: str) -> str:
    """UTF-32 encoding — contourne filtres non-Unicode."""
    try:
        encoded = s.encode('utf-32')
        return encoded.decode('utf-32')
    except Exception:
        return s


def _unicode_normalize(s: str) -> str:
    """Unicode NFKD normalization — contourne filtres strict."""
    return unicodedata.normalize('NFKD', s)


def _punycode_encode(s: str) -> str:
    """Punycode IDN — contourne filtres domaine."""
    try:
        return "xn--" + s.encode('punycode').decode('ascii')
    except Exception:
        return s


# Basse priorité (3 encoders) - Edge cases

def _rot13_encode(s: str) -> str:
    """ROT13 rotation — obfuscation basique."""
    return codecs.encode(s, 'rot13')


def _chunked_transfer(s: str) -> str:
    """HTTP chunked encoding — contourne filtres HTTP."""
    # Simplified chunked encoding for payload obfuscation
    chunk_size = 4
    chunks = [s[i:i+chunk_size] for i in range(0, len(s), chunk_size)]
    return "\r\n".join(f"{len(chunk):x}\r\n{chunk}" for chunk in chunks) + "\r\n0\r\n\r\n"


def _custom_obfuscation(s: str) -> str:
    """Obfuscation customisée projet-spécifique."""
    # Placeholder for custom project-specific obfuscation
    # Can be overridden by users via EncoderRegistry.register()
    return s


ENCODING_STRATEGIES: list[EncodingStrategy] = [
    EncodingStrategy(
        name="url_encode",
        transform=lambda s: urllib.parse.quote(s, safe=""),
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
    # Phase 1: 16 nouveaux encoders
    # Haute priorité
    EncodingStrategy(
        name="base64",
        transform=_base64_encode,
        waf_effective_against={"waf:cloudflare", "waf:akamai", "waf:generic"},
        description="Base64 encoding — contourne filtres regex basiques",
    ),
    EncodingStrategy(
        name="octal",
        transform=_octal_encode,
        waf_effective_against={"waf:modsecurity", "waf:barracuda"},
        description="Octal encoding — contourne filtres MySQL CHAR()",
    ),
    EncodingStrategy(
        name="whitespace_obfuscation",
        transform=_whitespace_obfuscation,
        waf_effective_against={"waf:modsecurity", "waf:f5_bigip"},
        description="Tab/newline/space variation — contourne regex linéaires",
    ),
    EncodingStrategy(
        name="json_unicode",
        transform=_json_unicode,
        waf_effective_against={"waf:aws_waf", "waf:cloudflare"},
        description="JSON \\uXXXX escaping — contourne filtres API",
    ),
    EncodingStrategy(
        name="xml_entities",
        transform=_xml_entities,
        waf_effective_against={"waf:generic", "waf:imperva"},
        description="XML numeric entities — contourne filtres XML",
    ),
    EncodingStrategy(
        name="js_unicode",
        transform=_js_unicode,
        waf_effective_against={"waf:cloudflare", "waf:sucuri"},
        description="JavaScript \\uXXXX escaping — contourne filtres XSS",
    ),
    EncodingStrategy(
        name="backtick_unicode",
        transform=_backtick_unicode,
        waf_effective_against={"waf:generic"},
        description="Backtick/dollar hex encoding — CMDi bypass",
    ),
    EncodingStrategy(
        name="mixed_encoding",
        transform=_mixed_encoding,
        waf_effective_against={"waf:generic", "waf:cloudflare"},
        description="Encoding mixte aléatoire — bypass filtres multi-couches",
    ),
    # Moyenne priorité
    EncodingStrategy(
        name="utf7",
        transform=_utf7_encode,
        waf_effective_against={"waf:legacy", "waf:iis"},
        description="UTF-7 encoding — contourne anciens WAF",
    ),
    EncodingStrategy(
        name="utf16",
        transform=_utf16_encode,
        waf_effective_against={"waf:imperva"},
        description="UTF-16 with BOM — contourne détection charset",
    ),
    EncodingStrategy(
        name="utf32",
        transform=_utf32_encode,
        waf_effective_against={"waf:generic"},
        description="UTF-32 encoding — contourne filtres non-Unicode",
    ),
    EncodingStrategy(
        name="unicode_normalize",
        transform=_unicode_normalize,
        waf_effective_against={"waf:cloudflare", "waf:akamai"},
        description="Unicode NFKD normalization — contourne filtres strict",
    ),
    EncodingStrategy(
        name="punycode",
        transform=_punycode_encode,
        waf_effective_against={"waf:generic"},
        description="Punycode IDN — contourne filtres domaine",
    ),
    # Basse priorité
    EncodingStrategy(
        name="rot13",
        transform=_rot13_encode,
        waf_effective_against=set(),
        description="ROT13 rotation — obfuscation basique",
    ),
    EncodingStrategy(
        name="chunked_transfer",
        transform=_chunked_transfer,
        waf_effective_against={"waf:modsecurity"},
        description="HTTP chunked encoding — contourne filtres HTTP",
    ),
    EncodingStrategy(
        name="custom_obfuscation",
        transform=_custom_obfuscation,
        waf_effective_against={"waf:generic"},
        description="Obfuscation customisée — logique métier",
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
