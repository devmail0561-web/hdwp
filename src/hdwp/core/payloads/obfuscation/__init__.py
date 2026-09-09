# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Obfuscation package: 20 obfuscation techniques pour SQLi, CMDi, XSS.

Phase 1: Infrastructure obfuscation centralisée avec ObfuscatorRegistry singleton.
"""
from __future__ import annotations

from hdwp.core.payloads.obfuscation.obfuscator_registry import (
    ObfuscationTechnique,
    ObfuscatorRegistry,
    get_obfuscator_registry,
)

__all__ = [
    "ObfuscationTechnique",
    "ObfuscatorRegistry",
    "get_obfuscator_registry",
]
