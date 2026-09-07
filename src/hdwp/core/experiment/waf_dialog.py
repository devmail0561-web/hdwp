# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import re
from enum import Enum
from typing import Any


class WAFType(str, Enum):
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    MODSECURITY = "modsecurity"
    F5_ASM = "f5_asm"
    UNKNOWN = "unknown"


_WAF_SIGNATURES: list[tuple[WAFType, str, re.Pattern[str] | str]] = [
    (WAFType.CLOUDFLARE, "header:cf-ray", ""),
    (WAFType.CLOUDFLARE, "header:cf-cache-status", ""),
    (WAFType.CLOUDFLARE, "server:cloudflare", ""),
    (WAFType.AWS_WAF, "header:x-amzn-requestid", ""),
    (WAFType.AWS_WAF, "header:x-amzn-trace-id", ""),
    (WAFType.AWS_WAF, "header:x-amz-apigw-id", ""),
    (WAFType.MODSECURITY, "server:modsecurity", ""),
    (WAFType.MODSECURITY, "header:x-mod-security", ""),
    (WAFType.F5_ASM, "header:x-wa-info", ""),
    (WAFType.F5_ASM, "server:bigip", ""),
]

_BYPASS_STRATEGIES: dict[WAFType, list[dict[str, Any]]] = {
    WAFType.CLOUDFLARE: [
        {"name": "unicode_normalization", "transform": "unicode_escape"},
        {"name": "double_url_encode", "transform": "double_urlencode"},
        {"name": "chunked_transfer", "transform": "chunked"},
    ],
    WAFType.AWS_WAF: [
        {"name": "case_variation", "transform": "random_case"},
        {"name": "json_unicode", "transform": "json_unicode_escape"},
        {"name": "parameter_pollution", "transform": "duplicate_param"},
    ],
    WAFType.MODSECURITY: [
        {"name": "comment_injection", "transform": "sql_comment_inline"},
        {"name": "null_byte", "transform": "null_byte_prefix"},
        {"name": "multiline_payload", "transform": "newline_split"},
    ],
    WAFType.F5_ASM: [
        {"name": "whitespace_variation", "transform": "tab_space_mix"},
        {"name": "encoding_mix", "transform": "mixed_encoding"},
    ],
    WAFType.UNKNOWN: [
        {"name": "double_url_encode", "transform": "double_urlencode"},
        {"name": "case_variation", "transform": "random_case"},
    ],
}


class WAFDialogEngine:
    def identify_waf(self, headers: dict[str, str], server: str = "") -> WAFType:
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        server_lower = server.lower() or headers_lower.get("server", "")

        for waf_type, sig_key, _ in _WAF_SIGNATURES:
            if sig_key.startswith("header:"):
                header_name = sig_key[7:]
                if header_name in headers_lower:
                    return waf_type
            elif sig_key.startswith("server:"):
                server_match = sig_key[7:]
                if server_match in server_lower:
                    return waf_type

        return WAFType.UNKNOWN

    def get_bypass_strategies(self, waf_type: WAFType) -> list[dict[str, Any]]:
        return list(_BYPASS_STRATEGIES.get(waf_type, _BYPASS_STRATEGIES[WAFType.UNKNOWN]))
