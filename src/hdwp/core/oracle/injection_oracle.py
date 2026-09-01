# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
InjectionOracle: détecte les vulnérabilités d'injection par analyse de la réponse.

Contrairement au ViolationOracle (qui compare baseline vs mutation),
l'InjectionOracle analyse directement la réponse de l'expérience pour des
indicateurs d'injection réussie.

Types supportés :
  sqli       : erreurs SQL dans la réponse ou status 500 avec stack trace
  xss        : payload reflété non-encodé dans une réponse HTML
  ssti       : résultat de l'évaluation du template ({{7*7}} → 49)
  mass_assign: champ supplémentaire accepté et reflété dans la réponse
"""
from __future__ import annotations

import html as html_module
import re

from hdwp.core.model.schemas import ExperimentResult
from hdwp.core.oracle.violation_oracle import ViolationAssessment, ViolationVerdict

# Patterns d'erreur SQL (MySQL, PostgreSQL, SQLite, Oracle, MSSQL, DB2, Sybase, Informix)
SQL_ERROR_PATTERNS = [
    r"SQL syntax",
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"Driver.*SQL[\-_ ]*Server",
    r"OLE DB.*SQL Server",
    r"\bSQL Server\b",
    r"Unclosed quotation mark after the character string",
    r"SQLite\/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*\Wsqlite_",
    r"Warning.*SQLite3::",
    r"\[SQLITE_ERROR\]",
    r"ORA-[0-9]{4,}",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*\Woci_",
    r"Warning.*\Wora_",
    r"CLI Driver.*DB2",
    r"DB2 SQL error",
    r"\bSQLCODE\b",
    r"Sybase message",
    r"Sybase.*Server message",
    r"SybSQLException",
    r"com\.informix\.jdbc",
    r"Exception.*Informix",
]

# Patterns de stack trace exposés
STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"at [\w.$]+\([\w.]+:\d+\)",
    r'File ".*\.py", line \d+',
    r"PHP (?:Fatal|Parse) error",
    r"Warning:.*on line \d+",
    r"javax\.servlet",
    r"java\.lang\.",
]


def assess_sqli(payload: str, experiment: ExperimentResult) -> ViolationAssessment:
    """Détecte SQLi par erreurs SQL ou 500 avec stack trace."""
    body = str(experiment.response_received.body or "")
    status = experiment.response_received.status_code

    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            return ViolationAssessment(
                verdict=ViolationVerdict.CONFIRMED,
                rationale=f"Erreur SQL détectée (pattern: {pattern[:50]})",
                confidence_hint=0.95,
            )

    if status == 500:
        for pattern in STACK_TRACE_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return ViolationAssessment(
                    verdict=ViolationVerdict.CONFIRMED,
                    rationale="Status 500 avec stack trace exposée — injection probable",
                    confidence_hint=0.75,
                )
        return ViolationAssessment(
            verdict=ViolationVerdict.AMBIGUOUS,
            rationale=f"Status 500 avec payload '{payload[:30]}' — peut indiquer une injection",
            confidence_hint=0.5,
        )

    return ViolationAssessment(
        verdict=ViolationVerdict.REFUTED,
        rationale="Aucun indicateur SQLi dans la réponse",
        confidence_hint=0.6,
    )


def assess_xss(payload: str, experiment: ExperimentResult) -> ViolationAssessment:
    """Détecte XSS réfléchi : le payload est présent non-encodé dans la réponse HTML."""
    body = str(experiment.response_received.body or "")
    content_type = experiment.response_received.content_type or ""

    if payload not in body:
        if html_module.escape(payload) in body:
            return ViolationAssessment(
                verdict=ViolationVerdict.REFUTED,
                rationale="Payload HTML-encodé dans la réponse (protection en place)",
                confidence_hint=0.85,
            )
        return ViolationAssessment(
            verdict=ViolationVerdict.REFUTED,
            rationale="Payload non reflété dans la réponse",
            confidence_hint=0.7,
        )

    if "text/html" in content_type or "<" in body:
        return ViolationAssessment(
            verdict=ViolationVerdict.CONFIRMED,
            rationale="Payload XSS reflété non-encodé dans réponse HTML",
            confidence_hint=0.95,
        )

    return ViolationAssessment(
        verdict=ViolationVerdict.AMBIGUOUS,
        rationale="Payload reflété dans réponse non-HTML — évaluer manuellement",
        confidence_hint=0.5,
    )


def assess_ssti(
    payload: str, expected_result: str, experiment: ExperimentResult
) -> ViolationAssessment:
    """Détecte SSTI : {{7*7}} évalué donne 49, pas '{{7*7}}'."""
    body = str(experiment.response_received.body or "")

    if expected_result and expected_result in body:
        return ViolationAssessment(
            verdict=ViolationVerdict.CONFIRMED,
            rationale=f"Template évalué : '{payload}' → '{expected_result}' dans la réponse",
            confidence_hint=0.98,
        )
    if payload in body:
        return ViolationAssessment(
            verdict=ViolationVerdict.REFUTED,
            rationale="Template non évalué (payload reflété tel quel)",
            confidence_hint=0.85,
        )
    return ViolationAssessment(
        verdict=ViolationVerdict.INSUFFICIENT,
        rationale="Payload ni évalué ni reflété — résultat non concluant",
        confidence_hint=0.2,
    )


def assess_mass_assignment(
    extra_field: str, experiment: ExperimentResult
) -> ViolationAssessment:
    """Détecte mass assignment : champ supplémentaire accepté et reflété dans la réponse."""
    body = experiment.response_received.body
    status = experiment.response_received.status_code

    if status not in range(200, 300):
        return ViolationAssessment(
            verdict=ViolationVerdict.REFUTED,
            rationale=f"Requête rejetée ({status})",
            confidence_hint=0.7,
        )

    if isinstance(body, dict) and extra_field in body:
        return ViolationAssessment(
            verdict=ViolationVerdict.CONFIRMED,
            rationale=f"Champ '{extra_field}' accepté et présent dans la réponse",
            confidence_hint=0.9,
        )

    return ViolationAssessment(
        verdict=ViolationVerdict.AMBIGUOUS,
        rationale=f"Requête acceptée mais champ '{extra_field}' absent de la réponse",
        confidence_hint=0.4,
    )


NEGATIVE_VALUE_IN_FINANCIAL_FIELD = re.compile(
    r"""['"](total|balance|amount|price|cost|sum|credit|debit|fee)['"]\s*:\s*-\d""",
    re.IGNORECASE,
)


def assess_business_boundary(payload: str, experiment: ExperimentResult) -> ViolationAssessment:
    """
    Détecte les violations de logique métier.

    - 400/422/403/405 → REFUTED (validation correcte)
    - 200 + valeur négative dans champ financier du body → CONFIRMED
    - 200 + valeur injectée reflétée → AMBIGUOUS
    - 200 + valeur clairement invalide sans indication → AMBIGUOUS (faible)
    """
    status = experiment.response_received.status_code
    body_str = str(experiment.response_received.body or "")

    if status in (400, 422, 403, 405):
        return ViolationAssessment(
            verdict=ViolationVerdict.REFUTED,
            rationale=f"Validation correcte : {status} pour valeur '{payload}'",
            confidence_hint=0.85,
        )

    if status < 300:
        if NEGATIVE_VALUE_IN_FINANCIAL_FIELD.search(body_str):
            return ViolationAssessment(
                verdict=ViolationVerdict.CONFIRMED,
                rationale=(
                    f"Business logic : valeur négative dans champ financier "
                    f"après payload '{payload}'"
                ),
                confidence_hint=0.85,
            )
        # Détection de reflection : chercher la valeur dans un contexte JSON (pas dans du texte libre)
        # Ex: `"amount": -1` ou `"quantity": 0.001` — pas dans une description textuelle
        if payload not in ("9999999",):
            import re as _re_boundary
            reflection_in_json = _re_boundary.search(
                rf'["\'][\w_]+["\']\s*:\s*{_re_boundary.escape(payload)}(?:[,\s}}])',
                body_str,
            )
            if reflection_in_json:
                return ViolationAssessment(
                    verdict=ViolationVerdict.AMBIGUOUS,
                    rationale=(
                        f"Business boundary : valeur '{payload}' présente dans un champ JSON "
                        f"(validation insuffisante ?)"
                    ),
                    confidence_hint=0.55,
                )
        if payload in ("-1", "-9999", "0"):
            return ViolationAssessment(
                verdict=ViolationVerdict.AMBIGUOUS,
                rationale=f"Business boundary : valeur '{payload}' acceptée sans erreur",
                confidence_hint=0.40,
            )

    return ViolationAssessment(
        verdict=ViolationVerdict.REFUTED,
        rationale=f"Pas d'anomalie business pour payload '{payload}'",
        confidence_hint=0.60,
    )


def assess_injection(
    payload_type: str,
    payload: str,
    experiment: ExperimentResult,
    expected_result: str = "",
    extra_field: str = "",
    baseline: ExperimentResult | None = None,
) -> ViolationAssessment:
    """Point d'entrée unifié pour tous les types d'injection."""
    match payload_type:
        case "sqli":
            return assess_sqli(payload, experiment)
        case "xss":
            return assess_xss(payload, experiment)
        case "ssti":
            return assess_ssti(payload, expected_result or "49", experiment)
        case "mass_assign":
            return assess_mass_assignment(extra_field or payload, experiment)
        case "ssrf":
            return assess_ssrf(payload, experiment)
        case "boundary":
            return assess_business_boundary(payload, experiment)
        case "type_confusion" | "injection_agnostic" | _:
            # Generic fallback: try SQL pattern detection first, then INSUFFICIENT
            result = assess_sqli(payload, experiment)
            if result.verdict == ViolationVerdict.REFUTED:
                return ViolationAssessment(
                    verdict=ViolationVerdict.INSUFFICIENT,
                    rationale=f"Type '{payload_type}' — analyse générique non concluante",
                    confidence_hint=0.0,
                )
            return result


def assess_ssrf(payload: str, experiment: ExperimentResult) -> ViolationAssessment:
    """
    Détecte SSRF sans callback server (heuristique) :
    - Contenu de fichier interne (/etc/passwd)
    - Erreurs révélatrices de tentative de connexion interne
    - Réponse localhost anormalement rapide
    """
    body = str(experiment.response_received.body or "")

    # Contenu /etc/passwd — confirmation forte
    if "root:x:" in body or "daemon:x:" in body:
        return ViolationAssessment(
            verdict=ViolationVerdict.CONFIRMED,
            rationale=f"SSRF : contenu /etc/passwd exposé avec payload '{payload}'",
            confidence_hint=0.99,
        )

    # Erreurs révélatrices de tentative de connexion interne
    _SSRF_INDICATORS = [
        "connection refused", "connection timed out", "no route to host",
        "network unreachable", "169.254", "metadata",
    ]
    for indicator in _SSRF_INDICATORS:
        if indicator in body.lower():
            return ViolationAssessment(
                verdict=ViolationVerdict.AMBIGUOUS,
                rationale=f"SSRF : indicateur '{indicator}' dans la réponse — connexion interne tentée",
                confidence_hint=0.6,
            )

    # Heuristique délai : localhost répond en < 10 ms
    if experiment.timing_ms < 10 and "127.0.0.1" in payload:
        return ViolationAssessment(
            verdict=ViolationVerdict.AMBIGUOUS,
            rationale="SSRF : réponse localhost anormalement rapide",
            confidence_hint=0.4,
        )

    return ViolationAssessment(
        verdict=ViolationVerdict.REFUTED,
        rationale="Aucun indicateur SSRF détecté",
        confidence_hint=0.5,
    )
