# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
PassiveFindingEngine: génère des findings directement depuis les observations.

Contrairement au SemanticOracle (qui évalue des paires baseline/mutation),
le PassiveFindingEngine détecte les problèmes directement observables :
- Headers de sécurité manquants (HSTS, CSP, XFO, XCTO)
- Informations server/framework exposées (Server:, X-Powered-By:)
- Cookies sans flags HttpOnly/Secure/SameSite
- Réponses contenant des stack traces
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import FINDING_CONFIRMED, OBSERVATION_RAW, HDWPEvent
from hdwp.core.model.schemas import ConfidenceScore, Finding, RawObservation, generate_id

if TYPE_CHECKING:
    from hdwp.store.repository import Repository

log = structlog.get_logger()

# tag → (description, owasp, cwe, severity)
MISSING_HEADER_FINDINGS: dict[str, tuple[str, str, str, str]] = {
    "missing:HSTS": (
        "Strict-Transport-Security absent",
        "A05:2021", "CWE-319", "LOW",
    ),
    "missing:CSP": (
        "Content-Security-Policy absent",
        "A05:2021", "CWE-693", "MEDIUM",
    ),
    "missing:XFO": (
        "X-Frame-Options absent",
        "A05:2021", "CWE-1021", "LOW",
    ),
    "missing:XCTO": (
        "X-Content-Type-Options absent",
        "A05:2021", "CWE-693", "INFO",
    ),
}

COOKIE_FLAG_FINDINGS: dict[str, tuple[str, str, str, str, str]] = {
    "cookie:missing-httponly": (
        "Cookie sans HttpOnly",
        "A05:2021", "CWE-1004", "LOW",
        "Ajouter le flag HttpOnly sur tous les cookies de session.",
    ),
    "cookie:missing-secure": (
        "Cookie sans Secure",
        "A02:2021", "CWE-614", "MEDIUM",
        "Ajouter le flag Secure sur tous les cookies transmis sur HTTPS.",
    ),
    "cookie:missing-samesite": (
        "Cookie sans SameSite",
        "A05:2021", "CWE-1275", "LOW",
        "Ajouter SameSite=Strict ou SameSite=Lax sur les cookies de session.",
    ),
}

STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r'File ".*\.py", line \d+',
    r"in <module>",
    r"PHP Fatal error",
    r"PHP Warning:",
    r"Warning:.*on line \d+",
    r"at [\w.$<>]+\([\w./]+:\d+\)",   # Java/Kotlin stack trace
    r"RuntimeException",
    r"NullPointerException",
    r"System\.Exception:",
]

_STACK_RE = [re.compile(p) for p in STACK_TRACE_PATTERNS]


def _passive_score() -> ConfidenceScore:
    """Observation directe : score de confiance élevé mais reproductibilité honnête.

    Les findings passifs (headers manquants, cookies mal configurés) sont
    observationnels — pas de replay actif. La reproductibilité est réelle
    (la config est stable) mais pas vérifiée par un second test HTTP distinct.
    overall = 0.25*1.0 + 0.30*0.65 + 0.15*0.8 + 0.15*1.0 + 0.15*0.5 = 0.77
    """
    return ConfidenceScore(
        oracle_strength=1.0,
        reproducibility=0.65,    # config stable mais non re-testée
        observation_quality=0.8,
        behavioral_specificity=1.0,
        experiment_coverage=0.5, # une seule observation, pas de replay
        overall=0.77,
    )


class PassiveFindingEngine:
    """
    Génère des findings de configuration directement depuis les observations.
    Aucune expérience HTTP requise — ce sont des problèmes directement observables.
    """

    def __init__(self, bus: AsyncEventBus, repository: Repository) -> None:
        self._bus = bus
        self._repo = repository
        # Déduplication : (owasp_category, endpoint) → déjà signalé
        self._seen: set[str] = set()
        bus.on(OBSERVATION_RAW, self._on_observation)

    async def _on_observation(self, event: HDWPEvent) -> None:
        data = event.payload
        obs = RawObservation.model_validate(data) if isinstance(data, dict) else data
        if obs.response is None or obs.request is None:
            return

        for finding in self._analyse(obs):
            # Normaliser l'URL vers le path pattern pour éviter N findings
            # identiques sur /api/users/1, /api/users/2, etc.
            raw_endpoint = finding.affected_endpoints[0] if finding.affected_endpoints else ""
            from hdwp.core.model.url_utils import normalize_url_path
            path_key = normalize_url_path(raw_endpoint)
            dedup_key = f"{finding.owasp_category}:{finding.cwe_id}:{path_key}"
            if dedup_key in self._seen:
                continue
            self._seen.add(dedup_key)
            await self._repo.save_finding(finding)
            await self._bus.emit(FINDING_CONFIRMED, finding.model_dump(), source="passive_engine")
            log.info(
                "passive.finding",
                id=finding.id,
                severity=finding.severity,
                owasp=finding.owasp_category,
                cwe=finding.cwe_id,
            )

    def _analyse(self, obs: RawObservation) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_missing_headers(obs))
        findings.extend(self._check_server_disclosure(obs))
        findings.extend(self._check_cookie_flags(obs))
        findings.extend(self._check_stack_traces(obs))
        return findings

    def _check_missing_headers(self, obs: RawObservation) -> list[Finding]:
        findings = []
        for tag, (desc, owasp, cwe, severity) in MISSING_HEADER_FINDINGS.items():
            if tag in obs.tags:
                findings.append(self._make_finding(
                    obs, desc, owasp, cwe, severity,
                    remediation=f"Ajouter le header {tag.split(':')[1]} dans toutes les réponses HTTP.",
                    passive_tags=[tag],
                ))
        return findings

    def _check_server_disclosure(self, obs: RawObservation) -> list[Finding]:
        server_tags = [t for t in obs.tags if t.startswith("server:")]
        if not server_tags:
            return []
        return [self._make_finding(
            obs,
            description=f"Version serveur exposée : {server_tags[0].split(':', 1)[1]}",
            owasp="A05:2021",
            cwe="CWE-200",
            severity="INFO",
            remediation="Supprimer ou généraliser le header Server / X-Powered-By.",
        )]

    def _check_cookie_flags(self, obs: RawObservation) -> list[Finding]:
        findings = []
        for tag, (desc, owasp, cwe, severity, remediation) in COOKIE_FLAG_FINDINGS.items():
            if tag in obs.tags:
                findings.append(self._make_finding(obs, desc, owasp, cwe, severity, remediation, passive_tags=[tag]))
        return findings

    def _check_stack_traces(self, obs: RawObservation) -> list[Finding]:
        body = str(obs.response.body or "") if obs.response else ""
        if not body:
            return []
        for pattern_re in _STACK_RE:
            if pattern_re.search(body):
                return [self._make_finding(
                    obs,
                    description="Stack trace exposée dans la réponse HTTP",
                    owasp="A05:2021",
                    cwe="CWE-209",
                    severity="MEDIUM",
                    remediation=(
                        "Désactiver les messages d'erreur détaillés en production. "
                        "Utiliser un gestionnaire d'erreurs générique."
                    ),
                )]
        return []

    def _make_finding(
        self,
        obs: RawObservation,
        description: str,
        owasp: str,
        cwe: str,
        severity: str,
        remediation: str,
        passive_tags: list[str] | None = None,
    ) -> Finding:
        assert obs.request is not None
        endpoint = obs.request.url
        return Finding(
            id=generate_id("FIND"),
            hypothesis_id="passive-observation",
            property_id="",
            status="CONFIRMED",
            confidence=0.96,
            confidence_breakdown=_passive_score(),
            owasp_category=owasp,
            cwe_id=cwe,
            severity=severity,
            affected_endpoints=[endpoint],
            proof={
                "observations": [obs.id],
                "experiments": [],
                "diffs": [],
                "reproduction_steps": [
                    f"1. Envoyer {obs.request.method} {endpoint}",
                    f"2. Observer la réponse : {description}",
                ],
                "passive_tags": passive_tags or [],
            },
            remediation_hint=remediation,
        )
