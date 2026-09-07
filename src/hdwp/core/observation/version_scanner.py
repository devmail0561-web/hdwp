# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
VersionScanner: détecte les bibliothèques JS/CSS vulnérables et crée des findings OWASP A06:2021.
Interroge OSV.dev (https://api.osv.dev/v1/querybatch) pour les CVEs.
"""
from __future__ import annotations

import re
import uuid
from typing import TYPE_CHECKING

import httpx
import structlog

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus
    from hdwp.store.repository import Repository

log = structlog.get_logger()

_CDN_PATTERNS = [
    re.compile(r'cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([0-9][^/]*)/', re.IGNORECASE),
    re.compile(r'cdn\.jsdelivr\.net/npm/([^@/]+)@([0-9][^/]*)', re.IGNORECASE),
    re.compile(r'unpkg\.com/([^@/]+)@([0-9][^/]*)', re.IGNORECASE),
]

_NAMED_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("jquery",    re.compile(r'(?:jQuery\.fn\.jquery|\$\.fn\.jquery)\s*=\s*["\']([0-9][^"\']+)', re.IGNORECASE)),
    ("react",     re.compile(r'React\.version\s*=\s*["\']([0-9][^"\']+)', re.IGNORECASE)),
    ("angular",   re.compile(r'angular\.version\.full\s*=\s*["\']([0-9][^"\']+)', re.IGNORECASE)),
    ("bootstrap", re.compile(r'Bootstrap\.VERSION\s*=\s*["\']([0-9][^"\']+)', re.IGNORECASE)),
    ("vue",       re.compile(r'Vue\.version\s*=\s*["\']([0-9][^"\']+)', re.IGNORECASE)),
    ("lodash",    re.compile(r'lodash\.VERSION\s*=\s*["\']([0-9][^"\']+)', re.IGNORECASE)),
]

_GENERIC_COMMENT = re.compile(r'/\*[!*]?\s*([A-Za-z][A-Za-z0-9.-]{2,})\s+v([0-9]+\.[0-9]+[^\s*]*)')

# Module-level cache: (lib, version) -> (vulns, cached_at_monotonic)
# TTL de 3600s : les CVEs ajoutées en cours de session seront détectées au prochain scan
_OSV_CACHE_TTL = 3600.0
_osv_cache: dict[tuple[str, str], tuple[list[dict], float]] = {}


def _extract_from_cdn_url(url: str) -> tuple[str, str] | None:
    for pattern in _CDN_PATTERNS:
        m = pattern.search(url)
        if m:
            lib = m.group(1).lower().split(".")[0]
            ver = m.group(2).split("/")[0]
            if lib and ver:
                return lib, ver
    return None


def _extract_from_js_content(content: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for lib_name, pattern in _NAMED_PATTERNS:
        m = pattern.search(content)
        if m:
            found.append((lib_name, m.group(1)))
    for m in _GENERIC_COMMENT.finditer(content[:2000]):
        lib = m.group(1).lower()
        ver = m.group(2)
        if (lib, ver) not in found:
            found.append((lib, ver))
    return found


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


async def _check_osv_batch(libs: list[tuple[str, str]]) -> dict[tuple[str, str], list[dict]]:
    import time
    now = time.monotonic()
    uncached = [
        lv for lv in libs
        if lv not in _osv_cache or (now - _osv_cache[lv][1]) > _OSV_CACHE_TTL
    ]
    if not uncached:
        return {lv: _osv_cache[lv][0] for lv in libs}

    queries = [
        {"package": {"name": lib, "ecosystem": "npm"}, "version": ver}
        for lib, ver in uncached
    ]
    try:
        from hdwp.core.http_client import build_client
        async with build_client(timeout=10.0) as client:
            resp = await client.post(
                "https://api.osv.dev/v1/querybatch",
                json={"queries": queries},
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])
            for i, (lib, ver) in enumerate(uncached):
                vulns = results[i].get("vulns", []) if i < len(results) else []
                _osv_cache[(lib, ver)] = (vulns, time.monotonic())
    except Exception as exc:
        log.warning("version_scanner.osv_failed", error=str(exc))
        # Ne PAS mettre en cache les erreurs réseau — une liste vide permanente
        # ferait croire que les bibliothèques sont saines sur les rescans suivants.

    return {lv: _osv_cache[lv][0] if lv in _osv_cache else [] for lv in libs}


async def scan_and_emit(
    script_urls: frozenset[str],
    script_contents: dict[str, str],
    script_pages: dict[str, list[str]],
    bus: AsyncEventBus,
    repository: Repository,
    model_accessor: object = None,  # callable → ApplicationModelData | None
) -> int:
    """Détecte les versions, interroge OSV.dev, crée findings ET hypothèses d'exploitation."""
    from hdwp.core.bus.events import FINDING_CONFIRMED, HYPOTHESIS_GENERATED
    from hdwp.core.model.schemas import ConfidenceScore, Finding

    detections: dict[tuple[str, str], list[str]] = {}

    for url in script_urls:
        result = _extract_from_cdn_url(url)
        if result:
            key = (result[0], result[1])
            pages = script_pages.get(url, [url])
            detections[key] = list(set(detections.get(key, []) + pages))

    for url, content in script_contents.items():
        for lib, ver in _extract_from_js_content(content):
            key = (lib, ver)
            pages = script_pages.get(url, [url])
            detections[key] = list(set(detections.get(key, []) + pages))

    if not detections:
        return 0

    log.info("version_scanner.detected", count=len(detections), libs=list(detections.keys()))

    vuln_map = await _check_osv_batch(list(detections.keys()))

    count = 0
    for (lib, ver), pages in detections.items():
        vulns = vuln_map.get((lib, ver), [])
        if not vulns:
            continue

        max_cvss = 5.0
        for v in vulns:
            # OSV v1 API returns severity in a top-level "severity" array:
            # [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/.../AH"}]
            # The numeric base score must be parsed from the vector string.
            for sev in v.get("severity", []):
                sev_type = sev.get("type", "")
                # OSV retourne le score soit comme nombre, soit comme vecteur CVSS v3
                raw_score = sev.get("score", "")
                if isinstance(raw_score, (int, float)):
                    max_cvss = max(max_cvss, float(raw_score))
                    continue
                if not isinstance(raw_score, str):
                    continue
                # Score numérique direct (ex: "9.8")
                try:
                    max_cvss = max(max_cvss, float(raw_score))
                    continue
                except ValueError:
                    pass
                # Vecteur CVSS v3 : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                # Le score numérique n'est PAS dans le vecteur lui-même — il faut
                # l'extraire depuis le champ "baseScore" dans database_specific,
                # ou depuis l'alias "base_score" retourné par certains fournisseurs.
                # Pour les vecteurs purs sans score adjacent, dériver depuis les
                # composantes Impact (C/I/A) : H→9.8, L→4.0, N→0.0 (approximation).
                if sev_type.upper() in ("CVSS_V3", "CVSS_V2") and raw_score.startswith("CVSS:"):
                    cia = re.findall(r':([HLN])', raw_score[-9:])
                    if cia:
                        weights = {"H": 3, "L": 1, "N": 0}
                        impact = sum(weights.get(c, 0) for c in cia[-3:])
                        # H/H/H (9) → ~9.8 ; L/L/L (3) → ~4.0 ; N/N/N (0) → 0.0
                        approx = round(impact * 9.8 / 9, 1)
                        max_cvss = max(max_cvss, approx)
            # Also honour database_specific fields that some ecosystems populate
            db = v.get("database_specific", {})
            for _key in ("cvss_v3", "cvss"):
                _nested = db.get(_key, {})
                if isinstance(_nested, dict):
                    _score = _nested.get("base_score") or _nested.get("score")
                    if isinstance(_score, (int, float)):
                        max_cvss = max(max_cvss, float(_score))

        cve_ids = [v["id"] for v in vulns[:5]]
        finding = Finding(
            id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
            hypothesis_id="",
            property_id="",
            status="CONFIRMED",
            confidence=0.95,
            confidence_breakdown=ConfidenceScore(
                oracle_strength=1.0,
                reproducibility=1.0,
                observation_quality=0.9,
                behavioral_specificity=0.9,
                experiment_coverage=0.9,
                overall=0.95,
            ),
            owasp_category="A06:2021",
            cwe_id="CWE-1395",
            severity=_severity_from_cvss(max_cvss),
            affected_endpoints=pages[:10],
            proof={
                "library": lib,
                "version": ver,
                "cve_ids": cve_ids,
                "mutation_type": "static_analysis",
                "reproduction_steps": [
                    f"{lib} v{ver} détecté",
                    f"CVEs: {', '.join(cve_ids)}",
                ],
            },
            remediation_hint=f"Mettre à jour {lib} vers la dernière version stable.",
        )

        await repository.save_finding(finding)
        await bus.emit(FINDING_CONFIRMED, finding.model_dump(), source="version_scanner")
        log.info("version_scanner.finding", lib=lib, version=ver, cves=cve_ids)
        count += 1

        # Générer des hypothèses d'exploitation si le modèle est disponible
        if model_accessor is not None:
            try:
                from hdwp.core.observation.cve_to_exploit_map import generate_cve_hypotheses
                model = model_accessor()  # type: ignore[operator]
                if model is not None:
                    # Attacher le CVSS aux vulns pour la génération
                    for v in vulns:
                        v["_cvss"] = max_cvss
                    exploit_hyps = generate_cve_hypotheses(lib, ver, vulns, model)
                    for hyp in exploit_hyps:
                        await bus.emit(
                            HYPOTHESIS_GENERATED,
                            hyp.model_dump(),
                            source="cve_exploit_generator",
                        )
                    if exploit_hyps:
                        log.info(
                            "version_scanner.exploit_hypotheses",
                            lib=lib, version=ver,
                            hypotheses=len(exploit_hyps),
                        )
            except Exception as exc:
                log.warning("version_scanner.exploit_gen_failed", error=str(exc))

    return count


# ── OSV multi-écosystème pour les frameworks backend ─────────────────────────

_TECH_TO_OSV: dict[str, tuple[str, str]] = {
    "framework:django":   ("django",                          "PyPI"),
    "framework:flask":    ("flask",                           "PyPI"),
    "framework:fastapi":  ("fastapi",                         "PyPI"),
    "framework:rails":    ("rails",                           "RubyGems"),
    "framework:laravel":  ("laravel/framework",               "Packagist"),
    "framework:spring":   ("org.springframework:spring-core", "Maven"),
    "framework:express":  ("express",                         "npm"),
    "framework:nextjs":   ("next",                            "npm"),
    "framework:aspnet":   ("Microsoft.AspNetCore.App",        "NuGet"),
}

_OWASP_FOR_BACKEND_CVE = "A06:2021"


async def scan_backend_cves(
    tech_stack: list[str],
    detected_versions: dict[str, str],
    knowledge_base: object | None = None,
    offline_db_path: str | None = None,
) -> list[dict]:
    """Interroge OSV.dev pour les CVE des frameworks backend détectés.

    Requiert detected_versions pour filtrer par version — sans version connue,
    les résultats OSV ne sont pas exploitables.
    Persiste les résultats dans KnowledgeBase si fournie.

    Mode offline : charge depuis offline_db_path (JSON) au lieu d'interroger OSV.
    """
    import json
    import time

    if offline_db_path:
        try:
            with open(offline_db_path) as f:
                return json.load(f)
        except Exception as exc:
            log.warning("version_scanner.offline_db_failed", error=str(exc))
            return []

    sigs: list[dict] = []
    queries_to_make: list[tuple[str, str, str, str]] = []  # (tech_tag, package, ecosystem, version)

    for tech_tag in tech_stack:
        if tech_tag not in _TECH_TO_OSV:
            continue
        package, ecosystem = _TECH_TO_OSV[tech_tag]
        version = detected_versions.get(tech_tag, "")
        if not version:
            continue  # sans version, OSV retourne tous les CVE non filtrés
        queries_to_make.append((tech_tag, package, ecosystem, version))

    if not queries_to_make:
        return []

    queries = [
        {"package": {"name": pkg, "ecosystem": eco}, "version": ver}
        for _, pkg, eco, ver in queries_to_make
    ]

    try:
        from hdwp.core.http_client import build_client
        async with build_client(timeout=15.0) as client:
            resp = await client.post(
                "https://api.osv.dev/v1/querybatch",
                json={"queries": queries},
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])

        for i, (tech_tag, package, ecosystem, version) in enumerate(queries_to_make):
            vulns = results[i].get("vulns", []) if i < len(results) else []
            for vuln in vulns:
                cvss = 0.0
                for sev in vuln.get("severity", []):
                    score = sev.get("score", "")
                    if isinstance(score, (int, float)):
                        cvss = max(cvss, float(score))
                    elif isinstance(score, str) and score.replace(".", "").isdigit():
                        cvss = max(cvss, float(score))

                fixed = ""
                for aff in vuln.get("affected", []):
                    for rng in aff.get("ranges", []):
                        for evt in rng.get("events", []):
                            if "fixed" in evt:
                                fixed = evt["fixed"]
                                break

                sig = {
                    "vuln_id": vuln.get("id", ""),
                    "ecosystem": ecosystem,
                    "package": package,
                    "version_range": f">={version}",
                    "fixed_version": fixed,
                    "cvss_score": cvss,
                    "owasp_category": _OWASP_FOR_BACKEND_CVE,
                    "attack_vector": tech_tag,
                }
                sigs.append(sig)
                log.info(
                    "version_scanner.backend_cve",
                    vuln_id=sig["vuln_id"], package=package,
                    ecosystem=ecosystem, version=version, cvss=cvss,
                )

    except Exception as exc:
        log.warning("version_scanner.osv_backend_failed", error=str(exc))

    if sigs and knowledge_base is not None:
        try:
            await knowledge_base.upsert_vuln_signatures(sigs)  # type: ignore[attr-defined]
        except Exception as exc:
            log.warning("version_scanner.kb_upsert_failed", error=str(exc))

    return sigs


def extract_framework_versions(
    tech_stack: list[str],
    observed_headers: dict[str, str],
    error_page_content: str = "",
) -> dict[str, str]:
    """Extrait les versions des frameworks depuis les headers HTTP et les pages d'erreur.

    Retourne {tech_tag: version_string}.
    """
    import re
    versions: dict[str, str] = {}

    # Headers : X-Powered-By: PHP/8.1.2, Server: gunicorn/21.2.0
    for header_name, header_val in observed_headers.items():
        h = header_name.lower()
        if h in ("x-powered-by", "server"):
            # PHP/8.1.2
            m = re.search(r'php/(\d+\.\d+[\.\d]*)', header_val, re.I)
            if m:
                versions["framework:php"] = m.group(1)
            # gunicorn/21.2.0
            m = re.search(r'gunicorn/(\d+\.\d+[\.\d]*)', header_val, re.I)
            if m:
                versions["server:gunicorn"] = m.group(1)
            # Express (version rarement dans le header, mais parfois)
            m = re.search(r'express/(\d+\.\d+[\.\d]*)', header_val, re.I)
            if m:
                versions["framework:express"] = m.group(1)

    # Error page content : Django debug, Rails error, Spring whitespace
    if error_page_content:
        # Django version dans la page 500
        m = re.search(r'Django version (\d+\.\d+[\.\d]*)', error_page_content)
        if m:
            versions["framework:django"] = m.group(1)
        # Rails version
        m = re.search(r'Rails (\d+\.\d+[\.\d]*)', error_page_content)
        if m:
            versions["framework:rails"] = m.group(1)
        # Flask/Werkzeug version
        m = re.search(r'Werkzeug/(\d+\.\d+[\.\d]*)', error_page_content)
        if m:
            versions["framework:flask"] = m.group(1)
        # Spring Boot version
        m = re.search(r'"Spring Boot".*?"(\d+\.\d+[\.\d]*)"', error_page_content)
        if m:
            versions["framework:spring"] = m.group(1)

    return versions
