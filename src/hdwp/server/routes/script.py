# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Routes API pour l'exécution de scripts POC d'exploitation."""
from __future__ import annotations

from pathlib import Path

import structlog
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from hdwp.core.exploit.script_runner import ScriptRunner

log = structlog.get_logger()

router = APIRouter()


class ScriptRunRequest(BaseModel):
    """Request body for script execution."""

    finding_id: str
    script_path: str
    env_vars: dict[str, str] = {}


@router.post("/script/run")
async def run_script(body: ScriptRunRequest, request: Request) -> dict:
    """Exécute un script POC pour un finding donné.

    Le contexte du finding (target_url, endpoint, param_name, cwe_id) est
    injecté comme variables d'environnement HDWP_*.

    Returns:
        {success, stdout, stderr, exit_code, elapsed_ms}
    """
    session = request.app.state.server_state.get_active()
    if not session or not session.repository:
        raise HTTPException(404, "Aucune session active")

    # Charger finding
    finding = await session.repository.get_finding(body.finding_id)
    if not finding:
        raise HTTPException(404, f"Finding {body.finding_id!r} introuvable")

    # Préparer contexte d'exécution
    context = {
        "finding_id": finding.id,
        "target_url": getattr(session, "target_url", ""),
        "endpoint": finding.affected_endpoints[0] if finding.affected_endpoints else "",
        "cwe_id": finding.cwe_id,
        "severity": finding.severity,
    }

    # Extraire param_name depuis proof.experiment_spec.mutation_params
    proof = finding.proof or {}
    exp_spec = proof.get("experiment_spec", {})
    if isinstance(exp_spec, dict):
        mutation_params = exp_spec.get("mutation_params", {})
        if isinstance(mutation_params, dict):
            param_name = mutation_params.get("parameter_name", "")
            if param_name:
                context["param_name"] = param_name

    # Résoudre et valider le chemin du script contre le répertoire templates
    templates_dir = (
        Path(__file__).parent.parent.parent / "core" / "exploit" / "templates"
    ).resolve()
    try:
        script_path = Path(body.script_path).resolve()
    except Exception:
        raise HTTPException(400, "Chemin de script invalide")

    # Bloquer path traversal : le script doit être dans le répertoire templates
    if not str(script_path).startswith(str(templates_dir)):
        raise HTTPException(403, "Accès refusé : le script doit être dans le répertoire templates")

    if not script_path.exists():
        raise HTTPException(404, f"Script introuvable: {body.script_path}")

    # Exécuter script
    runner = ScriptRunner()
    try:
        result = await runner.execute_script(script_path, context, body.env_vars)
        log.info(
            "script.executed",
            finding_id=body.finding_id,
            script=script_path.name,
            success=result.success,
            exit_code=result.exit_code,
        )
        return result.to_dict()
    except Exception as exc:
        log.error("script.execution_failed", error=str(exc), finding_id=body.finding_id)
        raise HTTPException(500, f"Erreur d'exécution: {exc}") from exc


@router.get("/script/templates")
async def list_script_templates() -> list[dict]:
    """Liste les templates de scripts disponibles.

    Returns:
        [{name, path, type, description}, ...]
    """
    # Trouver répertoire templates (relatif à ce fichier)
    current_file = Path(__file__)
    templates_dir = current_file.parent.parent.parent / "core" / "exploit" / "templates"

    if not templates_dir.exists():
        log.warning("script.templates_dir_not_found", path=str(templates_dir))
        return []

    templates = []
    for script_file in templates_dir.glob("*"):
        if script_file.suffix in {".py", ".sh", ".js"}:
            templates.append({
                "name": script_file.stem,
                "path": str(script_file.absolute()),
                "type": script_file.suffix[1:],  # Remove leading dot
                "description": _extract_script_description(script_file),
            })

    log.info("script.templates_listed", count=len(templates))
    return templates


def _extract_script_description(script_path: Path) -> str:
    """Extrait la description depuis la première ligne de doc du script.

    Pour Python: première ligne après le shebang
    Pour Shell: première ligne de commentaire après shebang
    """
    try:
        with script_path.open() as f:
            lines = [line.strip() for line in f.readlines()[:5]]  # Lire max 5 premières lignes

            # Skip shebang
            if lines and lines[0].startswith("#!"):
                lines = lines[1:]

            # Python: chercher docstring
            if script_path.suffix == ".py":
                for line in lines:
                    if '"""' in line or "'''" in line:
                        # Extraire contenu entre guillemets
                        desc = line.strip('"""').strip("'''").strip()
                        return desc if desc else "Script d'exploitation Python"

            # Shell/JS: chercher commentaire
            for line in lines:
                if line.startswith("#"):
                    desc = line[1:].strip()
                    if desc:
                        return desc

    except Exception as exc:
        log.warning("script.description_extraction_failed", script=script_path.name, error=str(exc))

    return "Script d'exploitation personnalisé"
