# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import re

import yaml
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from hdwp.core.exploit.strategy_registry import _default_registry
from hdwp.core.paths import EXPLOIT_STRATEGIES_DIR

router = APIRouter()

_SLUG_RE = re.compile(r'^user\.[a-z][a-z0-9_.]*$')

_STRATEGY_TEMPLATE = '''\
id: {strategy_id}
vuln_type: {vuln_type}
name: "{name}"
description: "{description}"
proof_type: {proof_type}
mode: sequential
tech_stack: {tech_stack}
params: {{}}

phases:
  - name: test
    inject: query_param
    payloads: []
    success:
      type: status_2xx
'''


class StrategyInfo(BaseModel):
    id: str
    name: str
    vuln_type: str
    description: str
    source: str
    proof_type: str
    tech_stack: list[str]
    params: dict
    phases_count: int
    enabled: bool


class ToggleRequest(BaseModel):
    strategy_id: str


class ScaffoldRequest(BaseModel):
    name: str
    id: str
    vuln_type: str
    proof_type: str = "network"
    description: str = ""
    tech_stack: list[str] = []


def _to_info(s, enabled_ids: set) -> StrategyInfo:
    return StrategyInfo(
        id=s.id, name=s.name, vuln_type=s.vuln_type,
        description=s.description, source=s.source,
        proof_type=s.proof_type, tech_stack=s.tech_stack,
        params=s.params, phases_count=len(s.phases),
        enabled=s.id in enabled_ids,
    )


@router.get("/strategies", response_model=list[StrategyInfo])
async def list_strategies(request: Request) -> list[StrategyInfo]:
    enabled_ids = {s.id for s in _default_registry.list_enabled()}
    return [_to_info(s, enabled_ids) for s in _default_registry.list_all()]


@router.post("/strategies/toggle")
async def toggle_strategy(req: ToggleRequest, request: Request) -> dict:
    enabled_ids = {s.id for s in _default_registry.list_enabled()}
    if req.strategy_id in enabled_ids:
        _default_registry.disable(req.strategy_id)
        return {"ok": True, "enabled": False, "strategy_id": req.strategy_id}
    _default_registry.enable(req.strategy_id)
    return {"ok": True, "enabled": True, "strategy_id": req.strategy_id}


@router.post("/strategies/scaffold")
async def scaffold_strategy(req: ScaffoldRequest, request: Request) -> dict:
    if not _SLUG_RE.match(req.id):
        raise HTTPException(422, "id doit commencer par 'user.' suivi d'un slug valide (minuscules, chiffres, _, .)")
    if not req.name:
        raise HTTPException(422, "name requis")
    EXPLOIT_STRATEGIES_DIR.mkdir(parents=True, exist_ok=True)
    yaml_file = EXPLOIT_STRATEGIES_DIR / f"{req.id.replace('.', '_')}.yaml"
    if yaml_file.exists():
        raise HTTPException(409, f"La stratégie '{req.id}' existe déjà dans {yaml_file}")
    tech_stack_yaml = yaml.dump(req.tech_stack, default_flow_style=True).strip()
    content = _STRATEGY_TEMPLATE.format(
        strategy_id=req.id,
        vuln_type=req.vuln_type,
        name=req.name.replace('"', "'"),
        description=(req.description or f"Stratégie utilisateur : {req.name}").replace('"', "'"),
        proof_type=req.proof_type,
        tech_stack=tech_stack_yaml,
    )
    yaml_file.write_text(content, encoding="utf-8")
    return {"ok": True, "path": str(yaml_file)}


@router.post("/strategies/reload")
async def reload_strategies(request: Request) -> list[StrategyInfo]:
    _default_registry.discover()
    enabled_ids = {s.id for s in _default_registry.list_enabled()}
    return [_to_info(s, enabled_ids) for s in _default_registry.list_all()]
