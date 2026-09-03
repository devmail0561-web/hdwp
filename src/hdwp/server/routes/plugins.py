# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from hdwp.core.paths import PLUGINS_DIR

router = APIRouter()

_SLUG_RE = re.compile(r'^[a-z][a-z0-9_]*$')

_PLUGIN_TEMPLATE = '''\
from __future__ import annotations
from hdwp.plugins.base import HDWPPlugin
from hdwp.core.model.schemas import ApplicationModelData, Hypothesis, SecurityProperty


class {class_name}Plugin(HDWPPlugin):
    @property
    def id(self) -> str: return "{plugin_id}"

    @property
    def name(self) -> str: return "{display_name}"

    @property
    def version(self) -> str: return "0.1.0"

    @property
    def category(self) -> str: return "{category}"

    @property
    def description(self) -> str: return "{description}"

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        return []  # TODO

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        return []  # TODO


PLUGIN_CLASS = {class_name}Plugin
'''


class PluginInfo(BaseModel):
    id: str
    name: str
    version: str
    category: str
    enabled: bool
    source: str = "builtin"
    description: str = ""
    owasp_mapping: list[str] = []
    cwe_mapping: list[str] = []
    data_access: str = "MODEL_READ"


class ToggleRequest(BaseModel):
    plugin_id: str


def _registry(request: Request):
    return request.app.state.plugin_registry


def _plugin_to_info(p, registry) -> PluginInfo:
    return PluginInfo(
        id=p.id,
        name=p.name,
        version=p.version,
        category=p.category,
        enabled=registry.is_enabled(p.id),
        source=registry.source_of(p.id),
        description=getattr(p, "description", ""),
        owasp_mapping=list(p.owasp_mapping),
        cwe_mapping=list(p.cwe_mapping),
        data_access=getattr(p, "data_access", "MODEL_READ"),
    )


@router.get("/plugins", response_model=list[PluginInfo])
async def list_plugins(request: Request) -> list[PluginInfo]:
    reg = _registry(request)
    return [_plugin_to_info(p, reg) for p in reg.list_all()]


@router.get("/plugin/{plugin_id}", response_model=PluginInfo)
async def get_plugin(plugin_id: str, request: Request) -> PluginInfo:
    reg = _registry(request)
    p = reg.get(plugin_id)
    if not p:
        raise HTTPException(404, f"Plugin {plugin_id!r} introuvable")
    return _plugin_to_info(p, reg)


@router.post("/plugins/toggle")
async def toggle_plugin(req: ToggleRequest, request: Request) -> dict:
    reg = _registry(request)
    if reg.is_enabled(req.plugin_id):
        reg.disable(req.plugin_id)
        return {"ok": True, "enabled": False, "plugin_id": req.plugin_id}
    ok = reg.enable(req.plugin_id)
    return {"ok": ok, "enabled": ok, "plugin_id": req.plugin_id}


class ScaffoldRequest(BaseModel):
    name: str          # slug, ex: rate_limit_bypass
    id: str            # ex: user.rate_limit_bypass
    category: str = "authorization"
    description: str = ""


@router.post("/plugins/scaffold")
async def scaffold_plugin(req: ScaffoldRequest, request: Request) -> dict:
    if not _SLUG_RE.match(req.name):
        raise HTTPException(422, "name doit être en snake_case (lettres minuscules, chiffres, _)")
    if not req.id.startswith("user."):
        raise HTTPException(422, "id doit commencer par 'user.'")

    plugin_dir = PLUGINS_DIR / req.name
    if plugin_dir.exists():
        raise HTTPException(409, f"Un plugin '{req.name}' existe déjà dans {plugin_dir}")

    class_name = "".join(w.capitalize() for w in req.name.split("_"))
    display_name = req.name.replace("_", " ").title()
    content = _PLUGIN_TEMPLATE.format(
        class_name=class_name,
        plugin_id=req.id,
        display_name=display_name,
        category=req.category,
        description=req.description or f"Plugin utilisateur : {display_name}",
    )

    # Vérifier la syntaxe avant d'écrire
    try:
        compile(content, str(plugin_dir / "hdwp_plugin.py"), "exec")
    except SyntaxError as exc:
        raise HTTPException(500, f"Erreur de syntaxe dans le template généré : {exc}") from exc

    plugin_dir.mkdir(parents=True, exist_ok=False)
    plugin_file = plugin_dir / "hdwp_plugin.py"
    plugin_file.write_text(content, encoding="utf-8")

    return {"ok": True, "path": str(plugin_file), "class_name": f"{class_name}Plugin"}


@router.post("/plugins/reload")
async def reload_plugins(request: Request) -> list[PluginInfo]:
    reg = _registry(request)
    reg.discover()
    return [_plugin_to_info(p, reg) for p in reg.list_all()]
