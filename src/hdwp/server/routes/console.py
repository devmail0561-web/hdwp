# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Route pour recevoir les erreurs JS injectées via le proxy MITM."""
from __future__ import annotations

import structlog
from fastapi import APIRouter, Request

log = structlog.get_logger()
router = APIRouter()


@router.post("/__hdwp_console__")
async def receive_console_logs(request: Request) -> dict:
    """Reçoit les erreurs JS collectées par le snippet injecté dans les pages HTML."""
    try:
        data = await request.json()
        if isinstance(data, list):
            for entry in data[:20]:
                level = entry.get("t", "unknown")
                message = str(entry.get("m", ""))[:200]
                src = entry.get("src", "")
                line = entry.get("line", "")
                log.info("browser.console", level=level, message=message, src=src, line=line)
    except Exception:
        pass
    return {"ok": True}
