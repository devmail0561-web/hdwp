# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for HDWP — Hypothesis-Driven Web Pentesting Engine

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_all, copy_metadata, collect_data_files, collect_submodules

SRC = Path("src")
HDWP_PKG = SRC / "hdwp"

# ── Collect full hdwp package (modules + data) ───────────────────────────────
datas, binaries, hiddenimports = collect_all("hdwp")

# ── Dist-info for importlib.metadata.entry_points ────────────────────────────
datas += copy_metadata("hdwp")

# ── Runtime dependencies metadata (needed by some libs) ──────────────────────
for pkg in ("typer", "rich", "sqlmodel", "fastapi", "uvicorn", "httpx",
            "pydantic", "structlog", "anyio", "starlette", "click"):
    try:
        datas += copy_metadata(pkg)
    except Exception:
        pass

# ── uvicorn internals loaded dynamically ─────────────────────────────────────
_uvicorn_hidden = collect_submodules("uvicorn")

# ── aiosqlite / SQLAlchemy async backend ─────────────────────────────────────
_sql_hidden = [
    "aiosqlite",
    "sqlalchemy.dialects.sqlite",
    "sqlalchemy.dialects.sqlite.aiosqlite",
    "_sqlite3",
]

# ── All core plugin modules (loaded via importlib entry_points) ───────────────
_plugin_hidden = collect_submodules("hdwp.plugins")

# ── websockets / h11 / h2 transports ─────────────────────────────────────────
_net_hidden = [
    "websockets",
    "websockets.legacy",
    "websockets.legacy.server",
    "h11",
    "httpcore",
    "httpcore._async",
    "httpcore._sync",
]

ALL_HIDDEN = (
    hiddenimports
    + _uvicorn_hidden
    + _sql_hidden
    + _plugin_hidden
    + _net_hidden
    + ["socksio", "yaml", "pyee", "pywebview"]
)

a = Analysis(
    ["hdwp_entry.py"],
    pathex=[str(SRC)],
    binaries=binaries,
    datas=datas,
    hiddenimports=ALL_HIDDEN,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # dev/test tools — not needed at runtime
        "pytest", "mypy", "ruff",
        # optional LLM/ML extras — exclude unless bundling them
        "anthropic", "openai", "numpy", "sklearn",
        # playwright — heavy, optional
        "playwright",
        # mitmproxy — optional proxy
        "mitmproxy",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="hdwp",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
