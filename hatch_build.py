# Copyright (c) 2026 M. TENDENG
"""Hook Hatchling : build le frontend React avant de packager le wheel."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        app_dir = Path(__file__).parent / "src" / "hdwp" / "app"

        if not (app_dir / "package.json").exists():
            return

        # Skip frontend build in CI — tests don't need the React bundle
        if os.getenv("CI"):
            return

        # Skip rebuild if dist is already present (e.g. wheel built from sdist)
        if (app_dir / "dist" / "index.html").exists():
            build_data.setdefault("artifacts", [])
            build_data["artifacts"].append("src/hdwp/app/dist/")
            return

        # Use pnpm if lock file present, fallback to npm
        pkg_manager = "pnpm" if (app_dir / "pnpm-lock.yaml").exists() else "npm"

        if not (app_dir / "node_modules").exists():
            subprocess.run([pkg_manager, "install", "--frozen-lockfile", "--silent"],
                           cwd=app_dir, check=True)

        subprocess.run([pkg_manager, "run", "build", "--silent"], cwd=app_dir, check=True)

        build_data.setdefault("artifacts", [])
        build_data["artifacts"].append("src/hdwp/app/dist/")
