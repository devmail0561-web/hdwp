# Copyright (c) 2026 M. TENDENG
"""Hook Hatchling : build le frontend React avant de packager le wheel."""
from __future__ import annotations

import subprocess
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        app_dir = Path(__file__).parent / "src" / "hdwp" / "app"

        if not (app_dir / "package.json").exists():
            return

        if not (app_dir / "node_modules").exists():
            subprocess.run(["npm", "ci", "--silent"], cwd=app_dir, check=True)

        subprocess.run(["npm", "run", "build", "--silent"], cwd=app_dir, check=True)

        build_data.setdefault("artifacts", [])
        build_data["artifacts"].append("src/hdwp/app/dist/")
