# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import importlib.metadata
import importlib.util
import sys

import structlog

from hdwp.plugins.base import HDWPPlugin

logger = structlog.get_logger()


class PluginRegistry:
    """Discovers and manages HDWP plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, HDWPPlugin] = {}
        self._enabled: set[str] = set()
        self._sources: dict[str, str] = {}

    def discover(self) -> None:
        """Discover plugins via importlib entry_points and ~/.hdwp/plugins/."""
        self._discover_entry_points()
        self._discover_user_plugins()
        self._load_config()
        self._wire_plugin_registries()

    def _wire_plugin_registries(self) -> None:
        """Appelle register_mutations() sur chaque plugin."""
        from hdwp.core import mutation_registry as _mr

        for plugin in self._plugins.values():
            for spec in plugin.register_mutations():
                try:
                    _mr.register(**spec)
                except Exception as exc:
                    logger.warning("plugin.register_mutation_failed",
                                   plugin_id=plugin.id, error=str(exc))

    def _instantiate_plugin(self, plugin_class: type) -> HDWPPlugin:
        return plugin_class()

    def _config_path(self):  # type: ignore[return]
        from hdwp.core.paths import HDWP_HOME
        return HDWP_HOME / "plugins_config.json"

    def _load_config(self) -> None:
        import json
        p = self._config_path()
        if not p.exists():
            self._enabled = set(self._plugins.keys())
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            self._enabled = set(data.get("enabled", list(self._plugins.keys())))
        except Exception:
            self._enabled = set(self._plugins.keys())

    def _save_config(self) -> None:
        import json
        p = self._config_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"enabled": sorted(self._enabled)}, indent=2), encoding="utf-8")

    def _discover_entry_points(self) -> None:
        """Discover plugins via importlib entry_points."""
        try:
            eps = importlib.metadata.entry_points(group="hdwp.plugins")
            for ep in eps:
                try:
                    plugin_class = ep.load()
                    plugin = self._instantiate_plugin(plugin_class)
                    self._plugins[plugin.id] = plugin
                    self._sources[plugin.id] = "builtin"
                    logger.debug("plugin.discovered", plugin_id=plugin.id)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "plugin.load_failed", entry_point=ep.name, error=str(exc)
                    )
        except Exception as exc:  # noqa: BLE001
            logger.warning("plugin.discovery_failed", error=str(exc))

    def _discover_user_plugins(self) -> None:
        """Discover plugins from ~/.hdwp/plugins/ directory."""
        from hdwp.core.paths import PLUGINS_DIR

        if not PLUGINS_DIR.exists():
            return

        for plugin_subdir in PLUGINS_DIR.iterdir():
            if not plugin_subdir.is_dir():
                continue
            plugin_file = plugin_subdir / "hdwp_plugin.py"
            if not plugin_file.exists():
                continue
            try:
                # Add plugin dir to sys.path temporarily
                sys.path.insert(0, str(plugin_subdir))
                try:
                    spec = importlib.util.spec_from_file_location(
                        "hdwp_plugin", plugin_file
                    )
                    if spec is None or spec.loader is None:
                        continue
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    plugin_class = getattr(module, "PLUGIN_CLASS", None)
                    if plugin_class is None:
                        continue
                    plugin = self._instantiate_plugin(plugin_class)
                    self._plugins[plugin.id] = plugin
                    self._sources[plugin.id] = "user"
                    logger.debug(
                        "plugin.user_discovered",
                        plugin_id=plugin.id,
                        path=str(plugin_file),
                    )
                finally:
                    # Remove from sys.path
                    if str(plugin_subdir) in sys.path:
                        sys.path.remove(str(plugin_subdir))
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "plugin.user_load_failed",
                    path=str(plugin_file),
                    error=str(exc),
                )

    def register(self, plugin: HDWPPlugin) -> None:
        self._plugins[plugin.id] = plugin

    def unregister(self, plugin_id: str) -> None:
        self._plugins.pop(plugin_id, None)
        self._enabled.discard(plugin_id)

    def enable(self, plugin_id: str) -> bool:
        if plugin_id in self._plugins:
            self._enabled.add(plugin_id)
            self._save_config()
            return True
        return False

    def disable(self, plugin_id: str) -> None:
        self._enabled.discard(plugin_id)
        self._save_config()

    def source_of(self, plugin_id: str) -> str:
        return self._sources.get(plugin_id, "builtin")

    def get(self, plugin_id: str) -> HDWPPlugin | None:
        return self._plugins.get(plugin_id)

    def list_all(self) -> list[HDWPPlugin]:
        return list(self._plugins.values())

    def list_enabled(self, tech_stack: set[str] | None = None) -> list[HDWPPlugin]:
        """Retourne les plugins activés.
        Si tech_stack est fourni, filtre les plugins qui requièrent une tech non détectée.
        """
        enabled = [p for pid, p in self._plugins.items() if pid in self._enabled]
        if tech_stack is None:
            return enabled
        result = []
        for p in enabled:
            required = p.tech_stack_required()
            if not required or required & tech_stack:
                result.append(p)
        return result

    def get_by_category(self, category: str) -> list[HDWPPlugin]:
        return [p for p in self._plugins.values() if p.category == category]

    def is_enabled(self, plugin_id: str) -> bool:
        return plugin_id in self._enabled
