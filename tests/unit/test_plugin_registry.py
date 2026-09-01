# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.model.schemas import ApplicationModelData, Hypothesis, SecurityProperty
from hdwp.plugins.base import HDWPPlugin
from hdwp.plugins.registry import PluginRegistry


class _DummyPlugin(HDWPPlugin):
    def __init__(self, plugin_id: str = "test.dummy", cat: str = "authorization") -> None:
        self._id = plugin_id
        self._cat = cat

    @property
    def id(self) -> str:
        return self._id

    @property
    def name(self) -> str:
        return "Dummy"

    @property
    def version(self) -> str:
        return "0.0.1"

    @property
    def category(self) -> str:
        return self._cat

    def infer_properties(self, model: ApplicationModelData) -> list[SecurityProperty]:
        return []

    def generate_hypotheses(self, model: ApplicationModelData) -> list[Hypothesis]:
        return []


def test_register_and_get() -> None:
    reg = PluginRegistry()
    plug = _DummyPlugin()
    reg.register(plug)
    assert reg.get("test.dummy") is plug
    assert reg.get("nonexistent") is None


def test_enable_disable() -> None:
    reg = PluginRegistry()
    plug = _DummyPlugin()
    reg.register(plug)

    assert not reg.is_enabled("test.dummy")
    assert reg.enable("test.dummy") is True
    assert reg.is_enabled("test.dummy")

    reg.disable("test.dummy")
    assert not reg.is_enabled("test.dummy")


def test_enable_unknown_returns_false() -> None:
    reg = PluginRegistry()
    assert reg.enable("nope") is False


def test_list_enabled() -> None:
    reg = PluginRegistry()
    p1 = _DummyPlugin("p1")
    p2 = _DummyPlugin("p2")
    reg.register(p1)
    reg.register(p2)
    reg.enable("p1")

    enabled = reg.list_enabled()
    assert len(enabled) == 1
    assert enabled[0].id == "p1"


def test_get_by_category() -> None:
    reg = PluginRegistry()
    reg.register(_DummyPlugin("a", cat="authorization"))
    reg.register(_DummyPlugin("b", cat="injection"))
    reg.register(_DummyPlugin("c", cat="authorization"))

    auth_plugins = reg.get_by_category("authorization")
    assert len(auth_plugins) == 2
    assert reg.get_by_category("injection") == [reg.get("b")]


def test_unregister() -> None:
    reg = PluginRegistry()
    plug = _DummyPlugin()
    reg.register(plug)
    reg.enable("test.dummy")

    reg.unregister("test.dummy")
    assert reg.get("test.dummy") is None
    assert not reg.is_enabled("test.dummy")
