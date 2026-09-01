# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.context.config_schema import (
    HDWPContextConfig,
    OptionsConfig,
    ScopeConfig,
    TargetConfig,
)
from hdwp.core.context.loader import EngineContext
from hdwp.core.context.scope_guard import ScopeGuard, ScopeVerdict


def _make_context(
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    allow_write: bool = False,
) -> EngineContext:
    return EngineContext(
        config=HDWPContextConfig(
            target=TargetConfig(base_url="http://localhost:8080", name="Test"),
            scope=ScopeConfig(
                include=include or ["http://localhost:8080/*"],
                exclude=exclude or [],
            ),
            options=OptionsConfig(allow_write=allow_write),
        ),
        base_url="http://localhost:8080",
        session_id="SESSION-test0001",
    )


def test_url_in_scope_allowed() -> None:
    guard = ScopeGuard(_make_context())
    assert guard.check("http://localhost:8080/api/users", "GET") == ScopeVerdict.ALLOWED


def test_url_out_of_scope_blocked() -> None:
    guard = ScopeGuard(_make_context())
    assert guard.check("http://evil.com/x", "GET") == ScopeVerdict.BLOCKED_OUT_OF_SCOPE


def test_excluded_url_blocked() -> None:
    guard = ScopeGuard(_make_context(exclude=["http://localhost:8080/logout"]))
    assert guard.check("http://localhost:8080/logout", "GET") == ScopeVerdict.BLOCKED_OUT_OF_SCOPE


def test_post_without_allow_write_blocked() -> None:
    guard = ScopeGuard(_make_context(allow_write=False))
    assert guard.check("http://localhost:8080/api/users", "POST") == ScopeVerdict.BLOCKED_DESTRUCTIVE


def test_post_with_allow_write_allowed() -> None:
    guard = ScopeGuard(_make_context(allow_write=True))
    assert guard.check("http://localhost:8080/api/users", "POST") == ScopeVerdict.ALLOWED


def test_put_patch_delete_blocked_without_allow_write() -> None:
    guard = ScopeGuard(_make_context(allow_write=False))
    for method in ("PUT", "PATCH", "DELETE"):
        assert guard.check("http://localhost:8080/api/x", method) == ScopeVerdict.BLOCKED_DESTRUCTIVE


def test_get_always_allowed_in_scope() -> None:
    guard = ScopeGuard(_make_context(allow_write=False))
    assert guard.check("http://localhost:8080/api/anything", "GET") == ScopeVerdict.ALLOWED


def test_case_insensitive_method() -> None:
    guard = ScopeGuard(_make_context(allow_write=False))
    assert guard.check("http://localhost:8080/api/x", "post") == ScopeVerdict.BLOCKED_DESTRUCTIVE
    assert guard.check("http://localhost:8080/api/x", "Post") == ScopeVerdict.BLOCKED_DESTRUCTIVE


def test_exclude_takes_precedence_over_include() -> None:
    guard = ScopeGuard(_make_context(
        include=["http://localhost:8080/*"],
        exclude=["http://localhost:8080/admin*"],
    ))
    assert guard.check("http://localhost:8080/admin/panel", "GET") == ScopeVerdict.BLOCKED_OUT_OF_SCOPE
    assert guard.check("http://localhost:8080/api/users", "GET") == ScopeVerdict.ALLOWED
