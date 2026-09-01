# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from enum import Enum
from fnmatch import fnmatch

import structlog

from hdwp.core.context.loader import EngineContext

log = structlog.get_logger()

DESTRUCTIVE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class ScopeVerdict(str, Enum):
    ALLOWED = "allowed"
    BLOCKED_OUT_OF_SCOPE = "blocked_out_of_scope"
    BLOCKED_DESTRUCTIVE = "blocked_destructive"
    BLOCKED_RATE_LIMIT = "blocked_rate_limit"


class ScopeGuard:
    def __init__(self, context: EngineContext) -> None:
        self._include_patterns = context.config.scope.include
        self._exclude_patterns = context.config.scope.exclude
        self._allow_write = context.config.options.allow_write

    def check(self, url: str, method: str) -> ScopeVerdict:
        method_upper = method.upper()

        for pattern in self._exclude_patterns:
            if fnmatch(url, pattern):
                verdict = ScopeVerdict.BLOCKED_OUT_OF_SCOPE
                self._log(url, method_upper, verdict)
                return verdict

        in_scope = any(fnmatch(url, pattern) for pattern in self._include_patterns)
        if not in_scope:
            verdict = ScopeVerdict.BLOCKED_OUT_OF_SCOPE
            self._log(url, method_upper, verdict)
            return verdict

        if method_upper in DESTRUCTIVE_METHODS and not self._allow_write:
            verdict = ScopeVerdict.BLOCKED_DESTRUCTIVE
            self._log(url, method_upper, verdict)
            return verdict

        verdict = ScopeVerdict.ALLOWED
        self._log(url, method_upper, verdict)
        return verdict

    def _log(self, url: str, method: str, verdict: ScopeVerdict) -> None:
        log.info("scope_check", url=url, method=method, verdict=verdict.value)
