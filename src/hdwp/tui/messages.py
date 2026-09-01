# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Textual Message classes for bridging the HDWP event bus to the TUI."""
from __future__ import annotations

from textual.message import Message


class BusEvent(Message):
    """Generic HDWP bus event forwarded to the TUI."""

    def __init__(self, event_type: str, payload: dict) -> None:
        super().__init__()
        self.event_type = event_type
        self.payload = payload


class FindingUpdate(Message):
    """A finding was confirmed -- update the findings table."""

    def __init__(self, finding_data: dict) -> None:
        super().__init__()
        self.finding_data = finding_data


class CredentialCaptured(Message):
    """A session token was captured through the proxy."""

    def __init__(self, data: dict) -> None:
        super().__init__()
        self.data = data


class EngineComplete(Message):
    """The HDWP engine finished its run."""

    def __init__(self, finding_count: int) -> None:
        super().__init__()
        self.finding_count = finding_count


class EngineError(Message):
    """The engine encountered an unrecoverable error."""

    def __init__(self, error: str) -> None:
        super().__init__()
        self.error = error


class StatusUpdate(Message):
    """Progress update from the engine pipeline."""

    def __init__(self, phase: str, progress: float, detail: str = "") -> None:
        super().__init__()
        self.phase = phase
        self.progress = progress
        self.detail = detail


class ProxyUnavailable(Message):
    """mitmproxy absent ou port occupe."""



class ProxyStarted(Message):
    """Proxy demarre avec succes."""

    def __init__(self, port: int = 8080) -> None:
        super().__init__()
        self.port = port
