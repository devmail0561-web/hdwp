# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""TokensScreen: saisie manuelle de credentials."""
from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Input, Label, RadioSet, Static

from hdwp.core.context.config_schema import CredentialConfig, RoleConfig


class TokensScreen(Screen):
    """Saisie manuelle de credentials."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "pop_screen", "Retour"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._tokens: list[RoleConfig] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="tokens-container"):
            yield Static("AJOUTER CREDENTIALS", id="tokens-title")
            yield Label("Role name :", id="role-label")
            yield Input(placeholder="user_a", id="role-input")
            yield Label("Type :", id="type-label")
            yield RadioSet(
                "Bearer",
                "Cookie",
                "API Key",
                id="type-radio",
            )
            yield Label("Token :", id="token-label")
            yield Input(placeholder="Bearer eyJ...", id="token-input")
            yield Static("", id="tokens-count")
            with Vertical(id="tokens-buttons"):
                yield Button("+ Ajouter", id="add-btn", variant="primary")
                yield Button("-> Continuer", id="continue-btn", variant="success")

    def _get_selected_type(self) -> str:
        radio = self.query_one("#type-radio", RadioSet)
        match radio.pressed_index:
            case 0:
                return "bearer"
            case 1:
                return "cookie"
            case 2:
                return "api_key"
            case _:
                return "bearer"

    def _action_add(self) -> None:
        """Ajoute le token courant a la liste."""
        role_name = self.query_one("#role-input", Input).value.strip()
        token = self.query_one("#token-input", Input).value.strip()
        if not role_name or not token:
            self.notify(
                "Role name et token requis",
                severity="error",
                timeout=2.0,
            )
            return
        role = RoleConfig(
            name=role_name,
            credentials=CredentialConfig(
                type=self._get_selected_type(),  # type: ignore[arg-type]
                token=token,
            ),
        )
        self._tokens.append(role)
        self.query_one("#role-input", Input).value = ""
        self.query_one("#token-input", Input).value = ""
        self.query_one("#tokens-count", Static).update(
            f"{len(self._tokens)} token(s) ajoute(s)"
        )
        self.notify(f"Token ajoute : {role.name}", severity="information", timeout=2.0)

    def _action_continue(self) -> None:
        """Retourne les tokens a TargetScreen."""
        self.dismiss(self._tokens)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        match event.button.id:
            case "add-btn":
                self._action_add()
            case "continue-btn":
                self._action_continue()
