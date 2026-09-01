# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""TargetScreen: ecran de demarrage -- saisie URL + choix du mode credentials."""
from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Input, Label, RadioSet, Static

from hdwp.core.context.config_schema import RoleConfig


class TargetScreen(Screen):
    """Ecran de demarrage : saisie URL + choix du mode credentials."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("enter", "launch", "Lancer", show=True),
        Binding("q", "quit", "Quitter", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._manual_tokens: list[RoleConfig] = []

    def compose(self) -> ComposeResult:
        yield Static(
            "  ##  ## #####  ##   ## #####\n"
            "  ##  ## ##  ## ##   ## ##  ##  HYPOTHESIS-DRIVEN\n"
            "  ###### ##  ## ## # ## #####   WEB PENTESTING ENGINE\n"
            "  ##  ## ##  ## ##### ## ##\n"
            "  ##  ## #####  ###  ### ##",
            id="target-logo",
        )
        yield Label("TARGET URL", id="url-label")
        yield Input(placeholder="https://", id="url-input")
        yield Label("CREDENTIALS MODE", id="cred-label")
        yield RadioSet(
            "Auto -- proxy MITM (naviguez et connectez-vous dans Firefox)",
            "Fichier de contexte YAML",
            "Saisir les tokens manuellement",
            id="mode-radio",
        )
        with Vertical(id="yaml-container"):
            yield Label("Chemin du fichier YAML :", id="yaml-label")
            yield Input(placeholder="/chemin/vers/context.yaml", id="yaml-input")
        with Vertical(id="manual-container"):
            yield Static("", id="manual-tokens-info")
        with Vertical(id="target-buttons"):
            yield Button("[ENTER] Lancer l'analyse", id="launch-btn", variant="primary")
            yield Button("[C] Charger YAML", id="yaml-btn", variant="default")
            yield Button("[Q] Quitter", id="quit-btn", variant="error")

    def on_mount(self) -> None:
        self.query_one("#yaml-container", Vertical).display = False
        self.query_one("#manual-container", Vertical).display = False

    def _get_selected_mode(self) -> str:
        radio = self.query_one("#mode-radio", RadioSet)
        match radio.pressed_index:
            case 0:
                return "auto"
            case 1:
                return "yaml"
            case 2:
                return "manual"
            case _:
                return "auto"

    def _action_launch(self) -> None:
        """[ENTER] -- valider et lancer le scan."""
        url = self.query_one("#url-input", Input).value.strip()
        if not url.startswith(("http://", "https://")):
            self.notify(
                "URL invalide (doit commencer par http:// ou https://)",
                severity="error",
                timeout=3.0,
            )
            return

        mode = self._get_selected_mode()

        if mode == "yaml":
            yaml_path = Path(self.query_one("#yaml-input", Input).value.strip())
            if not yaml_path.exists():
                self.notify(
                    f"Fichier introuvable : {yaml_path}",
                    severity="error",
                    timeout=3.0,
                )
                return
            from hdwp.tui.screens.scan import ScanScreen

            self.app.push_screen(
                ScanScreen(
                    target_url=url,
                    mode="yaml",
                    context_path=yaml_path,
                )
            )
        elif mode == "manual":
            if not self._manual_tokens:
                self.notify(
                    "Aucun token saisi. Cliquez d'abord sur le mode manuel.",
                    severity="warning",
                    timeout=3.0,
                )
                return
            from hdwp.tui.screens.scan import ScanScreen

            self.app.push_screen(
                ScanScreen(
                    target_url=url,
                    mode="manual",
                    manual_tokens=self._manual_tokens,
                )
            )
        else:
            # mode "auto" : proxy MITM
            from hdwp.tui.screens.scan import ScanScreen

            self.app.push_screen(ScanScreen(target_url=url, mode="auto"))

    def _on_radio_changed(self, event: RadioSet.Changed) -> None:
        """Affiche/masque le champ YAML selon le mode selectionne."""
        yaml_container = self.query_one("#yaml-container", Vertical)
        manual_container = self.query_one("#manual-container", Vertical)
        yaml_container.display = event.radio_set.pressed_index == 1
        manual_container.display = event.radio_set.pressed_index == 2

        if event.radio_set.pressed_index == 2:
            from hdwp.tui.screens.tokens import TokensScreen

            def _on_tokens(tokens: list[RoleConfig] | None) -> None:
                if tokens:
                    self._manual_tokens = tokens
                    self.query_one("#manual-tokens-info", Static).update(
                        f"{len(tokens)} token(s) saisi(s)"
                    )

            self.app.push_screen(TokensScreen(), callback=_on_tokens)

    def action_quit(self) -> None:
        self.app.exit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        match event.button.id:
            case "launch-btn":
                self._action_launch()
            case "quit-btn":
                self.action_quit()
            case "yaml-btn":
                self.query_one("#mode-radio", RadioSet).pressed_index = 1
                self._on_radio_changed(
                    RadioSet.Changed(self.query_one("#mode-radio", RadioSet), 1)
                )
