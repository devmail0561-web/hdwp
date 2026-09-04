# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests pour les plugins temporaux (SessionReplayPlugin)."""
import pytest

from hdwp.core.model.schemas import (
    ApplicationModelData,
    EndpointNode,
)
from hdwp.plugins.core.temporal.session_replay import SessionReplayPlugin


def make_model_with_auth_and_logout():
    """Modèle avec endpoint authentifié + logout."""
    auth_ep = EndpointNode(
        path="/api/profile",
        methods=["GET"],
        auth_required=True,
        roles_observed=["user"],
    )
    logout_ep = EndpointNode(path="/api/logout", methods=["POST"])
    return ApplicationModelData(endpoints=[auth_ep, logout_ep])


def make_model_no_logout():
    """Modèle avec endpoint authentifié mais sans logout."""
    auth_ep = EndpointNode(
        path="/api/profile",
        methods=["GET"],
        auth_required=True,
    )
    return ApplicationModelData(endpoints=[auth_ep])


def test_session_replay_plugin_generates_hypotheses():
    """SessionReplayPlugin génère des hypothèses si auth + logout présents."""
    plugin = SessionReplayPlugin()
    model = make_model_with_auth_and_logout()

    hypotheses = plugin.generate_hypotheses(model)

    assert len(hypotheses) >= 1
    hyp = hypotheses[0]
    assert hyp.source_plugin == "core.temporal.session_replay"
    assert "token" in hyp.statement.lower()
    assert "logout" in hyp.statement.lower()
    assert hyp.priority == "HIGH"
    # Vérifie mutation_type
    assert len(hyp.required_experiments) == 1
    exp = hyp.required_experiments[0]
    assert exp.mutation_type == "token_reuse"
    assert "authenticated_endpoint" in exp.mutation_params
    assert "logout_endpoint" in exp.mutation_params


def test_session_replay_plugin_infers_properties():
    """SessionReplayPlugin infère des propriétés TEMPORAL."""
    plugin = SessionReplayPlugin()
    model = make_model_with_auth_and_logout()

    properties = plugin.infer_properties(model)

    assert len(properties) == 1
    prop = properties[0]
    assert prop.type.value == "temporal"
    assert "token" in prop.formal_statement.lower()
    assert "logout" in prop.formal_statement.lower()


def test_session_replay_plugin_no_hypotheses_without_logout():
    """SessionReplayPlugin ne génère rien sans endpoint logout."""
    plugin = SessionReplayPlugin()
    model = make_model_no_logout()

    hypotheses = plugin.generate_hypotheses(model)

    # Pas de logout -> pas d'hypothèse
    assert len(hypotheses) == 0


def test_session_replay_plugin_no_properties_empty_model():
    """SessionReplayPlugin ne génère rien sur un modèle vide."""
    plugin = SessionReplayPlugin()
    model = ApplicationModelData()

    assert plugin.generate_hypotheses(model) == []
    assert plugin.infer_properties(model) == []


def test_session_replay_plugin_metadata():
    """SessionReplayPlugin a les métadonnées correctes."""
    plugin = SessionReplayPlugin()

    assert plugin.id == "core.temporal.session_replay"
    assert plugin.category == "temporal"
    assert "A07:2021" in plugin.owasp_mapping
    assert "CWE-613" in plugin.cwe_mapping
    assert plugin.version == "1.0.0"
