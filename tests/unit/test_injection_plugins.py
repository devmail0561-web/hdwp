# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests pour les plugins d'injection (SQLi, XSS, SSTI)."""
import pytest

from hdwp.core.model.schemas import (
    ApplicationModelData,
    EndpointNode,
    ParameterNode,
)
from hdwp.plugins.core.injection.sqli import SQLiPlugin
from hdwp.plugins.core.injection.ssti import SSTIPlugin
from hdwp.plugins.core.injection.xss import XSSPlugin


def make_model_with_sql_param():
    """Modèle avec paramètre suspect pour SQLi."""
    ep = EndpointNode(path="/api/users", methods=["GET"])
    param = ParameterNode(name="id", location="query", type_inferred="integer")
    return ApplicationModelData(endpoints=[ep], parameters=[param])


def make_model_with_xss_param():
    """Modèle avec paramètre suspect pour XSS."""
    ep = EndpointNode(path="/api/comments", methods=["POST"])
    param = ParameterNode(name="comment", location="body", type_inferred="string")
    return ApplicationModelData(endpoints=[ep], parameters=[param])


def make_model_with_ssti_param():
    """Modèle avec paramètre suspect pour SSTI."""
    ep = EndpointNode(path="/render", methods=["POST"])
    param = ParameterNode(name="template", location="body", type_inferred="string")
    return ApplicationModelData(endpoints=[ep], parameters=[param])


def test_sqli_plugin_generates_hypotheses():
    """SQLiPlugin génère des hypothèses pour paramètres SQL-sensibles."""
    plugin = SQLiPlugin()
    model = make_model_with_sql_param()

    hypotheses = plugin.generate_hypotheses(model)

    assert len(hypotheses) == 1
    hyp = hypotheses[0]
    assert hyp.source_plugin == "core.injection.sqli"
    assert "id" in hyp.statement
    assert "injection SQL" in hyp.statement
    assert hyp.priority == "HIGH"
    # Vérifie qu'il y a plusieurs expériences (plusieurs payloads)
    assert len(hyp.required_experiments) > 0
    # Vérifie que mutation_type est field_injection
    assert all(exp.mutation_type == "field_injection" for exp in hyp.required_experiments)
    # Vérifie que payload_type est sqli
    assert all(exp.mutation_params.get("payload_type") == "sqli" for exp in hyp.required_experiments)


def test_sqli_plugin_infers_properties():
    """SQLiPlugin infère des propriétés INTEGRITY."""
    plugin = SQLiPlugin()
    model = make_model_with_sql_param()

    properties = plugin.infer_properties(model)

    assert len(properties) == 1
    prop = properties[0]
    assert prop.type.value == "integrity"
    assert "SQL injection" in prop.formal_statement


def test_sqli_plugin_no_hypotheses_empty_model():
    """SQLiPlugin ne génère rien sur un modèle vide."""
    plugin = SQLiPlugin()
    model = ApplicationModelData()

    assert plugin.generate_hypotheses(model) == []
    assert plugin.infer_properties(model) == []


def test_xss_plugin_generates_hypotheses():
    """XSSPlugin génère des hypothèses pour paramètres réfléchis."""
    plugin = XSSPlugin()
    model = make_model_with_xss_param()

    hypotheses = plugin.generate_hypotheses(model)

    assert len(hypotheses) == 1
    hyp = hypotheses[0]
    assert hyp.source_plugin == "core.injection.xss"
    assert "comment" in hyp.statement
    assert "XSS" in hyp.statement
    assert all(exp.mutation_params.get("payload_type") == "xss" for exp in hyp.required_experiments)


def test_xss_plugin_infers_properties():
    """XSSPlugin infère des propriétés INTEGRITY."""
    plugin = XSSPlugin()
    model = make_model_with_xss_param()

    properties = plugin.infer_properties(model)

    assert len(properties) == 1
    assert properties[0].type.value == "integrity"
    assert "XSS" in properties[0].formal_statement


def test_ssti_plugin_generates_hypotheses():
    """SSTIPlugin génère des hypothèses pour paramètres template."""
    plugin = SSTIPlugin()
    model = make_model_with_ssti_param()

    hypotheses = plugin.generate_hypotheses(model)

    assert len(hypotheses) == 1
    hyp = hypotheses[0]
    assert hyp.source_plugin == "core.injection.ssti"
    assert "template" in hyp.statement
    assert "SSTI" in hyp.statement
    assert all(exp.mutation_params.get("payload_type") == "ssti" for exp in hyp.required_experiments)
    # Vérifie que expected_result est présent
    assert any(
        exp.mutation_params.get("expected_result") for exp in hyp.required_experiments
    )


def test_ssti_plugin_infers_properties():
    """SSTIPlugin infère des propriétés INTEGRITY."""
    plugin = SSTIPlugin()
    model = make_model_with_ssti_param()

    properties = plugin.infer_properties(model)

    assert len(properties) == 1
    assert properties[0].type.value == "integrity"


def test_all_injection_plugins_have_correct_metadata():
    """Tous les plugins d'injection ont les métadonnées correctes."""
    plugins = [SQLiPlugin(), XSSPlugin(), SSTIPlugin()]

    for plugin in plugins:
        assert plugin.category == "injection"
        assert "A03:2021" in plugin.owasp_mapping
        assert plugin.cwe_mapping  # Au moins un CWE
        assert plugin.id.startswith("core.injection.")
        assert plugin.version == "1.0.0"
