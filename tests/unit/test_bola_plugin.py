# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    EndpointNode,
    ParameterNode,
    PropertyType,
    RoleNode,
)
from hdwp.plugins.core.authorization.authz import AuthZPlugin
from hdwp.plugins.core.authorization.bola import BOLAPlugin


def _model_with_bola_param() -> ApplicationModelData:
    return ApplicationModelData(
        endpoints=[
            EndpointNode(
                id="EP-1",
                path="/api/users/{id_0}",
                methods=["GET"],
                auth_required=True,
                roles_observed=["user_a"],
                parameters=["PARAM-1"],  # wire endpoint → parameter
            )
        ],
        parameters=[
            ParameterNode(
                id="PARAM-1",
                name="id_0",
                location="path",
                type_inferred="integer",
                affects_object="OBJ-1",
            )
        ],
        roles=[
            RoleNode(id="R-1", name="user_a"),
            RoleNode(id="R-2", name="user_b"),
        ],
    )


def _model_without_bola() -> ApplicationModelData:
    return ApplicationModelData(
        endpoints=[
            EndpointNode(id="EP-1", path="/api/public", methods=["GET"])
        ],
        parameters=[
            ParameterNode(id="PARAM-1", name="q", location="query", type_inferred="string")
        ],
    )


def test_bola_infer_properties_with_bola_param() -> None:
    plugin = BOLAPlugin()
    props = plugin.infer_properties(_model_with_bola_param())
    assert len(props) == 1
    assert props[0].type == PropertyType.AUTHORIZATION
    assert "BOLA" in props[0].formal_statement
    assert props[0].inference_confidence == 0.85


def test_bola_generate_hypotheses_with_bola_param() -> None:
    plugin = BOLAPlugin()
    hyps = plugin.generate_hypotheses(_model_with_bola_param())
    assert len(hyps) == 1
    assert hyps[0].source_plugin == "core.authorization.bola"
    assert hyps[0].required_experiments[0].mutation_type == "object_ref_change"


def test_bola_no_properties_without_affects_object() -> None:
    plugin = BOLAPlugin()
    assert plugin.infer_properties(_model_without_bola()) == []
    assert plugin.generate_hypotheses(_model_without_bola()) == []


def test_authz_infer_properties() -> None:
    plugin = AuthZPlugin()
    props = plugin.infer_properties(_model_with_bola_param())
    assert len(props) == 1
    assert "restricted to roles" in props[0].formal_statement


def test_authz_generate_hypotheses() -> None:
    plugin = AuthZPlugin()
    model = _model_with_bola_param()
    hyps = plugin.generate_hypotheses(model)
    assert len(hyps) == 1
    assert hyps[0].required_experiments[0].mutation_type == "privilege_escalation"
    assert "user_b" in hyps[0].statement
