# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

import pytest

from hdwp.core.ml.embedders.endpoint_embedder import EndpointEmbedder
from hdwp.core.model.schemas import BehavioralProfile, EndpointNode, ParameterNode


def _make_endpoint(
    path: str = "/api/users",
    methods: list[str] | None = None,
    auth: bool = False,
    roles: list[str] | None = None,
    waf: str | None = None,
    is_graphql: bool = False,
    accepts_xml: bool = False,
    status_by_role: dict | None = None,
    behavioral_profile: BehavioralProfile | None = None,
    contains_privilege_field: bool = False,
    error_tech_signals: list[str] | None = None,
) -> EndpointNode:
    return EndpointNode(
        path=path,
        methods=methods or ["GET"],
        auth_required=auth,
        roles_observed=roles or [],
        detected_waf=waf,
        is_graphql=is_graphql,
        accepts_xml=accepts_xml,
        status_by_role=status_by_role or {},
        behavioral_profile=behavioral_profile,
        contains_privilege_field=contains_privilege_field,
        error_tech_signals=error_tech_signals or [],
    )


def _make_param(type_inferred: str = "string", location: str = "query") -> ParameterNode:
    return ParameterNode(
        name="p",
        location=location,  # type: ignore[arg-type]
        type_inferred=type_inferred,  # type: ignore[arg-type]
        is_user_controlled=True,
    )


def test_dimension_is_30():
    assert len(EndpointEmbedder().embed(_make_endpoint())) == 30


def test_all_values_in_unit_interval():
    ep = _make_endpoint(methods=["GET", "POST"], auth=True, roles=["admin", "user"])
    assert all(0.0 <= x <= 1.0 for x in EndpointEmbedder().embed(ep))


def test_get_method_sets_first_bit():
    ep = _make_endpoint(methods=["GET"])
    vec = EndpointEmbedder().embed(ep)
    assert vec[0] == 1.0  # GET
    assert vec[1] == 0.0  # POST


def test_post_method_sets_second_bit():
    ep = _make_endpoint(methods=["POST"])
    vec = EndpointEmbedder().embed(ep)
    assert vec[0] == 0.0
    assert vec[1] == 1.0


def test_delete_method_sets_fourth_bit():
    ep = _make_endpoint(methods=["DELETE"])
    vec = EndpointEmbedder().embed(ep)
    assert vec[3] == 1.0


def test_multiple_methods():
    ep = _make_endpoint(methods=["GET", "POST", "DELETE"])
    vec = EndpointEmbedder().embed(ep)
    assert vec[0] == 1.0
    assert vec[1] == 1.0
    assert vec[3] == 1.0
    assert vec[2] == 0.0  # PUT absent


def test_path_depth_normalized():
    ep = _make_endpoint(path="/api/v1/users")
    vec = EndpointEmbedder().embed(ep)
    assert vec[6] == pytest.approx(3 / 6.0)


def test_auth_required_bit_false():
    assert EndpointEmbedder().embed(_make_endpoint(auth=False))[7] == 0.0


def test_auth_required_bit_true():
    assert EndpointEmbedder().embed(_make_endpoint(auth=True))[7] == 1.0


def test_role_count_normalized():
    ep = _make_endpoint(roles=["admin", "user", "guest"])
    vec = EndpointEmbedder().embed(ep)
    assert vec[8] == pytest.approx(3 / 10.0)


def test_waf_absent_bit_zero():
    assert EndpointEmbedder().embed(_make_endpoint(waf=None))[26] == 0.0


def test_waf_present_bit_one():
    assert EndpointEmbedder().embed(_make_endpoint(waf="waf:cloudflare"))[26] == 1.0


def test_graphql_bit():
    assert EndpointEmbedder().embed(_make_endpoint(is_graphql=True))[28] == 1.0
    assert EndpointEmbedder().embed(_make_endpoint(is_graphql=False))[28] == 0.0


def test_accepts_xml_bit():
    assert EndpointEmbedder().embed(_make_endpoint(accepts_xml=True))[29] == 1.0
    assert EndpointEmbedder().embed(_make_endpoint(accepts_xml=False))[29] == 0.0


def test_contains_privilege_field_bit():
    assert EndpointEmbedder().embed(_make_endpoint(contains_privilege_field=True))[25] == 1.0
    assert EndpointEmbedder().embed(_make_endpoint(contains_privilege_field=False))[25] == 0.0


def test_param_type_distribution_integer():
    params = [_make_param("integer"), _make_param("integer"), _make_param("string")]
    vec = EndpointEmbedder().embed(_make_endpoint(), params=params)
    assert vec[9] == pytest.approx(2 / 3, abs=1e-4)   # integer = index 0
    assert vec[10] == pytest.approx(1 / 3, abs=1e-4)  # string = index 1


def test_param_location_distribution():
    params = [_make_param(location="query"), _make_param(location="body"), _make_param(location="query")]
    vec = EndpointEmbedder().embed(_make_endpoint(), params=params)
    assert vec[15] == pytest.approx(2 / 3, abs=1e-4)  # query = index 0
    assert vec[16] == pytest.approx(1 / 3, abs=1e-4)  # body = index 1


def test_param_features_zero_when_no_params():
    vec = EndpointEmbedder().embed(_make_endpoint(), params=None)
    assert all(v == 0.0 for v in vec[9:20])


def test_status_2xx_ratio():
    ep = _make_endpoint(status_by_role={"admin": 200, "user": 200, "anon": 403})
    vec = EndpointEmbedder().embed(ep)
    assert vec[22] == pytest.approx(2 / 3, abs=1e-4)
    assert vec[23] == pytest.approx(1 / 3, abs=1e-4)
    assert vec[24] == pytest.approx(0.0)


def test_status_all_forbidden():
    ep = _make_endpoint(status_by_role={"anon": 403, "user": 401})
    vec = EndpointEmbedder().embed(ep)
    assert vec[22] == pytest.approx(0.0)
    assert vec[23] == pytest.approx(1.0)


def test_behavioral_profile_normalized():
    bp = BehavioralProfile(mean=500.0, std=100.0, sample_count=10, max_zscore_seen=None)
    ep = _make_endpoint(behavioral_profile=bp)
    vec = EndpointEmbedder().embed(ep)
    assert vec[20] == pytest.approx(500.0 / 1000.0)
    assert vec[21] == pytest.approx(100.0 / 500.0)


def test_behavioral_profile_absent_zeros():
    ep = _make_endpoint(behavioral_profile=None)
    vec = EndpointEmbedder().embed(ep)
    assert vec[20] == 0.0
    assert vec[21] == 0.0


def test_error_tech_signals_normalized():
    ep = _make_endpoint(error_tech_signals=["django", "postgres"])
    vec = EndpointEmbedder().embed(ep)
    assert vec[27] == pytest.approx(2 / 5.0)


def test_deterministic():
    ep = _make_endpoint(methods=["GET", "DELETE"], auth=True)
    emb = EndpointEmbedder()
    assert emb.embed(ep) == emb.embed(ep)
