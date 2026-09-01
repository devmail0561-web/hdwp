# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from datetime import UTC, datetime

from hdwp.core.model.schemas import (
    ApplicationModelData,
    EndpointNode,
    ExperimentResult,
    ExperimentSpec,
    NormalizedRequest,
    NormalizedResponse,
    ParameterNode,
    RoleNode,
)
from hdwp.core.oracle.injection_oracle import assess_ssrf
from hdwp.core.oracle.violation_oracle import ViolationVerdict
from hdwp.plugins.core.information_flow.info_disclosure import InfoDisclosurePlugin
from hdwp.plugins.core.information_flow.ssrf import SSRFPlugin


def _make_model(**kwargs) -> ApplicationModelData:
    defaults = dict(endpoints=[], parameters=[], objects=[], roles=[], relations=[])
    defaults.update(kwargs)
    return ApplicationModelData(**defaults)


def _make_exp(body: object, status: int = 200, timing_ms: float = 100.0) -> ExperimentResult:
    spec = ExperimentSpec(
        mutation_type="field_injection",
        base_request=NormalizedRequest(method="GET", url="http://t/"),
        mutation_params={"payload": "test", "payload_type": "ssrf"},
    )
    return ExperimentResult(
        hypothesis_id="HYP-test",
        experiment_spec=spec,
        request_sent=NormalizedRequest(method="GET", url="http://t/"),
        response_received=NormalizedResponse(status_code=status, body=body, timing_ms=timing_ms),
        timing_ms=timing_ms,
        timestamp=datetime.now(UTC).isoformat(),
    )


# ── InfoDisclosurePlugin ──────────────────────────────────────────────────────

def test_info_disclosure_with_endpoints_generates_hypotheses() -> None:
    ep = EndpointNode(path="/api/users", methods=["GET"])
    model = _make_model(endpoints=[ep])
    hyps = InfoDisclosurePlugin().generate_hypotheses(model)
    assert len(hyps) >= 1
    assert hyps[0].source_plugin == "core.information_flow.info_disclosure"


def test_info_disclosure_empty_model_no_hypotheses() -> None:
    assert InfoDisclosurePlugin().generate_hypotheses(_make_model()) == []


def test_info_disclosure_infer_properties_with_endpoints() -> None:
    ep = EndpointNode(path="/api/users", methods=["GET"])
    props = InfoDisclosurePlugin().infer_properties(_make_model(endpoints=[ep]))
    assert len(props) == 1


def test_info_disclosure_max_3_hypotheses() -> None:
    eps = [EndpointNode(path=f"/api/ep{i}", methods=["GET"]) for i in range(10)]
    hyps = InfoDisclosurePlugin().generate_hypotheses(_make_model(endpoints=eps))
    assert len(hyps) <= 3


# ── SSRFPlugin ────────────────────────────────────────────────────────────────

def test_ssrf_no_url_params_no_properties() -> None:
    param = ParameterNode(name="name", location="query", type_inferred="string")
    model = _make_model(parameters=[param])
    assert SSRFPlugin().infer_properties(model) == []


def test_ssrf_url_param_generates_property() -> None:
    param = ParameterNode(name="redirect_url", location="query", type_inferred="string")
    model = _make_model(parameters=[param])
    props = SSRFPlugin().infer_properties(model)
    assert len(props) == 1
    assert "redirect_url" in props[0].formal_statement


def test_ssrf_url_param_generates_hypotheses() -> None:
    param = ParameterNode(name="callback", location="query", type_inferred="string")
    model = _make_model(parameters=[param])
    hyps = SSRFPlugin().generate_hypotheses(model)
    assert len(hyps) >= 1
    assert any("ssrf" in exp.mutation_params.get("payload_type", "") for exp in hyps[0].required_experiments)


# ── assess_ssrf ───────────────────────────────────────────────────────────────

def test_ssrf_etc_passwd_confirmed() -> None:
    exp = _make_exp("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:/usr/sbin:/bin/sh")
    result = assess_ssrf("file:///etc/passwd", exp)
    assert result.verdict == ViolationVerdict.CONFIRMED
    assert result.confidence_hint >= 0.9


def test_ssrf_connection_refused_ambiguous() -> None:
    exp = _make_exp("connection refused to 127.0.0.1:80")
    result = assess_ssrf("http://127.0.0.1", exp)
    assert result.verdict == ViolationVerdict.AMBIGUOUS


def test_ssrf_normal_response_refuted() -> None:
    exp = _make_exp({"status": "ok", "data": []})
    result = assess_ssrf("http://127.0.0.1", exp)
    assert result.verdict == ViolationVerdict.REFUTED
