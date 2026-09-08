# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

import pytest

from hdwp.core.ml.embedders.response_embedder import ResponseEmbedder
from hdwp.core.model.schemas import NormalizedResponse


def _make_response(
    status: int = 200,
    body=None,
    headers: dict | None = None,
    timing_ms: float = 100.0,
) -> NormalizedResponse:
    return NormalizedResponse(
        status_code=status,
        body=body,
        headers=headers or {},
        timing_ms=timing_ms,
        content_type=None,
    )


def test_embed_returns_list_of_floats():
    vec = ResponseEmbedder().embed(_make_response())
    assert isinstance(vec, list)
    assert all(isinstance(x, float) for x in vec)


def test_embed_dimension_is_22():
    assert len(ResponseEmbedder().embed(_make_response())) == 22


def test_all_values_in_unit_interval():
    vec = ResponseEmbedder().embed(_make_response(status=404, body={"err": "not found"}))
    assert all(0.0 <= x <= 1.0 for x in vec)


def test_status_2xx_sets_correct_category():
    vec = ResponseEmbedder().embed(_make_response(status=200))
    assert vec[1] == 1.0  # 2xx
    assert vec[0] == 0.0  # 1xx


def test_status_4xx_sets_correct_category():
    vec = ResponseEmbedder().embed(_make_response(status=403))
    assert vec[3] == 1.0
    assert vec[1] == 0.0


def test_status_5xx_sets_correct_category():
    vec = ResponseEmbedder().embed(_make_response(status=500))
    assert vec[4] == 1.0


def test_status_categories_are_mutually_exclusive():
    for code in [100, 200, 301, 404, 503]:
        vec = ResponseEmbedder().embed(_make_response(status=code))
        assert sum(vec[0:5]) == pytest.approx(1.0)


def test_status_out_of_range_has_no_category():
    vec = ResponseEmbedder().embed(_make_response(status=600))
    assert sum(vec[0:5]) == pytest.approx(0.0)


def test_sql_error_signal_detected():
    body = {"error": "syntax error near 'OR 1=1'"}
    vec = ResponseEmbedder().embed(_make_response(body=body))
    assert vec[18] == 1.0


def test_oracle_error_signal_detected():
    body = {"error": "ORA-00942: table or view does not exist"}
    vec = ResponseEmbedder().embed(_make_response(body=body))
    assert vec[18] == 1.0


def test_stack_trace_signal_detected():
    body = {"message": "Traceback (most recent call last): File app.py"}
    vec = ResponseEmbedder().embed(_make_response(body=body))
    assert vec[19] == 1.0


def test_disclosure_signal_detected():
    body = {"debug": "/etc/passwd contents"}
    vec = ResponseEmbedder().embed(_make_response(body=body))
    assert vec[20] == 1.0


def test_template_injection_signal_detected():
    body = {"output": "{{7*7}}"}
    vec = ResponseEmbedder().embed(_make_response(body=body))
    assert vec[21] == 1.0


def test_csp_header_detected():
    vec = ResponseEmbedder().embed(
        _make_response(headers={"content-security-policy": "default-src 'self'"})
    )
    assert vec[12] == 1.0


def test_hsts_header_detected():
    vec = ResponseEmbedder().embed(
        _make_response(headers={"strict-transport-security": "max-age=31536000"})
    )
    assert vec[13] == 1.0


def test_no_security_headers_all_zero():
    vec = ResponseEmbedder().embed(_make_response(headers={}))
    assert all(v == 0.0 for v in vec[12:18])


def test_timing_normalized_at_max():
    vec = ResponseEmbedder().embed(_make_response(timing_ms=5000.0))
    assert vec[5] == pytest.approx(1.0)


def test_timing_normalized_at_zero():
    vec = ResponseEmbedder().embed(_make_response(timing_ms=0.0))
    assert vec[5] == pytest.approx(0.0)


def test_timing_clamped_above_max():
    vec = ResponseEmbedder().embed(_make_response(timing_ms=99999.0))
    assert vec[5] == pytest.approx(1.0)


def test_body_null_type():
    vec = ResponseEmbedder().embed(_make_response(body=None))
    assert vec[6] == 1.0   # null
    assert sum(vec[6:10]) == pytest.approx(1.0)


def test_body_dict_type():
    vec = ResponseEmbedder().embed(_make_response(body={"a": 1}))
    assert vec[7] == 1.0   # dict
    assert sum(vec[6:10]) == pytest.approx(1.0)


def test_body_list_type():
    vec = ResponseEmbedder().embed(_make_response(body=[1, 2, 3]))
    assert vec[8] == 1.0   # list
    assert sum(vec[6:10]) == pytest.approx(1.0)


def test_body_string_type():
    vec = ResponseEmbedder().embed(_make_response(body="hello"))
    assert vec[9] == 1.0   # str
    assert sum(vec[6:10]) == pytest.approx(1.0)


def test_key_count_normalized():
    body = {f"k{i}": i for i in range(10)}
    vec = ResponseEmbedder().embed(_make_response(body=body))
    assert vec[11] == pytest.approx(10 / 50.0)


def test_embed_deterministic():
    r = _make_response(status=200, body={"id": 1})
    embedder = ResponseEmbedder()
    assert embedder.embed(r) == embedder.embed(r)
