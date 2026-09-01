# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from hdwp.core.observation.normalizer import normalize_request, normalize_response


def test_parses_query_params_from_url() -> None:
    req = normalize_request("GET", "http://example.com/api?page=2&sort=name")
    assert req.query_params == {"page": "2", "sort": "name"}


def test_extracts_path_params() -> None:
    req = normalize_request("GET", "http://example.com/users/42/orders/7")
    assert req.path_params == {"param_0": "42", "param_1": "7"}


def test_extracts_uuid_path_params() -> None:
    req = normalize_request("GET", "http://example.com/users/550e8400-e29b-41d4-a716-446655440000")
    assert "param_0" in req.path_params
    assert req.path_params["param_0"] == "550e8400-e29b-41d4-a716-446655440000"


def test_redacts_authorization_header() -> None:
    req = normalize_request(
        "GET",
        "http://example.com/api",
        headers={"Authorization": "Bearer secret_token", "Accept": "application/json"},
    )
    assert req.headers["Authorization"] == "[REDACTED]"
    assert req.headers["Accept"] == "application/json"


def test_redacts_cookie_header() -> None:
    req = normalize_request(
        "GET",
        "http://example.com/api",
        headers={"Cookie": "session=abc123"},
    )
    assert req.headers["Cookie"] == "[REDACTED]"


def test_method_uppercased() -> None:
    req = normalize_request("get", "http://example.com/api")
    assert req.method == "GET"


def test_normalize_response_parses_json_body() -> None:
    resp = normalize_response(
        status_code=200,
        headers={"content-type": "application/json"},
        body='{"id": 1, "name": "test"}',
        timing_ms=50.0,
    )
    assert resp.body == {"id": 1, "name": "test"}
    assert resp.status_code == 200
    assert resp.timing_ms == 50.0


def test_normalize_response_sets_content_type() -> None:
    resp = normalize_response(
        status_code=200,
        headers={"content-type": "text/html; charset=utf-8"},
        body="<html></html>",
    )
    assert resp.content_type == "text/html; charset=utf-8"


def test_normalize_response_no_content_type() -> None:
    resp = normalize_response(status_code=204, headers={}, body=None)
    assert resp.content_type is None


def test_normalize_response_non_json_body_preserved() -> None:
    resp = normalize_response(
        status_code=200,
        headers={"content-type": "text/plain"},
        body="hello world",
    )
    assert resp.body == "hello world"
