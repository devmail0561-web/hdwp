# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from hdwp.store.credential_filter import REDACTED, filter_credentials


def test_authorization_header_redacted():
    data = {
        "request": {
            "headers": {"Authorization": "Bearer secret123", "Content-Type": "application/json"}
        }
    }
    result = filter_credentials(data)
    assert result["request"]["headers"]["Authorization"] == REDACTED
    assert result["request"]["headers"]["Content-Type"] == "application/json"


def test_body_content_not_redacted():
    data = {
        "request": {
            "headers": {"Content-Type": "application/json"},
            "body": {"authorization": "this-is-body-data", "token": "keep-me"},
        }
    }
    result = filter_credentials(data)
    assert result["request"]["body"]["authorization"] == "this-is-body-data"
    assert result["request"]["body"]["token"] == "keep-me"


def test_nested_dict_handling():
    data = {
        "request": {
            "headers": {
                "Authorization": "Bearer secret",
                "X-Api-Key": "key123",
            }
        },
        "response": {
            "headers": {
                "Set-Cookie": "session=abc",
                "Content-Length": "42",
            }
        },
    }
    result = filter_credentials(data)
    assert result["request"]["headers"]["Authorization"] == REDACTED
    assert result["request"]["headers"]["X-Api-Key"] == REDACTED
    assert result["response"]["headers"]["Set-Cookie"] == REDACTED
    assert result["response"]["headers"]["Content-Length"] == "42"


def test_non_sensitive_headers_preserved():
    data = {
        "headers": {"Content-Type": "text/html", "Accept": "application/json"}
    }
    result = filter_credentials(data)
    assert result["headers"]["Content-Type"] == "text/html"
    assert result["headers"]["Accept"] == "application/json"


def test_custom_sensitive_patterns():
    data = {
        "headers": {"X-Custom-Secret": "hidden", "Content-Type": "text/html"}
    }
    result = filter_credentials(data, sensitive_patterns=["X-Custom-Secret"])
    assert result["headers"]["X-Custom-Secret"] == REDACTED
    assert result["headers"]["Content-Type"] == "text/html"


def test_original_dict_not_mutated():
    data = {
        "headers": {"Authorization": "Bearer secret"}
    }
    original_value = data["headers"]["Authorization"]
    filter_credentials(data)
    assert data["headers"]["Authorization"] == original_value


def test_list_of_observations():
    data = {
        "observations": [
            {"headers": {"Authorization": "token1"}},
            {"headers": {"Authorization": "token2", "Accept": "*/*"}},
        ]
    }
    result = filter_credentials(data)
    assert result["observations"][0]["headers"]["Authorization"] == REDACTED
    assert result["observations"][1]["headers"]["Authorization"] == REDACTED
    assert result["observations"][1]["headers"]["Accept"] == "*/*"
