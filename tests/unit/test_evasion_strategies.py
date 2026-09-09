# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for the 8 evasion bypass strategies."""

from __future__ import annotations

from urllib.parse import urlparse, parse_qsl

import pytest

from hdwp.core.model.schemas import NormalizedRequest
from hdwp.core.payloads.waf_bypass.strategies.evasion import EVASION_STRATEGIES


def _get(name: str):
    for s in EVASION_STRATEGIES:
        if s.name == name:
            return s
    raise KeyError(f"Strategy {name!r} not found")


def _req(
    url: str = "http://target/api",
    method: str = "POST",
    headers: dict | None = None,
    body: object = None,
    query_params: dict | None = None,
) -> NormalizedRequest:
    return NormalizedRequest(
        method=method,
        url=url,
        headers=headers or {"Content-Type": "application/json"},
        body=body,
        query_params=query_params or {},
        path_params={},
    )


# ── whitespace_variation ──────────────────────────────────────────────────

class TestWhitespaceVariation:
    s = _get("whitespace_variation")

    def test_spaces_replaced_in_string_body(self):
        req = _req(body="SELECT 1 FROM users")
        result = self.s.apply(req, {})
        assert result.request.body == "SELECT\t1\tFROM\tusers"

    def test_spaces_replaced_in_dict_body_values(self):
        req = _req(body={"q": "hello world", "id": "no change"})
        result = self.s.apply(req, {})
        assert result.request.body["q"] == "hello\tworld"
        assert result.request.body["id"] == "no\tchange"

    def test_adds_xff_header_with_tab(self):
        req = _req()
        result = self.s.apply(req, {})
        assert result.request.headers["X-Forwarded-For"].endswith("\t")

    def test_raw_override_is_none(self):
        result = self.s.apply(_req(), {})
        assert result.raw_override is None


# ── junk_char ─────────────────────────────────────────────────────────────

class TestJunkChar:
    s = _get("junk_char")
    JUNK = "­‌"

    def test_injects_into_first_query_param(self):
        req = _req(query_params={"id": "test"})
        result = self.s.apply(req, {})
        assert self.JUNK in result.request.query_params["id"]

    def test_injects_into_body_dict_first_value(self):
        req = _req(body={"username": "admin"}, query_params={})
        result = self.s.apply(req, {})
        assert self.JUNK in str(result.request.body["username"])

    def test_custom_inject_pos(self):
        req = _req(query_params={"x": "abcde"})
        result = self.s.apply(req, {"inject_pos": 3})
        val = result.request.query_params["x"]
        assert val[:3] == "abc"
        assert self.JUNK in val

    def test_no_params_no_crash(self):
        req = _req(query_params={}, body=None)
        result = self.s.apply(req, {})
        assert result.request is not None


# ── cl_te_smuggling ───────────────────────────────────────────────────────

class TestClTeSmuggling:
    s = _get("cl_te_smuggling")

    def test_sets_raw_override(self):
        req = _req(body="payload")
        result = self.s.apply(req, {})
        assert result.raw_override is not None

    def test_te_header_has_trailing_space(self):
        req = _req(body="payload")
        result = self.s.apply(req, {})
        assert result.request.headers["Transfer-Encoding"] == "chunked "

    def test_raw_contains_chunked_encoding(self):
        req = _req(body="data")
        result = self.s.apply(req, {})
        assert b"\r\n" in result.raw_override

    def test_raw_contains_smuggled_prefix(self):
        req = _req(body="x")
        result = self.s.apply(req, {"smuggled_prefix": "POISON\r\n"})
        assert b"POISON" in result.raw_override

    def test_raw_ends_with_terminating_chunk(self):
        req = _req(body="body")
        result = self.s.apply(req, {})
        assert b"0\r\n\r\n" in result.raw_override


# ── te_cl_smuggling ───────────────────────────────────────────────────────

class TestTeClSmuggling:
    s = _get("te_cl_smuggling")

    def test_sets_raw_override(self):
        result = self.s.apply(_req(body="payload"), {})
        assert result.raw_override is not None

    def test_content_length_shorter_than_body(self):
        body = "abcde"
        req = _req(body=body)
        result = self.s.apply(req, {})
        cl = int(result.request.headers["Content-Length"])
        assert cl < len(body)

    def test_te_header_set(self):
        result = self.s.apply(_req(body="x"), {})
        assert result.request.headers["Transfer-Encoding"] == "chunked"


# ── hpp ───────────────────────────────────────────────────────────────────

class TestHpp:
    s = _get("hpp")

    def test_duplicates_target_param_in_url(self):
        req = _req(url="http://target/api?id=1", query_params={"id": "1"})
        result = self.s.apply(req, {"target_param": "id"})
        parsed = urlparse(result.request.url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        id_values = [v for k, v in pairs if k == "id"]
        assert len(id_values) == 2

    def test_safe_value_appears_before_payload(self):
        req = _req(url="http://target/api?id=PAYLOAD", query_params={"id": "PAYLOAD"})
        result = self.s.apply(req, {"target_param": "id", "safe_value": "SAFE"})
        url = result.request.url
        assert url.index("id=SAFE") < url.index("id=PAYLOAD")

    def test_auto_selects_first_param_when_no_target(self):
        req = _req(url="http://target/api?x=v", query_params={"x": "v"})
        result = self.s.apply(req, {})
        assert "x=" in result.request.url

    def test_raw_override_none(self):
        req = _req(query_params={"id": "1"})
        result = self.s.apply(req, {})
        assert result.raw_override is None


# ── multipart_boundary ────────────────────────────────────────────────────

class TestMultipartBoundary:
    s = _get("multipart_boundary")

    def test_changes_content_type(self):
        req = _req(body={"field": "value"})
        result = self.s.apply(req, {})
        ct = result.request.headers["Content-Type"]
        assert ct.startswith("multipart/form-data; boundary=")

    def test_boundary_is_unique(self):
        req = _req(body={"a": "1"})
        r1 = self.s.apply(req, {})
        r2 = self.s.apply(req, {})
        ct1 = r1.request.headers["Content-Type"]
        ct2 = r2.request.headers["Content-Type"]
        assert ct1 != ct2

    def test_body_contains_form_parts(self):
        req = _req(body={"key": "val"})
        result = self.s.apply(req, {})
        assert "Content-Disposition: form-data" in result.request.body

    def test_dict_fields_serialized(self):
        req = _req(body={"username": "admin", "password": "secret"})
        result = self.s.apply(req, {})
        body = result.request.body
        assert "admin" in body
        assert "secret" in body


# ── chunked_abuse ─────────────────────────────────────────────────────────

class TestChunkedAbuse:
    s = _get("chunked_abuse")

    def test_sets_raw_override(self):
        result = self.s.apply(_req(body="data"), {})
        assert result.raw_override is not None

    def test_raw_contains_chunk_extension(self):
        result = self.s.apply(_req(body="abc"), {})
        assert b";waf=bypass" in result.raw_override

    def test_raw_ends_with_terminating_chunk(self):
        result = self.s.apply(_req(body="abc"), {})
        assert result.raw_override.endswith(b"0\r\n\r\n")

    def test_te_header_set(self):
        result = self.s.apply(_req(body="x"), {})
        assert result.request.headers["Transfer-Encoding"] == "chunked"

    def test_custom_chunk_size(self):
        result = self.s.apply(_req(body="abcde"), {"chunk_size": 2})
        assert b";waf=bypass" in result.raw_override


# ── content_type_confusion ────────────────────────────────────────────────

class TestContentTypeConfusion:
    s = _get("content_type_confusion")

    def test_ebcdic_hint_appends_charset(self):
        req = _req(headers={"Content-Type": "application/json"})
        result = self.s.apply(req, {"confusion_mode": "ebcdic_hint"})
        assert result.request.headers["Content-Type"].endswith("; charset=ibm037")

    def test_ebcdic_hint_is_default(self):
        req = _req(headers={"Content-Type": "application/json"})
        result = self.s.apply(req, {})
        assert "ibm037" in result.request.headers["Content-Type"]

    def test_xml_facade_changes_content_type(self):
        result = self.s.apply(_req(), {"confusion_mode": "xml_facade"})
        assert result.request.headers["Content-Type"] == "text/xml; charset=utf-8"

    def test_form_encoded_serializes_dict_body(self):
        req = _req(body={"a": "1", "b": "2"})
        result = self.s.apply(req, {"confusion_mode": "form_encoded"})
        assert result.request.headers["Content-Type"] == "application/x-www-form-urlencoded"
        assert isinstance(result.request.body, str)
        assert "a=1" in result.request.body

    def test_raw_override_none_for_all_modes(self):
        for mode in ("ebcdic_hint", "xml_facade", "form_encoded"):
            result = self.s.apply(_req(body={"x": "1"}), {"confusion_mode": mode})
            assert result.raw_override is None


# ── All strategies have required fields ───────────────────────────────────

def test_all_evasion_strategies_have_required_fields():
    for s in EVASION_STRATEGIES:
        assert s.name
        assert s.category == "evasion"
        assert callable(s.apply)
        assert s.description
        assert s.risk_level in ("low", "medium", "high")
