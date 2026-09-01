# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for MutationRegistry."""
from __future__ import annotations

import pytest

from hdwp.core.mutation_registry import (
    all_mutations,
    assess,
    get,
    owasp_cwe,
    register,
    remediation,
    specificity,
)


class TestMutationRegistry:
    def test_builtins_registered(self) -> None:
        mutations = all_mutations()
        assert "identity_swap" in mutations
        assert "object_ref_change" in mutations
        assert "privilege_escalation" in mutations
        assert "field_injection" in mutations
        assert "jwt_manipulation" in mutations
        assert "origin_test" in mutations

    def test_get_returns_spec(self) -> None:
        spec = get("identity_swap")
        assert spec is not None
        assert spec.name == "identity_swap"
        assert spec.owasp_category == "A01:2021"
        assert spec.cwe_id == "CWE-639"

    def test_get_unknown_returns_none(self) -> None:
        assert get("unknown_mutation") is None

    def test_owasp_cwe_known(self) -> None:
        owasp, cwe = owasp_cwe("identity_swap")
        assert owasp == "A01:2021"
        assert cwe == "CWE-639"

    def test_owasp_cwe_unknown(self) -> None:
        owasp, cwe = owasp_cwe("unknown_mutation")
        assert owasp == "A01:2021"
        assert cwe == "CWE-284"

    def test_remediation_known(self) -> None:
        rem = remediation("identity_swap")
        assert "ownership" in rem.lower() or "Ownership" in rem

    def test_remediation_unknown(self) -> None:
        rem = remediation("unknown_mutation")
        assert "autorisation" in rem.lower() or "Autorisation" in rem

    def test_register_custom_mutation(self) -> None:
        register(
            name="custom_test",
            owasp_category="A99:2021",
            cwe_id="CWE-999",
            remediation="Custom fix.",
        )
        spec = get("custom_test")
        assert spec is not None
        assert spec.owasp_category == "A99:2021"
        assert spec.cwe_id == "CWE-999"
        assert spec.remediation == "Custom fix."
