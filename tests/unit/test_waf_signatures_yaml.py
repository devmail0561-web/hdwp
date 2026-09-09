# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for waf_signatures.yaml — structure and consistency with registry."""

from __future__ import annotations

import pytest

from hdwp.core.payloads.waf_bypass.bypass_registry import BypassRegistry


@pytest.fixture(autouse=True)
def reset_registry():
    BypassRegistry.reset_for_testing()
    yield
    BypassRegistry.reset_for_testing()


EXPECTED_WAFS = {"cloudflare", "aws_waf", "akamai", "imperva", "modsecurity", "f5_bigip"}


class TestWafSignaturesYaml:
    def test_all_six_waf_present(self):
        r = BypassRegistry()
        sigs = set(r.list_waf_signatures())
        assert EXPECTED_WAFS <= sigs

    def test_generic_fallback_present(self):
        r = BypassRegistry()
        assert "generic" in r.list_waf_signatures()

    def test_seven_total_entries(self):
        r = BypassRegistry()
        assert len(r.list_waf_signatures()) == 7

    def test_all_effective_bypasses_exist_in_registry(self):
        r = BypassRegistry()
        missing = []
        for waf_id, sig in r._waf_signatures.items():
            for bypass_name in sig.effective_bypasses:
                if r.get_by_name(bypass_name) is None:
                    missing.append(f"{waf_id}: {bypass_name}")
        assert missing == [], f"Missing strategies: {missing}"

    def test_each_waf_has_at_least_one_bypass(self):
        r = BypassRegistry()
        for waf_id, sig in r._waf_signatures.items():
            assert len(sig.effective_bypasses) >= 1, f"{waf_id} has no effective_bypasses"

    def test_cloudflare_has_hpp_as_first_bypass(self):
        r = BypassRegistry()
        sig = r._waf_signatures["cloudflare"]
        assert sig.effective_bypasses[0] == "hpp"

    def test_aws_waf_has_cl_te_smuggling(self):
        r = BypassRegistry()
        sig = r._waf_signatures["aws_waf"]
        assert "cl_te_smuggling" in sig.effective_bypasses

    def test_modsecurity_block_codes_include_406(self):
        r = BypassRegistry()
        sig = r._waf_signatures["modsecurity"]
        assert 406 in sig.block_status_codes

    def test_all_waf_block_403(self):
        r = BypassRegistry()
        for waf_id, sig in r._waf_signatures.items():
            assert 403 in sig.block_status_codes, f"{waf_id} missing 403 in block_status_codes"

    def test_waf_signatures_are_frozen(self):
        r = BypassRegistry()
        sig = r._waf_signatures["cloudflare"]
        with pytest.raises((AttributeError, TypeError)):
            sig.waf_id = "modified"  # type: ignore[misc]
