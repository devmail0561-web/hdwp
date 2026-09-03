# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for MutationRegistry."""
from __future__ import annotations

import pytest

from hdwp.core.mutation_registry import (
    all_mutations,
    apply,
    assess,
    get,
    owasp_cwe,
    plan,
    register,
    remediation,
    specificity,
)
from hdwp.core.model.schemas import (
    ApplicationModelData,
    ConcreteExperimentPlan,
    ExperimentSpec,
    Hypothesis,
    NormalizedRequest,
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


class TestPluggableMutations:
    def test_builtin_has_plan_function(self) -> None:
        spec = get("identity_swap")
        assert spec is not None
        assert spec.plan_experiment is not None
        assert callable(spec.plan_experiment)

    def test_builtin_has_apply_function(self) -> None:
        spec = get("identity_swap")
        assert spec is not None
        assert spec.apply_mutation is not None
        assert callable(spec.apply_mutation)

    def test_plan_delegates_to_registered_function(self) -> None:
        hyp = Hypothesis(
            source_plugin="test",
            property_id="PROP-test",
            statement="test",
            required_experiments=[],
        )
        spec = ExperimentSpec(
            mutation_type="identity_swap",
            base_request=NormalizedRequest(method="GET", url="http://test"),
        )
        model = ApplicationModelData(roles=[])
        corpus: dict[str, list[tuple[str, NormalizedRequest]]] = {}
        result = plan("identity_swap", hyp, spec, model, corpus)
        assert isinstance(result, list)

    def test_plan_returns_empty_for_unknown(self) -> None:
        result = plan("unknown_mutation", None, None, None, {})
        assert result == []

    def test_apply_delegates_to_registered_function(self) -> None:
        plan_obj = ConcreteExperimentPlan(
            hypothesis_id="HYP-test",
            mutation_type="object_ref_change",
            baseline_request=NormalizedRequest(method="GET", url="http://test/api/1"),
            baseline_role="user",
            target_role=None,
            mutated_value="2",
            mutated_param_name="id",
            mutated_param_location="path",
            description="test",
            experiment_spec=ExperimentSpec(
                mutation_type="object_ref_change",
                base_request=NormalizedRequest(method="GET", url="http://test/api/1"),
            ),
        )
        result = apply("object_ref_change", plan_obj, None)
        assert result is not None
        assert "2" in result.url

    def test_apply_returns_none_for_unknown(self) -> None:
        result = apply("unknown_mutation", None, None)
        assert result is None

    def test_register_with_plan_and_apply(self) -> None:
        def my_plan(hyp, spec, model, corpus):
            return []

        def my_apply(plan_obj, sm):
            return plan_obj.baseline_request

        register(
            name="test_custom_mutation",
            owasp_category="A99:2021",
            cwe_id="CWE-999",
            remediation="Test fix.",
            plan_experiment=my_plan,
            apply_mutation=my_apply,
        )
        spec = get("test_custom_mutation")
        assert spec is not None
        assert spec.plan_experiment is my_plan
        assert spec.apply_mutation is my_apply
