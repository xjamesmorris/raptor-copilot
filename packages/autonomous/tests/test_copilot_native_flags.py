"""Copilot-native CLI compatibility routing."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from raptor_agentic import (
    _copilot_native_audit_policy,
    _copilot_native_incompatible_flags,
    _copilot_native_model_plan,
    build_parser,
)


def _args(**overrides):
    values = {
        "sequential": False,
        "validate": False,
        "gap_audit": False,
        "gap_audit_budget": None,
        "gap_audit_strategy": None,
        "gap_audit_scope": [],
        "gap_audit_no_adversarial": False,
        "gap_audit_reserved_cost": None,
        "understand": False,
        "threat_model": False,
        "threat_model_only": False,
        "model": [],
        "consensus": None,
        "judge": None,
        "aggregate": None,
        "max_cost_usd": None,
        "binary": [],
        "binary_auto": False,
        "no_binary_oracle": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_validate_has_native_adapter():
    assert _copilot_native_incompatible_flags(
        _args(validate=True),
    ) == []


def test_parser_accepts_native_validate_combination():
    args = build_parser().parse_args([
        "--repo",
        "/tmp/target",
        "--copilot-native",
        "--validate",
    ])

    assert args.copilot_native is True
    assert args.validate is True
    assert _copilot_native_incompatible_flags(args) == []


def test_understand_and_threat_model_have_native_adapter():
    assert _copilot_native_incompatible_flags(
        _args(understand=True, threat_model=True),
    ) == []


def test_gap_audit_has_native_adapter():
    assert _copilot_native_incompatible_flags(
        _args(gap_audit=True),
    ) == []


def test_sequential_has_native_scheduler():
    assert _copilot_native_incompatible_flags(
        _args(sequential=True),
    ) == []


def test_model_roles_have_native_adapter():
    args = _args(
        model=["model-a", "model-b"],
        consensus="model-c",
        judge="model-d",
        aggregate="model-e",
    )

    assert _copilot_native_incompatible_flags(args) == []
    assert _copilot_native_model_plan(args) == {
        "enabled": True,
        "analysis_models": ["model-a", "model-b"],
        "consensus_model": "model-c",
        "judge_model": "model-d",
        "aggregate_model": "model-e",
        "canonical_model": "model-e",
    }


def test_parser_accepts_native_model_roles():
    args = build_parser().parse_args([
        "--repo",
        "/tmp/target",
        "--copilot-native",
        "--model",
        "model-a",
        "--model",
        "model-b",
        "--consensus",
        "model-c",
        "--judge",
        "model-d",
        "--aggregate",
        "model-e",
    ])

    assert _copilot_native_incompatible_flags(args) == []
    assert _copilot_native_model_plan(args)["canonical_model"] == "model-e"


def test_native_aggregate_requires_two_analysis_models():
    with pytest.raises(ValueError, match="at least two"):
        _copilot_native_model_plan(
            _args(
                model=["model-a"],
                aggregate="model-e",
            )
        )


def test_native_audit_policy_preserves_operator_scope(tmp_path):
    policy = _copilot_native_audit_policy(
        _args(
            gap_audit=True,
            validate=True,
            gap_audit_budget=25,
            gap_audit_strategy="auth",
            gap_audit_scope=["src/auth"],
            binary=["build/app"],
            binary_auto=True,
        ),
        tmp_path,
    )

    assert policy["validate_after"] is True
    assert policy["budget"] == 25
    assert policy["strategy"] == "auth"
    assert policy["scopes"] == ["src/auth"]
    assert policy["binary"] == ["build/app"]
    assert policy["binary_auto"] is True
    assert policy["coverage_policy"] == "map_grade_is_not_review"


def test_other_unadapted_flags_remain_refused():
    assert _copilot_native_incompatible_flags(
        _args(
            threat_model_only=True,
        ),
    ) == ["--threat-model-only"]


def test_agentic_routes_native_validate_to_finalizer_handoff():
    source = (
        Path(__file__).resolve().parents[3] / "raptor_agentic.py"
    ).read_text(encoding="utf-8")

    assert "validate_postpass=bool(args.validate)" in source
    assert "prepare_native_context_prepass" in source
    assert "_copilot_native_audit_policy" in source
    assert "_copilot_native_model_plan" in source
    assert "1 if args.sequential else args.max_parallel" in source
    assert "sequential=bool(args.sequential)" in source
    assert "context_handoff=" in source
    assert "if args.understand and not args.copilot_native:" in source
    assert "if args.threat_model and not args.copilot_native:" in source
    assert "if args.validate and not args.copilot_native:" in source
