"""Pure construction and refusal tests for the synthetic Copilot probe."""

from __future__ import annotations

import dataclasses
import os
import shutil
from pathlib import Path

import pytest

from core.config import RaptorConfig
from core.llm import copilot_probe as probe_module
from core.llm.copilot_probe import (
    CopilotProbeCaptureMode,
    CopilotProbeRefused,
    CopilotRuntimeReceipt,
    build_copilot_probe_plan,
    execute_copilot_probe,
)
from core.llm.copilot_protocol import CandidateRequestedSettings
from core.testing import FakeCLIBehavior, make_hermetic_cli

FIXTURE = Path(__file__).parent / "fixtures" / "copilot_candidate" / "complete.jsonl"
SESSION_ID = "11111111-1111-4111-8111-111111111111"
PROMPT = b"Synthetic prompt content."
SECRET_ENV = "COPILOT_GITHUB_TOKEN"


def _owned_fake(tmp_path: Path):
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "copilot",
        FakeCLIBehavior(
            stdout=FIXTURE.read_text(encoding="utf-8"),
            secret_env_names=(SECRET_ENV,),
        ),
    )
    return workspace, workspace.owned_executable("copilot")


def _plan(capability, *, mode=CopilotProbeCaptureMode.CANDIDATE_ADMISSION):
    kwargs = {}
    if mode is CopilotProbeCaptureMode.RECORD_ONLY:
        kwargs = {
            "evidence_owner": "pytest",
            "evidence_retention_seconds": 3600,
        }
    return build_copilot_probe_plan(
        synthetic_capability=capability,
        prompt=PROMPT,
        model="synthetic-model-v1",
        reasoning_effort="max",
        context_tier="long_context",
        session_id=SESSION_ID,
        capture_mode=mode,
        timeout_s=30,
        **kwargs,
    )


def test_plan_is_nonspawning_and_prompt_free(tmp_path: Path) -> None:
    workspace, capability = _owned_fake(tmp_path)
    plan = _plan(capability)

    assert plan.prompt_bytes == len(PROMPT)
    assert len(plan.prompt_sha256) == 64
    assert PROMPT.decode() not in repr(plan)
    assert PROMPT.decode() not in repr(dataclasses.asdict(plan))
    assert PROMPT.decode() not in "\0".join(plan.argv)
    assert not plan.execution_marker.exists()
    assert workspace.invocations("copilot") == []


def test_test_session_defaults_to_copilot_transport_denial() -> None:
    assert os.environ["RAPTOR_COPILOT_TRANSPORT_DISABLED"] == "1"


def test_safe_env_preserves_only_the_denial_switch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RAPTOR_COPILOT_TRANSPORT_DISABLED", "1")
    monkeypatch.setenv("COPILOT_GITHUB_TOKEN", "must-not-cross")
    env = RaptorConfig.get_safe_env()
    assert env["RAPTOR_COPILOT_TRANSPORT_DISABLED"] == "1"
    assert "COPILOT_GITHUB_TOKEN" not in env
    stripped = RaptorConfig.strip_llm_env_vars(
        {"RAPTOR_COPILOT_TRANSPORT_DISABLED": "0"}
    )
    assert stripped["RAPTOR_COPILOT_TRANSPORT_DISABLED"] == "1"


def test_command_carries_exact_private_noninteractive_invariants(
    tmp_path: Path,
) -> None:
    workspace, capability = _owned_fake(tmp_path)
    plan = _plan(capability)
    argv = plan.argv

    expected_pairs = {
        "--model": "synthetic-model-v1",
        "--effort": "max",
        "--context": "long_context",
        "--session-id": SESSION_ID,
        "--output-format": "json",
        "--usage-output-file": str(plan.usage_output_path),
        "--log-dir": str(plan.log_dir),
        "--log-level": "none",
        "--secret-env-vars": SECRET_ENV,
        "-C": str(workspace.cwd),
    }
    for flag, value in expected_pairs.items():
        index = argv.index(flag)
        assert argv[index + 1] == value
    for flag in (
        "--no-auto-update",
        "--no-custom-instructions",
        "--no-ask-user",
        "--no-remote-export",
        "--disable-builtin-mcps",
        "--disallow-temp-dir",
        "--no-bash-env",
        "--available-tools=",
    ):
        assert flag in argv
    forbidden = (
        "-p",
        "--prompt",
        "--add-dir",
        "--share",
        "--share-gist",
        "--autopilot",
        "--plan",
        "--allow-all",
        "--allow-all-tools",
        "--allow-all-paths",
        "--allow-all-urls",
        "--prefer-version",
        "--server",
        "--headless",
        "--stdio",
    )
    assert not set(forbidden).intersection(argv)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("model", "auto"),
        ("reasoning_effort", ""),
        ("context_tier", ""),
        ("session_id", "not-a-uuid"),
    ],
)
def test_exact_request_settings_are_required(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    kwargs = {
        "synthetic_capability": capability,
        "prompt": PROMPT,
        "model": "synthetic-model-v1",
        "reasoning_effort": "max",
        "context_tier": "long_context",
        "session_id": SESSION_ID,
        "capture_mode": CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
        "timeout_s": 30,
    }
    kwargs[field] = value
    with pytest.raises((TypeError, ValueError)):
        build_copilot_probe_plan(**kwargs)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("prompt", "not-bytes"),
        ("prompt", b""),
        ("prompt", b"x" * (probe_module._MAX_PROMPT_BYTES + 1)),
        ("session_id", 7),
        ("session_id", "00000000-0000-1000-8000-000000000000"),
        ("capture_mode", "candidate_admission"),
        ("timeout_s", True),
        ("timeout_s", "30"),
        ("stream_limits", object()),
        ("reasoning_effort", None),
        ("context_tier", None),
    ],
    ids=[
        "prompt-type",
        "prompt-empty",
        "prompt-oversize",
        "session-type",
        "session-not-v4",
        "mode-type",
        "timeout-bool",
        "timeout-type",
        "limits-type",
        "effort-missing",
        "context-missing",
    ],
)
def test_plan_builder_rejects_malformed_public_contracts(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    kwargs = {
        "synthetic_capability": capability,
        "prompt": PROMPT,
        "model": "synthetic-model-v1",
        "reasoning_effort": "max",
        "context_tier": "long_context",
        "session_id": SESSION_ID,
        "capture_mode": CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
        "timeout_s": 30,
    }
    kwargs[field] = value
    with pytest.raises((TypeError, ValueError)):
        build_copilot_probe_plan(**kwargs)


@pytest.mark.parametrize("seconds", [True, 0, 30 * 24 * 60 * 60 + 1])
def test_record_only_rejects_malformed_retention_lifetime(
    tmp_path: Path,
    seconds: object,
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    with pytest.raises(ValueError, match="retention"):
        build_copilot_probe_plan(
            synthetic_capability=capability,
            prompt=PROMPT,
            model="synthetic-model-v1",
            reasoning_effort="max",
            context_tier="long_context",
            session_id=SESSION_ID,
            capture_mode=CopilotProbeCaptureMode.RECORD_ONLY,
            timeout_s=30,
            evidence_owner="pytest",
            evidence_retention_seconds=seconds,
        )


def test_candidate_mode_rejects_raw_evidence_retention(
    tmp_path: Path,
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    with pytest.raises(ValueError, match="does not retain"):
        build_copilot_probe_plan(
            synthetic_capability=capability,
            prompt=PROMPT,
            model="synthetic-model-v1",
            reasoning_effort="max",
            context_tier="long_context",
            session_id=SESSION_ID,
            capture_mode=CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
            timeout_s=30,
            evidence_owner="pytest",
            evidence_retention_seconds=60,
        )


def test_record_only_requires_explicit_retention_owner_and_lifetime(
    tmp_path: Path,
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    with pytest.raises(ValueError, match="evidence_owner"):
        build_copilot_probe_plan(
            synthetic_capability=capability,
            prompt=PROMPT,
            model="synthetic-model-v1",
            reasoning_effort="max",
            context_tier="long_context",
            session_id=SESSION_ID,
            capture_mode=CopilotProbeCaptureMode.RECORD_ONLY,
            timeout_s=30,
        )


def test_plan_rejects_owned_fake_with_wrong_secret_policy(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "copilot",
        FakeCLIBehavior(secret_env_names=("OTHER_SECRET",)),
    )
    capability = workspace.owned_executable("copilot")

    with pytest.raises(ValueError, match="redact exactly"):
        _plan(capability)


def test_transport_guard_precedes_any_path_visible_copilot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    plan = _plan(capability)
    marker = tmp_path / "operator-copilot-ran"
    operator_bin = tmp_path / "operator-bin"
    operator_bin.mkdir()
    operator = operator_bin / "copilot"
    operator.write_text(
        f"#!/bin/sh\ntouch {marker}\n",
        encoding="utf-8",
    )
    operator.chmod(0o700)
    monkeypatch.setenv("PATH", str(operator_bin))
    monkeypatch.setenv("RAPTOR_COPILOT_TRANSPORT_DISABLED", "1")

    with pytest.raises(CopilotProbeRefused, match="disabled"):
        execute_copilot_probe(
            plan,
            prompt=PROMPT,
            synthetic_capability=capability,
        )
    assert not marker.exists()


def test_allow_live_never_grants_authority(
    tmp_path: Path,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    plan = _plan(capability)
    copilot_synthetic_transport_enabled(capability)

    with pytest.raises(CopilotProbeRefused, match="Level A"):
        execute_copilot_probe(
            plan,
            prompt=PROMPT,
            synthetic_capability=capability,
            allow_live=True,
        )


def test_clearing_guard_without_capability_never_spawns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, capability = _owned_fake(tmp_path)
    plan = _plan(capability)
    monkeypatch.setenv("RAPTOR_COPILOT_TRANSPORT_DISABLED", "0")

    with pytest.raises(CopilotProbeRefused, match="fixture-issued"):
        execute_copilot_probe(
            plan,
            prompt=PROMPT,
            synthetic_capability=None,
        )
    assert workspace.invocations("copilot") == []


def test_caller_forged_synthetic_receipt_is_not_authority(
    tmp_path: Path,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    plan = _plan(capability)
    forged = CopilotRuntimeReceipt(
        executable=Path("/bin/true"),
        cli_version=plan.runtime_receipt.cli_version,
        executable_sha256=plan.runtime_receipt.executable_sha256,
        executable_size=plan.runtime_receipt.executable_size,
        executable_device=plan.runtime_receipt.executable_device,
        executable_inode=plan.runtime_receipt.executable_inode,
        origin="synthetic",
        factory_id=plan.runtime_receipt.factory_id,
    )
    tampered = dataclasses.replace(plan, runtime_receipt=forged)
    copilot_synthetic_transport_enabled(capability)

    with pytest.raises(CopilotProbeRefused, match="receipt"):
        execute_copilot_probe(
            tampered,
            prompt=PROMPT,
            synthetic_capability=capability,
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"timeout_s": float("nan")},
        {"timeout_s": float("inf")},
        {"timeout_s": 0},
        {"timeout_s": 3601},
        {"session_id": "../../path-shaped-session"},
        {"capture_mode": "candidate_admission"},
        {"stream_limits": object()},
        {"requested_settings": object()},
        {"prompt_bytes": -1},
    ],
    ids=[
        "nan-timeout",
        "infinite-timeout",
        "zero-timeout",
        "over-limit-timeout",
        "path-session",
        "string-mode",
        "malformed-limits",
        "malformed-settings",
        "negative-prompt-size",
    ],
)
def test_execute_revalidates_mutated_plan_before_state_or_sandbox(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
    changes: dict[str, object],
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    plan = dataclasses.replace(_plan(capability), **changes)
    calls = []

    def unexpected_sandbox(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("invalid plan reached the sandbox")

    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        unexpected_sandbox,
    )
    copilot_synthetic_transport_enabled(capability)

    with pytest.raises(CopilotProbeRefused) as excinfo:
        execute_copilot_probe(
            plan,
            prompt=PROMPT,
            synthetic_capability=capability,
        )

    assert excinfo.value.code == "plan_invalid"
    assert calls == []
    assert not plan.execution_marker.exists()
    assert not (plan.copilot_home / "settings.json").exists()
    assert not plan.log_dir.exists()
    assert not plan.evidence_root.exists()
    assert not plan.home.exists()


@pytest.mark.parametrize(
    "changes",
    [
        {"prompt_bytes": "23"},
        {"prompt_bytes": probe_module._MAX_PROMPT_BYTES + 1},
        {"prompt_sha256": object()},
        {"prompt_sha256": "not-a-digest"},
        {"argv": []},
        {"runtime_receipt": object()},
        {"private_root": Path("relative")},
        {
            "requested_settings": CandidateRequestedSettings(
                model="synthetic-model-v1",
                reasoning_effort=None,
                context_tier="long_context",
            )
        },
    ],
    ids=[
        "prompt-size-type",
        "prompt-size-limit",
        "prompt-digest-type",
        "prompt-digest-format",
        "argv-type",
        "receipt-type",
        "relative-path",
        "implicit-effort",
    ],
)
def test_execute_rejects_additional_mutated_plan_contracts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
    changes: dict[str, object],
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    plan = dataclasses.replace(_plan(capability), **changes)
    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        lambda *args, **kwargs: pytest.fail("invalid plan reached sandbox"),
    )
    copilot_synthetic_transport_enabled(capability)

    with pytest.raises(CopilotProbeRefused) as excinfo:
        execute_copilot_probe(
            plan,
            prompt=PROMPT,
            synthetic_capability=capability,
        )

    assert excinfo.value.code == "plan_invalid"
    assert not plan.execution_marker.exists()


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("private_root", Path("/tmp/not-the-owned-root"), "private_root_mismatch"),
        ("proxy_hosts", ("other.invalid",), "proxy_policy_mismatch"),
        ("secret_env_names", ("OTHER_SECRET",), "secret_policy_mismatch"),
        ("log_dir", Path("/tmp/not-the-owned-log"), "private_path_mismatch"),
        ("argv", ("/bin/false",), "command_policy_mismatch"),
    ],
)
def test_execute_rejects_mutated_probe_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
    field: str,
    value: object,
    code: str,
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    plan = dataclasses.replace(_plan(capability), **{field: value})
    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        lambda *args, **kwargs: pytest.fail("mutated policy reached sandbox"),
    )
    copilot_synthetic_transport_enabled(capability)

    with pytest.raises(CopilotProbeRefused) as excinfo:
        execute_copilot_probe(
            plan,
            prompt=PROMPT,
            synthetic_capability=capability,
        )
    assert excinfo.value.code == code


@pytest.mark.parametrize(
    ("field", "value"),
    [("no_degrade", False), ("level", "B-live")],
)
def test_execute_rejects_mutated_init_false_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
    field: str,
    value: object,
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    plan = _plan(capability)
    object.__setattr__(plan, field, value)
    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        lambda *args, **kwargs: pytest.fail("mutated policy reached sandbox"),
    )
    copilot_synthetic_transport_enabled(capability)

    with pytest.raises(CopilotProbeRefused) as excinfo:
        execute_copilot_probe(
            plan,
            prompt=PROMPT,
            synthetic_capability=capability,
        )
    assert excinfo.value.code == "plan_invalid"


def test_execute_rejects_non_plan_object_before_sandbox(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    copilot_synthetic_transport_enabled(capability)
    with pytest.raises(CopilotProbeRefused) as excinfo:
        execute_copilot_probe(
            object(),
            prompt=PROMPT,
            synthetic_capability=capability,
        )
    assert excinfo.value.code == "plan_invalid"


def test_execute_rejects_inheritable_cancel_fd_before_state(
    tmp_path: Path,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    plan = _plan(capability)
    read_fd, write_fd = os.pipe()
    try:
        os.set_inheritable(read_fd, True)
        copilot_synthetic_transport_enabled(capability)
        with pytest.raises(CopilotProbeRefused) as excinfo:
            execute_copilot_probe(
                plan,
                prompt=PROMPT,
                synthetic_capability=capability,
                cancel_fd=read_fd,
            )
        assert excinfo.value.code == "cancel_fd_invalid"
        assert not plan.execution_marker.exists()
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_execute_rejects_closed_cancel_fd_before_state(
    tmp_path: Path,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    plan = _plan(capability)
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    os.close(write_fd)
    copilot_synthetic_transport_enabled(capability)

    with pytest.raises(CopilotProbeRefused) as excinfo:
        execute_copilot_probe(
            plan,
            prompt=PROMPT,
            synthetic_capability=capability,
            cancel_fd=read_fd,
        )
    assert excinfo.value.code == "cancel_fd_invalid"
    assert not plan.execution_marker.exists()


def test_execute_rejects_prompt_mismatch_before_state(
    tmp_path: Path,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    plan = _plan(capability)
    copilot_synthetic_transport_enabled(capability)

    with pytest.raises(CopilotProbeRefused) as excinfo:
        execute_copilot_probe(
            plan,
            prompt=b"different synthetic prompt",
            synthetic_capability=capability,
        )
    assert excinfo.value.code == "prompt_mismatch"
    assert not plan.execution_marker.exists()


@pytest.mark.parametrize("component", ["raptor", ".home", "xdg"])
def test_execute_refuses_symlinked_workspace_parent_without_external_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
    component: str,
) -> None:
    workspace, capability = _owned_fake(tmp_path)
    plan = _plan(capability)
    original = workspace.root / component
    backup = workspace.root / f"{component}.backup"
    if original.exists():
        original.rename(backup)
    outside = tmp_path / f"outside-{component.replace('.', 'dot')}"
    outside.mkdir(mode=0o700)
    if component == "raptor":
        (outside / "out").mkdir(mode=0o700)
    original.symlink_to(outside, target_is_directory=True)
    calls = []

    def unexpected_sandbox(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("unsafe parent reached the sandbox")

    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        unexpected_sandbox,
    )
    copilot_synthetic_transport_enabled(capability)

    with pytest.raises(CopilotProbeRefused):
        execute_copilot_probe(
            plan,
            prompt=PROMPT,
            synthetic_capability=capability,
        )

    assert calls == []
    assert list(outside.rglob("*")) == (
        [outside / "out"] if component == "raptor" else []
    )


def test_invalid_cancel_fd_is_rejected_before_state_or_sandbox(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability = _owned_fake(tmp_path)
    plan = _plan(capability)
    calls = []

    def unexpected_sandbox(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("invalid cancel fd reached the sandbox")

    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        unexpected_sandbox,
    )
    copilot_synthetic_transport_enabled(capability)

    with pytest.raises(CopilotProbeRefused) as excinfo:
        execute_copilot_probe(
            plan,
            prompt=PROMPT,
            synthetic_capability=capability,
            cancel_fd=1,
        )

    assert excinfo.value.code == "cancel_fd_invalid"
    assert calls == []
    assert not plan.execution_marker.exists()
    assert not (plan.copilot_home / "settings.json").exists()


def test_real_binary_copied_over_owned_path_is_rejected(
    tmp_path: Path,
) -> None:
    workspace, capability = _owned_fake(tmp_path)
    executable = workspace.executable("copilot")
    executable.unlink()
    shutil.copy2("/bin/true", executable)
    executable.chmod(0o700)

    with pytest.raises(ValueError, match="owned fake"):
        _plan(capability)


def test_same_content_inode_swap_is_rejected(
    tmp_path: Path,
) -> None:
    workspace, capability = _owned_fake(tmp_path)
    executable = workspace.executable("copilot")
    replacement = executable.with_name("copilot-replacement")
    shutil.copy2(executable, replacement)
    replacement.chmod(0o700)
    replacement.replace(executable)

    with pytest.raises(ValueError, match="identity"):
        _plan(capability)
