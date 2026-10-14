"""Real-sandbox evidence for the Level-A synthetic Copilot probe."""

from __future__ import annotations

import base64
import dataclasses
import json
import os
import shutil
import stat
import sys
import urllib.parse
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.llm import copilot_probe as probe_module
from core.llm.copilot_probe import (
    CopilotProbeCaptureMode,
    CopilotProbeStatus,
    build_copilot_probe_plan,
    execute_copilot_probe,
)
from core.llm.copilot_protocol import CandidateTranscriptOutcome
from core.sandbox import _spawn, spawn_backend_available
from core.sandbox.tests.capability import (
    requires_landlock,
    requires_mount,
    requires_userns,
)
from core.testing import FakeCLIBehavior, make_hermetic_cli

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "copilot_candidate"
COMPLETE = FIXTURE_DIR / "complete.jsonl"
SESSION_ID = "11111111-1111-4111-8111-111111111111"
PROMPT = b"Synthetic prompt content."
SECRET_ENV = "COPILOT_GITHUB_TOKEN"

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="Linux probe sandbox"),
    requires_landlock,
    requires_mount,
    requires_userns,
]


@pytest.fixture(autouse=True)
def _require_spawn_backend() -> None:
    if not spawn_backend_available():
        pytest.skip("Linux fork/mount sandbox backend unavailable")


def _encode_without_usage() -> str:
    events = [
        json.loads(line)
        for line in COMPLETE.read_text(encoding="utf-8").splitlines()
        if json.loads(line)["type"] != "assistant.usage"
    ]
    previous = None
    for event in events:
        event["parentId"] = previous
        previous = event["id"]
    return (
        "\n".join(json.dumps(event, separators=(",", ":")) for event in events) + "\n"
    )


def _make(
    tmp_path: Path,
    *,
    stdout: str,
    mode: CopilotProbeCaptureMode,
    exit_code: int = 0,
    session_id: str = SESSION_ID,
    delay_seconds: float = 0,
):
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "copilot",
        FakeCLIBehavior(
            stdout=stdout,
            exit_code=exit_code,
            delay_seconds=delay_seconds,
            secret_env_names=(SECRET_ENV,),
        ),
    )
    capability = workspace.owned_executable("copilot")
    kwargs = {}
    if mode is CopilotProbeCaptureMode.RECORD_ONLY:
        kwargs = {
            "evidence_owner": "pytest",
            "evidence_retention_seconds": 3600,
        }
    plan = build_copilot_probe_plan(
        synthetic_capability=capability,
        prompt=PROMPT,
        model="synthetic-model-v1",
        reasoning_effort="max",
        context_tier="long_context",
        session_id=session_id,
        capture_mode=mode,
        timeout_s=30,
        **kwargs,
    )
    return workspace, capability, plan


def _synthetic_result(
    stdout: bytes,
    *,
    returncode: int = 0,
    capture_enabled: bool = True,
    stdout_truncated: bool = False,
    stderr_truncated: bool = False,
    backend: str | None = "linux-fork-mount-pid-netns",
    mount_ns_active: bool | None = True,
    restrict_reads: bool | None = True,
    proxy_enforcement: str | None = "netns",
    degrade_waiver_honored: bool | None = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        returncode=returncode,
        stdout=stdout,
        stderr=b"",
        sandbox_info={
            "backend": backend,
            "mount_ns_active": mount_ns_active,
            "restrict_reads": restrict_reads,
            "proxy_enforcement": proxy_enforcement,
            "degrade_waiver_honored": degrade_waiver_honored,
            "capture": {
                "enabled": capture_enabled,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
                "stdout_bytes_kept": len(stdout),
                "stderr_bytes_kept": 0,
            },
        },
    )


def _encoded_variants(value: bytes) -> tuple[bytes, ...]:
    return (
        value,
        base64.b64encode(value),
        base64.urlsafe_b64encode(value),
    )


def test_candidate_execution_uses_real_strict_sandbox_and_private_stdin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
) -> None:
    workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
    )
    monkeypatch.setenv("GH_TOKEN", "operator-gh-token")
    monkeypatch.setenv("GITHUB_TOKEN", "operator-github-token")
    monkeypatch.setenv("COPILOT_MODEL", "operator-model")
    monkeypatch.setenv("COPILOT_CLI_DIST_DIR", "/operator/dist")
    monkeypatch.setenv("COPILOT_PKG_CACHE_HOME", "/operator/pkg-cache")
    monkeypatch.setenv("COPILOT_CACHE_HOME", "/operator/cache")
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is CopilotProbeStatus.CANDIDATE_ADMITTED
    assert execution.candidate_completion is not None
    assert execution.candidate_completion.provenance.evidence_level == (
        "schema-derived-candidate-unverified"
    )
    assert execution.sandbox.backend == "linux-fork-mount-pid-netns"
    assert execution.sandbox.mount_ns_active is True
    assert execution.sandbox.restrict_reads is True
    assert execution.sandbox.proxy_enforcement == "netns"
    assert execution.sandbox.degrade_waiver_honored is False
    assert execution.capture.stdout_truncated is False
    assert execution.capture.stderr_truncated is False

    (invocation,) = workspace.invocations("copilot")
    assert invocation.argv == plan.argv[1:]
    assert invocation.stdin == PROMPT
    assert PROMPT.decode() not in invocation.argv
    assert invocation.stdin_fd_access == "read_only"
    assert invocation.stdin_fd_target.endswith(" (deleted)")
    assert SECRET_ENV not in invocation.env
    assert "GH_TOKEN" not in invocation.env
    assert "GITHUB_TOKEN" not in invocation.env
    assert "COPILOT_MODEL" not in invocation.env
    assert "COPILOT_CLI_DIST_DIR" not in invocation.env
    assert "COPILOT_PKG_CACHE_HOME" not in invocation.env
    # Current sandbox policy strips the complete RAPTOR_* family from
    # untrusted target processes. The parent-side capability gate remains
    # authoritative; the fake Copilot child receives no framework marker.
    assert "RAPTOR_COPILOT_TRANSPORT_DISABLED" not in invocation.env
    assert invocation.secret_env[0].name == SECRET_ENV
    assert invocation.secret_env[0].present is True
    assert invocation.secret_env[0].hmac_sha256 == (
        execution.synthetic_secret_challenge_hmac
    )

    canary = workspace.synthetic_secret_canary(SESSION_ID).encode()
    sanitized_files = [
        plan.execution_marker,
        plan.copilot_home / "settings.json",
        *workspace.log_dir.iterdir(),
        *plan.log_dir.iterdir(),
    ]
    for event_path in sanitized_files:
        if event_path.is_file():
            payload = event_path.read_bytes()
            assert all(value not in payload for value in _encoded_variants(canary))
    public = repr(execution).encode()
    assert all(value not in public for value in _encoded_variants(canary))
    assert PROMPT not in public
    assert stat.S_IMODE(plan.copilot_home.stat().st_mode) == 0o700
    assert stat.S_IMODE(plan.log_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((plan.copilot_home / "settings.json").stat().st_mode) == 0o600


def test_record_only_timeout_retains_bounded_partial_evidence(
    tmp_path: Path,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability, plan = _make(
        tmp_path,
        stdout="ready\n",
        mode=CopilotProbeCaptureMode.RECORD_ONLY,
        delay_seconds=5,
    )
    plan = dataclasses.replace(plan, timeout_s=0.2)
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is CopilotProbeStatus.TIMED_OUT
    assert execution.timed_out is True
    assert execution.cancelled is False
    assert execution.raw_evidence is not None
    assert execution.raw_evidence.stdout_path.read_bytes() == b"ready\n"


def test_record_only_parent_cancellation_retains_bounded_partial_evidence(
    tmp_path: Path,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability, plan = _make(
        tmp_path,
        stdout="ready\n",
        mode=CopilotProbeCaptureMode.RECORD_ONLY,
        delay_seconds=5,
    )
    read_fd, write_fd = os.pipe()
    try:
        os.close(write_fd)
        copilot_synthetic_transport_enabled(capability)
        execution = execute_copilot_probe(
            plan,
            prompt=PROMPT,
            synthetic_capability=capability,
            cancel_fd=read_fd,
        )
    finally:
        os.close(read_fd)

    assert execution.status is CopilotProbeStatus.CANCELLED
    assert execution.timed_out is False
    assert execution.cancelled is True
    assert execution.raw_evidence is not None


def test_record_only_retains_parser_rejected_stream(
    tmp_path: Path,
    copilot_synthetic_transport_enabled,
) -> None:
    raw = '{"unexpected":"shape"}\n'
    _workspace, capability, plan = _make(
        tmp_path,
        stdout=raw,
        mode=CopilotProbeCaptureMode.RECORD_ONLY,
        exit_code=7,
    )
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is CopilotProbeStatus.RECORDED
    assert execution.candidate_completion is None
    assert execution.parser_diagnostic.status == "rejected"
    assert execution.raw_evidence is not None
    assert execution.raw_evidence.stdout_path.read_bytes() == raw.encode()
    assert raw.strip() not in repr(execution)
    assert stat.S_IMODE(execution.raw_evidence.stdout_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(execution.raw_evidence.manifest_path.stat().st_mode) == 0o600
    manifest = json.loads(
        execution.raw_evidence.manifest_path.read_text(encoding="utf-8")
    )
    assert manifest["owner"] == "pytest"
    assert manifest["process"] == {
        "cancelled": False,
        "returncode": 7,
        "timed_out": False,
    }
    assert manifest["parser"]["status"] == "rejected"
    assert manifest["sandbox"]["backend"] == "linux-fork-mount-pid-netns"


def test_truncated_capture_is_recorded_but_never_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=CopilotProbeCaptureMode.RECORD_ONLY,
    )
    monkeypatch.setattr(_spawn, "_CAPTURE_CAP", 256)
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is CopilotProbeStatus.RECORDED
    assert execution.capture.stdout_truncated is True
    assert execution.candidate_completion is None
    assert execution.parser_diagnostic.status == "not_attempted"
    assert execution.raw_evidence is not None
    assert len(execution.raw_evidence.stdout_path.read_bytes()) == 256


def test_candidate_mode_never_admits_truncated_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
    )
    monkeypatch.setattr(_spawn, "_CAPTURE_CAP", 256)
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is CopilotProbeStatus.CAPTURE_INCOMPLETE
    assert execution.candidate_completion is None
    assert execution.candidate_transcript is None
    assert execution.raw_evidence is None


def test_unevidenced_completion_remains_unevidenced(
    tmp_path: Path,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability, plan = _make(
        tmp_path,
        stdout=_encode_without_usage(),
        mode=CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
    )
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is (CopilotProbeStatus.CANDIDATE_COMPLETE_UNEVIDENCED)
    assert execution.candidate_completion is None
    assert execution.candidate_transcript is not None
    assert execution.candidate_transcript.outcome is (
        CandidateTranscriptOutcome.CANDIDATE_COMPLETE_UNEVIDENCED
    )


@pytest.mark.parametrize(
    "encoding",
    ["exact", "base64", "base64url", "percent"],
)
def test_contaminated_record_is_quarantined_and_blocks_admission(
    tmp_path: Path,
    copilot_synthetic_transport_enabled,
    encoding: str,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    canary = workspace.synthetic_secret_canary(SESSION_ID)
    encoded = {
        "exact": canary,
        "base64": base64.b64encode(canary.encode()).decode(),
        "base64url": base64.urlsafe_b64encode(canary.encode()).decode(),
        "percent": urllib.parse.quote_from_bytes(canary.encode()),
    }[encoding]
    workspace.configure_cli(
        "copilot",
        FakeCLIBehavior(
            stdout=encoded + "\n",
            secret_env_names=(SECRET_ENV,),
        ),
    )
    capability = workspace.owned_executable("copilot")
    plan = build_copilot_probe_plan(
        synthetic_capability=capability,
        prompt=PROMPT,
        model="synthetic-model-v1",
        reasoning_effort="max",
        context_tier="long_context",
        session_id=SESSION_ID,
        capture_mode=CopilotProbeCaptureMode.RECORD_ONLY,
        timeout_s=30,
        evidence_owner="pytest",
        evidence_retention_seconds=3600,
    )
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is CopilotProbeStatus.EVIDENCE_CONTAMINATED
    assert execution.candidate_completion is None
    assert execution.raw_evidence is not None
    assert execution.raw_evidence.quarantined is True
    assert execution.raw_evidence.classification == (
        "prompt-bearing_potentially-secret-bearing"
    )
    assert encoding in execution.raw_evidence.contamination_encodings
    assert "quarantine" in execution.raw_evidence.stdout_path.parts
    assert canary not in repr(execution)


@pytest.mark.parametrize("encoding", ["exact", "base64"])
@pytest.mark.parametrize(
    "mode",
    [
        CopilotProbeCaptureMode.RECORD_ONLY,
        CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
    ],
)
def test_known_settings_canary_is_private_quarantine_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
    encoding: str,
    mode: CopilotProbeCaptureMode,
) -> None:
    workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=mode,
    )
    canary = workspace.synthetic_secret_canary(SESSION_ID).encode()
    contaminated = canary if encoding == "exact" else base64.b64encode(canary)
    settings_path = plan.copilot_home / "settings.json"

    def contaminate_known_file(*args, **kwargs):
        settings_path.write_bytes(contaminated)
        settings_path.chmod(0o600)
        return _synthetic_result(COMPLETE.read_bytes())

    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        contaminate_known_file,
    )
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is CopilotProbeStatus.EVIDENCE_CONTAMINATED
    assert execution.candidate_completion is None
    assert execution.candidate_transcript is None
    public = repr(execution).encode()
    assert canary not in public
    assert contaminated not in public
    if mode is CopilotProbeCaptureMode.RECORD_ONLY:
        assert execution.raw_evidence is not None
        assert execution.raw_evidence.quarantined is True
        assert encoding in execution.raw_evidence.contamination_encodings
        assert execution.raw_evidence.stdout_path.parent.name == "quarantine"
        assert not (plan.evidence_root / "raw").exists()
        assert contaminated not in execution.raw_evidence.stdout_path.read_bytes()
    else:
        assert execution.raw_evidence is None


@pytest.mark.parametrize(
    ("condition", "expected_status"),
    [
        ("exact-size-limit", CopilotProbeStatus.CANDIDATE_ADMITTED),
        ("over-size-limit", CopilotProbeStatus.EVIDENCE_CONTAMINATED),
        ("mode-0644", CopilotProbeStatus.EVIDENCE_CONTAMINATED),
        ("non-regular", CopilotProbeStatus.EVIDENCE_CONTAMINATED),
    ],
)
def test_known_settings_file_bounds_mode_and_type_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
    condition: str,
    expected_status: CopilotProbeStatus,
) -> None:
    _workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
    )
    settings_path = plan.copilot_home / "settings.json"

    def mutate_known_file(*args, **kwargs):
        if condition == "non-regular":
            settings_path.unlink()
            settings_path.mkdir(mode=0o700)
        else:
            size = (
                probe_module._MAX_SCAN_FILE_BYTES + 1
                if condition == "over-size-limit"
                else probe_module._MAX_SCAN_FILE_BYTES
                if condition == "exact-size-limit"
                else 4
            )
            settings_path.write_bytes(b"x" * size)
            settings_path.chmod(0o644 if condition == "mode-0644" else 0o600)
        return _synthetic_result(COMPLETE.read_bytes())

    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        mutate_known_file,
    )
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is expected_status
    assert execution.raw_evidence is None
    if expected_status is CopilotProbeStatus.CANDIDATE_ADMITTED:
        assert execution.candidate_completion is not None
    else:
        assert execution.candidate_completion is None
        assert execution.parser_diagnostic.status == "incomplete"
        assert execution.parser_diagnostic.error_code == "unscannable_private_state"


def test_missing_required_known_settings_file_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
    )

    def remove_known_file(*args, **kwargs):
        (plan.copilot_home / "settings.json").unlink()
        return _synthetic_result(COMPLETE.read_bytes())

    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        remove_known_file,
    )
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is CopilotProbeStatus.EVIDENCE_CONTAMINATED
    assert execution.candidate_completion is None
    assert execution.raw_evidence is None
    assert execution.parser_diagnostic.status == "incomplete"
    assert execution.parser_diagnostic.error_code == "unscannable_private_state"


def test_executable_swap_after_parent_pin_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
) -> None:
    workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
    )
    executable = workspace.executable("copilot")
    moved = executable.with_name("copilot-original")
    real_pin = _spawn._pin_bind_sources
    swapped = False

    def pin_then_swap(*args, **kwargs):
        nonlocal swapped
        pins = real_pin(*args, **kwargs)
        if not swapped:
            executable.rename(moved)
            shutil.copy2("/bin/true", executable)
            executable.chmod(0o700)
            swapped = True
        return pins

    monkeypatch.setattr(_spawn, "_pin_bind_sources", pin_then_swap)
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )
    assert execution.status is CopilotProbeStatus.PROCESS_FAILED
    assert execution.candidate_completion is None
    assert workspace.invocations("copilot") == []


@pytest.mark.parametrize(
    "mode",
    [
        CopilotProbeCaptureMode.RECORD_ONLY,
        CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
    ],
)
def test_post_execution_out_parent_replacement_never_writes_or_admits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
    mode: CopilotProbeCaptureMode,
) -> None:
    workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=mode,
    )
    original = workspace.root / "raptor"
    backup = workspace.root / "raptor.post-run-backup"
    outside = tmp_path / f"post-run-outside-{mode.value}"
    outside.mkdir(mode=0o700)
    (outside / "out").mkdir(mode=0o700)

    def replace_parent_then_return(*args, **kwargs):
        original.rename(backup)
        original.symlink_to(outside, target_is_directory=True)
        return _synthetic_result(COMPLETE.read_bytes())

    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        replace_parent_then_return,
    )
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is CopilotProbeStatus.EVIDENCE_CONTAMINATED
    assert execution.candidate_completion is None
    assert execution.raw_evidence is None
    assert execution.parser_diagnostic.status == "incomplete"
    assert execution.parser_diagnostic.error_code == "unscannable_private_state"
    assert list((outside / "out").iterdir()) == []


@pytest.mark.parametrize("directory_kind", ["probe_log", "fixture_log"])
def test_post_execution_log_parent_replacement_is_explicitly_contaminated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
    directory_kind: str,
) -> None:
    workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
    )
    target = plan.log_dir if directory_kind == "probe_log" else workspace.log_dir
    backup = target.with_name(target.name + ".post-run-backup")
    outside = tmp_path / f"outside-{directory_kind}"
    outside.mkdir(mode=0o700)

    def replace_log_then_return(*args, **kwargs):
        target.rename(backup)
        target.symlink_to(outside, target_is_directory=True)
        return _synthetic_result(COMPLETE.read_bytes())

    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        replace_log_then_return,
    )
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is CopilotProbeStatus.EVIDENCE_CONTAMINATED
    assert execution.candidate_completion is None
    assert execution.parser_diagnostic.status == "incomplete"
    assert execution.parser_diagnostic.error_code == "unscannable_private_state"
    assert list(outside.iterdir()) == []


def test_post_execution_evidence_root_replacement_is_explicitly_contaminated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=CopilotProbeCaptureMode.RECORD_ONLY,
    )
    backup = plan.evidence_root.with_name(plan.evidence_root.name + ".post-run-backup")
    outside = tmp_path / "outside-evidence-root"
    outside.mkdir(mode=0o700)

    def replace_evidence_then_return(*args, **kwargs):
        plan.evidence_root.rename(backup)
        plan.evidence_root.symlink_to(outside, target_is_directory=True)
        return _synthetic_result(COMPLETE.read_bytes())

    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        replace_evidence_then_return,
    )
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is CopilotProbeStatus.EVIDENCE_CONTAMINATED
    assert execution.raw_evidence is None
    assert execution.parser_diagnostic.error_code == "unscannable_private_state"
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize(
    ("entry_count", "expected_status"),
    [
        (probe_module._MAX_SCAN_FILES, CopilotProbeStatus.CANDIDATE_ADMITTED),
        (
            probe_module._MAX_SCAN_FILES + 1,
            CopilotProbeStatus.EVIDENCE_CONTAMINATED,
        ),
    ],
    ids=["exact-limit", "over-limit"],
)
def test_log_scan_entry_cap_is_measured_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
    entry_count: int,
    expected_status: CopilotProbeStatus,
) -> None:
    _workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
    )
    outside = tmp_path / "outside-scan-state"
    outside.mkdir(mode=0o700)

    def populate_private_log(*args, **kwargs):
        assert kwargs["no_degrade"] is True
        for index in range(entry_count):
            path = plan.log_dir / f"safe-{index:04d}.log"
            path.write_bytes(b"safe")
            path.chmod(0o600)
        return _synthetic_result(COMPLETE.read_bytes())

    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        populate_private_log,
    )
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is expected_status
    assert len(list(plan.log_dir.iterdir())) == entry_count
    assert list(outside.iterdir()) == []
    if entry_count > probe_module._MAX_SCAN_FILES:
        assert execution.candidate_completion is None
        assert execution.raw_evidence is None
        assert execution.parser_diagnostic.status == "incomplete"
        assert execution.parser_diagnostic.error_code == "unscannable_private_state"
    else:
        assert execution.candidate_completion is not None


def test_candidate_admission_requires_exact_transcript_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
) -> None:
    requested_session = "22222222-2222-4222-8222-222222222222"
    _workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
        session_id=requested_session,
    )
    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        lambda *args, **kwargs: _synthetic_result(COMPLETE.read_bytes()),
    )
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is CopilotProbeStatus.CANDIDATE_REJECTED
    assert execution.candidate_completion is None
    assert execution.candidate_transcript is not None
    assert execution.candidate_transcript.session_id == SESSION_ID
    assert execution.parser_diagnostic.error_code == "session_id_mismatch"


def test_record_only_retains_session_mismatch_with_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
) -> None:
    requested_session = "22222222-2222-4222-8222-222222222222"
    _workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=CopilotProbeCaptureMode.RECORD_ONLY,
        session_id=requested_session,
    )
    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        lambda *args, **kwargs: _synthetic_result(COMPLETE.read_bytes()),
    )
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is CopilotProbeStatus.RECORDED
    assert execution.candidate_completion is None
    assert execution.parser_diagnostic.status == "rejected"
    assert execution.parser_diagnostic.error_code == "session_id_mismatch"
    assert execution.raw_evidence is not None
    manifest = json.loads(
        execution.raw_evidence.manifest_path.read_text(encoding="utf-8")
    )
    assert manifest["parser"]["error_code"] == "session_id_mismatch"


def test_candidate_mode_rejects_model_mismatch_after_valid_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
    )
    mismatched = dataclasses.replace(
        plan,
        requested_settings=dataclasses.replace(
            plan.requested_settings,
            model="different-model",
        ),
    )
    mismatched = dataclasses.replace(
        mismatched,
        argv=probe_module._command(
            executable=capability.path,
            requested=mismatched.requested_settings,
            session_id=mismatched.session_id,
            cwd=mismatched.cwd,
            usage_output_path=mismatched.usage_output_path,
            log_dir=mismatched.log_dir,
        ),
    )
    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        lambda *args, **kwargs: _synthetic_result(COMPLETE.read_bytes()),
    )
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        mismatched,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is CopilotProbeStatus.CANDIDATE_REJECTED
    assert execution.candidate_completion is None
    assert execution.parser_diagnostic.error_code == "selected_model_mismatch"


@pytest.mark.parametrize(
    ("result_kwargs", "stdout", "expected"),
    [
        (
            {"backend": "linux-landlock-only"},
            COMPLETE.read_bytes(),
            CopilotProbeStatus.SANDBOX_POSTURE_REJECTED,
        ),
        (
            {"capture_enabled": False},
            COMPLETE.read_bytes(),
            CopilotProbeStatus.CAPTURE_INCOMPLETE,
        ),
        (
            {"returncode": 9},
            COMPLETE.read_bytes(),
            CopilotProbeStatus.PROCESS_FAILED,
        ),
        (
            {},
            b'{"unexpected":"shape"}\n',
            CopilotProbeStatus.CANDIDATE_REJECTED,
        ),
    ],
    ids=["posture", "capture", "process", "parser"],
)
def test_candidate_mode_refuses_missing_execution_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
    result_kwargs: dict[str, object],
    stdout: bytes,
    expected: CopilotProbeStatus,
) -> None:
    _workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=CopilotProbeCaptureMode.CANDIDATE_ADMISSION,
    )
    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        lambda *args, **kwargs: _synthetic_result(
            stdout,
            **result_kwargs,
        ),
    )
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is expected
    assert execution.candidate_completion is None


def test_record_only_retains_capture_but_rejects_missing_posture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copilot_synthetic_transport_enabled,
) -> None:
    _workspace, capability, plan = _make(
        tmp_path,
        stdout=COMPLETE.read_text(encoding="utf-8"),
        mode=CopilotProbeCaptureMode.RECORD_ONLY,
    )
    monkeypatch.setattr(
        probe_module,
        "run_untrusted_networked",
        lambda *args, **kwargs: _synthetic_result(
            COMPLETE.read_bytes(),
            backend=None,
            mount_ns_active=None,
            restrict_reads=None,
            proxy_enforcement=None,
            degrade_waiver_honored=None,
        ),
    )
    copilot_synthetic_transport_enabled(capability)

    execution = execute_copilot_probe(
        plan,
        prompt=PROMPT,
        synthetic_capability=capability,
    )

    assert execution.status is CopilotProbeStatus.SANDBOX_POSTURE_REJECTED
    assert execution.raw_evidence is not None
    assert execution.candidate_completion is None
