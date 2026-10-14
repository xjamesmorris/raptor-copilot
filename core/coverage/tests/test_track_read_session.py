"""Session-owned read attribution through the shared coverage implementation."""

from __future__ import annotations

import contextlib
import copy
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from core.coverage import track_read
from core.coverage.record import build_from_manifest
from core.project import sessions
from core.run import metadata
from core.run.host_events import (
    HostEventEffectDisposition,
    HostEventParseDisposition,
    HostEventProfileId,
    PROFILE_META,
)
from core.startup.host import (
    Frontend,
    SessionHostClaim,
    SessionOwner,
    build_session_host_claim,
)
from core.startup.runtime_receipt.canonical import canonical_bytes
from core.startup.runtime_receipt.plumbing_types import (
    PlumbingFailure,
    RuntimeReceiptSnapshot,
    reference_from_receipt,
    serialize_snapshot,
)
from core.startup.runtime_receipt.reasons import ReceiptRejection
from core.startup.runtime_receipt.verify import parse_receipt, serialize_receipt
from core.testing.host_events import (
    FixtureEvidenceLevel,
    copilot_candidate_read_event,
)
from core.testing.runtime_receipt_fake import (
    RuntimeReceiptRunEnvironment as _ReceiptEnvironment,
    build_runtime_receipt_document as _receipt_document,
    forbid_receipt_sidecar_reads as _sidecar_reads_forbidden,
    resign_runtime_receipt_document,
    runtime_receipt_run_environment,
    start_runtime_receipt_run as _start_receipt,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
HOOK = REPO_ROOT / "plugins" / "coverage" / "libexec" / "raptor-hook-read"
_ABSENT = object()
_HOST_V2_TOKEN = "00112233445566778899aabbccddeeff"


@pytest.fixture
def stage3a2_receipt_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_ReceiptEnvironment]:
    with runtime_receipt_run_environment(tmp_path, monkeypatch) as environment:
        yield environment


def _wait_for_process(pid: int) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if sessions.proc_starttime(pid) is not None:
            return
        time.sleep(0.01)
    raise AssertionError(f"owned process {pid} did not become observable")


@contextlib.contextmanager
def _owned_claude(tmp_path: Path, *, strong: bool):
    source = shutil.which("sleep")
    assert source is not None, "sleep is required for owned process fixtures"
    executable = tmp_path / ("strong-bin" if strong else "legacy-bin") / "claude"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(Path(source).read_bytes())
    executable.chmod(0o700)
    process = subprocess.Popen(
        [str(executable), "60"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        _wait_for_process(process.pid)
        token = sessions.mint_token()
        claim = (
            build_session_host_claim(Frontend.CLAUDE, executable) if strong else None
        )
        recorded = sessions.record_session(
            sessions.NONE_SENTINEL,
            pid=process.pid,
            token=token,
            host_claim=claim,
        )
        assert recorded == process.pid
        yield process, executable, token, claim
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


@pytest.fixture
def isolated_registry(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(sessions, "SESSIONS_DIR", sessions_dir)
    return home, sessions_dir


def _owner_env(home: Path, pid: int, token: str) -> dict[str, str]:
    return {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "RAPTOR_SESSION_PID": str(pid),
        "RAPTOR_SESSION_TOKEN": token,
        "_RAPTOR_TRUSTED": "1",
        "RAPTOR_CC_TRANSPORT_DISABLED": "1",
        "RAPTOR_COPILOT_TRANSPORT_DISABLED": "1",
    }


def _write_run(
    root: Path,
    *,
    pid: int,
    name: str,
    target: object = _ABSENT,
    status: str = "running",
) -> Path:
    run_dir = root / "out" / name
    run_dir.mkdir(parents=True)
    fields = sessions._parse_entry(sessions.SESSIONS_DIR / str(pid))
    meta: dict[str, object] = {
        "status": status,
        "command": "scan",
        "session_pid": pid,
    }
    for meta_key, entry_key in (
        ("session_start", "starttime"),
        ("session_boot_id", "boot_id"),
        ("session_pidns", "pidns"),
    ):
        if entry_key in fields:
            meta[meta_key] = fields[entry_key]
    claim = sessions.session_host_claim(pid)
    if claim is not None:
        meta.update(claim.metadata_fields())
    if target is not _ABSENT:
        meta["target_path"] = target
    (run_dir / metadata.RUN_METADATA_FILE).write_text(
        json.dumps(meta),
        encoding="utf-8",
    )
    sessions.ledger_record_start(run_dir, pid=pid)
    return run_dir


def _payload(path: object, **extra: object) -> bytes:
    if isinstance(path, Path):
        path = str(path)
    value = {"tool_input": {"file_path": path}, **extra}
    return json.dumps(value).encode()


def _candidate_read_payload(path: str) -> bytes:
    fixture = copilot_candidate_read_event(path)
    assert fixture.evidence_level is FixtureEvidenceLevel.CANDIDATE_UNVERIFIED
    return fixture.to_bytes()


def _process_with_env(raw: bytes, env: dict[str, str]):
    with patch.dict(os.environ, env, clear=True):
        return track_read.process_read_event(raw)


def _capture_from_document(
    document: dict[str, Any],
    receipt_env: _ReceiptEnvironment,
) -> sessions.SessionRuntimeReceiptCapture:
    del receipt_env
    receipt = parse_receipt(canonical_bytes(resign_runtime_receipt_document(document)))
    assert not isinstance(receipt, ReceiptRejection)
    reference = reference_from_receipt(receipt)
    assert not isinstance(reference, PlumbingFailure)
    snapshot = RuntimeReceiptSnapshot(reference=reference, receipt=receipt)
    return sessions.SessionRuntimeReceiptCapture(
        snapshot=snapshot,
        session_pid=reference.session_pid.value,
        reference=reference,
        _entry_sha256=b"\0" * 32,
        _sidecar_sha256=b"\1" * 32,
        _host_uid=reference.launcher_euid.value,
        _host_executable_device=10,
        _host_executable_inode=20,
    )


def _replace_registry_document(
    receipt_env: _ReceiptEnvironment,
    document: dict[str, Any],
) -> None:
    receipt = parse_receipt(canonical_bytes(resign_runtime_receipt_document(document)))
    assert not isinstance(receipt, ReceiptRejection)
    reference = reference_from_receipt(receipt)
    assert not isinstance(reference, PlumbingFailure)
    host = SessionHostClaim(
        frontend=Frontend.COPILOT,
        uid=reference.launcher_euid.value,
        executable=Path("/owned/copilot"),
        executable_device=10,
        executable_inode=20,
    )
    sidecar = receipt_env.root / reference.sidecar_name
    sidecar.write_bytes(serialize_receipt(receipt))
    sidecar.chmod(0o600)
    receipt_env.entry.write_bytes(
        sessions._serialize_session_receipt_entry(
            reference,
            since="2026-09-12T00:00:00.000000+00:00",
            host=host,
            token_hex=_HOST_V2_TOKEN,
        )
    )
    receipt_env.entry.chmod(0o600)


def _snapshot_variant(
    receipt_env: _ReceiptEnvironment,
    variant: str,
) -> dict[str, object]:
    if variant in {"exact", "pending", "rejected"}:
        value = json.loads(serialize_snapshot(receipt_env.snapshot))
        if variant != "exact":
            value["state"] = variant
            value["receipt"]["decision"]["state"] = variant
        return value
    if variant == "invalid":
        return {"malformed": True}

    document = copy.deepcopy(_receipt_document())
    if variant == "profile":
        document["stable_identity"]["profile_id"] = "other-profile"
    elif variant == "stable":
        document["stable_identity"]["cli_version"] = "9.9.9"
    elif variant == "nonce":
        document["launch_binding"]["receipt_nonce"] = "f" * 32
    elif variant == "session":
        replacement = "99999999-8888-4777-8666-555555555555"
        document["launch_instance"]["session_id"] = replacement
        document["launch_binding"]["session_id"] = replacement
    elif variant != "digest":
        raise AssertionError(f"unknown snapshot variant {variant}")
    capture = _capture_from_document(document, receipt_env)
    value = json.loads(serialize_snapshot(capture.snapshot))
    if variant == "digest":
        value["receipt_sha256"] = "f" * 64
    return value


def _registry_document_variant(variant: str) -> dict[str, object]:
    document = copy.deepcopy(_receipt_document())
    if variant == "digest":
        document["stable_identity"]["frontend_executable"]["sha256"] = "f" * 64
    elif variant == "profile":
        document["stable_identity"]["profile_id"] = "other-profile"
    elif variant == "stable":
        document["stable_identity"]["cli_version"] = "9.9.9"
    elif variant == "nonce":
        document["launch_binding"]["receipt_nonce"] = "f" * 32
    elif variant == "session":
        replacement = "99999999-8888-4777-8666-555555555555"
        document["launch_instance"]["session_id"] = replacement
        document["launch_binding"]["session_id"] = replacement
    else:
        raise AssertionError(f"unknown registry variant {variant}")
    return document


@contextlib.contextmanager
def _receipt_authority_calls_forbidden():
    paths = (
        "core.run.metadata.compare_run_runtime_receipt",
        "core.project.sessions.capture_current_session_runtime_receipt",
        "core.project.sessions.session_runtime_receipt_fence",
        "core.project.sessions._strict_session_lock",
        "core.run.metadata._metadata_lock",
        "core.project.oplock.project_op_lock",
    )
    with contextlib.ExitStack() as stack:
        for target in paths:
            stack.enter_context(
                patch(
                    target,
                    side_effect=AssertionError(
                        f"coverage deny-only path called {target}"
                    ),
                )
            )
        stack.enter_context(_sidecar_reads_forbidden("coverage deny-only path"))
        yield


def _install_active_project(
    home: Path,
    *,
    output_dir: Path,
    target: Path | None,
) -> None:
    projects = home / ".raptor" / "projects"
    projects.mkdir(parents=True)
    value: dict[str, object] = {
        "name": "p",
        "output_dir": str(output_dir),
    }
    if target is not None:
        value["target"] = str(target)
    (projects / "p.json").write_text(json.dumps(value), encoding="utf-8")
    (projects / ".active").symlink_to("p.json")


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize("strong", [False, True], ids=["legacy", "strong"])
def test_e01_e19_owned_claude_appends_exact_realpath(
    tmp_path,
    isolated_registry,
    strong,
):
    home, _sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=strong) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target = tmp_path / "target"
        target.mkdir()
        source = target / "main.c"
        source.write_text("int main(void) { return 0; }\n")
        run = _write_run(
            tmp_path, pid=process.pid, name=f"run-{strong}", target=str(target)
        )

        result = _process_with_env(
            _payload(source),
            _owner_env(home, process.pid, token),
        )

    assert result.parse_disposition is HostEventParseDisposition.PARSED
    assert result.effect_disposition is HostEventEffectDisposition.APPLIED
    assert result.recorded_path == source.resolve()
    assert result.route == (
        "session_owner_strong" if strong else "session_owner_legacy"
    )
    assert (run / track_read.MANIFEST_NAME).read_bytes() == (
        str(source.resolve()) + "\n"
    ).encode()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_e15_e29_payload_paths_cannot_redirect_attribution(
    tmp_path,
    isolated_registry,
):
    home, _sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target = tmp_path / "target"
        target.mkdir()
        source = target / "actual.py"
        source.write_text("x = 1\n")
        run = _write_run(tmp_path, pid=process.pid, name="owned", target=str(target))
        attacker = tmp_path / "attacker"
        attacker.mkdir()
        raw = _payload(
            source,
            run_dir=str(attacker),
            output_dir=str(attacker),
            project="other",
            target_path=str(attacker),
            manifest=str(attacker / "manifest"),
        )
        result = _process_with_env(raw, _owner_env(home, process.pid, token))

    assert result.effect_disposition is HostEventEffectDisposition.APPLIED
    assert (run / track_read.MANIFEST_NAME).read_text() == (
        str(source.resolve()) + "\n"
    )
    assert list(attacker.iterdir()) == []


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_token",
        "stale_start",
        "host_mismatch",
        "malformed_host",
        "unknown_host",
        "unknown_version",
    ],
)
def test_e16_e18_strong_credential_failures_never_use_active(
    tmp_path,
    isolated_registry,
    monkeypatch,
    mutation,
):
    home, sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=True) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target = tmp_path / "target"
        target.mkdir()
        source = target / "a.py"
        source.write_text("x = 1\n")
        run = _write_run(tmp_path, pid=process.pid, name="strong", target=str(target))
        env = _owner_env(home, process.pid, token)
        entry = sessions_dir / str(process.pid)
        if mutation == "wrong_token":
            env["RAPTOR_SESSION_TOKEN"] = "ff" * 16
        else:
            fields = entry.read_text(encoding="utf-8")
            if mutation == "stale_start":
                current = sessions.proc_starttime(process.pid)
                assert current is not None
                fields = fields.replace(
                    f"starttime={current}", f"starttime={int(current) + 1}"
                )
            elif mutation == "host_mismatch":
                claim = sessions.session_host_claim(process.pid)
                assert claim is not None
                fields = fields.replace(
                    f"host_exe_ino={claim.executable_inode}",
                    f"host_exe_ino={claim.executable_inode + 1}",
                )
            elif mutation == "malformed_host":
                fields = fields.replace("host_uid=", "host_uid=0")
            elif mutation == "unknown_host":
                fields += "host_future=1\n"
            else:
                fields = fields.replace("host_v=1", "host_v=2")
            entry.write_text(fields, encoding="utf-8")

        global_lookup = monkeypatch.setattr(
            track_read,
            "_find_global_run",
            lambda: (_ for _ in ()).throw(
                AssertionError("invalid credentials reached .active")
            ),
        )
        del global_lookup
        result = _process_with_env(_payload(source), env)

    assert result.effect_disposition is HostEventEffectDisposition.NO_OWNER
    assert not (run / track_read.MANIFEST_NAME).exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize(
    "env_delta",
    [
        {"RAPTOR_SESSION_PID": "not-digits", "RAPTOR_SESSION_TOKEN": "x"},
        {"RAPTOR_SESSION_TOKEN": "x"},
        {"RAPTOR_SESSION_PID": "424242"},
        {"RAPTOR_SESSION_PID": "", "RAPTOR_SESSION_TOKEN": ""},
        {"RAPTOR_SESSION_PID": "9" * 5000, "RAPTOR_SESSION_TOKEN": "x"},
    ],
    ids=["non-digit-pid", "token-only", "pid-only", "empty-pair", "huge-pid"],
)
def test_e16_partial_or_bad_credentials_do_not_fall_back(
    tmp_path,
    isolated_registry,
    monkeypatch,
    env_delta,
):
    home, _sessions_dir = isolated_registry
    source = tmp_path / "a.py"
    source.write_text("x = 1\n")
    monkeypatch.setattr(
        track_read,
        "_find_global_run",
        lambda: (_ for _ in ()).throw(
            AssertionError("present credential reached .active")
        ),
    )
    env = {"HOME": str(home), **env_delta}

    result = _process_with_env(_payload(source), env)

    assert result.effect_disposition is HostEventEffectDisposition.NO_OWNER


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_e17_legacy_wrong_token_can_resolve_by_legacy_walk(
    tmp_path,
    isolated_registry,
):
    home, _sessions_dir = isolated_registry
    bash = shutil.which("bash")
    assert bash is not None
    executable = tmp_path / "walk-bin" / "claude"
    executable.parent.mkdir()
    executable.write_bytes(Path(bash).read_bytes())
    executable.chmod(0o700)
    ready = tmp_path / "walk-ready"
    go = tmp_path / "walk-go"
    payload_file = tmp_path / "payload.json"
    env = {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "RAPTOR_SESSION_TOKEN": "ff" * 16,
        "_RAPTOR_TRUSTED": "1",
        "HOOK": str(HOOK),
        "PAYLOAD": str(payload_file),
        "READY": str(ready),
        "GO": str(go),
    }
    process = subprocess.Popen(
        [
            str(executable),
            "-c",
            (
                'export RAPTOR_SESSION_PID="$$"; '
                'printf "%s\\n" "$$" > "$READY"; '
                'while [ ! -e "$GO" ]; do sleep 0.01; done; '
                '"$HOOK" < "$PAYLOAD"'
            ),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not ready.exists():
            time.sleep(0.01)
        assert ready.exists()
        assert sessions._comm(process.pid) == "claude"
        token = sessions.mint_token()
        assert token != env["RAPTOR_SESSION_TOKEN"]
        assert (
            sessions.record_session(
                sessions.NONE_SENTINEL,
                pid=process.pid,
                token=token,
            )
            == process.pid
        )
        target = tmp_path / "target"
        target.mkdir()
        source = target / "a.py"
        source.write_text("x = 1\n")
        run = _write_run(
            tmp_path, pid=process.pid, name="legacy-walk", target=str(target)
        )
        payload_file.write_bytes(_payload(source))
        go.write_text("", encoding="utf-8")
        stdout, stderr = process.communicate(timeout=10)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)

    assert process.returncode == 0, (stdout, stderr)
    assert (run / track_read.MANIFEST_NAME).is_file()


def test_n4_walk_owner_pid_must_match_environment(monkeypatch):
    monkeypatch.setattr(
        sessions,
        "resolve_session_owner",
        lambda: SessionOwner(
            pid=9002,
            frontend=Frontend.CLAUDE,
            host_verified=False,
        ),
    )
    monkeypatch.setattr(
        track_read,
        "_find_global_run",
        lambda: (_ for _ in ()).throw(
            AssertionError("mismatched owner reached .active")
        ),
    )

    result = track_read.resolve_read_target(
        environ={
            sessions.ENV_SESSION_PID: "9001",
            sessions.ENV_SESSION_TOKEN: "aa" * 16,
        }
    )

    assert result.disposition is HostEventEffectDisposition.NO_OWNER
    assert result.reason_code == "owner_mismatch"


def test_c2_non_claude_owner_disables_effects(monkeypatch):
    monkeypatch.setattr(
        sessions,
        "resolve_session_owner",
        lambda: SessionOwner(
            pid=9001,
            frontend=Frontend.COPILOT,
            host_verified=True,
        ),
    )

    result = track_read.resolve_read_target(
        environ={
            sessions.ENV_SESSION_PID: "9001",
            sessions.ENV_SESSION_TOKEN: "aa" * 16,
        }
    )

    assert result.disposition is (HostEventEffectDisposition.EFFECTS_DISABLED)
    assert result.reason_code == "profile_mismatch"


def test_n4_no_credentials_uses_labelled_legacy_global_route(
    tmp_path,
    isolated_registry,
    monkeypatch,
):
    home, _sessions_dir = isolated_registry
    target = tmp_path / "target"
    target.mkdir()
    project_out = tmp_path / "project-out"
    run = project_out / "run1"
    run.mkdir(parents=True)
    (run / metadata.RUN_METADATA_FILE).write_text(
        json.dumps({"status": "running"}),
        encoding="utf-8",
    )
    projects = home / ".raptor" / "projects"
    projects.mkdir(parents=True)
    (projects / "p.json").write_text(
        json.dumps(
            {
                "name": "p",
                "target": str(target),
                "output_dir": str(project_out),
            }
        )
    )
    (projects / ".active").symlink_to("p.json")

    monkeypatch.setattr(
        sessions,
        "resolve_session_owner",
        lambda: (_ for _ in ()).throw(
            AssertionError("no-credential route used ancestry")
        ),
    )
    with patch.dict(os.environ, {"HOME": str(home)}, clear=True):
        result = track_read.resolve_read_target()

    assert result.target is not None
    assert result.target.run_dir == run
    assert result.route == "legacy_global_fallback"


def test_n4_no_credentials_honours_registry_override(
    tmp_path,
    isolated_registry,
):
    home, _sessions_dir = isolated_registry
    registry = tmp_path / "registry"
    projects = registry / "projects"
    projects.mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir()
    project_out = tmp_path / "project-out"
    run = project_out / "run1"
    run.mkdir(parents=True)
    (run / metadata.RUN_METADATA_FILE).write_text(
        json.dumps({"status": "running"}),
        encoding="utf-8",
    )
    (projects / "p.json").write_text(
        json.dumps(
            {
                "name": "p",
                "target": str(target),
                "output_dir": str(project_out),
            }
        ),
        encoding="utf-8",
    )
    (projects / ".active").symlink_to("p.json")

    with patch.dict(
        os.environ,
        {
            "HOME": str(home),
            "RAPTOR_REGISTRY_HOME": str(registry),
        },
        clear=True,
    ):
        result = track_read.resolve_read_target()

    assert result.target is not None
    assert result.target.run_dir == run
    assert result.route == "legacy_global_fallback"


def test_n4_relative_registry_override_never_falls_back_to_home(
    tmp_path,
    isolated_registry,
):
    home, _sessions_dir = isolated_registry
    target = tmp_path / "target"
    target.mkdir()
    project_out = tmp_path / "project-out"
    run = project_out / "run1"
    run.mkdir(parents=True)
    (run / metadata.RUN_METADATA_FILE).write_text(
        json.dumps({"status": "running"}),
        encoding="utf-8",
    )
    _install_active_project(home, output_dir=project_out, target=target)

    with patch.dict(
        os.environ,
        {
            "HOME": str(home),
            "RAPTOR_REGISTRY_HOME": "relative-registry",
        },
        clear=True,
    ):
        result = track_read.resolve_read_target()

    assert result.target is None
    assert result.disposition is HostEventEffectDisposition.NO_CANDIDATE
    assert result.route == "legacy_global_fallback"


def test_t6_legacy_project_without_target_is_unfiltered(
    tmp_path,
    isolated_registry,
):
    home, _sessions_dir = isolated_registry
    source = tmp_path / "outside.py"
    source.write_text("x = 1\n")
    project_out = tmp_path / "project-out"
    run = project_out / "run1"
    run.mkdir(parents=True)
    (run / metadata.RUN_METADATA_FILE).write_text(
        json.dumps({"status": "running"}),
        encoding="utf-8",
    )
    projects = home / ".raptor" / "projects"
    projects.mkdir(parents=True)
    (projects / "p.json").write_text(
        json.dumps({"output_dir": str(project_out)}),
        encoding="utf-8",
    )
    (projects / ".active").symlink_to("p.json")

    with patch.dict(os.environ, {"HOME": str(home)}, clear=True):
        result = track_read.process_read_event(_payload(source))

    assert result.effect_disposition is HostEventEffectDisposition.APPLIED
    assert result.route == "legacy_global_fallback"
    assert (run / track_read.MANIFEST_NAME).read_text(encoding="utf-8") == (
        str(source.resolve()) + "\n"
    )


@pytest.mark.parametrize(
    "variant",
    [
        "non-symlink-active",
        "path-shaped-link",
        "missing-project-file",
        "symlinked-project-file",
        "non-dict-project-json",
    ],
)
def test_t6_legacy_active_variants_are_no_candidate(
    tmp_path,
    isolated_registry,
    variant,
):
    home, _sessions_dir = isolated_registry
    source = tmp_path / "source.py"
    source.write_text("x = 1\n")
    projects = home / ".raptor" / "projects"
    projects.mkdir(parents=True)
    active = projects / ".active"
    if variant == "non-symlink-active":
        active.write_text("p.json\n", encoding="utf-8")
    elif variant == "path-shaped-link":
        active.symlink_to("nested/p.json")
    elif variant == "missing-project-file":
        active.symlink_to("missing.json")
    elif variant == "symlinked-project-file":
        project_out = tmp_path / "symlink-project-out"
        run = project_out / "run1"
        run.mkdir(parents=True)
        (run / metadata.RUN_METADATA_FILE).write_text(
            json.dumps({"status": "running"}),
            encoding="utf-8",
        )
        outside = tmp_path / "outside-project.json"
        outside.write_text(
            json.dumps({"output_dir": str(project_out)}),
            encoding="utf-8",
        )
        (projects / "p.json").symlink_to(outside)
        active.symlink_to("p.json")
    else:
        (projects / "p.json").write_text("[]", encoding="utf-8")
        active.symlink_to("p.json")

    with patch.dict(os.environ, {"HOME": str(home)}, clear=True):
        result = track_read.process_read_event(_payload(source))

    assert result.effect_disposition is HostEventEffectDisposition.NO_CANDIDATE
    assert result.route == "legacy_global_fallback"
    assert list(tmp_path.rglob(track_read.MANIFEST_NAME)) == []


@pytest.mark.parametrize(
    "state",
    ("pending", "verified", "rejected", "invalid", "missing-sidecar"),
)
def test_t25_matching_host_v2_credential_never_owns_coverage(
    stage3a2_receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
) -> None:
    receipt_env = stage3a2_receipt_env
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    source = target / "owned.py"
    source.write_text("x = 1\n", encoding="utf-8")
    entry = receipt_env.entry
    if state in {"pending", "rejected"}:
        entry.write_text(
            entry.read_text(encoding="utf-8").replace(
                "host_receipt_state=verified",
                f"host_receipt_state={state}",
            ),
            encoding="utf-8",
        )
    elif state == "invalid":
        entry.write_text(
            entry.read_text(encoding="utf-8").replace(
                "host_receipt_reference=",
                "host_receipt_reference={",
                1,
            ),
            encoding="utf-8",
        )
    elif state == "missing-sidecar":
        for sidecar in receipt_env.root.glob("*.receipt.*.json"):
            sidecar.unlink()
    entry_before = entry.read_bytes()
    sidecars_before = {
        path.name: path.read_bytes()
        for path in receipt_env.root.glob("*.receipt.*.json")
    }
    env = {
        "HOME": str(home),
        sessions.ENV_SESSION_PID: receipt_env.reference.session_pid.text,
        sessions.ENV_SESSION_TOKEN: _HOST_V2_TOKEN,
    }
    monkeypatch.setattr(
        track_read,
        "_find_global_run",
        lambda: (_ for _ in ()).throw(
            AssertionError("matching host-v2 credential reached .active")
        ),
    )

    with _receipt_authority_calls_forbidden():
        target_result = _process_with_env(
            _payload(source),
            env,
        )

    assert target_result.effect_disposition is HostEventEffectDisposition.NO_OWNER
    assert target_result.route == "session_owner"
    assert list(tmp_path.rglob(track_read.MANIFEST_NAME)) == []
    assert entry.read_bytes() == entry_before
    assert {
        path.name: path.read_bytes()
        for path in receipt_env.root.glob("*.receipt.*.json")
    } == sidecars_before


@pytest.mark.parametrize(
    "variant",
    ("digest", "profile", "stable", "nonce", "session"),
)
def test_t25_registry_mismatches_stay_non_authorizing_without_parsing(
    stage3a2_receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    variant: str,
) -> None:
    receipt_env = stage3a2_receipt_env
    _replace_registry_document(
        receipt_env,
        _registry_document_variant(variant),
    )
    target = tmp_path / "target"
    target.mkdir()
    source = target / "owned.py"
    source.write_text("x = 1\n", encoding="utf-8")
    entry_before = receipt_env.entry.read_bytes()
    sidecars_before = {
        path.name: path.read_bytes()
        for path in receipt_env.root.glob("*.receipt.*.json")
    }
    monkeypatch.setattr(
        track_read,
        "_find_global_run",
        lambda: (_ for _ in ()).throw(
            AssertionError("matching host-v2 credential reached .active")
        ),
    )
    env = {
        sessions.ENV_SESSION_PID: receipt_env.reference.session_pid.text,
        sessions.ENV_SESSION_TOKEN: _HOST_V2_TOKEN,
    }

    with _receipt_authority_calls_forbidden():
        result = _process_with_env(_payload(source), env)

    assert result.effect_disposition is HostEventEffectDisposition.NO_OWNER
    assert result.route == "session_owner"
    assert list(tmp_path.rglob(track_read.MANIFEST_NAME)) == []
    assert receipt_env.entry.read_bytes() == entry_before
    assert {
        path.name: path.read_bytes()
        for path in receipt_env.root.glob("*.receipt.*.json")
    } == sidecars_before


@pytest.mark.parametrize(
    "variant",
    (
        "exact",
        "pending",
        "rejected",
        "invalid",
        "digest",
        "profile",
        "stable",
        "nonce",
        "session",
    ),
)
def test_t25_forged_owner_cannot_attribute_snapshot_variants(
    stage3a2_receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    variant: str,
) -> None:
    receipt_env = stage3a2_receipt_env
    target = tmp_path / "target"
    target.mkdir()
    source = target / "owned.py"
    source.write_text("x = 1\n", encoding="utf-8")
    run = tmp_path / "runs" / variant
    run.mkdir(parents=True)
    meta = {
        "status": "running",
        "session_pid": receipt_env.reference.session_pid.value,
        "target_path": str(target),
        metadata.RUN_RUNTIME_RECEIPT_KEY: _snapshot_variant(
            receipt_env,
            variant,
        ),
    }
    (run / metadata.RUN_METADATA_FILE).write_text(
        json.dumps(meta),
        encoding="utf-8",
    )
    before = (run / metadata.RUN_METADATA_FILE).read_bytes()
    entry_before = receipt_env.entry.read_bytes()
    sidecars_before = {
        path.name: path.read_bytes()
        for path in receipt_env.root.glob("*.receipt.*.json")
    }
    monkeypatch.setattr(
        sessions,
        "resolve_session_owner",
        lambda: SessionOwner(
            pid=receipt_env.reference.session_pid.value,
            frontend=Frontend.CLAUDE,
            host_verified=False,
        ),
    )
    monkeypatch.setattr(
        sessions,
        "ledger_runs",
        lambda **_kwargs: [{"run_id": variant, "run_dir": str(run)}],
    )
    env = {
        sessions.ENV_SESSION_PID: receipt_env.reference.session_pid.text,
        sessions.ENV_SESSION_TOKEN: _HOST_V2_TOKEN,
    }

    with _receipt_authority_calls_forbidden():
        result = _process_with_env(_payload(source), env)

    assert result.effect_disposition is HostEventEffectDisposition.NO_CANDIDATE
    assert result.route == "session_owner_legacy"
    assert not (run / track_read.MANIFEST_NAME).exists()
    assert (run / metadata.RUN_METADATA_FILE).read_bytes() == before
    assert receipt_env.entry.read_bytes() == entry_before
    assert {
        path.name: path.read_bytes()
        for path in receipt_env.root.glob("*.receipt.*.json")
    } == sidecars_before


@pytest.mark.parametrize(
    ("key_kind", "variant"),
    (
        ("snapshot", "exact"),
        ("snapshot", "pending"),
        ("snapshot", "rejected"),
        ("snapshot", "invalid"),
        ("snapshot", "digest"),
        ("snapshot", "profile"),
        ("snapshot", "stable"),
        ("snapshot", "nonce"),
        ("snapshot", "session"),
        ("lineage", "lineage"),
    ),
)
def test_t26_global_discovery_skips_every_reserved_marker_variant(
    stage3a2_receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key_kind: str,
    variant: str,
) -> None:
    receipt_env = stage3a2_receipt_env
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    source = target / "global.py"
    source.write_text("x = 1\n", encoding="utf-8")
    project_out = tmp_path / "project-out"
    run = project_out / "receipt-copy"
    run.mkdir(parents=True)
    key = (
        metadata.RUN_RUNTIME_RECEIPT_KEY
        if key_kind == "snapshot"
        else metadata.RUN_RUNTIME_RECEIPT_LINEAGE_KEY
    )
    value = (
        _snapshot_variant(receipt_env, variant)
        if key_kind == "snapshot"
        else {"entries": []}
    )
    (run / metadata.RUN_METADATA_FILE).write_text(
        json.dumps({"status": "running", key: value}),
        encoding="utf-8",
    )
    before = (run / metadata.RUN_METADATA_FILE).read_bytes()
    entry_before = receipt_env.entry.read_bytes()
    sidecars_before = {
        path.name: path.read_bytes()
        for path in receipt_env.root.glob("*.receipt.*.json")
    }
    _install_active_project(home, output_dir=project_out, target=target)
    monkeypatch.delenv(sessions.ENV_SESSION_PID, raising=False)
    monkeypatch.delenv(sessions.ENV_SESSION_TOKEN, raising=False)

    with (
        patch.dict(os.environ, {"HOME": str(home)}, clear=True),
        _receipt_authority_calls_forbidden(),
    ):
        result = track_read.process_read_event(_payload(source))

    assert result.effect_disposition is HostEventEffectDisposition.NO_CANDIDATE
    assert result.route == "legacy_global_fallback"
    assert not (run / track_read.MANIFEST_NAME).exists()
    assert (run / metadata.RUN_METADATA_FILE).read_bytes() == before
    assert receipt_env.entry.read_bytes() == entry_before
    assert {
        path.name: path.read_bytes()
        for path in receipt_env.root.glob("*.receipt.*.json")
    } == sidecars_before


def test_t26_global_discovery_skips_valid_lineage_without_parsing(
    stage3a2_receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt_env = stage3a2_receipt_env
    source_run = _start_receipt(
        receipt_env,
        tmp_path,
        name="valid-lineage-source",
    )
    assert metadata.resume_run(source_run) == 2
    source_meta = source_run / metadata.RUN_METADATA_FILE

    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    source = target / "valid-lineage.py"
    source.write_text("x = 1\n", encoding="utf-8")
    project_out = tmp_path / "project-out"
    run = project_out / "valid-lineage-copy"
    run.mkdir(parents=True)
    (run / metadata.RUN_METADATA_FILE).write_bytes(source_meta.read_bytes())
    before = (run / metadata.RUN_METADATA_FILE).read_bytes()
    _install_active_project(home, output_dir=project_out, target=target)
    monkeypatch.delenv(sessions.ENV_SESSION_PID, raising=False)
    monkeypatch.delenv(sessions.ENV_SESSION_TOKEN, raising=False)

    with (
        patch.dict(os.environ, {"HOME": str(home)}, clear=True),
        _receipt_authority_calls_forbidden(),
    ):
        result = track_read.process_read_event(_payload(source))

    assert result.effect_disposition is HostEventEffectDisposition.NO_CANDIDATE
    assert not (run / track_read.MANIFEST_NAME).exists()
    assert (run / metadata.RUN_METADATA_FILE).read_bytes() == before


def test_t26_global_discovery_skips_newest_copy_and_selects_older_legacy(
    stage3a2_receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt_env = stage3a2_receipt_env
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    source = target / "global.py"
    source.write_text("x = 1\n", encoding="utf-8")
    project_out = tmp_path / "project-out"
    legacy = project_out / "legacy"
    receipt_copy = project_out / "receipt-copy"
    legacy.mkdir(parents=True)
    receipt_copy.mkdir()
    (legacy / metadata.RUN_METADATA_FILE).write_text(
        json.dumps({"status": "running"}),
        encoding="utf-8",
    )
    (receipt_copy / metadata.RUN_METADATA_FILE).write_text(
        json.dumps(
            {
                "status": "running",
                metadata.RUN_RUNTIME_RECEIPT_KEY: _snapshot_variant(
                    receipt_env,
                    "exact",
                ),
            }
        ),
        encoding="utf-8",
    )
    os.utime(legacy, (1, 1))
    os.utime(receipt_copy, (2, 2))
    _install_active_project(home, output_dir=project_out, target=target)
    monkeypatch.delenv(sessions.ENV_SESSION_PID, raising=False)
    monkeypatch.delenv(sessions.ENV_SESSION_TOKEN, raising=False)

    with (
        patch.dict(os.environ, {"HOME": str(home)}, clear=True),
        _receipt_authority_calls_forbidden(),
    ):
        result = track_read.process_read_event(_payload(source))

    assert result.effect_disposition is HostEventEffectDisposition.APPLIED
    assert result.target is not None
    assert result.target.run_dir == legacy
    assert (legacy / track_read.MANIFEST_NAME).read_text(encoding="utf-8") == (
        str(source.resolve()) + "\n"
    )
    assert not (receipt_copy / track_read.MANIFEST_NAME).exists()


def test_t26_payload_overrides_cannot_select_a_reserved_marker(
    stage3a2_receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt_env = stage3a2_receipt_env
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    source = target / "global.py"
    source.write_text("x = 1\n", encoding="utf-8")
    project_out = tmp_path / "project-out"
    run = project_out / "receipt-copy"
    run.mkdir(parents=True)
    (run / metadata.RUN_METADATA_FILE).write_text(
        json.dumps(
            {
                "status": "running",
                metadata.RUN_RUNTIME_RECEIPT_KEY: _snapshot_variant(
                    receipt_env,
                    "exact",
                ),
            }
        ),
        encoding="utf-8",
    )
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    _install_active_project(home, output_dir=project_out, target=target)
    monkeypatch.delenv(sessions.ENV_SESSION_PID, raising=False)
    monkeypatch.delenv(sessions.ENV_SESSION_TOKEN, raising=False)
    raw = _payload(
        source,
        run_dir=str(attacker),
        output_dir=str(attacker),
        project="attacker",
        target_path=str(attacker),
        manifest=str(attacker / "manifest"),
    )

    with (
        patch.dict(os.environ, {"HOME": str(home)}, clear=True),
        _receipt_authority_calls_forbidden(),
    ):
        result = track_read.process_read_event(raw)

    assert result.effect_disposition is HostEventEffectDisposition.NO_CANDIDATE
    assert list(attacker.iterdir()) == []
    assert not (run / track_read.MANIFEST_NAME).exists()


def test_t26_post_open_reserved_marker_race_writes_zero_bytes_128_times(
    stage3a2_receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt_env = stage3a2_receipt_env
    home = tmp_path / "home"
    home.mkdir()
    target_path = tmp_path / "target"
    target_path.mkdir()
    source = target_path / "race.py"
    source.write_text("x = 1\n", encoding="utf-8")
    project_out = tmp_path / "project-out"
    run = project_out / "legacy"
    run.mkdir(parents=True)
    meta_path = run / metadata.RUN_METADATA_FILE
    _install_active_project(home, output_dir=project_out, target=target_path)
    monkeypatch.delenv(sessions.ENV_SESSION_PID, raising=False)
    monkeypatch.delenv(sessions.ENV_SESSION_TOKEN, raising=False)
    observation = track_read.ReadObservation(
        event=object(),
        reported_path=str(source),
    )

    with (
        patch.dict(os.environ, {"HOME": str(home)}, clear=True),
        _receipt_authority_calls_forbidden(),
    ):
        for iteration in range(128):
            meta_path.write_text(
                json.dumps({"status": "running", "iteration": iteration}),
                encoding="utf-8",
            )
            resolved = track_read.resolve_read_target()
            assert resolved.target is not None
            meta_path.write_text(
                json.dumps(
                    {
                        "status": "running",
                        "iteration": iteration,
                        metadata.RUN_RUNTIME_RECEIPT_KEY: _snapshot_variant(
                            receipt_env,
                            "exact",
                        ),
                    }
                ),
                encoding="utf-8",
            )
            after_race = meta_path.read_bytes()
            disposition, reason, recorded = track_read.record_read(
                resolved.target,
                observation,
            )
            assert disposition is HostEventEffectDisposition.NO_CANDIDATE
            assert reason == "no_candidate"
            assert recorded is None
            assert meta_path.read_bytes() == after_race
            manifest = run / track_read.MANIFEST_NAME
            assert manifest.exists()
            assert manifest.read_bytes() == b""


def test_t26_post_open_denial_never_retries_ambient_discovery(
    stage3a2_receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt_env = stage3a2_receipt_env
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    source = target / "once.py"
    source.write_text("x = 1\n", encoding="utf-8")
    project_out = tmp_path / "project-out"
    run = project_out / "legacy"
    run.mkdir(parents=True)
    meta_path = run / metadata.RUN_METADATA_FILE
    meta_path.write_text(json.dumps({"status": "running"}), encoding="utf-8")
    _install_active_project(home, output_dir=project_out, target=target)
    monkeypatch.delenv(sessions.ENV_SESSION_PID, raising=False)
    monkeypatch.delenv(sessions.ENV_SESSION_TOKEN, raising=False)
    real_find = track_read._find_global_run
    calls = 0

    def select_then_fence():
        nonlocal calls
        calls += 1
        selected = real_find()
        current = json.loads(meta_path.read_text(encoding="utf-8"))
        current[metadata.RUN_RUNTIME_RECEIPT_KEY] = _snapshot_variant(
            receipt_env,
            "exact",
        )
        meta_path.write_text(json.dumps(current), encoding="utf-8")
        return selected

    with (
        patch.dict(os.environ, {"HOME": str(home)}, clear=True),
        patch.object(track_read, "_find_global_run", side_effect=select_then_fence),
        _receipt_authority_calls_forbidden(),
    ):
        result = track_read.process_read_event(_payload(source))

    assert calls == 1
    assert result.effect_disposition is HostEventEffectDisposition.NO_CANDIDATE
    manifest = run / track_read.MANIFEST_NAME
    assert manifest.exists()
    assert manifest.read_bytes() == b""


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_c3_same_owner_symlinked_run_directory_is_allowed(
    tmp_path,
    isolated_registry,
):
    home, sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target = tmp_path / "target"
        target.mkdir()
        source = target / "a.py"
        source.write_text("x = 1\n")
        real_run = _write_run(
            tmp_path, pid=process.pid, name="real-run", target=str(target)
        )
        linked_run = tmp_path / "linked-run"
        linked_run.symlink_to(real_run, target_is_directory=True)
        ledger = sessions_dir / f"{process.pid}.run"
        ledger.write_text(
            f"running 100 linked-run {linked_run}\n",
            encoding="utf-8",
        )

        result = _process_with_env(
            _payload(source), _owner_env(home, process.pid, token)
        )

    assert result.effect_disposition is HostEventEffectDisposition.APPLIED
    assert result.target is not None
    assert result.target.run_dir == linked_run
    assert (real_run / track_read.MANIFEST_NAME).read_text() == (
        str(source.resolve()) + "\n"
    )


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_e20_two_owned_running_runs_are_ambiguous(
    tmp_path,
    isolated_registry,
):
    home, _sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target = tmp_path / "target"
        target.mkdir()
        source = target / "a.py"
        source.write_text("x = 1\n")
        runs = [
            _write_run(tmp_path, pid=process.pid, name=name, target=str(target))
            for name in ("run-one", "run-two")
        ]
        result = _process_with_env(
            _payload(source), _owner_env(home, process.pid, token)
        )

    assert result.effect_disposition is HostEventEffectDisposition.AMBIGUOUS
    assert all(not (run / track_read.MANIFEST_NAME).exists() for run in runs)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_e20_dead_quiet_run_does_not_make_live_run_ambiguous(
    tmp_path,
    isolated_registry,
):
    home, _sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target = tmp_path / "target"
        target.mkdir()
        source = target / "a.py"
        source.write_text("x = 1\n")
        stale = _write_run(
            tmp_path, pid=process.pid, name="stale-run", target=str(target),
        )
        active = _write_run(
            tmp_path, pid=process.pid, name="active-run", target=str(target),
        )
        stale_meta_path = stale / metadata.RUN_METADATA_FILE
        stale_meta = json.loads(stale_meta_path.read_text(encoding="utf-8"))
        stale_meta["tool_pid"] = 999999999
        stale_meta_path.write_text(json.dumps(stale_meta), encoding="utf-8")
        old = time.time() - metadata._ABANDON_ACTIVITY_GRACE_S - 5
        os.utime(stale_meta_path, (old, old))
        os.utime(stale, (old, old))

        result = _process_with_env(
            _payload(source), _owner_env(home, process.pid, token)
        )

    assert result.effect_disposition is HostEventEffectDisposition.APPLIED
    assert result.target is not None
    assert result.target.run_dir == active
    assert not (stale / track_read.MANIFEST_NAME).exists()
    assert (active / track_read.MANIFEST_NAME).read_text() == (
        str(source.resolve()) + "\n"
    )


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_e21_resumed_foreign_owner_is_not_a_candidate(
    tmp_path,
    isolated_registry,
):
    home, _sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target = tmp_path / "target"
        target.mkdir()
        source = target / "a.py"
        source.write_text("x = 1\n")
        run = _write_run(tmp_path, pid=process.pid, name="resumed", target=str(target))
        meta_path = run / metadata.RUN_METADATA_FILE
        meta_value = json.loads(meta_path.read_text(encoding="utf-8"))
        meta_value["session_pid"] = process.pid + 1
        meta_path.write_text(json.dumps(meta_value), encoding="utf-8")

        result = _process_with_env(
            _payload(source), _owner_env(home, process.pid, token)
        )

    assert result.effect_disposition is HostEventEffectDisposition.NO_CANDIDATE
    assert not (run / track_read.MANIFEST_NAME).exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_c3_selection_to_append_recheck_refuses_changed_owner(
    tmp_path,
    isolated_registry,
):
    home, _sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target_dir = tmp_path / "target"
        target_dir.mkdir()
        source = target_dir / "a.py"
        source.write_text("x = 1\n")
        run = _write_run(
            tmp_path,
            pid=process.pid,
            name="owner-change",
            target=str(target_dir),
        )
        env = _owner_env(home, process.pid, token)
        with patch.dict(os.environ, env, clear=True):
            resolution = track_read.resolve_read_target()
        assert resolution.target is not None
        meta_path = run / metadata.RUN_METADATA_FILE
        meta_value = json.loads(meta_path.read_text(encoding="utf-8"))
        meta_value["session_pid"] = process.pid + 1
        meta_path.write_text(json.dumps(meta_value), encoding="utf-8")
        with patch.dict(os.environ, env, clear=True):
            parsed = track_read.process_read_event(
                _payload(source),
                profile=HostEventProfileId.CLAUDE_LEGACY_V1,
            )
        assert parsed.effect_disposition is (HostEventEffectDisposition.NO_CANDIDATE)
        # Exercise the post-open recheck against the target selected above.
        normalized = parsed.event
        assert normalized is not None
        observation = track_read.ReadObservation(
            event=normalized,
            reported_path=str(source),
        )
        disposition, _reason, _path = track_read.record_read(
            resolution.target,
            observation,
        )

    assert disposition is HostEventEffectDisposition.NO_CANDIDATE
    manifest = run / track_read.MANIFEST_NAME
    assert not manifest.exists() or manifest.read_bytes() == b""


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_t1_post_open_status_flip_returns_no_candidate_and_empty_manifest(
    tmp_path,
    isolated_registry,
    monkeypatch,
):
    """A terminal status observed at the post-open recheck writes no line."""
    from core.run.host_events import HostEventKind, normalize_host_event

    home, _sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target_dir = tmp_path / "target"
        target_dir.mkdir()
        source = target_dir / "a.py"
        source.write_text("x = 1\n")
        run = _write_run(
            tmp_path,
            pid=process.pid,
            name="status-change",
            target=str(target_dir),
        )
        env = _owner_env(home, process.pid, token)
        with patch.dict(os.environ, env, clear=True):
            resolution = track_read.resolve_read_target()
        assert resolution.target is not None
        parsed = normalize_host_event(
            _payload(source),
            profile=HostEventProfileId.CLAUDE_LEGACY_V1,
            registration_kind=HostEventKind.TOOL_SUCCESS,
        )
        assert parsed.event is not None
        observation = track_read.ReadObservation(
            event=parsed.event,
            reported_path=str(source),
        )
        meta_path = run / metadata.RUN_METADATA_FILE
        real_read = track_read._read_regular_json_at
        flipped = False

        def flip_status_on_recheck(name, *, dir_fd=None, path=None, max_bytes):
            nonlocal flipped
            if dir_fd is not None and not flipped:
                value = json.loads(meta_path.read_text(encoding="utf-8"))
                value["status"] = "completed"
                meta_path.write_text(json.dumps(value), encoding="utf-8")
                flipped = True
            return real_read(
                name,
                dir_fd=dir_fd,
                path=path,
                max_bytes=max_bytes,
            )

        monkeypatch.setattr(
            track_read,
            "_read_regular_json_at",
            flip_status_on_recheck,
        )
        disposition, _reason, recorded = track_read.record_read(
            resolution.target,
            observation,
        )

    assert flipped is True
    assert disposition is HostEventEffectDisposition.NO_CANDIDATE
    assert recorded is None
    manifest = run / track_read.MANIFEST_NAME
    assert manifest.exists()
    assert manifest.read_bytes() == b""


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_n1_absent_target_is_legitimately_unfiltered(
    tmp_path,
    isolated_registry,
):
    home, _sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        source = tmp_path / "outside.py"
        source.write_text("x = 1\n")
        run = _write_run(tmp_path, pid=process.pid, name="unfiltered")

        result = _process_with_env(
            _payload(source), _owner_env(home, process.pid, token)
        )

    assert result.effect_disposition is HostEventEffectDisposition.APPLIED
    assert (run / track_read.MANIFEST_NAME).read_text() == (
        str(source.resolve()) + "\n"
    )


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize(
    "invalid_target",
    [
        42,
        "relative/path",
        "/definitely/not/a/real/w4b1-target",
        "/bad\npath",
        "/",
    ],
    ids=["non-string", "relative", "missing", "control", "root"],
)
def test_n1_present_invalid_target_is_refused(
    tmp_path,
    isolated_registry,
    invalid_target,
):
    home, _sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        source = tmp_path / "a.py"
        source.write_text("x = 1\n")
        run = _write_run(
            tmp_path,
            pid=process.pid,
            name="invalid-target",
            target=invalid_target,
        )

        result = _process_with_env(
            _payload(source), _owner_env(home, process.pid, token)
        )

    assert result.effect_disposition is (HostEventEffectDisposition.INVALID_TARGET)
    assert not (run / track_read.MANIFEST_NAME).exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize("case", ["outside", "sibling-prefix", "symlink-out"])
def test_e25_e26_target_containment_is_realpath_component_based(
    tmp_path,
    isolated_registry,
    case,
):
    home, _sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target = tmp_path / "foo"
        target.mkdir()
        outside_dir = tmp_path / ("foobar" if case == "sibling-prefix" else "out")
        outside_dir.mkdir()
        outside = outside_dir / "a.py"
        outside.write_text("x = 1\n")
        if case == "symlink-out":
            reported = target / "linked.py"
            reported.symlink_to(outside)
        else:
            reported = outside
        run = _write_run(
            tmp_path, pid=process.pid, name=f"contain-{case}", target=str(target)
        )

        result = _process_with_env(
            _payload(reported), _owner_env(home, process.pid, token)
        )

    assert result.effect_disposition is (HostEventEffectDisposition.INVALID_TARGET)
    assert not (run / track_read.MANIFEST_NAME).exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_e26_symlink_resolution_cannot_inject_manifest_line(
    tmp_path,
    isolated_registry,
):
    home, _sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target = tmp_path / "target"
        target.mkdir()
        newline_target = target / "line\nbreak.py"
        newline_target.write_text("x = 1\n")
        reported = target / "safe.py"
        reported.symlink_to(newline_target)
        run = _write_run(
            tmp_path, pid=process.pid, name="control-symlink", target=str(target)
        )

        result = _process_with_env(
            _payload(reported), _owner_env(home, process.pid, token)
        )

    assert result.effect_disposition is (HostEventEffectDisposition.INVALID_TARGET)
    assert not (run / track_read.MANIFEST_NAME).exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_n1_target_symlink_resolving_to_control_path_is_invalid(
    tmp_path,
    isolated_registry,
):
    home, _sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        actual_target = tmp_path / "target\nresolved"
        actual_target.mkdir()
        target = tmp_path / "safe-target"
        target.symlink_to(actual_target, target_is_directory=True)
        (actual_target / "a.py").write_text("x = 1\n")
        reported = target / "a.py"
        run = _write_run(
            tmp_path, pid=process.pid, name="target-control", target=str(target)
        )

        result = _process_with_env(
            _payload(reported), _owner_env(home, process.pid, token)
        )

    assert result.effect_disposition is (HostEventEffectDisposition.INVALID_TARGET)
    assert not (run / track_read.MANIFEST_NAME).exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize(
    "bad_meta",
    ["missing", "symlink", "fifo", "oversize", "malformed", "non-object"],
)
def test_n2_bad_run_metadata_is_skipped_without_hanging(
    tmp_path,
    isolated_registry,
    bad_meta,
):
    home, _sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target = tmp_path / "target"
        target.mkdir()
        source = target / "a.py"
        source.write_text("x = 1\n")
        run = _write_run(
            tmp_path, pid=process.pid, name=f"bad-meta-{bad_meta}", target=str(target)
        )
        meta_path = run / metadata.RUN_METADATA_FILE
        meta_path.unlink()
        if bad_meta == "missing":
            pass
        elif bad_meta == "symlink":
            backing = run / "metadata-backing.json"
            backing.write_text(
                json.dumps({"status": "running", "session_pid": process.pid}),
                encoding="utf-8",
            )
            meta_path.symlink_to(backing.name)
        elif bad_meta == "fifo":
            os.mkfifo(meta_path)
        elif bad_meta == "oversize":
            meta_path.write_bytes(b" " * (1024 * 1024 + 1))
        elif bad_meta == "malformed":
            meta_path.write_text("{not-json", encoding="utf-8")
        else:
            meta_path.write_text("[]", encoding="utf-8")

        started = time.monotonic()
        result = _process_with_env(
            _payload(source), _owner_env(home, process.pid, token)
        )
        elapsed = time.monotonic() - started

    assert elapsed < 2
    assert result.effect_disposition is HostEventEffectDisposition.NO_CANDIDATE
    assert not (run / track_read.MANIFEST_NAME).exists()


def test_c3_ledger_read_failure_and_invalid_records_are_no_candidate(
    monkeypatch,
):
    monkeypatch.setattr(
        sessions,
        "resolve_session_owner",
        lambda: SessionOwner(
            pid=9001,
            frontend=Frontend.CLAUDE,
            host_verified=False,
        ),
    )
    env = {
        sessions.ENV_SESSION_PID: "9001",
        sessions.ENV_SESSION_TOKEN: "aa" * 16,
    }
    monkeypatch.setattr(
        sessions,
        "ledger_runs",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("unavailable")),
    )
    failed = track_read.resolve_read_target(environ=env)
    assert failed.disposition is HostEventEffectDisposition.NO_CANDIDATE

    monkeypatch.setattr(
        sessions,
        "ledger_runs",
        lambda **_kwargs: [
            {"run_id": "", "run_dir": "/owned/run"},
            {"run_id": "relative", "run_dir": "relative/run"},
            {"run_id": "control", "run_dir": "/owned/bad\nrun"},
        ],
    )
    invalid = track_read.resolve_read_target(environ=env)
    assert invalid.disposition is HostEventEffectDisposition.NO_CANDIDATE


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_t4_duplicate_ledger_record_remains_one_candidate(
    tmp_path,
    isolated_registry,
):
    home, sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target = tmp_path / "target"
        target.mkdir()
        source = target / "a.py"
        source.write_text("x = 1\n")
        run = _write_run(
            tmp_path,
            pid=process.pid,
            name="duplicate-ledger",
            target=str(target),
        )
        ledger = sessions_dir / f"{process.pid}.run"
        original = ledger.read_text(encoding="utf-8")
        ledger.write_text(original + original, encoding="utf-8")

        result = _process_with_env(
            _payload(source),
            _owner_env(home, process.pid, token),
        )

    assert result.effect_disposition is HostEventEffectDisposition.APPLIED
    assert (run / track_read.MANIFEST_NAME).read_text(encoding="utf-8") == (
        str(source.resolve()) + "\n"
    )


def test_e03_alias_does_not_create_file_path_argument():
    """The candidate-unverified fixture keeps native candidate argument keys."""
    from core.run.host_events import normalize_host_event, HostEventKind

    parsed = normalize_host_event(
        _candidate_read_payload("/owned/a.py"),
        profile=HostEventProfileId.COPILOT_1_0_84_4_HOOK_CANDIDATE,
        registration_kind=HostEventKind.TOOL_SUCCESS,
    )
    assert parsed.event is not None

    observed = track_read.extract_read_observation(
        parsed.event,
        track_read.ReadArgumentContract("Read", "file_path"),
    )

    assert observed.disposition is HostEventParseDisposition.INVALID
    assert observed.observation is None
    assert "file_path" not in (parsed.event.tool_args or {})


def test_e04_missing_or_bad_read_arguments_have_no_observation():
    from core.run.host_events import normalize_host_event, HostEventKind

    for payload in (
        {},
        {"tool_input": {}},
        {"tool_input": {"file_path": 7}},
    ):
        parsed = normalize_host_event(
            json.dumps(payload).encode(),
            profile=HostEventProfileId.CLAUDE_LEGACY_V1,
            registration_kind=HostEventKind.TOOL_SUCCESS,
        )
        assert parsed.event is not None
        observed = track_read.extract_read_observation(
            parsed.event,
            track_read.ReadArgumentContract("Read", "file_path"),
        )
        assert observed.disposition is HostEventParseDisposition.INVALID
        assert observed.observation is None


@pytest.mark.parametrize(
    ("payload", "reason_code"),
    [
        (b"{not-json", "malformed_json"),
        (json.dumps({"tool_input": {}}).encode(), "missing_file_path"),
    ],
    ids=["parse-invalid", "observation-invalid"],
)
def test_t5_process_read_event_invalid_early_return(
    monkeypatch,
    payload,
    reason_code,
):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("invalid input reached owner resolution")

    monkeypatch.setattr(track_read, "resolve_read_target", forbidden)
    result = track_read.process_read_event(payload)

    assert result.parse_disposition is HostEventParseDisposition.INVALID
    assert result.effect_disposition is None
    assert result.reason_code == reason_code


def test_e05_non_read_tool_is_unsupported():
    from core.run.host_events import normalize_host_event, HostEventKind

    parsed = normalize_host_event(
        json.dumps(
            {
                "tool_name": "Bash",
                "tool_input": {"file_path": "/owned/a.py"},
            }
        ).encode(),
        profile=HostEventProfileId.CLAUDE_LEGACY_V1,
        registration_kind=HostEventKind.TOOL_SUCCESS,
    )
    assert parsed.event is not None

    observed = track_read.extract_read_observation(
        parsed.event,
        track_read.ReadArgumentContract("Read", "file_path"),
    )

    assert observed.disposition is HostEventParseDisposition.UNSUPPORTED
    assert observed.observation is None


def test_n5_read_path_diagnostic_does_not_echo_payload():
    from core.run.host_events import normalize_host_event, HostEventKind

    secret = "SECRET-/owned/path\n"
    parsed = normalize_host_event(
        json.dumps({"tool_input": {"file_path": secret}}).encode(),
        profile=HostEventProfileId.CLAUDE_LEGACY_V1,
        registration_kind=HostEventKind.TOOL_SUCCESS,
    )
    assert parsed.event is not None

    observed = track_read.extract_read_observation(
        parsed.event,
        track_read.ReadArgumentContract("Read", "file_path"),
    )

    assert observed.disposition is HostEventParseDisposition.INVALID
    assert secret not in observed.detail


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_c3_source_extension_matching_remains_case_insensitive(
    tmp_path,
    isolated_registry,
):
    home, _sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target = tmp_path / "target"
        target.mkdir()
        source = target / "UPPER.PY"
        source.write_text("x = 1\n")
        run = _write_run(tmp_path, pid=process.pid, name="upper", target=str(target))

        result = _process_with_env(
            _payload(source), _owner_env(home, process.pid, token)
        )

    assert result.effect_disposition is HostEventEffectDisposition.APPLIED
    assert (run / track_read.MANIFEST_NAME).is_file()


@pytest.mark.parametrize(
    "reported",
    [
        "directory.py",
        "image.png",
        "missing-parent/source.py",
    ],
)
def test_c3_non_source_directory_and_missing_parent_are_refused(
    tmp_path,
    reported,
):
    target = tmp_path / "target"
    target.mkdir()
    if reported == "directory.py":
        value = target / reported
        value.mkdir()
    elif reported == "image.png":
        value = target / reported
        value.write_text("not source\n")
    else:
        value = target / reported

    assert track_read._resolve_source_path(str(value), target) is None


def test_e45_candidate_process_never_reaches_record_read(monkeypatch):
    """Candidate-unverified fixtures cannot reach the production write effect."""
    called = False

    def forbidden(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("candidate profile reached record_read")

    monkeypatch.setattr(track_read, "record_read", forbidden)
    raw = _candidate_read_payload("/owned/a.py")

    result = track_read.process_read_event(
        raw,
        profile=HostEventProfileId.COPILOT_1_0_84_4_HOOK_CANDIDATE,
        environ={},
    )

    assert result.effect_disposition is (HostEventEffectDisposition.EFFECTS_DISABLED)
    assert (
        PROFILE_META[HostEventProfileId.COPILOT_1_0_84_4_HOOK_CANDIDATE].effects_enabled
        is False
    )
    assert called is False


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_e30_duplicate_reads_append_twice_but_convert_once(
    tmp_path,
    isolated_registry,
):
    home, _sessions_dir = isolated_registry
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target = tmp_path / "target"
        target.mkdir()
        source = target / "a.py"
        source.write_text("x = 1\n")
        run = _write_run(
            tmp_path, pid=process.pid, name="duplicates", target=str(target)
        )
        env = _owner_env(home, process.pid, token)

        first = _process_with_env(_payload(source), env)
        second = _process_with_env(_payload(source), env)

    assert first.effect_disposition is HostEventEffectDisposition.APPLIED
    assert second.effect_disposition is HostEventEffectDisposition.APPLIED
    manifest = run / track_read.MANIFEST_NAME
    assert manifest.read_bytes() == ((str(source.resolve()) + "\n") * 2).encode()
    record = build_from_manifest(run, "read")
    assert record is not None
    assert record["files_examined"] == [str(source.resolve())]
