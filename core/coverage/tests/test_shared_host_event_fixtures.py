"""Cross-frontend read coverage through the shared host-event contract."""

from __future__ import annotations

import io
import json
import stat
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from core.coverage import track_read
from core.json import load_json
from core.project import sessions
from core.run import metadata
from core.startup.host import Frontend, SessionOwner
from core.testing.host_events import (
    HostEventFixture,
    claude_read_event,
    copilot_live_read_payload,
    copilot_read_event,
)

EventFactory = Callable[..., HostEventFixture]

_FRONTENDS = (
    pytest.param(Frontend.CLAUDE, claude_read_event, id="claude-read"),
    pytest.param(Frontend.COPILOT, copilot_read_event, id="copilot-view"),
)


def _owned_run(tmp_path: Path) -> tuple[Path, Path, Path, Path, int]:
    home = tmp_path / "home"
    target = home / "target"
    run = home / "out" / "scan-1"
    sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
    target.mkdir(parents=True)
    run.mkdir(parents=True)
    sessions_dir.mkdir(parents=True)
    source = target / "source.py"
    source.write_text("value = 1\n", encoding="utf-8")
    session_pid = 424242
    (run / metadata.RUN_METADATA_FILE).write_text(
        json.dumps(
            {
                "version": 1,
                "command": "scan",
                "status": "running",
                "session_pid": session_pid,
                "target_path": str(target),
            }
        ),
        encoding="utf-8",
    )
    (sessions_dir / f"{session_pid}.run").write_text(
        f"running 100 {run.name} {run}\n",
        encoding="utf-8",
    )
    return home, target, run, source, session_pid


def _fire(
    monkeypatch: pytest.MonkeyPatch,
    *,
    home: Path,
    session_pid: int,
    frontend: Frontend,
    payload: bytes,
) -> None:
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.setattr(
        sessions,
        "SESSIONS_DIR",
        home / ".local" / "share" / "raptor" / "sessions.d",
    )
    monkeypatch.setattr(
        sessions,
        "resolve_session_owner",
        lambda: SessionOwner(
            pid=session_pid,
            frontend=frontend,
            host_verified=frontend is Frontend.COPILOT,
        ),
    )
    monkeypatch.setenv("RAPTOR_SESSION_PID", str(session_pid))
    monkeypatch.setenv("RAPTOR_SESSION_TOKEN", "fixture-token")
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(payload.decode("utf-8")),
    )
    assert track_read.main() == 0


@pytest.mark.parametrize(("frontend", "event_factory"), _FRONTENDS)
def test_frontends_record_the_exact_in_target_realpath(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    frontend: Frontend,
    event_factory: EventFactory,
) -> None:
    home, target, run, source, session_pid = _owned_run(tmp_path)
    alias = target / "alias.py"
    alias.symlink_to(source.name)

    _fire(
        monkeypatch,
        home=home,
        session_pid=session_pid,
        frontend=frontend,
        payload=event_factory(str(alias)).to_bytes(),
    )

    manifest = run / track_read.MANIFEST_NAME
    assert manifest.read_text(encoding="utf-8") == f"{source.resolve()}\n"
    assert stat.S_IMODE(manifest.stat().st_mode) == 0o600


@pytest.mark.parametrize(("frontend", "event_factory"), _FRONTENDS)
def test_duplicate_reads_and_session_end_conversion_are_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    frontend: Frontend,
    event_factory: EventFactory,
) -> None:
    home, _target, run, source, session_pid = _owned_run(tmp_path)
    payload = event_factory(str(source)).to_bytes()

    for _ in range(2):
        _fire(
            monkeypatch,
            home=home,
            session_pid=session_pid,
            frontend=frontend,
            payload=payload,
        )

    manifest = run / track_read.MANIFEST_NAME
    assert manifest.read_text(encoding="utf-8") == (
        f"{source.resolve()}\n" * 2
    )

    metadata.fail_run(run, error="session ended before run completed")
    metadata.fail_run(run, error="session ended before run completed")

    coverage_path = run / "coverage-read.json"
    coverage = load_json(coverage_path)
    assert coverage["tool"] == "read"
    assert coverage["files_examined"] == [str(source.resolve())]
    assert stat.S_IMODE(manifest.stat().st_mode) == 0o600
    assert stat.S_IMODE(coverage_path.stat().st_mode) == 0o600


@pytest.mark.parametrize(("frontend", "event_factory"), _FRONTENDS)
def test_unsupported_extension_never_creates_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    frontend: Frontend,
    event_factory: EventFactory,
) -> None:
    home, target, run, _source, session_pid = _owned_run(tmp_path)
    unsupported = target / "probe.txt"
    unsupported.write_text("fixture only\n", encoding="utf-8")

    _fire(
        monkeypatch,
        home=home,
        session_pid=session_pid,
        frontend=frontend,
        payload=event_factory(str(unsupported)).to_bytes(),
    )

    assert not (run / track_read.MANIFEST_NAME).exists()


@pytest.mark.parametrize(("frontend", "event_factory"), _FRONTENDS)
def test_realpath_containment_refuses_direct_and_symlinked_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    frontend: Frontend,
    event_factory: EventFactory,
) -> None:
    home, target, run, _source, session_pid = _owned_run(tmp_path)
    outside = home / "outside.py"
    outside.write_text("outside = True\n", encoding="utf-8")
    escape = target / "escape.py"
    escape.symlink_to(outside)

    for reported in (outside, escape):
        _fire(
            monkeypatch,
            home=home,
            session_pid=session_pid,
            frontend=frontend,
            payload=event_factory(str(reported)).to_bytes(),
        )

    assert not (run / track_read.MANIFEST_NAME).exists()


@pytest.mark.parametrize(
    ("payload_factory", "frontend"),
    [
        pytest.param(
            lambda path: claude_read_event(path, tool_name="Bash").to_bytes(),
            Frontend.CLAUDE,
            id="claude-bash",
        ),
        pytest.param(
            lambda path: copilot_read_event(path, tool_name="shell").to_bytes(),
            Frontend.COPILOT,
            id="copilot-shell",
        ),
    ],
)
def test_arbitrary_tool_events_do_not_count_as_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload_factory: Callable[[str], bytes],
    frontend: Frontend,
) -> None:
    home, _target, run, source, session_pid = _owned_run(tmp_path)

    _fire(
        monkeypatch,
        home=home,
        session_pid=session_pid,
        frontend=frontend,
        payload=payload_factory(str(source)),
    )

    assert not (run / track_read.MANIFEST_NAME).exists()


def test_live_copilot_payload_requires_authenticated_copilot_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, _target, run, source, session_pid = _owned_run(tmp_path)

    _fire(
        monkeypatch,
        home=home,
        session_pid=session_pid,
        frontend=Frontend.CLAUDE,
        payload=copilot_live_read_payload(str(source)),
    )

    assert not (run / track_read.MANIFEST_NAME).exists()


def test_exact_live_compat_payload_materializes_owner_only_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, _target, run, source, session_pid = _owned_run(tmp_path)

    _fire(
        monkeypatch,
        home=home,
        session_pid=session_pid,
        frontend=Frontend.COPILOT,
        payload=copilot_live_read_payload(str(source)),
    )

    manifest = run / track_read.MANIFEST_NAME
    assert manifest.read_text(encoding="utf-8") == f"{source.resolve()}\n"
    assert stat.S_IMODE(manifest.stat().st_mode) == 0o600

    metadata.fail_run(run, error="session ended before run completed")
    coverage = run / "coverage-read.json"
    assert load_json(coverage)["files_examined"] == [str(source.resolve())]
    assert stat.S_IMODE(coverage.stat().st_mode) == 0o600


def test_identical_hybrid_aliases_record_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, _target, run, source, session_pid = _owned_run(tmp_path)
    path = str(source)
    payload = copilot_read_event(path).to_bytes(
        overrides={
            "hookEventName": "postToolUse",
            "hook_event_name": "PostToolUse",
            "session_id": "copilot-session-1",
            "tool_name": "Read",
            "toolArgs": {"path": path, "file_path": path},
            "tool_input": {"file_path": path},
        }
    )

    _fire(
        monkeypatch,
        home=home,
        session_pid=session_pid,
        frontend=Frontend.COPILOT,
        payload=payload,
    )

    assert (run / track_read.MANIFEST_NAME).read_text(
        encoding="utf-8"
    ) == f"{source.resolve()}\n"


@pytest.mark.parametrize(
    "overrides",
    [
        {"hookEventName": "sessionEnd"},
        {"hookEventName": "postToolUse\nforged"},
        {
            "hookEventName": "postToolUse",
            "hook_event_name": "SessionEnd",
        },
        {"session_id": "copilot-session-1"},
        {
            "session_id": "other-session",
            "tool_name": "Read",
            "tool_input": {"path": "/owned/source.py"},
        },
        {
            "session_id": "copilot-session-1",
            "tool_name": "Bash",
            "tool_input": {"path": "/owned/source.py"},
        },
        {
            "session_id": "copilot-session-1",
            "tool_name": "Read",
            "tool_input": {"path": "/owned/other.py"},
        },
        {
            "toolArgs": {
                "path": "/owned/source.py",
                "file_path": "/owned/other.py",
            },
        },
    ],
    ids=[
        "wrong-kind",
        "hostile-kind",
        "conflicting-kind-aliases",
        "incomplete-mixed-aliases",
        "conflicting-session-aliases",
        "conflicting-tool-aliases",
        "conflicting-argument-aliases",
        "conflicting-nested-path-aliases",
    ],
)
def test_hostile_or_conflicting_copilot_aliases_never_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
) -> None:
    home, _target, run, source, session_pid = _owned_run(tmp_path)
    payload = copilot_read_event(str(source)).to_bytes(overrides=overrides)

    _fire(
        monkeypatch,
        home=home,
        session_pid=session_pid,
        frontend=Frontend.COPILOT,
        payload=payload,
    )

    assert not (run / track_read.MANIFEST_NAME).exists()


@pytest.mark.parametrize(
    "payload",
    [
        copilot_read_event("/owned/source.py").to_bytes(
            omit_fields=("sessionId",)
        ),
        copilot_read_event("/owned/source.py").to_bytes(
            omit_fields=("toolName",)
        ),
        copilot_read_event("/owned/source.py").to_bytes(
            omit_fields=("toolArgs",)
        ),
        copilot_read_event("/owned/source.py").to_bytes(
            overrides={"toolArgs": {}}
        ),
    ],
    ids=["missing-session", "missing-tool", "missing-args", "missing-path"],
)
def test_missing_copilot_fields_do_not_create_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    home, _target, run, _source, session_pid = _owned_run(tmp_path)

    _fire(
        monkeypatch,
        home=home,
        session_pid=session_pid,
        frontend=Frontend.COPILOT,
        payload=payload,
    )

    assert not (run / track_read.MANIFEST_NAME).exists()


@pytest.mark.parametrize(
    "payload",
    [
        claude_read_event("/owned/source.py").to_bytes(
            omit_fields=("tool_input",)
        ),
        claude_read_event("/owned/source.py").to_bytes(
            overrides={"tool_input": {}}
        ),
    ],
    ids=["missing-args", "missing-path"],
)
def test_missing_claude_fields_do_not_create_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    home, _target, run, _source, session_pid = _owned_run(tmp_path)

    _fire(
        monkeypatch,
        home=home,
        session_pid=session_pid,
        frontend=Frontend.CLAUDE,
        payload=payload,
    )

    assert not (run / track_read.MANIFEST_NAME).exists()


@pytest.mark.parametrize(("frontend", "event_factory"), _FRONTENDS)
def test_hostile_paths_are_sanitized_and_never_echoed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    frontend: Frontend,
    event_factory: EventFactory,
) -> None:
    home, _target, run, source, session_pid = _owned_run(tmp_path)
    hostile = f"{source}\nSECRET-HOSTILE-PATH"

    _fire(
        monkeypatch,
        home=home,
        session_pid=session_pid,
        frontend=frontend,
        payload=event_factory(hostile).to_bytes(),
    )

    captured = capsys.readouterr()
    assert "SECRET-HOSTILE-PATH" not in captured.out
    assert "SECRET-HOSTILE-PATH" not in captured.err
    assert "bad_file_path" in captured.out
    assert not (run / track_read.MANIFEST_NAME).exists()
