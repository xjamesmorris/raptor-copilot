"""Real read-coverage consumer tests using the shared host fixtures."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

from core.coverage import track_read
from core.project import sessions
from core.startup.host import Frontend, SessionOwner
from core.testing.host_events import (
    claude_read_event,
    copilot_candidate_read_event,
)


def _owned_run(tmp_path: Path) -> tuple[Path, Path, Path, int]:
    home = tmp_path / "home"
    target = home / "target"
    run = home / "out" / "scan-1"
    sessions = home / ".local" / "share" / "raptor" / "sessions.d"
    target.mkdir(parents=True)
    run.mkdir(parents=True)
    sessions.mkdir(parents=True)
    source = target / "source.py"
    source.write_text("value = 1\n", encoding="utf-8")
    session_pid = 424242
    (run / ".raptor-run.json").write_text(
        json.dumps(
            {
                "status": "running",
                "session_pid": session_pid,
                "target_path": str(target),
            }
        ),
        encoding="utf-8",
    )
    (sessions / f"{session_pid}.run").write_text(
        f"running 100 {run.name} {run}\n",
        encoding="utf-8",
    )
    return home, target, run, session_pid


def _fire(
    monkeypatch,
    *,
    home: Path,
    session_pid: int,
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
            frontend=Frontend.CLAUDE,
            host_verified=False,
        ),
    )
    monkeypatch.setenv("RAPTOR_SESSION_PID", str(session_pid))
    monkeypatch.setenv("RAPTOR_SESSION_TOKEN", "fixture-token")
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(payload.decode("utf-8")),
    )
    track_read.main()


def test_shared_claude_fixture_exercises_existing_read_consumer(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home, _target, run, session_pid = _owned_run(tmp_path)
    source = home / "target" / "source.py"
    event = claude_read_event(str(source))

    _fire(
        monkeypatch,
        home=home,
        session_pid=session_pid,
        payload=event.to_bytes(),
    )

    assert (run / track_read.MANIFEST_NAME).read_text(
        encoding="utf-8"
    ) == f"{source.resolve()}\n"


def test_candidate_path_argument_does_not_cross_into_claude_consumer(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home, _target, run, session_pid = _owned_run(tmp_path)
    source = home / "target" / "source.py"
    event = copilot_candidate_read_event(str(source))

    _fire(
        monkeypatch,
        home=home,
        session_pid=session_pid,
        payload=event.to_bytes(),
    )

    assert not (run / track_read.MANIFEST_NAME).exists()


def test_argument_name_mismatch_is_not_synthesised(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home, _target, run, session_pid = _owned_run(tmp_path)
    source = home / "target" / "source.py"
    event = claude_read_event(str(source), argument_name="path")

    _fire(
        monkeypatch,
        home=home,
        session_pid=session_pid,
        payload=event.to_bytes(),
    )

    assert not (run / track_read.MANIFEST_NAME).exists()
