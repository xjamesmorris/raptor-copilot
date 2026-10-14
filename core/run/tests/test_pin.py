"""Run-scoped project pinning — start-time precedence,
write-once, the in-run state table, walk-up safety, and the lifecycle
ledger wiring."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterator
from unittest.mock import patch

import pytest

from core.json import load_json, save_json
from core.project.oplock import ProjectRunContention
from core.project import sessions
from core.project.project import ProjectManager
from core.run import RUN_METADATA_FILE, complete_run, start_run
from core.run import metadata as run_metadata
from core.run import pin as pin_module
from core.run.pin import (
    ARGV_NONE,
    ProjectArgvError,
    RunPin,
    resolve_pin_for_start,
    resolve_run_pin,
    set_process_project,
)
from core.startup.host import Frontend, build_session_host_claim
from core.testing.runtime_receipt_fake import (
    RuntimeReceiptRunEnvironment as _ReceiptEnvironment,
    forbid_receipt_sidecar_reads as _sidecar_reads_forbidden,
    runtime_receipt_run_environment,
    start_runtime_receipt_run as _start_receipt,
)

_REAL_FREEZE_RUN_PIN = pin_module.freeze_run_pin
_HOST_V2_TOKEN = "00112233445566778899aabbccddeeff"


@pytest.fixture
def stage3a2_receipt_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_ReceiptEnvironment]:
    with runtime_receipt_run_environment(tmp_path, monkeypatch) as environment:
        yield environment


def _write_host_v2_entry(root: Path, *, state: str = "pending") -> Path:
    fields = {
        "v": "2",
        "project": "-",
        "since": "2026-09-12T00:00:00+00:00",
        "starttime": "1",
        "boot_id": "00000000-0000-4000-8000-000000000000",
        "pidns": "1",
        "host_v": "2",
        "host": "copilot",
        "host_uid": str(os.geteuid()),
        "host_exe": "/owned/copilot",
        "host_exe_dev": "10",
        "host_exe_ino": "20",
        "host_receipt_v": "1",
        "host_receipt_state": state,
        "host_receipt_sha256": "a" * 64,
        "host_receipt_reference": "{}",
        "token": _HOST_V2_TOKEN,
        "seeded_by": "owned_fake",
    }
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    entry = root / str(os.getpid())
    entry.write_text(
        "".join(f"{key}={fields[key]}\n" for key in sessions._HOST_V2_ENTRY_KEYS),
        encoding="utf-8",
    )
    entry.chmod(0o600)
    return entry


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
                        f"deny-only pin consumer called {target}"
                    ),
                )
            )
        stack.enter_context(_sidecar_reads_forbidden("deny-only pin consumer"))
        yield


class _PinCase(unittest.TestCase):
    """Isolated projects dir + sessions dir + a claude-shaped self."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.projects_dir = self.root / "projects"
        self.sessions_dir = self.root / "sessions.d"
        (self.root / "code").mkdir()
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create(
            "pinned",
            str(self.root / "code"),
            output_dir=str(self.root / "out" / "pinned"),
        )
        for p in (
            patch("core.project.project.PROJECTS_DIR", self.projects_dir),
            patch.object(sessions, "SESSIONS_DIR", self.sessions_dir),
            patch.object(
                sessions, "_comm", lambda pid: "claude" if pid == os.getpid() else None
            ),
        ):
            p.start()
            self.addCleanup(p.stop)
        set_process_project(None)
        self.addCleanup(set_process_project, None)


class ResolveForStartTest(_PinCase):
    def test_argv_beats_binding_beats_symlink(self):
        self.mgr.create(
            "other",
            str(self.root / "code"),
            output_dir=str(self.root / "out" / "other"),
        )
        self.mgr.set_active("other")
        sessions.record_session("pinned", pid=os.getpid())
        with patch.object(sessions, "resolve_session_pid", return_value=os.getpid()):
            self.assertEqual(resolve_pin_for_start(), ("pinned", "session"))
            set_process_project("other")
            self.assertEqual(resolve_pin_for_start(), ("other", "argv"))
            set_process_project("-")
            self.assertEqual(resolve_pin_for_start(), (None, "argv"))

    def test_symlink_layer_when_no_binding(self):
        self.mgr.set_active("pinned")
        with patch.object(sessions, "resolve_session_pid", return_value=None):
            self.assertEqual(resolve_pin_for_start(), ("pinned", "symlink"))

    def test_none_when_nothing(self):
        with patch.object(sessions, "resolve_session_pid", return_value=None):
            self.assertEqual(resolve_pin_for_start(), (None, "none"))

    def test_bound_to_none_is_authoritative_over_symlink(self):
        self.mgr.set_active("pinned")
        sessions.bind_session(None, pid=os.getpid())
        with patch.object(sessions, "resolve_session_pid", return_value=os.getpid()):
            self.assertEqual(resolve_pin_for_start(), (None, "session"))

    def test_stale_binding_never_falls_through(self):
        self.mgr.create(
            "doomed",
            str(self.root / "code"),
            output_dir=str(self.root / "out" / "doomed"),
        )
        self.mgr.set_active("pinned")
        sessions.record_session("doomed", pid=os.getpid())
        self.mgr.delete("doomed")
        with patch.object(sessions, "resolve_session_pid", return_value=os.getpid()):
            self.assertEqual(resolve_pin_for_start(), (None, "session"))

    def test_threaded_env_marker_demotes_argv_to_threaded(self):
        # Harness-synthesized --project (skill dispatch threading a
        # parent pin into a lifecycle child) must not record the
        # operator-explicit "argv" source: the child sets the env
        # marker, and the pin writer records "threaded". Both shapes —
        # the null pin (`--project -`) and a named project.
        from core.run.pin import PIN_THREADED_ENV
        with patch.dict(os.environ, {PIN_THREADED_ENV: "1"}):
            set_process_project("-")
            self.assertEqual(resolve_pin_for_start(), (None, "threaded"))
            set_process_project("pinned")
            self.assertEqual(resolve_pin_for_start(),
                             ("pinned", "threaded"))

    def test_bootstrap_adoption_records_threaded(self):
        # adopt_process_pin promotes a run-marker pin to the process
        # override in-process (no argv, no env) — a run started later
        # in that process records "threaded" too.
        set_process_project("-", threaded=True)
        self.assertEqual(resolve_pin_for_start(), (None, "threaded"))
        # An operator-typed flag afterwards clears the harness flag.
        set_process_project("-")
        self.assertEqual(resolve_pin_for_start(), (None, "argv"))

    def test_invalid_argv_is_hard_error(self):
        set_process_project("no-such-project")
        with self.assertRaises(ProjectArgvError):
            resolve_pin_for_start()
        set_process_project("../evil")
        with self.assertRaises(ProjectArgvError):
            resolve_pin_for_start()


class StartRunPinTest(_PinCase):
    def test_pin_recorded_null_for_standalone(self):
        out = self.root / "standalone" / "run"
        with patch.object(sessions, "resolve_session_pid", return_value=None):
            start_run(out, "scan")
        meta = load_json(out / RUN_METADATA_FILE)
        self.assertIsNone(meta["project"])
        self.assertEqual(meta["project_source"], "none")

    def test_pin_write_once_across_reentrant_start(self):
        """The documented re-entrant flows must not re-pin: a binding
        change between the two starts is exactly the contamination the
        pin exists to stop."""
        out = self.root / "out" / "pinned" / "agentic-1"
        self.mgr.set_active("pinned")
        with patch.object(sessions, "resolve_session_pid", return_value=None):
            start_run(out, "agentic")
            self.mgr.set_active(None)  # layer moves under the run
            start_run(out, "agentic")  # re-entrant second start
        meta = load_json(out / RUN_METADATA_FILE)
        self.assertEqual(meta["project"], "pinned")
        self.assertEqual(meta["project_source"], "symlink")

    def test_conflicting_argv_on_reentrant_start_is_hard_error(self):
        out = self.root / "out" / "pinned" / "agentic-2"
        self.mgr.set_active("pinned")
        self.mgr.create(
            "other",
            str(self.root / "code"),
            output_dir=str(self.root / "out" / "other"),
        )
        with patch.object(sessions, "resolve_session_pid", return_value=None):
            start_run(out, "agentic")
            set_process_project("other")
            with self.assertRaises(ProjectArgvError):
                start_run(out, "agentic")

    def test_pin_survives_completion_metadata_merge(self):
        out = self.root / "out" / "pinned" / "scan-1"
        self.mgr.set_active("pinned")
        with patch.object(sessions, "resolve_session_pid", return_value=None):
            start_run(out, "scan")
        complete_run(out)
        meta = load_json(out / RUN_METADATA_FILE)
        self.assertEqual(meta["project"], "pinned")


class ResolveRunPinTest(_PinCase):
    def _run_dir(self, name: str, project, source: str) -> Path:
        d = self.root / "out" / name
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": project,
                "project_source": source,
            },
        )
        return d

    def test_pinned_project_authoritative(self):
        d = self._run_dir("r1", "pinned", "session")
        pin = resolve_run_pin(d)
        self.assertEqual((pin.project, pin.source), ("pinned", "session"))
        self.assertTrue(pin.authoritative)
        self.assertTrue(pin.writes_allowed)

    def test_null_pin_forbids_containment_inference(self):
        """A standalone run placed INSIDE a project dir via --out must
        stay standalone — containment would re-open the contamination
        pinning closes."""
        d = self.root / "out" / "pinned" / "smuggled"
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": None,
                "project_source": "none",
            },
        )
        pin = resolve_run_pin(d)
        self.assertIsNone(pin.project)
        self.assertTrue(pin.authoritative)

    def test_deleted_project_pin_is_authoritative_none(self):
        d = self._run_dir("r2", "ghost", "session")
        pin = resolve_run_pin(d)
        self.assertIsNone(pin.project)
        self.assertTrue(pin.authoritative)

    def test_child_out_dir_walks_up_to_owning_run(self):
        d = self._run_dir("r3", "pinned", "symlink")
        child = d / "scan"
        child.mkdir()
        pin = resolve_run_pin(child)
        self.assertEqual(pin.project, "pinned")
        self.assertEqual(pin.run_dir, d.resolve())

    def test_legacy_run_falls_back_to_containment_reads_only(self):
        d = Path(self.mgr.load("pinned").output_dir) / "old-run"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {"status": "running"})  # no pin
        pin = resolve_run_pin(d)
        self.assertEqual(pin.project, "pinned")
        self.assertFalse(pin.authoritative)
        self.assertFalse(pin.writes_allowed)

    def test_no_marker_containment_reads_only(self):
        d = Path(self.mgr.load("pinned").output_dir) / "not-a-run"
        d.mkdir(parents=True)
        pin = resolve_run_pin(d)
        self.assertEqual(pin.project, "pinned")
        self.assertFalse(pin.writes_allowed)

    def test_world_writable_marker_ignored(self):
        d = self.root / "out" / "planted"
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": "pinned",
                "project_source": "session",
            },
        )
        os.chmod(d, 0o777)
        sub = d / "victim"
        sub.mkdir()
        pin = resolve_run_pin(sub)
        self.assertFalse(pin.authoritative)
        self.assertFalse(pin.writes_allowed)


class LedgerWiringTest(_PinCase):
    def test_start_and_terminal_wire_the_ledger(self):
        sessions.record_session("pinned", pid=os.getpid())
        out = self.root / "out" / "pinned" / "scan-9"
        with (
            patch("core.run.metadata._get_session_pid", return_value=os.getpid()),
            patch.object(sessions, "resolve_session_pid", return_value=os.getpid()),
        ):
            start_run(out, "scan")
            runs = sessions.ledger_runs(pid=os.getpid())
            self.assertEqual(
                [(r["run_id"], r["status"]) for r in runs], [("scan-9", "running")]
            )
            complete_run(out)
        runs = sessions.ledger_runs(pid=os.getpid())
        self.assertEqual(runs[0]["status"], "completed")

    def test_unregistered_session_gets_no_ledger(self):
        out = self.root / "out" / "pinned" / "scan-10"
        with (
            patch("core.run.metadata._get_session_pid", return_value=os.getpid()),
            patch.object(sessions, "resolve_session_pid", return_value=os.getpid()),
        ):
            start_run(out, "scan")
        self.assertFalse((self.sessions_dir / f"{os.getpid()}.run").exists())


class RunPinShapeTest(unittest.TestCase):
    def test_dataclass_shape(self):
        pin = RunPin(None, "none", None, True, True)
        self.assertIsNone(pin.project)
        with self.assertRaises(AttributeError):
            pin.project = "x"  # frozen


@unittest.skipUnless(sys.platform == "linux", "Linux process identity")
class StrongHostProjectIsolationTest(unittest.TestCase):
    """Two verified frontend sessions keep bindings, contention, and pins apart."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.projects_dir = self.root / "projects"
        self.sessions_dir = self.root / "sessions.d"
        self.targets = {
            "alpha": self.root / "alpha-code",
            "beta": self.root / "beta-code",
        }
        for target in self.targets.values():
            target.mkdir()
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create(
            "alpha",
            str(self.targets["alpha"]),
            output_dir=str(self.root / "out" / "alpha"),
        )
        self.mgr.create(
            "beta",
            str(self.targets["beta"]),
            output_dir=str(self.root / "out" / "beta"),
        )
        self.mgr.set_active("beta")
        self._patches = (
            patch("core.project.project.PROJECTS_DIR", self.projects_dir),
            patch.object(sessions, "SESSIONS_DIR", self.sessions_dir),
        )
        for item in self._patches:
            item.start()
            self.addCleanup(item.stop)
        set_process_project(None)
        self.addCleanup(set_process_project, None)

    @contextlib.contextmanager
    def _credential(self, process, token):
        with patch.dict(
            os.environ,
            {
                sessions.ENV_SESSION_PID: str(process.pid),
                sessions.ENV_SESSION_TOKEN: token,
            },
        ):
            yield

    def test_concurrent_hosts_do_not_cross_projects_and_resume_keeps_pin(self):
        # Use exact host basenames: Linux task comm is the executed file's
        # basename, while the inode keeps the two owners distinct.
        source = shutil.which("sleep")
        if source is None:
            self.skipTest("sleep executable unavailable")
        claude_exe = self.root / "claude"
        copilot_exe = self.root / "copilot"
        shutil.copy2(source, claude_exe)
        shutil.copy2(source, copilot_exe)
        claude_exe.chmod(0o700)
        copilot_exe.chmod(0o700)
        claude = subprocess.Popen(
            [str(claude_exe), "60"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        copilot = subprocess.Popen(
            [str(copilot_exe), "60"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            claude_token = sessions.mint_token()
            copilot_token = sessions.mint_token()
            self.assertEqual(
                sessions.record_session(
                    "alpha",
                    pid=claude.pid,
                    token=claude_token,
                    host_claim=build_session_host_claim(Frontend.CLAUDE, claude_exe),
                ),
                claude.pid,
            )
            self.assertEqual(
                sessions.record_session(
                    "beta",
                    pid=copilot.pid,
                    token=copilot_token,
                    host_claim=build_session_host_claim(Frontend.COPILOT, copilot_exe),
                ),
                copilot.pid,
            )

            alpha_run = self.root / "out" / "alpha" / "scan-alpha"
            with self._credential(claude, claude_token):
                start_run(alpha_run, "scan")
            alpha_meta = load_json(alpha_run / RUN_METADATA_FILE)
            self.assertEqual(alpha_meta["project"], "alpha")
            self.assertEqual(alpha_meta["session_host"], "claude")

            with (
                self._credential(copilot, copilot_token),
                self.assertRaises(ProjectRunContention),
            ):
                start_run(
                    self.root / "out" / "alpha" / "scan-foreign",
                    "scan",
                )

            beta_run = self.root / "out" / "beta" / "scan-beta"
            with self._credential(copilot, copilot_token):
                start_run(beta_run, "scan")
            beta_meta = load_json(beta_run / RUN_METADATA_FILE)
            self.assertEqual(beta_meta["project"], "beta")
            self.assertEqual(beta_meta["session_host"], "copilot")

            with self._credential(claude, claude_token):
                sessions.bind_session(None)
                self.assertEqual(resolve_pin_for_start(), (None, "session"))
            with self._credential(copilot, copilot_token):
                self.assertEqual(resolve_pin_for_start(), ("beta", "session"))

            # The already-started run never moves with either ambient binding.
            self.assertEqual(resolve_run_pin(alpha_run).project, "alpha")

            from core.run.metadata import fail_run, resume_run

            fail_run(alpha_run, "handoff")
            with self._credential(copilot, copilot_token):
                resume_run(alpha_run)
            resumed = load_json(alpha_run / RUN_METADATA_FILE)
            self.assertEqual(resumed["project"], "alpha")
            self.assertEqual(resumed["session_host"], "copilot")
            self.assertEqual(resumed["session_pid"], copilot.pid)
        finally:
            for process in (copilot, claude):
                if process.poll() is None:
                    process.terminate()
            for process in (copilot, claude):
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()


class PinConsumerMigrationTest(_PinCase):
    """Wave-1 consumers follow the RUN PIN, not the ambient layers
    : trust markers, persisted binaries, and
     the child-process pin bootstrap."""

    def _pinned_run(self, project: str | None) -> Path:
        d = self.root / "out" / f"run-{project or 'none'}"
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": project,
                "project_source": "session",
            },
        )
        return d

    def test_trust_markers_follow_the_pin(self):
        proj = self.mgr.load("pinned")
        proj.trust = {"dynamic": "2026-08-23T00:00:00+00:00"}
        self.mgr._save(proj)
        self.mgr.create(
            "ambient",
            str(self.root / "code"),
            output_dir=str(self.root / "out" / "ambient"),
        )
        self.mgr.set_active("ambient")
        run = self._pinned_run("pinned")
        from core.project.trust import active_project_trust

        markers, name = active_project_trust(run_dir=run)
        self.assertEqual(name, "pinned")
        self.assertIn("dynamic", markers)
        # Ambient (no run_dir) resolves the active layer instead.
        _m, ambient_name = active_project_trust()
        self.assertEqual(ambient_name, "ambient")

    def test_dynamic_marker_gated_by_pinned_target(self):
        proj = self.mgr.load("pinned")
        proj.trust = {"dynamic": "2026-08-23T00:00:00+00:00"}
        self.mgr._save(proj)
        run = self._pinned_run("pinned")
        from core.project.trust import resolve_dynamic_validation

        self.assertTrue(
            resolve_dynamic_validation(
                None, banner=False, target_path=self.root / "code", run_dir=run
            )
        )
        self.assertFalse(
            resolve_dynamic_validation(
                None, banner=False, target_path=self.root / "elsewhere", run_dir=run
            )
        )

    def test_project_binaries_one_target_gate(self):
        """a security-review finding: project X's binaries must never drive absent
        verdicts for tree Y."""
        binary = self.root / "code" / "app.bin"
        binary.write_bytes(b"\x7fELF")
        proj = self.mgr.load("pinned")
        proj.binaries = [str(binary)]
        self.mgr._save(proj)
        self.mgr.set_active("pinned")
        from core.analysis.binary_oracle_cli import _project_binaries

        paths, name = _project_binaries(repo=self.root / "code")
        self.assertEqual([str(p) for p in paths], [str(binary)])
        foreign = self.root / "foreign-tree"
        foreign.mkdir()
        paths, name = _project_binaries(repo=foreign)
        self.assertEqual(paths, [])
        self.assertEqual(name, "pinned")

    def test_bootstrap_adopts_authoritative_pin_only(self):
        from core.run.pin import bootstrap_process_pin, get_process_project

        run = self._pinned_run("pinned")
        child_out = run / "scan"
        child_out.mkdir()
        bootstrap_process_pin(child_out)
        self.assertEqual(get_process_project(), "pinned")
        set_process_project(None)
        # Legacy (pin-less) run dir: containment is reads-only — the
        # bootstrap must NOT promote it to a process override.
        legacy = Path(self.mgr.load("pinned").output_dir) / "legacy"
        legacy.mkdir(parents=True)
        save_json(legacy / RUN_METADATA_FILE, {"status": "running"})
        bootstrap_process_pin(legacy)
        self.assertIsNone(get_process_project())

    def test_bootstrap_never_overwrites_explicit_argv(self):
        from core.run.pin import bootstrap_process_pin, get_process_project

        run = self._pinned_run("pinned")
        set_process_project("pinned")
        bootstrap_process_pin(run)
        self.assertEqual(get_process_project(), "pinned")

    def test_bootstrap_conflicting_argv_hard_errors(self):
        # --project X plus --out <run pinned to Y> would run SPLIT
        # (override for ambient consumers, pin for run-dir consumers):
        # hard error, never a silent pick.
        from core.run.pin import ProjectArgvError, bootstrap_process_pin

        run = self._pinned_run("pinned")
        set_process_project("-")
        with self.assertRaises(ProjectArgvError):
            bootstrap_process_pin(run)

    def test_null_pin_bootstraps_projectless(self):
        from core.run.pin import bootstrap_process_pin, get_process_project

        run = self._pinned_run(None)
        bootstrap_process_pin(run)
        self.assertEqual(get_process_project(), "-")

    def test_bootstrap_witness_disagreement_uses_witness(self):
        # The run marker is child-writable; the ledger witness is not.
        # A disagreement means the marker was rewritten — the witness
        # wins the adoption AND the seal.
        from core.run.pin import (
            _frozen_pins,
            bootstrap_process_pin,
            get_process_project,
        )

        run = self._pinned_run("pinned")
        with patch.object(
            sessions,
            "ledger_pin_witness",
            lambda run_dir, pid=None: (True, None, "session"),
        ):
            bootstrap_process_pin(run)
        self.assertEqual(get_process_project(), "-")
        frozen = _frozen_pins.get(str(run.resolve()))
        self.assertIsNotNone(frozen)
        self.assertIsNone(frozen.project)

    def test_bootstrap_unwitnessed_adoption_never_sealed(self):
        # No witness (pre-witness run, sessionless): the adoption keeps
        # compatibility, but an unwitnessed marker must never be
        # laundered into trusted frozen state for the process lifetime.
        from core.run.pin import (
            _frozen_pins,
            bootstrap_process_pin,
            get_process_project,
        )

        run = self._pinned_run("pinned")
        with patch.object(
            sessions,
            "ledger_pin_witness",
            lambda run_dir, pid=None: (False, None, None),
        ):
            bootstrap_process_pin(run)
        self.assertEqual(get_process_project(), "pinned")
        self.assertNotIn(str(run.resolve()), _frozen_pins)

    def test_bootstrap_witnessed_agreement_sealed(self):
        # Two-direction guard: a witnessed, agreeing marker still gets
        # the freeze-cache seal (marker-rewrite immunity).
        from core.run.pin import (
            _frozen_pins,
            bootstrap_process_pin,
            get_process_project,
        )

        run = self._pinned_run("pinned")
        with patch.object(
            sessions,
            "ledger_pin_witness",
            lambda run_dir, pid=None: (True, "pinned", "session"),
        ):
            bootstrap_process_pin(run)
        self.assertEqual(get_process_project(), "pinned")
        frozen = _frozen_pins.get(str(run.resolve()))
        self.assertIsNotNone(frozen)
        self.assertEqual(frozen.project, "pinned")


class PinFreezeCacheTest(_PinCase):
    """The process freeze cache seals the pin at start_run: a child
    rewriting the on-disk marker (the run dir is the sandbox write
    grant) must not move this process's consumers."""

    def _run_dir(self) -> Path:
        d = self.root / "out" / "pinned" / "scan_x"
        d.mkdir(parents=True)
        return d

    def test_marker_rewrite_cannot_move_frozen_pin(self):
        from core.run.metadata import start_run
        from core.run.pin import resolve_run_pin

        d = self._run_dir()
        self.mgr.set_active("pinned")
        start_run(d, "scan", target=str(self.root / "code"))
        self.assertEqual(resolve_run_pin(d).project, "pinned")
        # Hostile child rewrites the marker in place.
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": "evil",
                "project_source": "session",
            },
        )
        self.assertEqual(resolve_run_pin(d).project, "pinned")

    def test_reentrant_start_consults_cache_not_disk(self):
        from core.run.metadata import load_run_metadata, start_run

        d = self._run_dir()
        self.mgr.set_active("pinned")
        start_run(d, "scan", target=str(self.root / "code"))
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": "evil",
                "project_source": "session",
            },
        )
        start_run(d, "scan", target=str(self.root / "code"))
        self.assertEqual(load_run_metadata(d)["project"], "pinned")

    def test_pin_survives_completed_status(self):
        # /understand → /validate sharing one --out: the pin written at
        # the first start governs the second even after completion —
        # a mid-gap /project switch must not re-pin the dir. The
        # continuity is witness-backed: the first start's ledger
        # witness corroborates the disk pin for the second start
        # (an UNcorroborated disk pin in a reused --out dir does not
        # elect a project — that is the planted-marker defense).
        from core.run.metadata import complete_run, load_run_metadata, start_run
        from core.run.pin import _frozen_pins

        sessions.record_session("pinned", pid=os.getpid())
        patcher = patch.object(
            sessions, "resolve_session_pid", return_value=os.getpid()
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        d = self._run_dir()
        self.mgr.set_active("pinned")
        start_run(d, "understand", target=str(self.root / "code"))
        complete_run(d)
        _frozen_pins.clear()  # simulate a fresh process
        self.mgr.create(
            "other",
            str(self.root / "code"),
            output_dir=str(self.root / "out" / "other"),
        )
        self.mgr.set_active("other")
        start_run(d, "validate", target=str(self.root / "code"))
        self.assertEqual(load_run_metadata(d)["project"], "pinned")

    def test_uncorroborated_disagreement_is_a_hard_error(self):
        # A disagreeing pin with NO witness (planted marker — or a
        # legitimate reuse across a relaunch, indistinguishable) must
        # not silently elect EITHER side: the operator disambiguates
        # via --project.
        from core.json import save_json as _sj
        from core.run.metadata import start_run
        from core.run.pin import ProjectArgvError, set_process_project

        d = self.root / "out" / "reused"
        d.mkdir(parents=True)
        _sj(
            d / RUN_METADATA_FILE,
            {
                "status": "completed",
                "project": "pinned",
                "project_source": "argv",
            },
        )
        self.mgr.create(
            "ambient3",
            str(self.root / "code"),
            output_dir=str(self.root / "out" / "ambient3"),
        )
        self.mgr.set_active("ambient3")
        with self.assertRaises(ProjectArgvError):
            start_run(d, "scan", target=str(self.root / "code"))
        # Explicit --project resolves the ambiguity EITHER way: the
        # error's own remedies must both work.
        set_process_project("ambient3")  # re-pin to the fresh side
        try:
            start_run(d, "scan", target=str(self.root / "code"))
        finally:
            set_process_project(None)
        from core.run.metadata import load_run_metadata

        self.assertEqual(load_run_metadata(d)["project"], "ambient3")

    def test_uncorroborated_disagreement_error_is_inert(self):
        # The prior name comes from the disk marker — the
        # planted-marker case by definition, and every catcher
        # bare-prints str(e) to stderr. A name carrying ESC/OSC
        # bytes must arrive escaped in BOTH the description and the
        # --project remedy.
        from core.json import save_json as _sj
        from core.run.metadata import start_run
        from core.run.pin import ProjectArgvError
        d = self.root / "out" / "reused-esc"
        d.mkdir(parents=True)
        _sj(d / RUN_METADATA_FILE, {
            "status": "completed",
            "project": "pin\x1b]0;pwned\x07ned",
            "project_source": "argv",
        })
        self.mgr.set_active("pinned")
        with self.assertRaises(ProjectArgvError) as ctx:
            start_run(d, "scan", target=str(self.root / "code"))
        msg = str(ctx.exception)
        self.assertNotIn("\x1b", msg)
        self.assertNotIn("\x07", msg)
        self.assertIn("pwned", msg)  # legible, escaped

    def test_uncorroborated_keep_side_override_works(self):
        from core.json import save_json as _sj
        from core.run.metadata import load_run_metadata, start_run
        from core.run.pin import set_process_project

        d = self.root / "out" / "reused3"
        d.mkdir(parents=True)
        _sj(
            d / RUN_METADATA_FILE,
            {
                "status": "completed",
                "project": "pinned",
                "project_source": "argv",
            },
        )
        self.mgr.create(
            "ambient4",
            str(self.root / "code"),
            output_dir=str(self.root / "out" / "ambient4"),
        )
        self.mgr.set_active("ambient4")
        set_process_project("pinned")  # keep the dir's pin
        try:
            start_run(d, "scan", target=str(self.root / "code"))
        finally:
            set_process_project(None)
        self.assertEqual(load_run_metadata(d)["project"], "pinned")

    def test_uncorroborated_agreement_stands_silently(self):
        from core.json import save_json as _sj
        from core.run.metadata import load_run_metadata, start_run

        d = self.root / "out" / "reused2"
        d.mkdir(parents=True)
        _sj(
            d / RUN_METADATA_FILE,
            {
                "status": "completed",
                "project": "pinned",
                "project_source": "session",
            },
        )
        self.mgr.set_active("pinned")
        start_run(d, "scan", target=str(self.root / "code"))
        self.assertEqual(load_run_metadata(d)["project"], "pinned")


class OutermostMarkerTest(_PinCase):
    def test_nested_planted_marker_loses_to_outer(self):
        from core.run.pin import resolve_run_pin

        outer = self.root / "out" / "pinned" / "fuzz_1"
        inner = outer / "afl-out" / "crashes"
        inner.mkdir(parents=True)
        save_json(
            outer / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": "pinned",
                "project_source": "session",
            },
        )
        save_json(
            inner / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": "evil",
                "project_source": "session",
            },
        )
        pin = resolve_run_pin(inner)
        self.assertEqual(pin.project, "pinned")


class OneTargetGateTest(_PinCase):
    def _pinned_run(self, target: str) -> Path:
        d = self.root / "out" / "pinned" / "audit_1"
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "completed",
                "project": "pinned",
                "project_source": "session",
                "target_path": target,
            },
        )
        return d

    def test_matching_target_passes(self):
        from core.run.pin import pinned_write_target_ok

        d = self._pinned_run(str(self.root / "code"))
        self.assertTrue(pinned_write_target_ok(d))

    def test_foreign_target_suppresses_project_store_writes(self):
        from core.run.metadata import _journal_project_dir
        from core.run.pin import pinned_write_target_ok

        (self.root / "elsewhere").mkdir()
        d = self._pinned_run(str(self.root / "elsewhere"))
        self.assertFalse(pinned_write_target_ok(d))
        self.assertIsNone(_journal_project_dir(d))

    def test_pinned_marker_without_target_fails_closed(self):
        # Every pin-era start_run seals target_path beside the pin —
        # a pin WITHOUT it is the deletion forgery (a wrong-typed
        # value already failed closed; dropping the field was the
        # remaining pass-through), not legacy tolerance.
        from core.run.pin import pinned_write_target_ok

        d = self.root / "out" / "pinned" / "audit_1"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "completed", "project": "pinned",
            "project_source": "session",
        })
        self.assertFalse(pinned_write_target_ok(d))

    def test_legacy_marker_without_pin_still_passes(self):
        # Pre-series markers carry neither pin nor target — the gate
        # must not regress their projections.
        from core.run.pin import pinned_write_target_ok
        d = self.root / "out" / "loose" / "audit_1"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "completed", "command": "audit",
        })
        self.assertTrue(pinned_write_target_ok(d))


class WriteRunPinTest(_PinCase):
    def test_upsert_preserves_other_keys(self):
        from core.json import load_json
        from core.run.metadata import write_run_pin

        d = self.root / "out" / "loose" / "scan_9"
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "completed",
                "command": "scan",
                "extra": {"k": 1},
            },
        )
        write_run_pin(d, "pinned", "adopted")
        meta = load_json(d / RUN_METADATA_FILE)
        self.assertEqual(meta["project"], "pinned")
        self.assertEqual(meta["project_source"], "adopted")
        self.assertEqual(meta["command"], "scan")
        self.assertEqual(meta["extra"], {"k": 1})

    def test_invalid_source_refused(self):
        from core.run.metadata import write_run_pin

        d = self.root / "out" / "loose" / "scan_9"
        d.mkdir(parents=True)
        with self.assertRaises(ValueError):
            write_run_pin(d, "pinned", "containment")

    def test_updates_freeze_cache(self):
        from core.run.metadata import write_run_pin
        from core.run.pin import resolve_run_pin

        d = self.root / "out" / "loose" / "scan_9"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {"status": "completed"})
        write_run_pin(d, "pinned", "adopted")
        self.assertEqual(resolve_run_pin(d).project, "pinned")


class WitnessAndTamperTest(_PinCase):
    """The out-of-grant ledger witness, tampered markers failing
    closed, and the out-root capture stop."""

    def _sessioned(self):
        sessions.record_session("pinned", pid=os.getpid())
        # The conftest neutralises ambient session resolution for
        # hermeticity; the witness reader resolves ambiently like the
        # real completion path, so give it this test's session.
        patcher = patch.object(
            sessions, "resolve_session_pid", return_value=os.getpid()
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_forged_marker_loses_to_ledger_witness(self):
        from core.project.sessions import ledger_record_start
        from core.run.metadata import _journal_project_dir, _pin_witness_ok
        from core.run.pin import resolve_run_pin

        self._sessioned()
        d = self.root / "out" / "standalone" / "scan_1"
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": None,
                "project_source": "none",
            },
        )
        ledger_record_start(d, pid=os.getpid(), pin_project=None, record_pin=True)
        # Hostile child re-pins the standalone run to the victim.
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "completed",
                "project": "pinned",
                "project_source": "argv",
                "target_path": str(self.root / "code"),
            },
        )
        pin = resolve_run_pin(d)
        self.assertFalse(_pin_witness_ok(d, pin))
        self.assertIsNone(_journal_project_dir(d))

    def test_agreeing_witness_passes(self):
        from core.project.sessions import ledger_record_start
        from core.run.metadata import _pin_witness_ok
        from core.run.pin import resolve_run_pin

        self._sessioned()
        d = self.root / "out" / "pinned" / "scan_2"
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "completed",
                "project": "pinned",
                "project_source": "session",
            },
        )
        ledger_record_start(d, pid=os.getpid(), pin_project="pinned", record_pin=True)
        self.assertTrue(_pin_witness_ok(d, resolve_run_pin(d)))

    def test_corrupt_marker_fails_closed_for_writers(self):
        from core.run.metadata import _journal_project_dir
        from core.run.pin import legacy_probe_allowed, resolve_run_pin

        d = self.root / "out" / "pinned" / "scan_3"
        d.mkdir(parents=True)
        (d / RUN_METADATA_FILE).write_text("{garbage", encoding="utf-8")
        pin = resolve_run_pin(d)
        self.assertFalse(pin.authoritative)
        self.assertFalse(legacy_probe_allowed(pin))
        self.assertIsNone(_journal_project_dir(d))

    def test_preseries_marker_still_allows_legacy_probe(self):
        from core.run.pin import legacy_probe_allowed, resolve_run_pin

        d = self.root / "out" / "pinned" / "scan_4"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {"status": "completed"})
        pin = resolve_run_pin(d)
        self.assertTrue(legacy_probe_allowed(pin))

    def test_out_root_marker_cannot_capture_runs(self):
        from core.run.pin import resolve_run_pin

        out_root = self.root / "out"
        save_json(
            out_root / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": "pinned",
                "project_source": "argv",
            },
        )
        d = out_root / "scan_5"
        d.mkdir()
        with patch("core.config.RaptorConfig.get_out_dir", return_value=out_root):
            pin = resolve_run_pin(d)
        self.assertNotEqual(pin.project, "pinned")

    def test_write_run_pin_refuses_live_runs_and_odd_sources(self):
        from core.run.metadata import write_run_pin

        d = self.root / "out" / "loose" / "scan_6"
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "running",
                "session_pid": os.getpid(),
            },
        )
        with self.assertRaises(ValueError):
            write_run_pin(d, "pinned", "argv")  # not a rewrite source
        with (
            patch("core.run.metadata._session_alive_for_meta", return_value=True),
            self.assertRaises(ValueError),
        ):
            write_run_pin(d, "pinned", "adopted")  # live run


class ResumeAndTamperTest(_PinCase):
    """Resume laundering, witness restore on deleted marker,
    non-string tamper, bounded reads."""

    def _sessioned(self):
        sessions.record_session("pinned", pid=os.getpid())
        patcher = patch.object(
            sessions, "resolve_session_pid", return_value=os.getpid()
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_resume_refuses_laundered_marker_pin(self):
        from core.run.metadata import resume_run

        self._sessioned()
        self.mgr.create(
            "mallory",
            str(self.root / "code"),
            output_dir=str(self.root / "out" / "mallory"),
        )
        d = self.root / "out" / "standalone" / "scan_r"
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": None,
                "project_source": "none",
                "command": "scan",
            },
        )
        sessions.ledger_record_start(
            d, pid=os.getpid(), pin_project=None, record_pin=True
        )
        # Hostile child re-pins to mallory and makes the run resumable.
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "interrupted",
                "project": "mallory",
                "project_source": "argv",
                "command": "scan",
            },
        )
        from core.run.pin import _frozen_pins

        _frozen_pins.clear()  # fresh resuming process
        resume_run(d)
        from core.json import load_json

        meta = load_json(d / RUN_METADATA_FILE)
        self.assertIsNone(
            meta["project"],
            "resume must restore the witnessed pin, not seal the laundered one",
        )

    def test_deleted_marker_pin_restored_from_witness_at_restart(self):
        from core.json import load_json
        from core.run.metadata import start_run
        from core.run.pin import _frozen_pins

        self._sessioned()
        d = self.root / "out" / "pinned" / "scan_dw"
        d.mkdir(parents=True)
        self.mgr.set_active("pinned")
        start_run(d, "scan", target=str(self.root / "code"))
        # Hostile child DELETES the marker; a cross-process re-entrant
        # start must restore the pin from the witness, not re-pin
        # ambiently.
        (d / RUN_METADATA_FILE).unlink()
        _frozen_pins.clear()
        self.mgr.create(
            "ambient2",
            str(self.root / "code"),
            output_dir=str(self.root / "out" / "ambient2"),
        )
        self.mgr.set_active("ambient2")
        start_run(d, "scan", target=str(self.root / "code"))
        meta = load_json(d / RUN_METADATA_FILE)
        self.assertEqual(meta["project"], "pinned")

    def test_nonstring_marker_project_is_authoritative_none(self):
        from core.run.pin import resolve_run_pin

        d = self.root / "out" / "loose" / "scan_ns"
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "completed",
                "project": 123,
                "project_source": "argv",
            },
        )
        pin = resolve_run_pin(d)
        self.assertIsNone(pin.project)
        self.assertTrue(pin.authoritative)

    def test_nonstring_target_fails_the_write_gate(self):
        from core.run.pin import pinned_write_target_ok

        d = self.root / "out" / "pinned" / "scan_nt"
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "completed",
                "project": "pinned",
                "project_source": "session",
                "target_path": ["/x"],
            },
        )
        self.assertFalse(pinned_write_target_ok(d))


class ResumeWitnessLifecycleTest(_PinCase):
    """Resume-path witness semantics: locked restore, cross-session
    lookup via the prior owner's ledger, fresh witness for segment 2."""

    def _sessioned(self, name="pinned"):
        sessions.record_session(name, pid=os.getpid())
        patcher = patch.object(
            sessions, "resolve_session_pid", return_value=os.getpid()
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_cross_session_resume_consults_prior_owner_witness(self):
        from core.json import load_json
        from core.run.metadata import resume_run
        from core.run.pin import _frozen_pins

        self._sessioned()
        self.mgr.create(
            "mallory",
            str(self.root / "code"),
            output_dir=str(self.root / "out" / "mallory"),
        )
        d = self.root / "out" / "standalone" / "scan_x"
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": None,
                "project_source": "none",
                "command": "scan",
                "session_pid": os.getpid(),
            },
        )
        # The ORIGINAL owner's ledger carries the witness.
        sessions.ledger_record_start(
            d, pid=os.getpid(), pin_project=None, record_pin=True
        )
        # Hostile child re-pins + makes resumable; the RESUMING
        # session is a different pid with no witness of its own.
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "interrupted",
                "project": "mallory",
                "project_source": "argv",
                "command": "scan",
                "session_pid": os.getpid(),
            },
        )
        _frozen_pins.clear()
        other_pid = os.getpid() + 1  # no ledger for this pid
        with patch.object(sessions, "resolve_session_pid", return_value=other_pid):
            resume_run(d)
        meta = load_json(d / RUN_METADATA_FILE)
        self.assertIsNone(
            meta["project"],
            "the prior owner's witness must veto the "
            "laundered marker on a cross-session resume",
        )

    def test_resume_restore_is_a_fresh_locked_rmw(self):
        # The restore must re-read the file, not save a stale
        # snapshot: a field written by a concurrent locked writer
        # after resume's first save must survive the restore.
        from core.json import load_json
        from core.run import metadata as md
        from core.run.pin import _frozen_pins

        self._sessioned()
        d = self.root / "out" / "standalone" / "scan_y"
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": None,
                "project_source": "none",
                "command": "scan",
            },
        )
        sessions.ledger_record_start(
            d, pid=os.getpid(), pin_project=None, record_pin=True
        )
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "interrupted",
                "project": "pinned",
                "project_source": "argv",
                "command": "scan",
                "sentinel_field": "must-survive",
            },
        )
        _frozen_pins.clear()
        md.resume_run(d)
        meta = load_json(d / RUN_METADATA_FILE)
        self.assertIsNone(meta["project"])
        self.assertEqual(meta.get("sentinel_field"), "must-survive")

    def test_resume_writes_a_segment2_witness(self):
        from core.run.metadata import resume_run
        from core.run.pin import _frozen_pins

        self._sessioned()
        d = self.root / "out" / "pinned" / "scan_z"
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "interrupted",
                "project": "pinned",
                "project_source": "session",
                "command": "scan",
            },
        )
        sessions.ledger_record_start(
            d,
            pid=os.getpid(),
            pin_project="pinned",
            record_pin=True,
            pin_source="session",
        )
        _frozen_pins.clear()
        resume_run(d)
        found, project, _src = sessions.ledger_pin_witness(d, pid=os.getpid())
        self.assertTrue(found)
        self.assertEqual(project, "pinned")


class OutRootBoundaryTest(_PinCase):
    def test_stray_checklist_at_out_root_is_not_a_project_store(self):
        from core.run.metadata import _journal_project_dir

        out_root = self.root / "out"
        (out_root / "checklist.json").write_text("{}", encoding="utf-8")
        legacy = out_root / "scan_legacy"
        legacy.mkdir()
        with patch("core.config.RaptorConfig.get_out_dir", return_value=out_root):
            self.assertIsNone(_journal_project_dir(legacy))


class WalkBoundaryExactTest(_PinCase):
    def test_planted_subdir_marker_inside_project_dir_loses(self):
        # Inside a project dir the walk previously stopped at the
        # FIRST parent (descendant matching), so the nearest planted
        # marker won — the exact capture the outermost rule kills.
        from core.run.pin import resolve_run_pin

        run = Path(self.mgr.load("pinned").output_dir) / "fuzz_9"
        sub = run / "afl-out"
        sub.mkdir(parents=True)
        save_json(
            run / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": "pinned",
                "project_source": "session",
            },
        )
        save_json(
            sub / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": "attacker",
                "project_source": "argv",
            },
        )
        pin = resolve_run_pin(sub)
        self.assertEqual(pin.project, "pinned")


class FallbackWitnessVetoTest(_PinCase):
    def test_prior_owner_witness_vetoes_but_never_elects(self):
        # A fallback (prior-pid) witness that disagrees with the
        # marker freezes the run PROJECTLESS — a forged session_pid
        # steering the lookup can suppress, never choose a project.
        from core.json import load_json
        from core.run.metadata import resume_run
        from core.run.pin import _frozen_pins

        sessions.record_session("pinned", pid=os.getpid())
        d = self.root / "out" / "standalone" / "scan_v"
        d.mkdir(parents=True)
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": None,
                "project_source": "none",
                "command": "scan",
                "session_pid": os.getpid(),
            },
        )
        sessions.ledger_record_start(
            d, pid=os.getpid(), pin_project=None, record_pin=True
        )
        save_json(
            d / RUN_METADATA_FILE,
            {
                "status": "interrupted",
                "project": "pinned",
                "project_source": "argv",
                "command": "scan",
                "session_pid": os.getpid(),
            },
        )
        _frozen_pins.clear()
        other = os.getpid() + 1  # resuming session has no own witness
        with patch.object(sessions, "resolve_session_pid", return_value=other):
            resume_run(d)
        meta = load_json(d / RUN_METADATA_FILE)
        self.assertIsNone(meta["project"])
        self.assertEqual(meta["project_source"], "none")

    def test_forged_pid_at_unregistered_ledger_reads_not_found(self):
        # An explicit pid with no registered/verified entry must not
        # read an orphan ledger as authority.
        sessions.record_session("pinned", pid=os.getpid())
        d = self.root / "out" / "standalone" / "scan_w"
        d.mkdir(parents=True)
        ledger = Path(sessions.SESSIONS_DIR) / "999999.run"
        ledger.parent.mkdir(parents=True, exist_ok=True)
        ledger.write_text(
            f"pin 100 scan_w attacker:argv {d.resolve()}\n", encoding="utf-8"
        )
        found, _p, _s = sessions.ledger_pin_witness(d, pid=999999)
        self.assertFalse(found)


class Stage3A2bPinFenceTest(_PinCase):
    def _matching_env(self, *, state: str = "pending"):
        entry = _write_host_v2_entry(self.sessions_dir, state=state)
        env = {
            sessions.ENV_SESSION_PID: str(os.getpid()),
            sessions.ENV_SESSION_TOKEN: _HOST_V2_TOKEN,
        }
        return entry, patch.dict(os.environ, env, clear=False)

    def test_t27_matching_host_v2_fences_all_start_layers(self):
        self.mgr.set_active("pinned")
        for state in (
            "pending",
            "verified",
            "rejected",
            "invalid",
            "missing-sidecar",
        ):
            with self.subTest(state=state):
                entry, env_patch = self._matching_env(state=state)
                before = entry.read_bytes()
                with (
                    env_patch,
                    _receipt_authority_calls_forbidden(),
                    patch.object(
                        sessions,
                        "session_binding",
                        side_effect=AssertionError(
                            "host-v2 fence reached session binding"
                        ),
                    ),
                    patch.object(
                        ProjectManager,
                        "get_active",
                        side_effect=AssertionError(
                            "host-v2 fence reached active bookmark"
                        ),
                    ),
                    patch.object(
                        pin_module,
                        "_project_exists",
                        side_effect=AssertionError(
                            "host-v2 fence reached project lookup"
                        ),
                    ),
                ):
                    set_process_project(None)
                    self.assertEqual(
                        resolve_pin_for_start(),
                        (None, "session"),
                    )
                    set_process_project(ARGV_NONE)
                    self.assertEqual(resolve_pin_for_start(), (None, "argv"))
                    set_process_project("pinned")
                    with self.assertRaises(ProjectArgvError):
                        resolve_pin_for_start()
                self.assertEqual(entry.read_bytes(), before)
                set_process_project(None)

    def test_t27_wrong_host_v2_token_preserves_legacy_precedence(self):
        self.mgr.set_active("pinned")
        entry = _write_host_v2_entry(self.sessions_dir, state="verified")
        before = entry.read_bytes()
        with (
            patch.dict(
                os.environ,
                {
                    sessions.ENV_SESSION_PID: str(os.getpid()),
                    sessions.ENV_SESSION_TOKEN: "ff" * 16,
                },
                clear=False,
            ),
            _receipt_authority_calls_forbidden(),
        ):
            self.assertEqual(resolve_pin_for_start(), ("pinned", "symlink"))
        self.assertEqual(entry.read_bytes(), before)

    def test_t27_reserved_markers_are_authoritative_negative(self):
        from core.run.pin import legacy_probe_allowed, pin_project_dir

        project_out = Path(self.mgr.load("pinned").output_dir)
        cases = (
            (
                "snapshot-named",
                {
                    "project": "pinned",
                    "project_source": "session",
                    run_metadata.RUN_RUNTIME_RECEIPT_KEY: {"state": "verified"},
                },
                "session",
            ),
            (
                "lineage-only",
                {
                    run_metadata.RUN_RUNTIME_RECEIPT_LINEAGE_KEY: {
                        "entries": [],
                    },
                },
                "none",
            ),
            (
                "non-string-project",
                {
                    "project": {"name": "pinned"},
                    "project_source": "argv",
                    run_metadata.RUN_RUNTIME_RECEIPT_KEY: {},
                },
                "argv",
            ),
            (
                "privileged-source",
                {
                    "project": None,
                    "project_source": "adopted",
                    run_metadata.RUN_RUNTIME_RECEIPT_KEY: {},
                },
                "none",
            ),
            (
                "merged-source",
                {
                    "project": None,
                    "project_source": "merged",
                    run_metadata.RUN_RUNTIME_RECEIPT_KEY: {},
                },
                "none",
            ),
            (
                "symlink-source",
                {
                    "project": None,
                    "project_source": "symlink",
                    run_metadata.RUN_RUNTIME_RECEIPT_KEY: {},
                },
                "none",
            ),
            (
                "unknown-source",
                {
                    "project": None,
                    "project_source": "future",
                    run_metadata.RUN_RUNTIME_RECEIPT_KEY: {},
                },
                "none",
            ),
            (
                "non-string-source",
                {
                    "project": None,
                    "project_source": {"source": "session"},
                    run_metadata.RUN_RUNTIME_RECEIPT_KEY: {},
                },
                "none",
            ),
            (
                "snapshot-missing-project",
                {
                    "project_source": "session",
                    run_metadata.RUN_RUNTIME_RECEIPT_KEY: {},
                },
                "session",
            ),
        )
        for name, fields, expected_source in cases:
            with self.subTest(name=name):
                run = project_out / name
                run.mkdir(parents=True)
                save_json(
                    run / RUN_METADATA_FILE,
                    {"status": "running", **fields},
                )
                before = (run / RUN_METADATA_FILE).read_bytes()
                with _receipt_authority_calls_forbidden():
                    pin = resolve_run_pin(run)
                    self.assertIsNone(pin_project_dir(run))
                self.assertIsNone(pin.project)
                self.assertEqual(pin.source, expected_source)
                self.assertTrue(pin.authoritative)
                self.assertFalse(pin.writes_allowed)
                self.assertFalse(legacy_probe_allowed(pin))
                self.assertEqual((run / RUN_METADATA_FILE).read_bytes(), before)

    def test_t27_conflict_warning_is_bounded_and_redacted(self):
        secret = "secret-" + ("x" * 200)
        run = self.root / "out" / "tampered"
        run.mkdir(parents=True)
        save_json(
            run / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": secret,
                "project_source": secret,
                run_metadata.RUN_RUNTIME_RECEIPT_KEY: {
                    "token": "must-not-be-rendered",
                    "digest": "f" * 64,
                },
            },
        )

        with self.assertLogs("core.run.pin", level="WARNING") as captured:
            pin = resolve_run_pin(run)

        rendered = "\n".join(captured.output)
        self.assertIsNone(pin.project)
        self.assertFalse(pin.writes_allowed)
        self.assertNotIn(secret, rendered)
        self.assertNotIn("must-not-be-rendered", rendered)
        self.assertNotIn("f" * 64, rendered)

    def test_t27_freeze_rechecks_marker_and_cannot_be_rewritten(self):
        run = self.root / "out" / "freeze"
        run.mkdir(parents=True)
        save_json(
            run / RUN_METADATA_FILE,
            {
                "status": "completed",
                "project": "pinned",
                "project_source": "session",
                run_metadata.RUN_RUNTIME_RECEIPT_KEY: {},
            },
        )

        _REAL_FREEZE_RUN_PIN(run, "pinned", "adopted")
        frozen = pin_module._frozen_pins[str(run.resolve())]
        self.assertEqual(
            frozen,
            RunPin(None, "session", run.resolve(), True, False),
        )

        save_json(
            run / RUN_METADATA_FILE,
            {
                "status": "completed",
                "project": "pinned",
                "project_source": "adopted",
            },
        )
        self.assertEqual(resolve_run_pin(run), frozen)

    def test_t27_freeze_preserves_absent_and_non_dict_legacy_behavior(self):
        absent = self.root / "out" / "absent"
        absent.mkdir(parents=True)
        _REAL_FREEZE_RUN_PIN(absent, "pinned", "adopted")
        self.assertEqual(
            pin_module._frozen_pins[str(absent.resolve())],
            RunPin("pinned", "adopted", absent.resolve(), True, True),
        )

        non_dict = self.root / "out" / "non-dict"
        non_dict.mkdir(parents=True)
        (non_dict / RUN_METADATA_FILE).write_text("[]", encoding="utf-8")
        _REAL_FREEZE_RUN_PIN(non_dict, "pinned", "merged")
        self.assertEqual(
            pin_module._frozen_pins[str(non_dict.resolve())],
            RunPin("pinned", "merged", non_dict.resolve(), True, True),
        )

    def test_t27_freeze_is_safe_under_non_reentrant_metadata_lock(self):
        run = self.root / "out" / "locked"
        script = """
import json
import sys
from pathlib import Path
from core.run import metadata as md
from core.run.pin import freeze_run_pin, resolve_run_pin

run = Path(sys.argv[1])
run.mkdir(parents=True)
path = run / md.RUN_METADATA_FILE
path.write_text(json.dumps({
    "status": "running",
    "project": "pinned",
    "project_source": "session",
    md.RUN_RUNTIME_RECEIPT_KEY: {},
}), encoding="utf-8")
with md._metadata_lock(path):
    freeze_run_pin(run, "pinned", "adopted")
pin = resolve_run_pin(run)
assert pin.project is None
assert pin.authoritative is True
assert pin.writes_allowed is False
"""
        env = {
            "HOME": str(self.root / "home"),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        result = subprocess.run(
            [sys.executable, "-c", script, str(run)],
            cwd=Path(__file__).resolve().parents[3],
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_t27_bootstrap_denies_host_v2_and_marker_only_paths(self):
        from core.run.pin import bootstrap_process_pin, get_process_project

        entry, env_patch = self._matching_env(state="verified")
        before_entry = entry.read_bytes()
        no_marker = self.root / "child-no-marker"
        no_marker.mkdir()
        with (
            env_patch,
            patch.object(
                sessions,
                "ledger_pin_witness",
                side_effect=AssertionError("deny-only bootstrap consulted witness"),
            ),
            _receipt_authority_calls_forbidden(),
        ):
            bootstrap_process_pin(no_marker)
            self.assertEqual(get_process_project(), ARGV_NONE)
            self.assertEqual(pin_module._frozen_pins, {})

            set_process_project(None)
            legacy = self.root / "child-legacy"
            legacy.mkdir()
            save_json(
                legacy / RUN_METADATA_FILE,
                {
                    "status": "running",
                    "project": "pinned",
                    "project_source": "session",
                },
            )
            bootstrap_process_pin(legacy)
            self.assertEqual(get_process_project(), ARGV_NONE)
            self.assertEqual(
                pin_module._frozen_pins[str(legacy.resolve())],
                RunPin(None, "session", legacy.resolve(), True, False),
            )
        self.assertEqual(entry.read_bytes(), before_entry)

        set_process_project(None)
        marker_only = self.root / "marker-only"
        marker_only.mkdir()
        save_json(
            marker_only / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": "pinned",
                "project_source": "merged",
                run_metadata.RUN_RUNTIME_RECEIPT_KEY: {},
            },
        )
        with (
            patch.object(
                sessions,
                "ledger_pin_witness",
                side_effect=AssertionError("deny-only bootstrap consulted witness"),
            ),
            _receipt_authority_calls_forbidden(),
        ):
            bootstrap_process_pin(marker_only)
        self.assertEqual(get_process_project(), ARGV_NONE)
        self.assertEqual(
            pin_module._frozen_pins[str(marker_only.resolve())],
            RunPin(None, "none", marker_only.resolve(), True, False),
        )

    def test_t27_bootstrap_named_override_is_refused_before_resolution(self):
        from core.run.pin import bootstrap_process_pin

        _entry, env_patch = self._matching_env(state="invalid")
        set_process_project("pinned")
        with (
            env_patch,
            patch.object(
                pin_module,
                "resolve_run_pin",
                side_effect=AssertionError("named host-v2 override read marker"),
            ),
            _receipt_authority_calls_forbidden(),
            self.assertRaises(ProjectArgvError),
        ):
            bootstrap_process_pin(self.root / "not-read")

    def test_t27_marker_only_bootstrap_rejects_named_override(self):
        from core.run.pin import bootstrap_process_pin

        run = self.root / "marker-only-named"
        run.mkdir()
        save_json(
            run / RUN_METADATA_FILE,
            {
                "status": "running",
                "project": None,
                "project_source": "session",
                run_metadata.RUN_RUNTIME_RECEIPT_LINEAGE_KEY: {},
            },
        )
        set_process_project("pinned")
        with (
            patch.object(
                sessions,
                "ledger_pin_witness",
                side_effect=AssertionError("deny-only bootstrap consulted witness"),
            ),
            _receipt_authority_calls_forbidden(),
            self.assertRaises(ProjectArgvError),
        ):
            bootstrap_process_pin(run)

    def test_t27_write_run_pin_refuses_all_rewrite_sources(self):
        run = self.root / "out" / "rewrite"
        run.mkdir(parents=True)
        save_json(
            run / RUN_METADATA_FILE,
            {
                "status": "completed",
                "project": None,
                "project_source": "session",
                run_metadata.RUN_RUNTIME_RECEIPT_KEY: {},
            },
        )
        _REAL_FREEZE_RUN_PIN(run, None, "session")
        before_bytes = (run / RUN_METADATA_FILE).read_bytes()
        before_pin = pin_module._frozen_pins[str(run.resolve())]
        for project, source in (
            ("pinned", "adopted"),
            (None, "none"),
            ("pinned", "merged"),
        ):
            with (
                self.subTest(source=source),
                self.assertRaises(run_metadata.RunRuntimeReceiptError) as raised,
            ):
                run_metadata.write_run_pin(run, project, source)
            self.assertEqual(
                raised.exception.reason,
                run_metadata.RunReceiptReason.PIN_REWRITE_FORBIDDEN,
            )
            self.assertEqual((run / RUN_METADATA_FILE).read_bytes(), before_bytes)
            self.assertEqual(
                pin_module._frozen_pins[str(run.resolve())],
                before_pin,
            )

    def test_t27_deterministic_freeze_and_bootstrap_races(self):
        from core.run.pin import bootstrap_process_pin

        run = self.root / "out" / "race"
        run.mkdir(parents=True)
        real_load = load_json
        for iteration in range(128):
            pin_module._frozen_pins.clear()
            save_json(
                run / RUN_METADATA_FILE,
                {
                    "status": "running",
                    "project": None,
                    "project_source": "session",
                    run_metadata.RUN_RUNTIME_RECEIPT_KEY: {"i": iteration},
                },
            )
            barrier = threading.Barrier(2)
            errors: list[BaseException] = []

            def gated_load(path, *args, **kwargs):
                value = real_load(path, *args, **kwargs)
                barrier.wait()
                barrier.wait()
                return value

            def freeze_worker():
                try:
                    _REAL_FREEZE_RUN_PIN(run, "pinned", "adopted")
                except BaseException as exc:  # pragma: no cover - failure capture
                    errors.append(exc)

            with patch("core.json.load_json", side_effect=gated_load):
                worker = threading.Thread(target=freeze_worker)
                worker.start()
                barrier.wait()
                (run / RUN_METADATA_FILE).write_text(
                    json.dumps(
                        {
                            "status": "running",
                            "project": "pinned",
                            "project_source": "adopted",
                        }
                    ),
                    encoding="utf-8",
                )
                barrier.wait()
                worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
            frozen = pin_module._frozen_pins[str(run.resolve())]
            self.assertIsNone(frozen.project)
            self.assertFalse(frozen.writes_allowed)

        _write_host_v2_entry(self.sessions_dir, state="verified")
        with (
            patch.dict(
                os.environ,
                {
                    sessions.ENV_SESSION_PID: str(os.getpid()),
                    sessions.ENV_SESSION_TOKEN: _HOST_V2_TOKEN,
                },
                clear=False,
            ),
            patch.object(
                sessions,
                "ledger_pin_witness",
                side_effect=AssertionError("deny-only bootstrap consulted witness"),
            ),
            _receipt_authority_calls_forbidden(),
        ):
            real_resolve = pin_module.resolve_run_pin
            for iteration in range(128):
                set_process_project(None)
                pin_module._frozen_pins.clear()
                save_json(
                    run / RUN_METADATA_FILE,
                    {
                        "status": "running",
                        "project": "pinned",
                        "project_source": "session",
                    },
                )
                barrier = threading.Barrier(2)
                errors = []

                def gated_resolve(value):
                    observed = real_resolve(value)
                    barrier.wait()
                    barrier.wait()
                    return observed

                def bootstrap_worker():
                    try:
                        bootstrap_process_pin(run)
                    except BaseException as exc:  # pragma: no cover
                        errors.append(exc)

                with patch.object(
                    pin_module,
                    "resolve_run_pin",
                    side_effect=gated_resolve,
                ):
                    worker = threading.Thread(target=bootstrap_worker)
                    worker.start()
                    barrier.wait()
                    save_json(
                        run / RUN_METADATA_FILE,
                        {
                            "status": "running",
                            "project": f"tampered-{iteration}",
                            "project_source": "argv",
                        },
                    )
                    barrier.wait()
                    worker.join(timeout=2)
                self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(pin_module.get_process_project(), ARGV_NONE)
                frozen = pin_module._frozen_pins[str(run.resolve())]
                self.assertIsNone(frozen.project)
                self.assertFalse(frozen.writes_allowed)


@pytest.mark.parametrize(
    ("override", "expected_source"),
    ((None, "session"), (ARGV_NONE, "argv")),
)
def test_t27_real_receipt_start_and_bootstrap_preserve_negative_pin(
    stage3a2_receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: str | None,
    expected_source: str,
) -> None:
    monkeypatch.setattr(pin_module, "freeze_run_pin", _REAL_FREEZE_RUN_PIN)
    set_process_project(override)
    output = _start_receipt(
        stage3a2_receipt_env,
        tmp_path,
        name=f"real-freeze-{expected_source}",
    )
    assert run_metadata.resume_run(output) == 2
    assert run_metadata.RUN_RUNTIME_RECEIPT_LINEAGE_KEY in load_json(
        output / RUN_METADATA_FILE
    )
    pin = resolve_run_pin(output)
    assert pin == RunPin(None, expected_source, output.resolve(), True, False)

    pin_module._frozen_pins.clear()
    set_process_project(None)
    with (
        patch.object(
            sessions,
            "ledger_pin_witness",
            side_effect=AssertionError("deny-only bootstrap consulted witness"),
        ),
        _receipt_authority_calls_forbidden(),
    ):
        pin_module.bootstrap_process_pin(output)
    assert pin_module.get_process_project() == ARGV_NONE
    run_metadata.start_run(output, "scan")
    assert load_json(output / RUN_METADATA_FILE)["project_source"] == expected_source
