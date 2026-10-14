"""Session registry — v2 authoritative bindings, run ledger, pruning,
awareness lines, CLI + launcher wiring.

v2 entries are identity-stamped (starttime + boot_id + pidns) and carry
the authoritative session→project binding; v1 entries remain advisory.
These tests pin: the identity/foreign/prune predicates, the binding
state machine (bound/none/advisory/absent), sentinel semantics, the run
ledger (grammar, CAS finish, injection rejection, zombie correction,
resume), and the pre-series advisory surfaces (awareness lines,
launcher wiring) that must keep working unchanged.
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import subprocess
import sys
import unittest
from datetime import datetime, timezone

import pytest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project import sessions
from core.project.cli import main
from core.project.project import ProjectManager
from core.startup.host import (
    Frontend,
    SessionHostClaim,
    build_session_host_claim,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
LAUNCHER = REPO_ROOT / "bin" / "raptor"

DEAD_PID = 999999999

#: Unpatched starttime reader, for fixtures that fake ONE pid's identity
#: while leaving real pids alone.
_REAL_STARTTIME = sessions.proc_starttime
_REAL_WALK_SESSION_PID = sessions._walk_session_pid


class _RegistryCase(unittest.TestCase):
    """Shared fixture: isolated SESSIONS_DIR + claude-shaped self.

    Tests run under pytest (comm ``python3``), so pids that must read
    as sessions get a patched comm probe. Liveness stays real unless a
    test patches it.
    """

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.sessions_dir = Path(self._tmp.name) / "sessions.d"
        for p in (
            patch.object(sessions, "SESSIONS_DIR", self.sessions_dir),
            patch.object(sessions, "_comm",
                         lambda pid: "claude" if pid == os.getpid()
                         else None),
        ):
            p.start()
            self.addCleanup(p.stop)

    def _write_v1(self, pid: int, project: str,
                  since: str = "2026-08-20T00:00:00+00:00"):
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        (self.sessions_dir / str(pid)).write_text(
            f"project={project}\nsince={since}\n", encoding="utf-8")


class SessionsRegistryTest(_RegistryCase):

    def test_record_and_read_roundtrip(self):
        pid = sessions.record_session("myapp", pid=os.getpid())
        self.assertEqual(pid, os.getpid())
        entries = sessions.read_sessions()
        self.assertEqual(entries[os.getpid()]["project"], "myapp")
        self.assertIn("since", entries[os.getpid()])
        self.assertEqual(entries[os.getpid()]["v"], "2")

    def test_record_stamps_identity(self):
        sessions.record_session("myapp", pid=os.getpid())
        fields = sessions._parse_entry(self.sessions_dir / str(os.getpid()))
        self.assertTrue(fields.get("starttime"))
        self.assertTrue(fields.get("boot_id"))
        if sys.platform == "linux":
            self.assertTrue(fields.get("pidns"))

    def test_record_none_clears_entry_and_ledger(self):
        sessions.record_session("myapp", pid=os.getpid())
        sessions.ledger_record_start(self._tmp.name, pid=os.getpid())
        sessions.record_session(None, pid=os.getpid())
        self.assertNotIn(os.getpid(), sessions.read_sessions())
        self.assertFalse(
            (self.sessions_dir / f"{os.getpid()}.run").exists())

    def test_record_without_session_pid_is_noop(self):
        with patch.object(sessions, "resolve_session_pid",
                          return_value=None):
            self.assertIsNone(sessions.record_session("myapp"))
        self.assertFalse(self.sessions_dir.exists())

    def test_record_refuses_invalid_name(self):
        self.assertIsNone(
            sessions.record_session("../evil", pid=os.getpid()))
        self.assertIsNone(
            sessions.record_session("a\nb", pid=os.getpid()))

    def test_record_preserves_seeded_by_and_token_on_rebind(self):
        sessions.record_session("myapp", pid=os.getpid(),
                                token="ab" * 16, seeded_by="flag")
        sessions.record_session("other", pid=os.getpid())
        fields = sessions._parse_entry(self.sessions_dir / str(os.getpid()))
        self.assertEqual(fields["project"], "other")
        self.assertEqual(fields["token"], "ab" * 16)
        self.assertEqual(fields["seeded_by"], "flag")

    def test_record_refreshes_stale_identity_stamp(self):
        sessions.record_session("myapp", pid=os.getpid())
        entry = self.sessions_dir / str(os.getpid())
        fields = sessions._parse_entry(entry)
        good_start = fields["starttime"]
        # Corrupt the stamp on disk, rebind: the stale stamp must be
        # refreshed, never propagated.
        entry.write_text(
            entry.read_text(encoding="utf-8").replace(
                f"starttime={good_start}", "starttime=1"),
            encoding="utf-8")
        sessions.record_session("myapp", pid=os.getpid())
        fields = sessions._parse_entry(entry)
        self.assertEqual(fields["starttime"], good_start)

    def test_control_chars_stripped_from_fields(self):
        sessions.record_session("myapp", pid=os.getpid(),
                                seeded_by="use\x1b[2J\nproject=evil")
        entry = self.sessions_dir / str(os.getpid())
        text = entry.read_text(encoding="utf-8")
        self.assertNotIn("\x1b", text)
        # The newline was stripped, so no forged key LINE exists: the
        # parse must still see the real project, and the hostile text
        # survives only as inert substring inside the seeded_by value.
        self.assertNotIn("\nproject=evil", text)
        fields = sessions._parse_entry(entry)
        self.assertEqual(fields["project"], "myapp")

    def test_dead_pid_entries_pruned_at_read(self):
        self._write_v1(DEAD_PID, "myapp")
        self._write_v1(os.getpid(), "myapp")
        entries = sessions.read_sessions()
        self.assertIn(os.getpid(), entries)
        self.assertNotIn(DEAD_PID, entries)
        # v1 entries are skipped but never PRUNED by the python
        # reader: a namespace-blind reader cannot prove the pid dead.
        # The launcher's bash prune owns v1 cleanup.
        self.assertTrue((self.sessions_dir / str(DEAD_PID)).exists())

    # Positive starttime mismatch is the Linux identity machinery
    # (/proc/<pid>/stat field 22); off-Linux entries carry sentinel
    # stamps and are never positively-mismatch pruned.
    @pytest.mark.linux_native
    def test_stale_v2_prunes_ledger_too(self):
        sessions.record_session("myapp", pid=os.getpid())
        sessions.ledger_record_start(self._tmp.name, pid=os.getpid())
        entry = self.sessions_dir / str(os.getpid())
        # Positively mismatching stamp on a live pid → stale → pruned.
        content = entry.read_text(encoding="utf-8")
        fields = sessions._parse_entry(entry)
        entry.write_text(content.replace(
            f"starttime={fields['starttime']}", "starttime=1"),
            encoding="utf-8")
        self.assertNotIn(os.getpid(), sessions.read_sessions())
        self.assertFalse(entry.exists())
        self.assertFalse(
            (self.sessions_dir / f"{os.getpid()}.run").exists())

    def test_zero_padded_entry_never_touches_real_pids_files(self):
        # A planted '0<pid>' entry that reads as stale must not lock or
        # unlink the LIVE canonical pid's ledger and lock files — the
        # derived-int aliasing was the '007 prunes pid 7' hole.
        pid = os.getpid()
        sessions.record_session("myapp", pid=pid)
        sessions.ledger_record_start(self._tmp.name, pid=pid)
        padded = self.sessions_dir / f"0{pid}"
        padded.write_text("v=2\nproject=x\nstarttime=1\nboot_id=x\n",
                          encoding="utf-8")
        sessions.read_sessions()
        self.assertTrue((self.sessions_dir / f"{pid}.run").exists())
        self.assertTrue((self.sessions_dir / str(pid)).exists())
        # The padded name is not a canonical pid file — left alone, not
        # judged (and certainly not pruned via the aliased pid).
        self.assertTrue(padded.exists())

    def test_unicode_digit_filenames_do_not_crash_prune(self):
        # str.isdigit accepts '²' but int('²') raises — a planted
        # superscript filename crashed the whole read/prune pre-fix.
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        for name in ("²", "².run", "².run.lock"):
            (self.sessions_dir / name).write_text("", encoding="utf-8")
        entries = sessions.read_sessions()  # must not raise
        self.assertNotIn(2, entries)
        # Non-canonical names are never reaped.
        self.assertTrue((self.sessions_dir / "².run").exists())

    def test_foreign_boot_never_pruned_never_returned(self):
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        entry = self.sessions_dir / str(DEAD_PID)
        entry.write_text(
            "v=2\nproject=other\nsince=x\nstarttime=42\n"
            "boot_id=00000000-dead-beef-0000-000000000000\n"
            "pidns=1\n", encoding="utf-8")
        entries = sessions.read_sessions()
        self.assertNotIn(DEAD_PID, entries)
        self.assertTrue(entry.exists(), "foreign entry was pruned")

    @unittest.skipUnless(sys.platform == "linux", "pidns identity")
    def test_same_boot_different_pidns_is_foreign(self):
        sessions.record_session("myapp", pid=os.getpid())
        entry = self.sessions_dir / str(os.getpid())
        fields = sessions._parse_entry(entry)
        entry.write_text(
            entry.read_text(encoding="utf-8").replace(
                f"pidns={fields['pidns']}", "pidns=424242"),
            encoding="utf-8")
        self.assertTrue(
            sessions._foreign_entry(sessions._parse_entry(entry)))
        self.assertTrue(entry.exists())
        self.assertNotIn(os.getpid(), sessions.read_sessions())
        self.assertTrue(entry.exists(), "cross-pidns entry was pruned")

    def test_include_stale_labels_states(self):
        self._write_v1(os.getpid(), "adv")           # advisory (live)
        self._write_v1(DEAD_PID, "dead")             # stale
        entries = sessions.read_sessions(prune=False, include_stale=True)
        self.assertEqual(entries[os.getpid()]["_state"], "advisory")
        self.assertEqual(entries[DEAD_PID]["_state"], "v1-stale")

    def test_non_pid_files_left_alone(self):
        self.sessions_dir.mkdir(parents=True)
        stray = self.sessions_dir / "README"
        stray.write_text("not an entry", encoding="utf-8")
        sessions.read_sessions()
        self.assertTrue(stray.exists())

    def test_other_sessions_filters_project_and_self(self):
        self._write_v1(os.getpid(), "myapp",
                       since="2026-08-20T01:00:00+00:00")
        others = sessions.other_sessions("myapp")
        self.assertEqual([e["pid"] for e in others], [os.getpid()])
        self.assertEqual(
            sessions.other_sessions("myapp", exclude_pid=os.getpid()), [])
        self.assertEqual(sessions.other_sessions("otherapp"), [])

    def test_registry_dir_is_private(self):
        self.sessions_dir.mkdir(parents=True, mode=0o755)
        sessions.record_session("myapp", pid=os.getpid())
        self.assertEqual(self.sessions_dir.stat().st_mode & 0o777, 0o700)

    def test_hostile_since_field_is_escaped_and_bounded(self):
        self._write_v1(os.getpid(), "myapp",
                       since="2026\x1b[2J\x07" + "C" * 4000)
        lines = sessions.awareness_lines("myapp")
        self.assertEqual(len(lines), 1)
        self.assertNotIn("\x1b", lines[0])
        self.assertNotIn("\x07", lines[0])
        self.assertLess(len(lines[0]), 400)

    def test_awareness_line_wording(self):
        self._write_v1(os.getpid(), "myapp",
                       since="2026-08-20T01:00:00+00:00")
        lines = sessions.awareness_lines("myapp")
        self.assertEqual(lines, [
            f"project myapp is also active in session pid {os.getpid()} "
            f"(since 2026-08-20T01:00:00+00:00)"
        ])


class PriorBootEntryTest(unittest.TestCase):
    """``_prior_boot_entry``: the one foreignness shape that is
    decidably dead — this machine's identity, another boot."""

    def _fields(self, **overrides):
        fields = {"starttime": "7", "boot_id": "prior-boot",
                  "machine_id": "local-hash"}
        fields.update(overrides)
        return fields

    def _patched(self, local_machine="local-hash", live_boot="live-boot"):
        return (
            patch.object(sessions, "machine_id", lambda: local_machine),
            patch.object(sessions, "boot_id", lambda: live_boot),
        )

    def test_same_machine_other_boot_is_prior_boot(self):
        p1, p2 = self._patched()
        with p1, p2:
            self.assertTrue(sessions._prior_boot_entry(self._fields()))

    def test_same_machine_same_boot_is_not(self):
        p1, p2 = self._patched(live_boot="prior-boot")
        with p1, p2:
            self.assertFalse(sessions._prior_boot_entry(self._fields()))

    def test_other_machine_is_not(self):
        p1, p2 = self._patched(local_machine="other-hash")
        with p1, p2:
            self.assertFalse(sessions._prior_boot_entry(self._fields()))

    def test_absent_machine_field_is_not(self):
        p1, p2 = self._patched()
        with p1, p2:
            self.assertFalse(sessions._prior_boot_entry(
                self._fields(machine_id="")))

    def test_unreadable_local_machine_id_is_not(self):
        p1, p2 = self._patched(local_machine=None)
        with p1, p2:
            self.assertFalse(sessions._prior_boot_entry(self._fields()))

    def test_sentinel_stamp_is_not(self):
        # Off-Linux sentinel boot ids carry no boot identity at all.
        p1, p2 = self._patched()
        with p1, p2:
            self.assertFalse(sessions._prior_boot_entry(self._fields(
                starttime=sessions._STARTTIME_SENTINEL,
                boot_id="none-darwin")))

    def test_machine_id_is_a_hash_never_the_raw_value(self):
        # Hygiene contract: the recorded identity is a digest — the
        # raw /etc/machine-id must never appear in metadata.
        sessions.machine_id.cache_clear()
        try:
            mid = sessions.machine_id()
            if mid is None:
                self.skipTest("no readable /etc/machine-id on this host")
            self.assertRegex(mid, r"^[0-9a-f]{64}$")
            raw = Path("/etc/machine-id").read_text(
                encoding="utf-8").strip()
            if raw:
                self.assertNotIn(raw, mid)
                # Domain-separated: not the bare digest another
                # application would compute from the same file.
                import hashlib
                self.assertNotEqual(
                    mid, hashlib.sha256(raw.encode()).hexdigest())
        finally:
            sessions.machine_id.cache_clear()


class SessionBindingTest(_RegistryCase):
    """The authoritative binding state machine."""

    def test_bound(self):
        sessions.record_session("myapp", pid=os.getpid())
        self.assertEqual(sessions.session_binding(pid=os.getpid()),
                         ("myapp", "bound"))

    def test_none_sentinel(self):
        sessions.bind_session(None, pid=os.getpid())
        self.assertEqual(sessions.session_binding(pid=os.getpid()),
                         (None, "none"))
        text = (self.sessions_dir / str(os.getpid())).read_text(
            encoding="utf-8")
        self.assertIn("project=-", text)

    def test_v1_entry_is_advisory(self):
        self._write_v1(os.getpid(), "myapp")
        self.assertEqual(sessions.session_binding(pid=os.getpid()),
                         (None, "advisory"))

    def test_no_entry_is_absent(self):
        self.assertEqual(sessions.session_binding(pid=os.getpid()),
                         (None, "absent"))

    def test_corrupt_v2_is_authoritative_none_not_fallthrough(self):
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        # v2 shape, empty project value (the torn/legacy-empty case).
        stamp = sessions._identity_for(os.getpid())
        (self.sessions_dir / str(os.getpid())).write_text(
            "v=2\nproject=\nsince=x\n"
            f"starttime={stamp['starttime']}\n"
            f"boot_id={stamp['boot_id']}\n"
            + (f"pidns={stamp['pidns']}\n" if "pidns" in stamp else ""),
            encoding="utf-8")
        self.assertEqual(sessions.session_binding(pid=os.getpid()),
                         (None, "none"))

    @unittest.skipUnless(sys.platform == "linux", "starttime identity")
    def test_identity_mismatch_is_absent(self):
        sessions.record_session("myapp", pid=os.getpid())
        entry = self.sessions_dir / str(os.getpid())
        fields = sessions._parse_entry(entry)
        entry.write_text(
            entry.read_text(encoding="utf-8").replace(
                f"starttime={fields['starttime']}", "starttime=1"),
            encoding="utf-8")
        self.assertEqual(sessions.session_binding(pid=os.getpid()),
                         (None, "absent"))

    def test_env_credential_resolution(self):
        token = sessions.mint_token()
        sessions.record_session("myapp", pid=os.getpid(), token=token)
        with patch.dict(os.environ, {
            sessions.ENV_SESSION_PID: str(os.getpid()),
            sessions.ENV_SESSION_TOKEN: token,
        }):
            self.assertEqual(sessions._env_session_pid(), os.getpid())
        with patch.dict(os.environ, {
            sessions.ENV_SESSION_PID: str(os.getpid()),
            sessions.ENV_SESSION_TOKEN: "wrong" * 8,
        }):
            self.assertIsNone(sessions._env_session_pid())
        # Tokenless entry: env path unusable even with a "matching" var.
        sessions.record_session("myapp", pid=os.getpid())
        entry = self.sessions_dir / str(os.getpid())
        content = entry.read_text(encoding="utf-8")
        entry.write_text(
            "\n".join(ln for ln in content.splitlines()
                      if not ln.startswith("token=")) + "\n",
            encoding="utf-8")
        with patch.dict(os.environ, {
            sessions.ENV_SESSION_PID: str(os.getpid()),
            sessions.ENV_SESSION_TOKEN: token,
        }):
            self.assertIsNone(sessions._env_session_pid())


class RunLedgerTest(_RegistryCase):
    """Ledger grammar, CAS finish, injection defense, zombie
    correction, resume wiring."""

    def setUp(self):
        super().setUp()
        self.run_root = Path(self._tmp.name) / "runs"
        self.run_root.mkdir()
        # Ledger records belong to REGISTERED sessions only — give the
        # test pids entries (mandatory-seed invariant).
        sessions.record_session("ledgerapp", pid=os.getpid())
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        (self.sessions_dir / "777777").write_text(
            "project=ledgerapp\nsince=x\n", encoding="utf-8")

    def _mk_run(self, name: str, status: str = "running") -> Path:
        d = self.run_root / name
        d.mkdir()
        (d / ".raptor-run.json").write_text(
            f'{{"status": "{status}"}}', encoding="utf-8")
        return d

    def test_start_and_finish_roundtrip(self):
        d = self._mk_run("scan_1")
        sessions.ledger_record_start(d, pid=os.getpid())
        runs = sessions.ledger_runs(pid=os.getpid())
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["status"], "running")
        self.assertEqual(runs[0]["run_id"], "scan_1")
        self.assertEqual(runs[0]["run_dir"], str(d.resolve()))
        (d / ".raptor-run.json").write_text(
            '{"status": "completed"}', encoding="utf-8")
        sessions.ledger_record_finish(d, "completed", pid=os.getpid())
        runs = sessions.ledger_runs(pid=os.getpid())
        self.assertEqual(runs[0]["status"], "completed")

    def test_relative_finish_spelling_flips_the_record(self):
        # The run-attribution seam on the finish side: start records
        # the RESOLVED basename, so a finish spelled "." from inside
        # the run dir (raw name == "") must resolve to the SAME
        # run_id — otherwise the CAS never matches and the record
        # silently stays "running" forever.
        d = self._mk_run("scan_rel")
        sessions.ledger_record_start(d, pid=os.getpid())
        (d / ".raptor-run.json").write_text(
            '{"status": "completed"}', encoding="utf-8")
        prior_cwd = os.getcwd()
        os.chdir(d)
        try:
            sessions.ledger_record_finish(".", "completed",
                                          pid=os.getpid())
        finally:
            os.chdir(prior_cwd)
        runs = sessions.ledger_runs(pid=os.getpid())
        self.assertEqual(
            [(r["run_id"], r["status"]) for r in runs],
            [("scan_rel", "completed")])

    def test_true_statuses_no_coercion(self):
        d = self._mk_run("scan_2")
        sessions.ledger_record_start(d, pid=os.getpid())
        (d / ".raptor-run.json").write_text(
            '{"status": "interrupted"}', encoding="utf-8")
        sessions.ledger_record_finish(d, "interrupted", pid=os.getpid())
        self.assertEqual(
            sessions.ledger_runs(pid=os.getpid())[0]["status"],
            "interrupted")

    def test_finish_cas_only_touches_its_run(self):
        d1 = self._mk_run("a_1")
        d2 = self._mk_run("b_2")
        sessions.ledger_record_start(d1, pid=os.getpid())
        sessions.ledger_record_start(d2, pid=os.getpid())
        (d1 / ".raptor-run.json").write_text(
            '{"status": "failed"}', encoding="utf-8")
        sessions.ledger_record_finish(d1, "failed", pid=os.getpid())
        by_id = {r["run_id"]: r["status"]
                 for r in sessions.ledger_runs(pid=os.getpid())}
        self.assertEqual(by_id, {"a_1": "failed", "b_2": "running"})

    def test_linesep_injection_rejected(self):
        evil = self.run_root / ("x running 9 fake /victim")
        with contextlib.suppress(OSError):
            evil.mkdir()
        sessions.ledger_record_start(evil, pid=os.getpid())
        self.assertEqual(sessions.ledger_runs(pid=os.getpid()), [])

    def test_plain_space_in_parent_path_accepted(self):
        # An operator's "My Projects"-style tree keeps attribution:
        # the run-dir field is last on the line and read greedily.
        spaced = self.run_root / "with space"
        spaced.mkdir()
        d = spaced / "run_1"
        d.mkdir()
        sessions.ledger_record_start(d, pid=os.getpid())
        runs = sessions.ledger_runs(pid=os.getpid())
        self.assertEqual([r["run_dir"] for r in runs], [str(d.resolve())])

    def test_space_in_basename_rejected(self):
        d = self.run_root / "run 1"
        d.mkdir()
        sessions.ledger_record_start(d, pid=os.getpid())
        self.assertEqual(sessions.ledger_runs(pid=os.getpid()), [])

    def test_exotic_whitespace_rejected_everywhere(self):
        for bad in ("run\u2028x", "run\tx", "par\u00a0ent"):
            self.assertFalse(sessions._valid_run_dir(f"/tmp/{bad}/r1"))

    def test_zombie_running_records_corrected(self):
        d = self._mk_run("scan_3")
        sessions.ledger_record_start(d, pid=os.getpid())
        # Run dir's metadata flips terminal without a finish call
        # (crash path); the next write corrects the zombie.
        (d / ".raptor-run.json").write_text(
            '{"status": "failed"}', encoding="utf-8")
        d2 = self._mk_run("scan_4")
        sessions.ledger_record_start(d2, pid=os.getpid())
        by_id = {r["run_id"]: r["status"]
                 for r in sessions.ledger_runs(pid=os.getpid())}
        self.assertEqual(by_id["scan_3"], "failed")

    def test_cap_prunes_finished_only(self):
        live = self._mk_run("live_run")
        for i in range(40):
            d = self._mk_run(f"r{i}", status="completed")
            sessions.ledger_record_start(d, pid=os.getpid())
            sessions.ledger_record_finish(d, "completed", pid=os.getpid())
        sessions.ledger_record_start(live, pid=os.getpid())
        runs = sessions.ledger_runs(pid=os.getpid())
        self.assertLessEqual(len(runs), sessions._LEDGER_CAP + 1)
        self.assertIn("live_run", [r["run_id"] for r in runs])

    def test_resume_cross_session(self):
        d = self._mk_run("resumed_1")
        other = 777777
        # Original owner's ledger (fake pid) gets the running line.
        sessions.ledger_record_start(d, pid=other)
        # A different session resumes: own line running, old line
        # CAS-marked interrupted.
        sessions.ledger_record_resume(d, prior_session_pid=other,
                                      pid=os.getpid())
        mine = sessions.ledger_runs(pid=os.getpid())
        theirs = sessions.ledger_runs(pid=other)
        self.assertEqual(mine[0]["status"], "running")
        self.assertEqual(theirs[0]["status"], "interrupted")

    def test_dedup_on_reused_run_id(self):
        d = self._mk_run("dup_1")
        sessions.ledger_record_start(d, pid=os.getpid())
        sessions.ledger_record_start(d, pid=os.getpid())
        self.assertEqual(len(sessions.ledger_runs(pid=os.getpid())), 1)


class AllSessionsRunningRunsTest(_RegistryCase):
    """Box-wide running-record observation: only registered live
    sessions count; orphan ledgers, dead pids, and foreign-stamped
    entries never inflate the view."""

    def setUp(self):
        super().setUp()
        self.run_root = Path(self._tmp.name) / "runs"
        self.run_root.mkdir()
        sessions.record_session("obsapp", pid=os.getpid())

    def _mk_run(self, name: str) -> Path:
        d = self.run_root / name
        d.mkdir()
        (d / ".raptor-run.json").write_text(
            '{"status": "running"}', encoding="utf-8")
        return d

    def test_live_session_running_records_returned(self):
        d = self._mk_run("audit_1")
        done = self._mk_run("audit_2")
        sessions.ledger_record_start(d, pid=os.getpid())
        sessions.ledger_record_start(done, pid=os.getpid())
        (done / ".raptor-run.json").write_text(
            '{"status": "completed"}', encoding="utf-8")
        sessions.ledger_record_finish(done, "completed", pid=os.getpid())
        runs = sessions.ledger_running_runs_all_sessions()
        self.assertEqual([r["run_id"] for r in runs], ["audit_1"])
        self.assertEqual(runs[0]["session_pid"], os.getpid())
        self.assertEqual(runs[0]["status"], "running")

    def test_orphan_ledger_never_counts(self):
        # A ledger file whose session entry is gone is an orphan —
        # no owner, no liveness proof, no observation. Use a LIVE pid
        # (pid 1: kill-0 answers EPERM → alive) so this fixture
        # isolates the ENTRY gate — a dead-pid fixture would pass on
        # the kill-0 fallback alone and mask a dropped orphan check.
        (self.sessions_dir / "1.run").write_text(
            f"running 100 x_1 {self.run_root}/x\n", encoding="utf-8")
        self.assertEqual(
            sessions.ledger_running_runs_all_sessions(), [])

    def test_dead_pid_session_never_counts(self):
        # Pre-stamp (v1) entry: liveness falls back to kill-0, and a
        # dead pid's stale running lines must not inflate the count.
        self._write_v1(DEAD_PID, "obsapp")
        (self.sessions_dir / f"{DEAD_PID}.run").write_text(
            f"running 100 y_1 {self.run_root}/y\n", encoding="utf-8")
        self.assertEqual(
            sessions.ledger_running_runs_all_sessions(), [])

    def test_foreign_stamped_entry_never_counts(self):
        # A v2 entry whose identity stamp does not verify (recycled
        # pid, other boot) reads as dead for observation purposes.
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        (self.sessions_dir / "777777").write_text(
            "project=obsapp\nsince=x\nv=2\nstarttime=1\nboot_id=zz\n",
            encoding="utf-8")
        (self.sessions_dir / "777777.run").write_text(
            f"running 100 z_1 {self.run_root}/z\n", encoding="utf-8")
        self.assertEqual(
            sessions.ledger_running_runs_all_sessions(), [])

    def test_missing_sessions_dir_reads_empty(self):
        with patch.object(sessions, "SESSIONS_DIR",
                          Path(self._tmp.name) / "nonexistent"):
            self.assertEqual(
                sessions.ledger_running_runs_all_sessions(), [])


class UseCommandAwarenessTest(unittest.TestCase):
    """/project use writes the registry and prints the awareness line.

    NOTE (pre-P05 semantics): the CLI still calls the historical
    record/clear paths; P05 rewires `use`/`none` to the binding-first
    contract and updates these expectations.
    """

    FAKE_SELF = 555555

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.projects_dir = root / "projects"
        self.sessions_dir = root / "sessions.d"
        target = root / "code"
        target.mkdir()
        mgr = ProjectManager(projects_dir=self.projects_dir)
        mgr.create("myapp", str(target),
                   output_dir=str(root / "out" / "myapp"))
        for p in (
            patch.object(sessions, "SESSIONS_DIR", self.sessions_dir),
            patch("core.project.project.PROJECTS_DIR", self.projects_dir),
            # `use` runs outside a real claude session here; give it a
            # deterministic fake session pid, and make both our real
            # pid and the fake read as live claude sessions.
            patch.object(sessions, "resolve_session_pid",
                         return_value=self.FAKE_SELF),
            patch.object(sessions, "_pid_running",
                         lambda pid: pid in (os.getpid(), self.FAKE_SELF)),
            patch.object(sessions, "_comm",
                         lambda pid: "claude"
                         if pid in (os.getpid(), self.FAKE_SELF)
                         else None),
            # The fake session pid has no /proc entry; give it a
            # stable fake starttime so writer validation and the
            # subsequent authoritative read both succeed.
            patch.object(sessions, "proc_starttime",
                         lambda pid: "7777" if pid == self.FAKE_SELF
                         else _REAL_STARTTIME(pid)),
        ):
            p.start()
            self.addCleanup(p.stop)

    def _run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with patch.object(sys, "argv", ["raptor-project", *argv]), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            try:
                main()
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 1
        return code, out.getvalue(), err.getvalue()

    def test_use_records_entry(self):
        code, out, _ = self._run("use", "myapp")
        self.assertEqual(code, 0)
        entry = self.sessions_dir / str(self.FAKE_SELF)
        self.assertTrue(entry.exists())
        self.assertIn("project=myapp", entry.read_text(encoding="utf-8"))

    def test_use_prints_awareness_for_other_session(self):
        self.sessions_dir.mkdir(parents=True)
        (self.sessions_dir / str(os.getpid())).write_text(
            "project=myapp\nsince=2026-08-20T01:00:00+00:00\n",
            encoding="utf-8")
        code, out, _ = self._run("use", "myapp")
        self.assertEqual(code, 0)
        self.assertIn(
            f"project myapp is also active in session pid {os.getpid()}",
            out)

    def test_use_no_awareness_when_alone(self):
        code, out, _ = self._run("use", "myapp")
        self.assertEqual(code, 0)
        self.assertNotIn("also active", out)

    def test_use_none_binds_sentinel_and_keeps_bookmark(self):
        """In-session `/project none` is a session-only clear: the entry
        binds the `-` sentinel (authoritatively projectless) and the
        last-activated default is untouched."""
        self._run("use", "myapp")
        code, out, _ = self._run("none")
        self.assertEqual(code, 0)
        entry = self.sessions_dir / str(self.FAKE_SELF)
        self.assertTrue(entry.exists())
        self.assertIn("project=-", entry.read_text(encoding="utf-8"))
        self.assertIn("Session project cleared", out)
        self.assertIn("unchanged", out)
        # Bookmark still points at myapp.
        target = os.readlink(self.projects_dir / ".active")
        self.assertEqual(target, "myapp.json")


@unittest.skipIf(sys.platform == "win32", "bash launcher")
class LauncherAwarenessTest(unittest.TestCase):
    """The launcher prunes, warns, and registers before exec.

    Pre-P06: the launcher writes v1 entries and prunes with kill -0;
    P06 upgrades it to the v2 mandatory seed + sentinel handoff and
    extends these tests.
    """

    def _launch(self, home: Path, tmpdir: Path):
        path_dirs = [str(Path(sys.executable).resolve().parent)]
        path_dirs += [d for d in ("/usr/bin", "/bin") if os.path.isdir(d)]
        stub_dir = home / "stub-bin"
        stub_dir.mkdir(exist_ok=True)
        stub = stub_dir / "claude"
        stub.write_text("#!/usr/bin/env bash\necho STUB_CLAUDE_RAN\n",
                        encoding="utf-8")
        stub.chmod(0o755)
        return subprocess.run(
            ["bash", str(LAUNCHER)],
            capture_output=True, text=True, timeout=120, check=False,
            env={
                "PATH": ":".join([str(stub_dir)] + path_dirs),
                "HOME": str(home), "TMPDIR": str(tmpdir), "TERM": "xterm",
            },
            cwd=str(home),
        )

    def test_launcher_registers_prunes_and_warns(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            home = root / "home"
            home.mkdir()
            tmpdir = root / "tmp"
            tmpdir.mkdir()
            mgr = ProjectManager(projects_dir=home / ".raptor" / "projects")
            mgr.create("myapp", str(home),
                       output_dir=str(root / "out" / "myapp"))
            mgr.set_active("myapp")
            sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
            sessions_dir.mkdir(parents=True)
            (sessions_dir / str(os.getpid())).write_text(
                "project=myapp\nsince=2026-08-20T01:00:00+00:00\n",
                encoding="utf-8")
            (sessions_dir / str(DEAD_PID)).write_text(
                "project=myapp\nsince=2026-08-20T01:00:00+00:00\n",
                encoding="utf-8")
            r = self._launch(home, tmpdir)
            self.assertIn("STUB_CLAUDE_RAN", r.stdout,
                          (r.stdout, r.stderr))
            self.assertIn(
                f"project myapp is also active in session pid {os.getpid()}",
                r.stderr)
            self.assertNotIn(str(DEAD_PID), r.stderr,
                             "dead session produced an awareness line")
            self.assertFalse((sessions_dir / str(DEAD_PID)).exists(),
                             "dead entry not pruned at launch")
            own = [f for f in sessions_dir.iterdir()
                   if f.name.isdigit()
                   and f.name not in (str(os.getpid()), str(DEAD_PID))]
            self.assertEqual(len(own), 1, list(sessions_dir.iterdir()))
            self.assertIn("project=myapp",
                          own[0].read_text(encoding="utf-8"))
            self.assertEqual(sessions_dir.stat().st_mode & 0o777, 0o700,
                             "registry dir readable by other users")

    def test_launcher_awareness_escapes_hostile_since(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            home = root / "home"
            home.mkdir()
            tmpdir = root / "tmp"
            tmpdir.mkdir()
            mgr = ProjectManager(projects_dir=home / ".raptor" / "projects")
            mgr.create("myapp", str(home),
                       output_dir=str(root / "out" / "myapp"))
            mgr.set_active("myapp")
            sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
            sessions_dir.mkdir(parents=True)
            (sessions_dir / str(os.getpid())).write_text(
                "project=myapp\nsince=2026\x1b[2J\x07" + "C" * 4000 + "\n",
                encoding="utf-8")
            r = self._launch(home, tmpdir)
            self.assertIn("also active in session pid", r.stderr)
            self.assertNotIn("\x1b", r.stderr, "raw ESC reached stderr")
            self.assertNotIn("\x07", r.stderr)
            line = next(ln for ln in r.stderr.splitlines()
                        if "also active" in ln)
            self.assertLess(len(line), 300, "since field flooded the line")


if __name__ == "__main__":
    unittest.main()


class LayeredChokepointTest(unittest.TestCase):
    """get_active() / get_active_name() layered resolution:
    binding beats symlink, bound-to-none is authoritative, stale
    bindings never fall through, expiry remediation clears only the
    producing layer — and the two chokepoints always agree."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.projects_dir = root / "projects"
        self.sessions_dir = root / "sessions.d"
        (root / "code").mkdir()
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create("bound-proj", str(root / "code"),
                        output_dir=str(root / "out" / "bound-proj"))
        self.mgr.create("bookmark-proj", str(root / "code"),
                        output_dir=str(root / "out" / "bookmark-proj"))
        self.mgr.set_active("bookmark-proj")
        import core.startup as startup
        for p in (
            patch.object(sessions, "SESSIONS_DIR", self.sessions_dir),
            patch("core.project.project.PROJECTS_DIR", self.projects_dir),
            patch.object(startup, "PROJECTS_DIR", self.projects_dir),
            patch.object(startup, "ACTIVE_LINK",
                         self.projects_dir / ".active"),
            patch.object(sessions, "resolve_session_pid",
                         return_value=os.getpid()),
            patch.object(sessions, "_comm",
                         lambda pid: "claude" if pid == os.getpid()
                         else None),
        ):
            p.start()
            self.addCleanup(p.stop)
        self.startup = startup

    def test_binding_beats_bookmark_in_both_chokepoints(self):
        sessions.record_session("bound-proj", pid=os.getpid())
        self.assertEqual(self.mgr.get_active(), "bound-proj")
        self.assertEqual(self.startup.get_active_name(), "bound-proj")

    def test_bound_to_none_is_authoritative_in_both(self):
        sessions.bind_session(None, pid=os.getpid())
        self.assertIsNone(self.mgr.get_active())
        self.assertIsNone(self.startup.get_active_name())

    def test_no_binding_falls_to_bookmark_in_both(self):
        self.assertEqual(self.mgr.get_active(), "bookmark-proj")
        self.assertEqual(self.startup.get_active_name(), "bookmark-proj")

    def test_stale_binding_never_falls_through(self):
        self.mgr.create("doomed", str(Path(self._tmp.name) / "code"),
                        output_dir=str(Path(self._tmp.name) / "out" / "d"))
        sessions.record_session("doomed", pid=os.getpid())
        (self.projects_dir / "doomed.json").unlink()
        self.assertIsNone(self.mgr.get_active())
        self.assertIsNone(self.startup.get_active_name())

    def _make_expired_machine_project(self, name: str):
        self.mgr.create(name, "/tmp")
        proj = self.mgr.load(name)
        proj.expires_at = "2020-01-01T00:00:00+00:00"
        self.mgr._save(proj)

    def test_expired_binding_clears_binding_not_bookmark(self):
        """a review finding/a review finding: the expiry vet fired via a session binding
        must never destroy the machine-wide bookmark."""
        self._make_expired_machine_project("corpus-999")
        sessions.record_session("corpus-999", pid=os.getpid())
        self.assertIsNone(self.mgr.get_active())
        # Binding re-bound to none...
        name, state = sessions.session_binding(pid=os.getpid())
        self.assertEqual((name, state), (None, "none"))
        # ...bookmark untouched.
        self.assertEqual(
            os.readlink(self.projects_dir / ".active"),
            "bookmark-proj.json")

    def test_expired_bookmark_unlinks_symlink(self):
        self._make_expired_machine_project("corpus-888")
        self.mgr.set_active("corpus-888")
        self.assertIsNone(self.mgr.get_active())
        self.assertFalse(
            (self.projects_dir / ".active").is_symlink())


class ProjectMutationHygieneTest(unittest.TestCase):
    """delete/rename binding hygiene + the purge live-run guard
   ."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.projects_dir = root / "projects"
        self.sessions_dir = root / "sessions.d"
        (root / "code").mkdir()
        # Output under the expected base so purge containment passes.
        from core.project.project import DEFAULT_OUTPUT_BASE
        self.out_base = DEFAULT_OUTPUT_BASE / f"_test-{os.getpid()}"
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.out_base, ignore_errors=True))
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create("victim", str(root / "code"),
                        output_dir=str(self.out_base / "victim"))
        for p in (
            patch.object(sessions, "SESSIONS_DIR", self.sessions_dir),
            patch("core.project.project.PROJECTS_DIR", self.projects_dir),
            patch.object(sessions, "_comm",
                         lambda pid: "claude" if pid == os.getpid()
                         else None),
        ):
            p.start()
            self.addCleanup(p.stop)

    def test_delete_nulls_live_bindings(self):
        sessions.record_session("victim", pid=os.getpid())
        self.mgr.delete("victim")
        name, state = sessions.session_binding(pid=os.getpid())
        self.assertEqual((name, state), (None, "none"))

    def test_rename_repoints_live_bindings(self):
        sessions.record_session("victim", pid=os.getpid())
        self.mgr.rename("victim", "renamed")
        name, state = sessions.session_binding(pid=os.getpid())
        self.assertEqual((name, state), ("renamed", "bound"))

    def test_purge_refuses_on_live_run(self):
        from core.json import save_json
        run = Path(self.mgr.load("victim").output_dir) / "scan-live"
        run.mkdir(parents=True)
        save_json(run / ".raptor-run.json", {
            "status": "running", "tool_pid": os.getpid(),
        })
        with self.assertRaises(ValueError):
            self.mgr.delete("victim", purge=True)
        # force overrides.
        self.mgr.delete("victim", purge=True, force=True)
        self.assertFalse(run.exists())


@unittest.skipIf(sys.platform == "win32", "bash launcher")
class LauncherSeedV2Test(LauncherAwarenessTest):
    """The v2 mandatory seed: identity-stamped entry,
    exported env credential, seed even with an empty bookmark."""

    def test_seed_is_v2_with_identity_and_credential(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            home = root / "home"
            home.mkdir()
            tmpdir = root / "tmp"
            tmpdir.mkdir()
            mgr = ProjectManager(projects_dir=home / ".raptor" / "projects")
            mgr.create("myapp", str(home),
                       output_dir=str(root / "out" / "myapp"))
            mgr.set_active("myapp")
            # Stub claude echoes the exported credential.
            r = self._launch(home, tmpdir)
            self.assertIn("STUB_CLAUDE_RAN", r.stdout)
            sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
            own = [f for f in sessions_dir.iterdir() if f.name.isdigit()]
            self.assertEqual(len(own), 1, list(sessions_dir.iterdir()))
            text = own[0].read_text(encoding="utf-8")
            self.assertIn("v=2", text)
            self.assertIn("project=myapp", text)
            self.assertIn("seeded_by=bookmark", text)
            self.assertIn("starttime=", text)
            self.assertIn("boot_id=", text)
            self.assertIn("token=", text)
            self.assertEqual(own[0].stat().st_mode & 0o777, 0o600)

    def test_empty_bookmark_seeds_projectless_sentinel(self):
        """a review finding: a launch with NO active project still writes an
        entry — 'project=-' — so the session is insulated from later
        bookmark moves by other sessions."""
        with TemporaryDirectory() as d:
            root = Path(d)
            home = root / "home"
            home.mkdir()
            tmpdir = root / "tmp"
            tmpdir.mkdir()
            r = self._launch(home, tmpdir)
            self.assertIn("STUB_CLAUDE_RAN", r.stdout,
                          (r.stdout, r.stderr))
            sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
            own = [f for f in sessions_dir.iterdir() if f.name.isdigit()]
            self.assertEqual(len(own), 1)
            text = own[0].read_text(encoding="utf-8")
            self.assertIn("project=-", text)
            self.assertIn("v=2", text)

    def test_startup_check_sentinel_never_reaches_terminal_stdout(self):
        """The launcher consumes startup-check stdout — the sentinel
        line must not leak into what the operator sees."""
        with TemporaryDirectory() as d:
            root = Path(d)
            home = root / "home"
            home.mkdir()
            tmpdir = root / "tmp"
            tmpdir.mkdir()
            r = self._launch(home, tmpdir)
            self.assertNotIn("RAPTOR_RESOLVED_PROJECT", r.stdout)
            self.assertNotIn("RAPTOR_RESOLVED_PROJECT", r.stderr)


class SessionsSubcommandTest(unittest.TestCase):
    """`/project sessions` renders live/stale/foreign/advisory rows."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.projects_dir = root / "projects"
        self.sessions_dir = root / "sessions.d"
        self.sessions_dir.mkdir(parents=True)
        (root / "code").mkdir()
        ProjectManager(projects_dir=self.projects_dir).create(
            "myapp", str(root / "code"),
            output_dir=str(root / "out" / "myapp"))
        for p in (
            patch.object(sessions, "SESSIONS_DIR", self.sessions_dir),
            patch("core.project.project.PROJECTS_DIR", self.projects_dir),
            patch.object(sessions, "_comm",
                         lambda pid: "claude" if pid == os.getpid()
                         else None),
        ):
            p.start()
            self.addCleanup(p.stop)

    def _run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with patch.object(sys, "argv", ["raptor-project", *argv]), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            try:
                main()
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 1
        return code, out.getvalue(), err.getvalue()

    def test_rows_and_states(self):
        sessions.record_session("myapp", pid=os.getpid())      # live
        (self.sessions_dir / str(DEAD_PID)).write_text(
            "project=myapp\nsince=x\n", encoding="utf-8")      # v1 dead
        (self.sessions_dir / "111").write_text(
            "v=2\nproject=other\nsince=x\nstarttime=1\n"
            "boot_id=00000000-dead-beef-0000-000000000000\n"
            "pidns=1\n", encoding="utf-8")                     # foreign
        code, out, _ = self._run("sessions")
        self.assertEqual(code, 0)
        self.assertIn(str(os.getpid()), out)
        self.assertIn("live", out)
        self.assertIn("foreign", out)
        self.assertIn("stale", out)
        self.assertIn("Last-activated default", out)

    def test_empty_registry(self):
        code, out, _ = self._run("sessions")
        self.assertEqual(code, 0)
        self.assertIn("No registered sessions", out)

    def test_list_shows_two_markers(self):
        mgr = ProjectManager(projects_dir=self.projects_dir)
        mgr.create("bookmarked", str(Path(self._tmp.name) / "code"),
                   output_dir=str(Path(self._tmp.name) / "out" / "b"))
        mgr.set_active("bookmarked")
        sessions.record_session("myapp", pid=os.getpid())
        with patch.object(sessions, "resolve_session_pid",
                          return_value=os.getpid()):
            code, out, _ = self._run("list")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"\* myapp")
        self.assertRegex(out, r"> bookmarked")
        self.assertIn("this session's project", out)


class LedgerHardeningTest(_RegistryCase):
    """Recycled-pid ledger reset, orphan reaping, finish dir-match
    CAS, stale-credential drop."""

    def _mk_run(self, name: str, status: str = "running") -> Path:
        d = Path(self._tmp.name) / "runs" / name
        d.mkdir(parents=True)
        (d / ".raptor-run.json").write_text(
            '{"status": "%s"}' % status, encoding="utf-8")
        return d

    def test_stale_refresh_drops_token_and_seeded_by(self):
        sessions.record_session("myapp", pid=os.getpid(),
                                token="ab" * 16, seeded_by="flag")
        entry = self.sessions_dir / str(os.getpid())
        fields = sessions._parse_entry(entry)
        entry.write_text(
            entry.read_text(encoding="utf-8").replace(
                f"starttime={fields['starttime']}", "starttime=1"),
            encoding="utf-8")
        sessions.record_session("other", pid=os.getpid())
        fields = sessions._parse_entry(entry)
        self.assertNotIn("token", fields)
        self.assertNotIn("seeded_by", fields)

    def test_stale_refresh_clears_inherited_ledger(self):
        sessions.record_session("myapp", pid=os.getpid())
        d = self._mk_run("scan_old")
        sessions.ledger_record_start(d, pid=os.getpid())
        entry = self.sessions_dir / str(os.getpid())
        fields = sessions._parse_entry(entry)
        entry.write_text(
            entry.read_text(encoding="utf-8").replace(
                f"starttime={fields['starttime']}", "starttime=1"),
            encoding="utf-8")
        # Recycled pid re-registers: the dead session's run records
        # must not become this session's history.
        sessions.record_session("other", pid=os.getpid())
        self.assertEqual(sessions.ledger_runs(pid=os.getpid()), [])

    def test_orphan_ledger_reaped(self):
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        orphan = self.sessions_dir / f"{DEAD_PID}.run"
        orphan.write_text("running 1 r1 /tmp/r1\n", encoding="utf-8")
        sessions.read_sessions()
        self.assertFalse(orphan.exists())

    def test_finish_requires_matching_dir_not_just_run_id(self):
        sessions.record_session("myapp", pid=os.getpid())
        d = self._mk_run("scan_1")
        sessions.ledger_record_start(d, pid=os.getpid())
        # Colliding basename, different dir: must NOT CAS the record.
        other = Path(self._tmp.name) / "elsewhere" / "scan_1"
        other.mkdir(parents=True)
        sessions.ledger_record_finish(other, "interrupted",
                                      pid=os.getpid())
        runs = sessions.ledger_runs(pid=os.getpid())
        self.assertEqual([r["status"] for r in runs], ["running"])
        sessions.ledger_record_finish(d, "completed", pid=os.getpid())
        runs = sessions.ledger_runs(pid=os.getpid())
        self.assertEqual([r["status"] for r in runs], ["completed"])


class RegistryHostileInputTest(_RegistryCase):
    """Comm poisoning, sibling-record erasure, pin witness,
    env-credential robustness."""

    def _mk_run(self, name: str) -> Path:
        d = Path(self._tmp.name) / "runs" / name
        d.mkdir(parents=True)
        (d / ".raptor-run.json").write_text(
            '{"status": "running"}', encoding="utf-8")
        return d

    def test_hostile_comm_bytes_never_crash_the_registry(self):
        # A same-boot entry whose pid's comm decodes badly must not
        # blow up read_sessions / session_binding with UnicodeDecodeError.
        sessions.record_session("myapp", pid=os.getpid())
        with patch.object(
                sessions, "_comm",
                lambda pid: "cl�aude"):  # replace-decoded hostile name
            entries = sessions.read_sessions(prune=False)
            self.assertIsInstance(entries, dict)
            binding = sessions.session_binding(pid=os.getpid())
            self.assertIsInstance(binding, tuple)

    def test_same_basename_siblings_keep_both_records(self):
        sessions.record_session("myapp", pid=os.getpid())
        a = Path(self._tmp.name) / "a" / "out"
        b = Path(self._tmp.name) / "b" / "out"
        for d in (a, b):
            d.mkdir(parents=True)
            (d / ".raptor-run.json").write_text(
                '{"status": "running"}', encoding="utf-8")
        sessions.ledger_record_start(a, pid=os.getpid())
        sessions.ledger_record_start(b, pid=os.getpid())
        dirs = {r["run_dir"] for r in sessions.ledger_runs(pid=os.getpid())}
        self.assertEqual(dirs, {str(a.resolve()), str(b.resolve())})
        sessions.ledger_record_finish(a, "completed", pid=os.getpid())
        by_dir = {r["run_dir"]: r["status"]
                  for r in sessions.ledger_runs(pid=os.getpid())}
        self.assertEqual(by_dir[str(a.resolve())], "completed")
        self.assertEqual(by_dir[str(b.resolve())], "running")

    def test_pin_witness_roundtrip_and_survival(self):
        sessions.record_session("myapp", pid=os.getpid())
        d = self._mk_run("scan_w")
        sessions.ledger_record_start(d, pid=os.getpid(),
                                     pin_project="appx", record_pin=True)
        found, project, _src = sessions.ledger_pin_witness(
            d, pid=os.getpid())
        self.assertTrue(found)
        self.assertEqual(project, "appx")
        # The witness survives the finish RMW.
        sessions.ledger_record_finish(d, "completed", pid=os.getpid())
        found, project, _src = sessions.ledger_pin_witness(
            d, pid=os.getpid())
        self.assertTrue(found)
        self.assertEqual(project, "appx")

    def test_pin_witness_projectless_sentinel(self):
        sessions.record_session("myapp", pid=os.getpid())
        d = self._mk_run("scan_wn")
        sessions.ledger_record_start(d, pid=os.getpid(),
                                     pin_project=None, record_pin=True)
        found, project, _src = sessions.ledger_pin_witness(
            d, pid=os.getpid())
        self.assertTrue(found)
        self.assertIsNone(project)

    def test_no_witness_reads_as_not_found(self):
        sessions.record_session("myapp", pid=os.getpid())
        d = self._mk_run("scan_nw")
        sessions.ledger_record_start(d, pid=os.getpid())  # no pin line
        found, _project, _src = sessions.ledger_pin_witness(
            d, pid=os.getpid())
        self.assertFalse(found)

    def test_malformed_env_credential_never_raises(self):
        with patch.dict(os.environ, {
            sessions.ENV_SESSION_PID: "²",       # unicode digit
            sessions.ENV_SESSION_TOKEN: "tok\udcff",  # surrogate
        }):
            self.assertIsNone(sessions._env_session_pid())

    def test_v1_upgrade_keeps_own_ledger(self):
        # A live session upgrading from a v1 launcher entry must not
        # wipe its own in-flight ledger (only positively-recycled v2
        # stamps qualify).
        self._write_v1(os.getpid(), "myapp")
        d = self._mk_run("scan_v1")
        sessions.ledger_record_start(d, pid=os.getpid())
        self.assertEqual(len(sessions.ledger_runs(pid=os.getpid())), 1)
        sessions.record_session("myapp", pid=os.getpid())
        self.assertEqual(len(sessions.ledger_runs(pid=os.getpid())), 1)


class WitnessLifecycleTest(_RegistryCase):
    """Witness lifecycle, ledger budgets, corruption fail-direction,
    reap/writer races."""

    def _mk_run(self, name: str, status: str = "running") -> Path:
        d = Path(self._tmp.name) / "runs" / name
        d.mkdir(parents=True)
        (d / ".raptor-run.json").write_text(
            '{"status": "%s"}' % status, encoding="utf-8")
        return d

    def test_resume_append_preserves_the_witness(self):
        sessions.record_session("myapp", pid=os.getpid())
        d = self._mk_run("scan_rw")
        sessions.ledger_record_start(d, pid=os.getpid(),
                                     pin_project="appx", record_pin=True,
                                     pin_source="session")
        # Resume re-appends WITHOUT a pin — the original witness must
        # survive (it is the tamper defense for the whole run life).
        sessions.ledger_record_start(d, pid=os.getpid())
        found, project, source = sessions.ledger_pin_witness(
            d, pid=os.getpid())
        self.assertTrue(found)
        self.assertEqual(project, "appx")
        self.assertEqual(source, "session")

    def test_witness_rename_rewrite(self):
        sessions.record_session("myapp", pid=os.getpid())
        d = self._mk_run("scan_rn")
        sessions.ledger_record_start(d, pid=os.getpid(),
                                     pin_project="oldname",
                                     record_pin=True, pin_source="argv")
        sessions.ledger_rewrite_pin_project("oldname", "newname")
        found, project, source = sessions.ledger_pin_witness(
            d, pid=os.getpid())
        self.assertTrue(found)
        self.assertEqual(project, "newname")
        self.assertEqual(source, "argv")

    def test_ledger_runs_pinned_to_finds_external_runs(self):
        sessions.record_session("myapp", pid=os.getpid())
        d = self._mk_run("scan_ext")
        sessions.ledger_record_start(d, pid=os.getpid(),
                                     pin_project="appy", record_pin=True)
        recs = sessions.ledger_runs_pinned_to("appy")
        self.assertEqual([r["run_dir"] for r in recs],
                         [str(d.resolve())])
        self.assertEqual(sessions.ledger_runs_pinned_to("other"), [])

    def test_large_ledger_not_zeroed_and_budget_enforced(self):
        sessions.record_session("myapp", pid=os.getpid())
        # Long parent paths: 40 finished + 1 running with witnesses
        # once exceeded the old 64KB read cap and read as EMPTY.
        deep = Path(self._tmp.name) / ("p" * 200) / ("q" * 200)
        for i in range(40):
            d = deep / f"run_{i}"
            d.mkdir(parents=True)
            (d / ".raptor-run.json").write_text(
                '{"status": "completed"}', encoding="utf-8")
            sessions.ledger_record_start(d, pid=os.getpid(),
                                         pin_project="appz",
                                         record_pin=True)
            sessions.ledger_record_finish(d, "completed",
                                          pid=os.getpid())
        runs = sessions.ledger_runs(pid=os.getpid())
        self.assertTrue(runs, "ledger must not read as empty")
        size = (self.sessions_dir / f"{os.getpid()}.run").stat().st_size
        self.assertLessEqual(size, sessions._MAX_LEDGER_BYTES)

    def test_unknown_line_types_survive_rewrites(self):
        sessions.record_session("myapp", pid=os.getpid())
        d = self._mk_run("scan_u")
        sessions.ledger_record_start(d, pid=os.getpid())
        ledger = self.sessions_dir / f"{os.getpid()}.run"
        with ledger.open("a", encoding="utf-8") as fh:
            fh.write("futurekind 1 2 3 four\n")
        sessions.ledger_record_finish(d, "completed", pid=os.getpid())
        self.assertIn("futurekind 1 2 3 four",
                      ledger.read_text(encoding="utf-8"))

    def test_write_refused_once_entry_gone(self):
        # The resurrection gate: entry removed → no writer may
        # recreate the ledger, even one that passed the pre-lock gate.
        sessions.record_session("myapp", pid=os.getpid())
        records = [{"status": "running", "epoch": 1,
                    "run_id": "r1", "run_dir": "/tmp/r1"}]
        (self.sessions_dir / str(os.getpid())).unlink()
        self.assertFalse(sessions._write_ledger(os.getpid(), records))
        self.assertFalse(
            (self.sessions_dir / f"{os.getpid()}.run").exists())

    def test_stale_stamp_refuses_new_ledger_records(self):
        sessions.record_session("myapp", pid=os.getpid())
        entry = self.sessions_dir / str(os.getpid())
        fields = sessions._parse_entry(entry)
        entry.write_text(
            entry.read_text(encoding="utf-8").replace(
                f"starttime={fields['starttime']}", "starttime=1"),
            encoding="utf-8")
        d = self._mk_run("scan_st")
        sessions.ledger_record_start(d, pid=os.getpid())
        self.assertFalse(
            (self.sessions_dir / f"{os.getpid()}.run").exists(),
            "records written over a stale stamp would be wiped by the "
            "next refresh — refuse them up front")

    def test_corrupt_entry_reads_as_authoritative_none(self):
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        entry = self.sessions_dir / str(os.getpid())
        entry.write_bytes(b"\xff\xfe garbage \x00")
        name, state = sessions.session_binding(pid=os.getpid())
        self.assertIsNone(name)
        self.assertEqual(state, "none")

    def test_bom_entry_still_reads_v2(self):
        sessions.record_session("myapp", pid=os.getpid())
        entry = self.sessions_dir / str(os.getpid())
        entry.write_bytes(b"\xef\xbb\xbf" + entry.read_bytes())
        name, state = sessions.session_binding(pid=os.getpid())
        self.assertEqual((name, state), ("myapp", "bound"))

    def test_root_dir_refused_by_ledger(self):
        self.assertFalse(sessions._valid_run_dir("/"))

    def test_rebind_session_if_is_conditional(self):
        sessions.record_session("appa", pid=os.getpid())
        self.assertFalse(sessions.rebind_session_if(
            os.getpid(), "other", "appb"))
        self.assertTrue(sessions.rebind_session_if(
            os.getpid(), "appa", "appb"))
        self.assertEqual(sessions.session_binding(pid=os.getpid()),
                         ("appb", "bound"))


class LedgerBudgetDisciplineTest(_RegistryCase):
    """The writer guarantees an under-budget ledger even when pin
    witnesses (which survive while their run dirs exist) would
    otherwise hoard the whole budget — an over-budget file reads as
    EMPTY and the next RMW would wipe every record AND witness."""

    @pytest.mark.slow
    def test_witness_hoard_cannot_push_the_file_over_budget(self):
        sessions.record_session("myapp", pid=os.getpid())
        deep = Path(self._tmp.name) / ("p" * 220) / ("q" * 220)
        for i in range(700):
            d = deep / f"run_{i}"
            d.mkdir(parents=True)
            (d / ".raptor-run.json").write_text(
                '{"status": "completed"}', encoding="utf-8")
            sessions.ledger_record_start(d, pid=os.getpid(),
                                         pin_project="appz",
                                         record_pin=True)
            sessions.ledger_record_finish(d, "completed",
                                          pid=os.getpid())
        ledger = self.sessions_dir / f"{os.getpid()}.run"
        self.assertLessEqual(ledger.stat().st_size,
                             sessions._MAX_LEDGER_BYTES)
        # The reader must still see a non-empty ledger (newest
        # witnesses survive; oldest were evicted).
        _r, pins, _u = sessions._read_ledger_full(os.getpid())
        self.assertTrue(pins)
        self.assertIn(f"run_699", pins[-1]["run_id"])

    def test_finish_refuses_stale_stamped_entries(self):
        sessions.record_session("myapp", pid=os.getpid())
        d = Path(self._tmp.name) / "runs" / "scan_fs"
        d.mkdir(parents=True)
        (d / ".raptor-run.json").write_text(
            '{"status": "running"}', encoding="utf-8")
        sessions.ledger_record_start(d, pid=os.getpid())
        entry = self.sessions_dir / str(os.getpid())
        fields = sessions._parse_entry(entry)
        entry.write_text(
            entry.read_text(encoding="utf-8").replace(
                f"starttime={fields['starttime']}", "starttime=1"),
            encoding="utf-8")
        sessions.ledger_record_finish(d, "completed", pid=os.getpid())
        # The stale-stamped finish must not have landed.
        text = (self.sessions_dir / f"{os.getpid()}.run").read_text()
        self.assertIn("running", text)
        self.assertNotIn("completed", text)

    def test_far_future_epochs_clamped_on_rewrite(self):
        sessions.record_session("myapp", pid=os.getpid())
        d = Path(self._tmp.name) / "runs" / "scan_ep"
        d.mkdir(parents=True)
        (d / ".raptor-run.json").write_text(
            '{"status": "running"}', encoding="utf-8")
        ledger = self.sessions_dir / f"{os.getpid()}.run"
        ledger.write_text(
            f"running 99999999999 scan_ep {d.resolve()}\n",
            encoding="utf-8")
        d2 = Path(self._tmp.name) / "runs" / "scan_ep2"
        d2.mkdir(parents=True)
        (d2 / ".raptor-run.json").write_text(
            '{"status": "running"}', encoding="utf-8")
        sessions.ledger_record_start(d2, pid=os.getpid())
        import time as _t
        for r in sessions.ledger_runs(pid=os.getpid()):
            self.assertLessEqual(r["epoch"], int(_t.time()) + 86400)


class OwnRepairContinuityTest(_RegistryCase):
    def test_own_env_credential_repair_keeps_the_ledger(self):
        # A live session repairing its OWN corrupt entry (env
        # credential names this pid) keeps records AND pin witnesses —
        # the wipe is for dead predecessors.
        sessions.record_session("myapp", pid=os.getpid(),
                                token="cd" * 16)
        d = Path(self._tmp.name) / "runs" / "scan_keep"
        d.mkdir(parents=True)
        (d / ".raptor-run.json").write_text(
            '{"status": "running"}', encoding="utf-8")
        sessions.ledger_record_start(d, pid=os.getpid(),
                                     pin_project="myapp",
                                     record_pin=True)
        entry = self.sessions_dir / str(os.getpid())
        fields = sessions._parse_entry(entry)
        entry.write_text(
            entry.read_text(encoding="utf-8").replace(
                f"starttime={fields['starttime']}", "starttime=1"),
            encoding="utf-8")
        from unittest.mock import patch as _patch
        with _patch.dict(os.environ, {
            sessions.ENV_SESSION_PID: str(os.getpid()),
            sessions.ENV_SESSION_TOKEN: "cd" * 16,
        }):
            sessions.record_session("myapp", pid=os.getpid())
        self.assertTrue(sessions.ledger_runs(pid=os.getpid()),
                        "own-repair must keep the ledger")
        found, project, _s = sessions.ledger_pin_witness(
            d, pid=os.getpid())
        self.assertTrue(found)
        self.assertEqual(project, "myapp")
        self.assertEqual(
            sessions._parse_entry(entry).get("token"), "cd" * 16)

    def test_foreign_token_still_wipes(self):
        # A recycled pid whose env credential does NOT match the old
        # entry's token (a dead predecessor's entry) gets the wipe —
        # the token match is the discriminator.
        sessions.record_session("myapp", pid=os.getpid(),
                                token="ab" * 16)
        d = Path(self._tmp.name) / "runs" / "scan_wipe"
        d.mkdir(parents=True)
        (d / ".raptor-run.json").write_text(
            '{"status": "running"}', encoding="utf-8")
        sessions.ledger_record_start(d, pid=os.getpid())
        entry = self.sessions_dir / str(os.getpid())
        fields = sessions._parse_entry(entry)
        entry.write_text(
            entry.read_text(encoding="utf-8").replace(
                f"starttime={fields['starttime']}", "starttime=1"),
            encoding="utf-8")
        from unittest.mock import patch as _patch
        with _patch.dict(os.environ, {
            sessions.ENV_SESSION_PID: str(os.getpid()),
            sessions.ENV_SESSION_TOKEN: "ef" * 16,  # different token
        }):
            sessions.record_session("myapp", pid=os.getpid())
        self.assertEqual(sessions.ledger_runs(pid=os.getpid()), [])


class DrainRequestTest(_RegistryCase):
    """Drain-request records: the fleet's pause-at-a-safe-boundary
    channel. Lines ride the ledger's unknown-lines channel — every
    other writer preserves them verbatim — and are gated by the same
    registered-session + identity checks as the record writers."""

    def setUp(self):
        super().setUp()
        self.run_root = Path(self._tmp.name) / "runs"
        self.run_root.mkdir()
        sessions.record_session("drainapp", pid=os.getpid())

    def _mk_run(self, name: str) -> Path:
        d = self.run_root / name
        d.mkdir()
        (d / ".raptor-run.json").write_text(
            '{"status": "running"}', encoding="utf-8")
        return d

    def test_record_and_read_roundtrip(self):
        d = self._mk_run("eng_1")
        self.assertTrue(
            sessions.ledger_record_drain_request(d, pid=os.getpid()))
        reqs = sessions.ledger_drain_requests(d)
        self.assertEqual(len(reqs), 1)
        self.assertEqual(reqs[0]["run_dir"], str(d.resolve()))
        self.assertEqual(reqs[0]["run_id"], "eng_1")
        self.assertEqual(reqs[0]["session_pid"], os.getpid())
        self.assertIsInstance(reqs[0]["epoch"], int)

    def test_deduplicated_per_run_dir(self):
        d = self._mk_run("eng_dedup")
        sessions.ledger_record_drain_request(d, pid=os.getpid())
        sessions.ledger_record_drain_request(d, pid=os.getpid())
        self.assertEqual(len(sessions.ledger_drain_requests(d)), 1)

    def test_other_writers_preserve_drain_lines(self):
        """The forward-compat channel contract: run start/finish on
        OTHER runs never drops a drain line."""
        d = self._mk_run("eng_keep")
        other = self._mk_run("scan_other")
        sessions.ledger_record_drain_request(d, pid=os.getpid())
        sessions.ledger_record_start(other, pid=os.getpid())
        (other / ".raptor-run.json").write_text(
            '{"status": "completed"}', encoding="utf-8")
        sessions.ledger_record_finish(other, "completed",
                                      pid=os.getpid())
        self.assertEqual(len(sessions.ledger_drain_requests(d)), 1)

    def test_clear_removes_and_counts(self):
        d = self._mk_run("eng_clear")
        sessions.ledger_record_drain_request(d, pid=os.getpid())
        self.assertEqual(sessions.ledger_clear_drain_requests(d), 1)
        self.assertEqual(sessions.ledger_drain_requests(d), [])
        self.assertEqual(sessions.ledger_clear_drain_requests(d), 0)

    def test_clear_leaves_other_runs_requests(self):
        d1 = self._mk_run("eng_a")
        d2 = self._mk_run("eng_b")
        sessions.ledger_record_drain_request(d1, pid=os.getpid())
        sessions.ledger_record_drain_request(d2, pid=os.getpid())
        sessions.ledger_clear_drain_requests(d1)
        self.assertEqual(len(sessions.ledger_drain_requests(d2)), 1)

    def test_vanished_run_dir_pruned_on_next_record(self):
        import shutil
        d1 = self._mk_run("eng_gone")
        d2 = self._mk_run("eng_live")
        sessions.ledger_record_drain_request(d1, pid=os.getpid())
        shutil.rmtree(d1)
        sessions.ledger_record_drain_request(d2, pid=os.getpid())
        _r, _p, unknown = sessions._read_ledger_full(os.getpid())
        drains = [ln for ln in unknown
                  if sessions._drain_parse(ln) is not None]
        self.assertEqual(len(drains), 1)

    def test_owner_session_ledger_hosts_the_request(self):
        """pid=None routes the request to the session holding the
        run's RUNNING record."""
        d = self._mk_run("eng_owned")
        sessions.ledger_record_start(d, pid=os.getpid())
        self.assertTrue(sessions.ledger_record_drain_request(d))
        reqs = sessions.ledger_drain_requests(d)
        self.assertEqual(len(reqs), 1)
        self.assertEqual(reqs[0]["session_pid"], os.getpid())

    def test_unregistered_pid_refused(self):
        d = self._mk_run("eng_norefs")
        self.assertFalse(
            sessions.ledger_record_drain_request(d, pid=DEAD_PID))
        self.assertEqual(sessions.ledger_drain_requests(d), [])

    def test_hostile_run_dir_refused(self):
        evil = self.run_root / "eng\x1b[31mred"
        evil.mkdir()
        self.assertFalse(
            sessions.ledger_record_drain_request(evil,
                                                 pid=os.getpid()))

    def test_orphan_ledger_never_steers_reads(self):
        d = self._mk_run("eng_orphan")
        sessions.ledger_record_drain_request(d, pid=os.getpid())
        (self.sessions_dir / str(os.getpid())).unlink()
        self.assertEqual(sessions.ledger_drain_requests(d), [])

class StrongHostSessionTest(unittest.TestCase):
    """Strong host records require token + full process evidence."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.sessions_dir = self.root / "sessions.d"
        self._sessions_patch = patch.object(sessions, "SESSIONS_DIR", self.sessions_dir)
        self._sessions_patch.start()
        self.addCleanup(self._sessions_patch.stop)

    @contextlib.contextmanager
    def _host(self, name: str):
        source = shutil.which("sleep")
        if source is None:
            self.skipTest("sleep executable unavailable")
        executable = self.root / name
        shutil.copy2(source, executable)
        executable.chmod(0o700)
        process = subprocess.Popen(
            [str(executable), "60"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "HOME": str(self.root)},
        )
        try:
            yield process, executable
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    def _record(self, process, executable, *, frontend=Frontend.COPILOT):
        token = sessions.mint_token()
        claim = build_session_host_claim(frontend, executable)
        result = sessions.record_session(
            "myapp",
            pid=process.pid,
            token=token,
            seeded_by="flag",
            host_claim=claim,
        )
        self.assertEqual(result, process.pid)
        return token, claim

    def _resolve_with(self, process, token):
        with patch.dict(
            os.environ,
            {
                sessions.ENV_SESSION_PID: str(process.pid),
                sessions.ENV_SESSION_TOKEN: token,
            },
        ):
            return sessions.resolve_session_owner()

    @staticmethod
    def _claim(
        *,
        frontend: Frontend = Frontend.COPILOT,
        executable_device: int = 10,
        executable_inode: int = 20,
    ) -> SessionHostClaim:
        return SessionHostClaim(
            frontend=frontend,
            uid=os.geteuid(),
            executable=Path(f"/owned/{frontend.value}"),
            executable_device=executable_device,
            executable_inode=executable_inode,
        )

    @staticmethod
    def _fields(
        claim: SessionHostClaim,
        *,
        project: str = "myapp",
        token: str = "ab" * 16,
        starttime: str = "7",
        boot: str = "boot",
        pidns: str = "1",
    ) -> dict[str, str]:
        return {
            "v": "2",
            "project": project,
            "since": "2026-09-11T00:00:00+00:00",
            "starttime": starttime,
            "boot_id": boot,
            "pidns": pidns,
            "token": token,
            **claim.session_fields(),
        }

    def _write_fields(self, pid: int, fields: dict[str, str]) -> Path:
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        entry = self.sessions_dir / str(pid)
        entry.write_text(
            "".join(f"{key}={value}\n" for key, value in fields.items()),
            encoding="utf-8",
        )
        return entry

    @contextlib.contextmanager
    def _patched_identity(
        self,
        *,
        pid: int,
        comm,
        starttime: str = "7",
        executable_identity: tuple[int, int] = (10, 20),
    ):
        with (
            patch.object(sessions, "_pid_running", lambda candidate: candidate == pid),
            patch.object(sessions, "proc_starttime", lambda _pid: starttime),
            patch.object(sessions, "boot_id", lambda: "boot"),
            patch.object(sessions, "pidns_id", lambda: "1"),
            patch.object(sessions, "_comm", comm),
            patch.object(sessions, "_process_uid", lambda _pid: os.geteuid()),
            patch.object(
                sessions,
                "_process_executable_identity",
                lambda _pid: executable_identity,
            ),
        ):
            yield

    def test_a1_exec_transition_host_mismatch_is_kept_then_live(self):
        pid = 42420
        claim = self._claim()
        entry = self._write_fields(pid, self._fields(claim))
        state = {"comm": "bash"}
        with self._patched_identity(
            pid=pid,
            comm=lambda _pid: state["comm"],
        ):
            fields = sessions._parse_entry(entry)
            self.assertEqual(sessions._entry_state(pid, fields), "host-mismatch")
            self.assertEqual(sessions.read_sessions(prune=True), {})
            self.assertTrue(entry.exists())

            state["comm"] = "copilot"
            self.assertEqual(sessions._entry_state(pid, fields), "live")
            self.assertIn(pid, sessions.read_sessions(prune=True))

    def test_a2_invalid_entry_is_not_authority_listed_or_pruned(self):
        pid = 42421
        claim = self._claim()
        fields = self._fields(claim)
        fields.pop("host_exe_ino")
        entry = self._write_fields(pid, fields)
        with (
            self._patched_identity(
                pid=pid,
                comm=lambda _pid: "copilot",
            ),
            self.assertLogs("core.project.sessions", level="WARNING"),
        ):
            self.assertEqual(sessions._entry_state(pid, fields), "invalid")
            self.assertEqual(sessions.read_sessions(prune=True), {})
            self.assertIsNone(sessions._owner_for_pid(pid))
        self.assertTrue(entry.exists())

    def test_a3_malformed_existing_claim_refuses_rewrite(self):
        pid = 42422
        fields = self._fields(self._claim())
        fields.pop("host_exe_ino")
        entry = self._write_fields(pid, fields)
        with self.assertLogs("core.project.sessions", level="WARNING") as captured:
            self.assertIsNone(sessions.record_session("other", pid=pid))
        self.assertIn("refusing to rewrite", "\n".join(captured.output))
        self.assertEqual(sessions._parse_entry(entry), fields)

    def test_a3_own_repair_executable_mismatch_refuses(self):
        pid = 42423
        token = "cd" * 16
        claim = self._claim()
        fields = self._fields(claim, token=token, starttime="old-start")
        entry = self._write_fields(pid, fields)
        with (
            self._patched_identity(
                pid=pid,
                comm=lambda _pid: "copilot",
                starttime="new-start",
                executable_identity=(30, 40),
            ),
            patch.dict(
                os.environ,
                {
                    sessions.ENV_SESSION_PID: str(pid),
                    sessions.ENV_SESSION_TOKEN: token,
                },
            ),
            self.assertLogs("core.project.sessions", level="WARNING") as captured,
        ):
            self.assertIsNone(sessions.record_session("other", pid=pid))
        self.assertIn("refusing own-session repair", "\n".join(captured.output))
        self.assertEqual(sessions._parse_entry(entry), fields)

    def test_a3_valid_own_repair_preserves_token_and_claim(self):
        pid = 42424
        token = "ef" * 16
        claim = self._claim()
        fields = self._fields(claim, token=token, starttime="old-start")
        entry = self._write_fields(pid, fields)
        with (
            self._patched_identity(
                pid=pid,
                comm=lambda _pid: "copilot",
                starttime="new-start",
            ),
            patch.dict(
                os.environ,
                {
                    sessions.ENV_SESSION_PID: str(pid),
                    sessions.ENV_SESSION_TOKEN: token,
                },
            ),
        ):
            self.assertEqual(sessions.record_session("other", pid=pid), pid)
        repaired = sessions._parse_entry(entry)
        self.assertEqual(repaired["token"], token)
        self.assertEqual(repaired["starttime"], "new-start")
        self.assertEqual(repaired["project"], "other")
        for key, value in claim.session_fields().items():
            self.assertEqual(repaired[key], value)

    def test_owned_copilot_process_resolves_with_strong_evidence(self):
        with self._host("copilot") as (process, executable):
            token, claim = self._record(process, executable)
            owner = self._resolve_with(process, token)
            self.assertIsNotNone(owner)
            self.assertEqual(owner.pid, process.pid)
            self.assertEqual(owner.frontend, Frontend.COPILOT)
            self.assertTrue(owner.host_verified)
            self.assertEqual(owner.host_claim, claim)
            self.assertEqual(
                sessions.session_binding(pid=process.pid),
                ("myapp", "bound"),
            )

    def test_wrong_token_and_stale_pid_are_rejected(self):
        with self._host("copilot") as (process, executable):
            token, _claim = self._record(process, executable)
            self.assertIsNone(self._resolve_with(process, "00" * 16))
            self.assertIsNotNone(self._resolve_with(process, token))
        self.assertIsNone(self._resolve_with(process, token))

    def test_strong_record_never_falls_back_to_ancestry_without_token(self):
        pid = 40
        claim = build_session_host_claim(Frontend.CLAUDE, sys.executable)
        self.sessions_dir.mkdir(parents=True)
        fields = {
            "v": "2",
            "project": "myapp",
            "since": "2026-09-11T00:00:00+00:00",
            "starttime": "7",
            "boot_id": "boot",
            "pidns": "1",
            "token": "ab" * 16,
            **claim.session_fields(),
        }
        entry = self.sessions_dir / str(pid)
        entry.write_text(
            "".join(f"{key}={value}\n" for key, value in fields.items()),
            encoding="utf-8",
        )
        with (
            patch.object(sessions.os, "getpid", lambda: 100),
            patch.object(sessions.os, "getppid", lambda: pid),
            patch(
                "core.run.metadata._read_ppid",
                lambda current: 1 if current == pid else 0,
            ),
            patch.object(
                sessions, "_comm", lambda current: "claude" if current == pid else None
            ),
        ):
            self.assertIsNone(_REAL_WALK_SESSION_PID())

            # Removing the optional host claim restores exactly the legacy
            # Claude ancestry strength.
            entry.write_text(
                "".join(
                    f"{key}={value}\n"
                    for key, value in fields.items()
                    if key
                    not in {
                        "host_v",
                        "host",
                        "host_uid",
                        "host_exe",
                        "host_exe_dev",
                        "host_exe_ino",
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(_REAL_WALK_SESSION_PID(), pid)

    def _assert_inner_ancestry_entry_skipped(
        self, inner_fields: dict[str, str]
    ) -> None:
        inner = 50
        outer = 40
        self._write_fields(inner, inner_fields)
        self._write_fields(
            outer,
            {
                "v": "2",
                "project": "outer",
                "since": "x",
                "starttime": "7",
                "boot_id": "boot",
                "pidns": "1",
            },
        )
        parents = {100: inner, inner: outer, outer: 1}
        with (
            patch.object(sessions.os, "getpid", lambda: 100),
            patch.object(sessions.os, "getppid", lambda: parents[100]),
            patch("core.run.metadata._read_ppid", lambda pid: parents[pid]),
            patch.object(
                sessions,
                "_comm",
                lambda pid: "claude" if pid in (inner, outer) else None,
            ),
            patch.object(
                sessions,
                "_identity_matches",
                lambda pid, _fields: pid == outer,
            ),
        ):
            self.assertEqual(_REAL_WALK_SESSION_PID(), outer)

    def test_a5_walker_skips_strong_entry_for_outer_legacy(self):
        self._assert_inner_ancestry_entry_skipped(
            self._fields(
                self._claim(frontend=Frontend.CLAUDE),
                project="inner",
            )
        )

    def test_a5_walker_skips_invalid_entry_for_outer_legacy(self):
        fields = self._fields(
            self._claim(frontend=Frontend.CLAUDE),
            project="inner",
        )
        fields.pop("host_exe_ino")
        with self.assertLogs("core.project.sessions", level="WARNING"):
            self._assert_inner_ancestry_entry_skipped(fields)

    def test_a10_unknown_host_version_never_uses_legacy_fallback(self):
        pid = 42426
        token = "34" * 16
        fields = self._fields(
            self._claim(frontend=Frontend.CLAUDE),
            token=token,
        )
        fields["host_v"] = "2"
        self._write_fields(pid, fields)
        with (
            self._patched_identity(
                pid=pid,
                comm=lambda _pid: "claude",
            ),
            patch.dict(
                os.environ,
                {
                    sessions.ENV_SESSION_PID: str(pid),
                    sessions.ENV_SESSION_TOKEN: token,
                },
            ),
            self.assertLogs("core.project.sessions", level="WARNING"),
        ):
            self.assertFalse(sessions._identity_matches(pid, fields))
            self.assertIsNone(sessions._owner_for_pid(pid))
            self.assertEqual(sessions.session_binding(), (None, "none"))

        with (
            patch.object(sessions.os, "getpid", lambda: 100),
            patch.object(sessions.os, "getppid", lambda: pid),
            patch(
                "core.run.metadata._read_ppid",
                lambda current: 1 if current == pid else 0,
            ),
            patch.object(
                sessions,
                "_comm",
                lambda current: "claude" if current == pid else None,
            ),
            self.assertLogs("core.project.sessions", level="WARNING"),
        ):
            self.assertIsNone(_REAL_WALK_SESSION_PID())

    def test_a12_second_starttime_read_detects_pid_reuse_window(self):
        pid = 42427
        claim = self._claim()
        fields = self._fields(claim, starttime="S1")
        starts = iter(("S1", "S2"))
        with (
            patch.object(sessions, "_foreign_entry", return_value=False),
            patch.object(sessions, "_pid_running", lambda candidate: candidate == pid),
            patch.object(
                sessions, "proc_starttime", side_effect=lambda _pid: next(starts)
            ) as start_reader,
            patch.object(sessions, "_comm", lambda _pid: "copilot"),
            patch.object(sessions, "_process_uid", lambda _pid: os.geteuid()),
            patch.object(
                sessions,
                "_process_executable_identity",
                lambda _pid: (
                    claim.executable_device,
                    claim.executable_inode,
                ),
            ),
        ):
            self.assertFalse(sessions._identity_matches(pid, fields))
        self.assertEqual(start_reader.call_count, 2)

    def test_start_uid_namespace_and_executable_mismatches_are_rejected(self):
        with self._host("copilot") as (process, executable):
            token, claim = self._record(process, executable)
            entry = self.sessions_dir / str(process.pid)
            original = entry.read_text(encoding="utf-8")
            fields = sessions._parse_entry(entry)
            replacements = (
                (
                    f"starttime={fields['starttime']}",
                    f"starttime={int(fields['starttime']) + 1}",
                ),
                (
                    f"host_uid={claim.uid}",
                    f"host_uid={claim.uid + 1}",
                ),
                (
                    f"pidns={fields['pidns']}",
                    f"pidns={int(fields['pidns']) + 1}",
                ),
                (
                    f"host_exe_ino={claim.executable_inode}",
                    f"host_exe_ino={claim.executable_inode + 1}",
                ),
            )
            for old, new in replacements:
                entry.write_text(
                    original.replace(old, new),
                    encoding="utf-8",
                )
                self.assertIsNone(
                    self._resolve_with(process, token),
                    msg=f"mismatch unexpectedly authorized: {old}",
                )

    def test_unknown_or_partial_host_claim_fails_closed_visibly(self):
        with self._host("copilot") as (process, executable):
            token, _claim = self._record(process, executable)
            entry = self.sessions_dir / str(process.pid)
            original = entry.read_text(encoding="utf-8")
            for malformed in (
                original.replace("host=copilot", "host=unknown"),
                "\n".join(
                    line
                    for line in original.splitlines()
                    if not line.startswith("host_exe_ino=")
                )
                + "\n",
            ):
                entry.write_text(malformed, encoding="utf-8")
                with self.assertLogs(
                    "core.project.sessions", level="WARNING"
                ) as captured:
                    self.assertEqual(
                        sessions.session_binding(pid=process.pid),
                        (None, "none"),
                    )
                self.assertIn("malformed host claim", "\n".join(captured.output))
                self.assertIsNone(self._resolve_with(process, token))

    def test_matching_token_mutation_cannot_fall_through_to_bookmark(self):
        from core.project.project import ProjectManager

        projects_dir = self.root / "projects"
        target = self.root / "target"
        target.mkdir()
        manager = ProjectManager(projects_dir=projects_dir)
        manager.create(
            "bookmark",
            str(target),
            output_dir=str(self.root / "out" / "bookmark"),
        )
        manager.set_active("bookmark")
        with self._host("copilot") as (process, executable):
            token, _claim = self._record(process, executable)
            entry = self.sessions_dir / str(process.pid)
            entry.write_text(
                entry.read_text(encoding="utf-8").replace(
                    "host=copilot", "host=unknown"
                ),
                encoding="utf-8",
            )
            with (
                patch("core.project.project.PROJECTS_DIR", projects_dir),
                patch.dict(
                    os.environ,
                    {
                        sessions.ENV_SESSION_PID: str(process.pid),
                        sessions.ENV_SESSION_TOKEN: token,
                    },
                ),
            ):
                self.assertEqual(sessions.session_binding(), (None, "none"))
                self.assertIsNone(ProjectManager().get_active())

    def test_a6_preexec_executable_mismatch_is_projectless(self):
        from core.project.project import ProjectManager

        pid = 42425
        token = "12" * 16
        projects_dir = self.root / "projects"
        target = self.root / "target"
        target.mkdir()
        manager = ProjectManager(projects_dir=projects_dir)
        manager.create(
            "bookmark",
            str(target),
            output_dir=str(self.root / "out" / "bookmark"),
        )
        manager.set_active("bookmark")
        self._write_fields(
            pid,
            self._fields(self._claim(), token=token),
        )
        with (
            self._patched_identity(
                pid=pid,
                comm=lambda _pid: "copilot",
                executable_identity=(30, 40),
            ),
            patch("core.project.project.PROJECTS_DIR", projects_dir),
            patch.dict(
                os.environ,
                {
                    sessions.ENV_SESSION_PID: str(pid),
                    sessions.ENV_SESSION_TOKEN: token,
                },
            ),
        ):
            self.assertEqual(sessions.session_binding(), (None, "none"))
            self.assertIsNone(ProjectManager().get_active())

    def test_process_name_or_executable_alone_is_not_authority(self):
        source = shutil.which("sleep")
        if source is None:
            self.skipTest("sleep executable unavailable")
        wrong = self.root / "other-copilot"
        shutil.copy2(source, wrong)
        wrong.chmod(0o700)
        with self._host("copilot") as (process, executable):
            wrong_claim = build_session_host_claim(Frontend.COPILOT, wrong)
            self.assertIsNone(
                sessions.record_session(
                    "myapp",
                    pid=process.pid,
                    token=sessions.mint_token(),
                    host_claim=wrong_claim,
                )
            )

        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "HOME": str(self.root)},
        )
        try:
            python_claim = build_session_host_claim(Frontend.COPILOT, sys.executable)
            self.assertIsNone(
                sessions.record_session(
                    "myapp",
                    pid=process.pid,
                    token=sessions.mint_token(),
                    host_claim=python_claim,
                )
            )
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_strong_record_requires_launcher_token(self):
        with self._host("copilot") as (process, executable):
            claim = build_session_host_claim(Frontend.COPILOT, executable)
            with self.assertLogs("core.project.sessions", level="WARNING") as captured:
                self.assertIsNone(
                    sessions.record_session(
                        "myapp",
                        pid=process.pid,
                        host_claim=claim,
                    )
                )
            self.assertIn(
                "requires a launcher-minted token",
                "\n".join(captured.output),
            )

    def test_legacy_record_keeps_claude_only_strength(self):
        with patch.object(sessions, "_comm", lambda _pid: "claude"):
            sessions.record_session("myapp", pid=os.getpid())
            fields = sessions._parse_entry(self.sessions_dir / str(os.getpid()))
            self.assertFalse(
                any(
                    key in fields
                    for key in (
                        "host",
                        "host_uid",
                        "host_exe",
                    )
                )
            )
            owner = sessions._owner_for_pid(os.getpid())
            self.assertEqual(owner.frontend, Frontend.CLAUDE)
            self.assertFalse(owner.host_verified)


class ReceiptRegistrySafetyTest(_RegistryCase):

    def _host_v2_fields(
        self,
        pid: int,
        *,
        starttime: str | None = None,
        boot: str | None = None,
        pidns: str | None = None,
        digest: str = "a" * 64,
        token: str = "ab" * 16,
    ) -> dict[str, str]:
        return {
            "v": "2",
            "project": "-",
            "since": "2026-09-12T00:00:00+00:00",
            "starttime": starttime or sessions.proc_starttime(pid) or "1",
            "boot_id": boot
            or sessions.boot_id()
            or "00000000-0000-4000-8000-000000000000",
            "pidns": pidns or sessions.pidns_id() or "1",
            "host_v": "2",
            "host": "copilot",
            "host_uid": str(os.geteuid()),
            "host_exe": "/owned/copilot",
            "host_exe_dev": "10",
            "host_exe_ino": "20",
            "host_receipt_v": "1",
            "host_receipt_state": "pending",
            "host_receipt_sha256": digest,
            "host_receipt_reference": "{}",
            "token": token,
            "seeded_by": "owned_fake",
        }

    def _write_host_v2(
        self,
        pid: int,
        **kwargs,
    ) -> tuple[Path, dict[str, str]]:
        fields = self._host_v2_fields(pid, **kwargs)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        entry = self.sessions_dir / str(pid)
        entry.write_text(
            "".join(f"{key}={fields[key]}\n" for key in sessions._HOST_V2_ENTRY_KEYS),
            encoding="utf-8",
        )
        entry.chmod(0o600)
        return entry, fields

    def test_legacy_and_host_v1_entry_bytes_are_unchanged(self):
        fixed = datetime(2026, 9, 12, tzinfo=timezone.utc)

        class FixedDateTime:
            @classmethod
            def now(cls, _timezone):
                return fixed

        base = {
            "starttime": "7",
            "boot_id": "boot",
            "pidns": "1",
            "token": "ab" * 16,
            "seeded_by": "flag",
        }
        claim = SessionHostClaim(
            frontend=Frontend.COPILOT,
            uid=os.geteuid(),
            executable=Path("/owned/copilot"),
            executable_device=10,
            executable_inode=20,
        )
        with patch.object(sessions, "datetime", FixedDateTime):
            self.assertEqual(
                sessions._entry_content("myapp", base),
                "v=2\nproject=myapp\n"
                "since=2026-09-12T00:00:00+00:00\n"
                "starttime=7\nboot_id=boot\npidns=1\n"
                f"token={'ab' * 16}\nseeded_by=flag\n",
            )
            self.assertEqual(
                sessions._entry_content(
                    "myapp",
                    {**base, **claim.session_fields()},
                ),
                "v=2\nproject=myapp\n"
                "since=2026-09-12T00:00:00+00:00\n"
                "starttime=7\nboot_id=boot\npidns=1\n"
                "host_v=1\nhost=copilot\n"
                f"host_uid={os.geteuid()}\n"
                "host_exe=/owned/copilot\n"
                "host_exe_dev=10\nhost_exe_ino=20\n"
                f"token={'ab' * 16}\nseeded_by=flag\n",
            )

    def test_f1_receipt_backed_ancestor_never_mints_claude_owner(self):
        pid = 42426
        entry, fields = self._write_host_v2(pid)
        parents = {100: pid, pid: 1}
        with (
            patch.object(sessions.os, "getpid", lambda: 100),
            patch.object(sessions.os, "getppid", lambda: parents[100]),
            patch(
                "core.run.metadata._read_ppid",
                lambda current: parents[current],
            ),
            patch.object(
                sessions,
                "_comm",
                lambda current: "claude" if current == pid else None,
            ),
            patch.object(sessions, "_identity_matches", return_value=True),
        ):
            self.assertEqual(
                sessions._host_claim_state(fields, pid=pid),
                ("invalid", None),
            )
            self.assertIsNone(sessions._walk_session_pid())
            self.assertIsNone(sessions._owner_for_pid(pid))
            self.assertIsNone(sessions.resolve_session_owner())
        self.assertTrue(entry.exists())

    def test_matching_token_host_v2_fences_tree_walk(self):
        pid = 42427
        token = "cd" * 16
        self._write_host_v2(pid, token=token)
        with (
            patch.dict(
                os.environ,
                {
                    sessions.ENV_SESSION_PID: str(pid),
                    sessions.ENV_SESSION_TOKEN: token,
                },
            ),
            patch.object(
                sessions,
                "_walk_session_pid",
                side_effect=AssertionError("tree walk must be fenced"),
            ),
        ):
            self.assertIsNone(sessions.resolve_session_pid())
            self.assertIsNone(sessions.resolve_session_owner())
            self.assertEqual(sessions.session_binding(), (None, "none"))

    def test_host_claim_state_vocabulary_remains_closed(self):
        complete = self._host_v2_fields(42428)
        partial = {"host_v": "2", "token": "ab" * 16}
        receipt_only = {
            "host_receipt_state": "pending",
            "token": "ab" * 16,
        }
        for fields in (complete, partial, receipt_only):
            self.assertEqual(
                sessions._host_claim_state(fields, pid=42428),
                ("invalid", None),
            )

    def test_generic_writers_refuse_and_removal_cleans_exact_companion(self):
        pid = os.getpid()
        digest = "b" * 64
        entry, _fields = self._write_host_v2(pid, digest=digest)
        selected = self.sessions_dir / f"{pid}.receipt.{digest}.json"
        selected.write_bytes(b"selected")
        selected.chmod(0o600)
        unrelated = self.sessions_dir / f"{pid}.receipt.{'c' * 64}.json"
        unrelated.write_bytes(b"unrelated")
        unrelated.chmod(0o600)
        before = entry.read_bytes()
        self.assertIsNone(sessions.record_session("other", pid=pid))
        self.assertIsNone(sessions.bind_session("other", pid=pid))
        self.assertFalse(sessions.rebind_session_if(pid, "-", "other"))
        self.assertIsNone(
            sessions._record_session_locked(
                "other",
                pid,
                None,
                None,
                entry,
            )
        )
        self.assertEqual(entry.read_bytes(), before)
        self.assertEqual(sessions.record_session(None, pid=pid), pid)
        self.assertFalse(entry.exists())
        self.assertFalse(selected.exists())
        self.assertTrue(unrelated.exists())
        self.assertTrue((self.sessions_dir / f"{pid}.receipt.lock").exists())

    def test_dead_and_recycled_receipt_entries_get_exact_cleanup(self):
        pid = DEAD_PID
        digest = "d" * 64
        entry, _fields = self._write_host_v2(pid, digest=digest)
        sidecar = self.sessions_dir / f"{pid}.receipt.{digest}.json"
        sidecar.write_bytes(b"selected")
        sidecar.chmod(0o600)
        unrelated = self.sessions_dir / f"{pid}.receipt.{'e' * 64}.json.bak"
        unrelated.write_bytes(b"unrelated")
        unrelated.chmod(0o600)
        self.assertEqual(sessions.read_sessions(), {})
        self.assertFalse(entry.exists())
        self.assertFalse(sidecar.exists())
        self.assertTrue(unrelated.exists())
        self.assertTrue((self.sessions_dir / f"{pid}.receipt.lock").exists())
        self.assertFalse((self.sessions_dir / f"{pid}.run.lock").exists())

        live = os.getpid()
        digest = "f" * 64
        entry, _fields = self._write_host_v2(
            live,
            starttime="1",
            digest=digest,
        )
        sidecar = self.sessions_dir / f"{live}.receipt.{digest}.json"
        sidecar.write_bytes(b"selected")
        sidecar.chmod(0o600)
        sessions.read_sessions()
        self.assertFalse(entry.exists())
        self.assertFalse(sidecar.exists())

    def test_orphan_sweep_is_bounded_exact_and_live_safe(self):
        dead = DEAD_PID
        orphan = self.sessions_dir / f"{dead}.receipt.{'1' * 64}.json"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        orphan.write_bytes(b"not-json")
        orphan.chmod(0o600)
        decoys = (
            self.sessions_dir / f"0{dead}.receipt.{'1' * 64}.json",
            self.sessions_dir / f"{dead}.receipt.{'A' * 64}.json",
            self.sessions_dir / f"{dead}.receipt.{'2' * 63}.json",
            self.sessions_dir / f"{dead}.receipt.{'3' * 64}.json.bak",
        )
        for decoy in decoys:
            decoy.write_bytes(b"keep")
        sessions.sweep_session_receipt_sidecars()
        self.assertFalse(orphan.exists())
        self.assertTrue(all(decoy.exists() for decoy in decoys))
        self.assertTrue((self.sessions_dir / f"{dead}.receipt.lock").exists())
        self.assertFalse((self.sessions_dir / f"{dead}.run.lock").exists())

        live = os.getpid()
        live_orphan = self.sessions_dir / f"{live}.receipt.{'4' * 64}.json"
        live_orphan.write_bytes(b"not-json")
        live_orphan.chmod(0o600)
        sessions.sweep_session_receipt_sidecars()
        self.assertTrue(live_orphan.exists())
        self.assertFalse((self.sessions_dir / f"{live}.run.lock").exists())

    def test_orphan_sweep_rechecks_session_takeover_under_lock(self):
        pid = DEAD_PID
        digest = "6" * 64
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        sidecar = self.sessions_dir / f"{pid}.receipt.{digest}.json"
        sidecar.write_bytes(b"not-json")
        sidecar.chmod(0o600)
        fired = False

        def install_replacement(_pid: int, _fd: int) -> None:
            nonlocal fired
            if fired:
                return
            fired = True
            self._write_host_v2(pid, digest=digest)

        with patch.object(
            sessions,
            "_after_session_lock_open",
            install_replacement,
        ):
            sessions.sweep_session_receipt_sidecars()
        self.assertTrue(fired)
        self.assertTrue(sidecar.exists())
        self.assertTrue((self.sessions_dir / str(pid)).exists())

    def test_foreign_receipt_entry_and_sidecar_are_never_pruned(self):
        pid = DEAD_PID
        digest = "5" * 64
        entry, _fields = self._write_host_v2(
            pid,
            boot="00000000-dead-beef-0000-000000000000",
            pidns="1",
            digest=digest,
        )
        sidecar = self.sessions_dir / f"{pid}.receipt.{digest}.json"
        sidecar.write_bytes(b"not-json")
        sidecar.chmod(0o600)
        sessions.read_sessions()
        self.assertTrue(entry.exists())
        self.assertTrue(sidecar.exists())

    @unittest.skipUnless(sys.platform != "win32", "fcntl semantics")
    def test_strict_session_lock_refuses_unsafe_shapes_and_contention(self):
        import fcntl

        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        pid = 42429
        lock = self.sessions_dir / f"{pid}.run.lock"
        lock.write_bytes(b"")
        lock.chmod(0o644)
        with sessions._strict_session_lock(pid, attempts=1, interval=0):
            pass

        for shape in ("symlink", "fifo", "directory", "hardlink"):
            if lock.exists() or lock.is_symlink():
                if lock.is_dir():
                    lock.rmdir()
                else:
                    lock.unlink()
            if shape == "symlink":
                peer = self.sessions_dir / "lock-peer"
                peer.write_bytes(b"")
                lock.symlink_to(peer)
            elif shape == "fifo":
                os.mkfifo(lock, 0o600)
            elif shape == "directory":
                lock.mkdir(mode=0o700)
            else:
                peer = self.sessions_dir / "lock-hardlink-peer"
                peer.write_bytes(b"")
                os.link(peer, lock)
            with self.assertRaises(sessions._SessionReceiptAbort):
                with sessions._strict_session_lock(
                    pid,
                    attempts=1,
                    interval=0,
                ):
                    pass

        if lock.is_dir():
            lock.rmdir()
        elif lock.exists() or lock.is_symlink():
            lock.unlink()
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(sessions._SessionReceiptAbort):
                with sessions._strict_session_lock(
                    pid,
                    attempts=2,
                    interval=0,
                ):
                    pass
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

        with patch.dict(sys.modules, {"fcntl": None}):
            with self.assertRaises(sessions._SessionReceiptAbort):
                with sessions._strict_session_lock(
                    pid + 1,
                    attempts=1,
                    interval=0,
                ):
                    pass

    @unittest.skipUnless(sys.platform != "win32", "fcntl semantics")
    def test_strict_session_lock_retries_replaced_inode(self):
        pid = 42430
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        fired = False

        def replace(_pid: int, _fd: int) -> None:
            nonlocal fired
            if fired:
                return
            fired = True
            lock = self.sessions_dir / f"{pid}.run.lock"
            lock.unlink()
            lock.write_bytes(b"")
            lock.chmod(0o644)

        with patch.object(sessions, "_after_session_lock_open", replace):
            with sessions._strict_session_lock(
                pid,
                attempts=2,
                interval=0,
            ):
                pass
        self.assertTrue(fired)

    def test_importing_sessions_does_not_load_receipt_modules(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys, tempfile; from pathlib import Path; "
                "import core.project.sessions as sessions; "
                "sessions.SESSIONS_DIR=Path(tempfile.mkdtemp()); "
                "sessions.read_sessions(); "
                "print(any(name.startswith("
                "'core.startup.runtime_receipt.'"
                ") for name in sys.modules))",
            ],
            cwd=REPO_ROOT,
            env={
                "PATH": os.environ.get("PATH", ""),
                "PYTHONDONTWRITEBYTECODE": "1",
                "TMPDIR": self._tmp.name,
            },
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
