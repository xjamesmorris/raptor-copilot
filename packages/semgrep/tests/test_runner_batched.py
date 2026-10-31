"""Tests for extra scan targets and the sandbox scratch layout.

``extra_targets`` lets one semgrep invocation carry ride-along
targets (the negative-control fixture batching in core/audit/sweep).
The sandbox scratch is a process-shared PARENT with one fresh
fake-HOME subdirectory per invocation; scan results must never depend
on scratch contents, and no invocation may share its writable scratch
with another (fake-home symlink-TOCTOU isolation).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import packages.semgrep.runner as runner_mod
from packages.semgrep.runner import (
    _default_sandbox_runner,
    build_cmd,
    run_rule,
)


def _sarif_result(rule_id: str, uri: str, line: int) -> dict:
    return {
        "ruleId": rule_id,
        "message": {"text": rule_id},
        "level": "warning",
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line},
            },
        }],
    }


class TestBuildCmdExtraTargets:
    def test_extra_targets_appended_after_target(self, tmp_path: Path):
        cmd = build_cmd(
            Path("/src/a.c"), "p/x", semgrep_bin="semgrep",
            extra_targets=[Path("/ctrl/fixture.c")],
        )
        assert cmd[-2:] == ["/src/a.c", "/ctrl/fixture.c"]

    def test_default_is_single_target(self):
        cmd = build_cmd(Path("/src/a.c"), "p/x", semgrep_bin="semgrep")
        assert cmd[-1] == "/src/a.c"


class TestSandboxScratch:
    @pytest.fixture(autouse=True)
    def _fresh_scratch(self):
        runner_mod._reset_sandbox_scratch()
        yield
        runner_mod._reset_sandbox_scratch()

    def test_each_invocation_gets_a_fresh_scratch_dir(self, tmp_path: Path):
        """Per-invocation isolation is the TOCTOU defence: a live
        (compromised) child of call A holds write access to ITS
        output dir, so a dir shared with call B would let it race B's
        parent-side ``.home`` lstat sweep vs makedirs. Distinct dirs
        remove the shared write surface entirely."""
        captured: list[str] = []

        def fake_sandbox_run(cmd, **kwargs):
            captured.append(kwargs["output"])
            # Hostile child: damage this call's own scratch. Must not
            # be able to poison the NEXT call's scratch.
            home = Path(kwargs["output"]) / ".home"
            home.mkdir(parents=True, exist_ok=True)
            return MagicMock(stdout="", stderr="", returncode=0)

        with patch("core.sandbox.context.run", side_effect=fake_sandbox_run):
            for _ in range(2):
                runner = _default_sandbox_runner(tmp_path, "/local/rules.yaml")
                runner(["semgrep"], capture_output=True)

        assert len(captured) == 2
        assert captured[0] != captured[1]
        for out in captured:
            assert Path(out).is_dir()
        # The second invocation started from an empty dir — nothing
        # the first call's child wrote persists into it.
        assert not (Path(captured[1]) / ".home" / "poison").exists()

    def test_invocation_dirs_share_one_atexit_parent(self, tmp_path: Path):
        """The process-shared parent amortises cleanup: one atexit
        rmtree reclaims every per-invocation subdir."""
        captured: list[str] = []

        def fake_sandbox_run(cmd, **kwargs):
            captured.append(kwargs["output"])
            return MagicMock(stdout="", stderr="", returncode=0)

        with patch("core.sandbox.context.run", side_effect=fake_sandbox_run):
            for _ in range(2):
                runner = _default_sandbox_runner(tmp_path, "/local/rules.yaml")
                runner(["semgrep"], capture_output=True)

        parent = runner_mod._sandbox_scratch_parent()
        assert [str(Path(c).parent) for c in captured] == [parent, parent]

    def test_reset_removes_scratch(self):
        parent = runner_mod._sandbox_scratch_parent()
        sub = runner_mod._invocation_scratch_dir()
        assert Path(parent).is_dir()
        assert Path(sub).is_dir()
        runner_mod._reset_sandbox_scratch()
        assert not Path(parent).exists()
        assert not Path(sub).exists()

    def test_leftover_scratch_state_does_not_reach_results(
        self, tmp_path: Path,
    ):
        """Results parse from stdout/--json-output only: junk an
        invocation's child leaves in its scratch (fake-HOME logs,
        settings) must never surface in a later result."""
        t = tmp_path / "src"
        t.mkdir()
        (t / "a.c").write_text("void f(void) {}\n", encoding="utf-8")
        sarif = json.dumps(
            {"runs": [{"results": [_sarif_result("r1", "src/a.c", 1)]}]},
        )

        def fake_sandbox_run(cmd, **kwargs):
            home = Path(kwargs["output"]) / ".home" / ".semgrep"
            home.mkdir(parents=True, exist_ok=True)
            (home / "semgrep.log").open("a").write("per-call log noise\n")
            (home / "settings.yml").write_text("anonymous_user_id: x\n")
            return MagicMock(stdout=sarif, stderr="", returncode=1)

        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("core.sandbox.context.run", side_effect=fake_sandbox_run), \
             patch("packages.semgrep.runner._default_sandbox_runner",
                   wraps=runner_mod._default_sandbox_runner):
            first = run_rule(t, "/local/rules.yaml")
            second = run_rule(t, "/local/rules.yaml")

        assert [f.to_dict() for f in first.findings] == [
            f.to_dict() for f in second.findings
        ]
        assert first.errors == second.errors == []
