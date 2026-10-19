"""Agentic SCA must launch its own agent inside a different target's sandbox."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

import pytest

import core.sandbox
from core.config import RaptorConfig
from core.sandbox.tests.capability import requires_mount, requires_userns
from packages.sca.agent import _find_sca_agent, run_sca_subprocess


def test_missing_agent_is_not_silently_replaced(tmp_path):
    with patch("core.sandbox.run") as sandbox_run:
        with pytest.raises(FileNotFoundError, match="SCA agent file"):
            run_sca_subprocess(
                tmp_path / "missing.py", tmp_path / "target", tmp_path / "out",
            )
    sandbox_run.assert_not_called()
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("explicit_env", [False, True])
def test_external_target_mounts_canonical_source_not_checkout(
    tmp_path, monkeypatch, explicit_env,
):
    monkeypatch.delenv("RAPTOR_SCA_AGENT", raising=False)
    stale_root = str(tmp_path / "stale-checkout")
    monkeypatch.setenv("RAPTOR_DIR", stale_root)
    agent = _find_sca_agent()
    captured = {}

    def fake_run(cmd, **kwargs):
        captured.update(cmd=cmd, kwargs=kwargs)
        return subprocess.CompletedProcess(cmd, 0, "{}", "")

    with patch("core.sandbox.run", fake_run):
        supplied_env = {"RAPTOR_DIR": stale_root} if explicit_env else None
        run_sca_subprocess(
            agent, tmp_path / "target", tmp_path / "out", env=supplied_env,
        )

    roots = {str(RaptorConfig.REPO_ROOT / name) for name in ("core", "packages")}
    paths = set(captured["kwargs"]["tool_paths"])
    assert roots <= paths
    assert str(RaptorConfig.REPO_ROOT) not in paths
    assert str(agent) not in paths
    assert captured["cmd"][1] == str(agent)
    assert captured["kwargs"]["env"]["RAPTOR_DIR"] == str(RaptorConfig.REPO_ROOT)
    if supplied_env is not None:
        assert supplied_env["RAPTOR_DIR"] == stale_root


def test_external_agent_grants_file_not_parent(tmp_path):
    agent = tmp_path / "agents" / "agent.py"
    agent.parent.mkdir()
    agent.write_text("# agent stub\n", encoding="utf-8")
    captured = {}

    def fake_run(cmd, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, "{}", "")

    with patch("core.sandbox.run", fake_run):
        run_sca_subprocess(agent, tmp_path / "target", tmp_path / "out")

    assert str(agent) in captured["tool_paths"]
    assert str(agent.parent) not in captured["tool_paths"]


@pytest.mark.linux_native
@requires_mount
@requires_userns
def test_external_target_sca_completes_inside_mount_namespace(tmp_path, monkeypatch):
    monkeypatch.delenv("RAPTOR_SCA_AGENT", raising=False)
    target = tmp_path / "target"
    target.mkdir()
    (target / "package.json").write_text(
        '{"name":"sca-fixture","version":"1.0.0"}', encoding="utf-8",
    )
    output = tmp_path / "out"

    real_run = core.sandbox.run
    sandbox_info = []

    def track_run(cmd, **kwargs):
        result = real_run(cmd, **kwargs)
        sandbox_info.append(result.sandbox_info)
        return result

    with patch("core.sandbox.run", track_run):
        rc, stdout, stderr = run_sca_subprocess(
            _find_sca_agent(), target, output,
            sandbox_args=["--offline"], timeout=90,
        )

    assert rc == 0, (stderr[-1200:], stdout[-400:])
    assert len(sandbox_info) == 1
    assert sandbox_info[0]["mount_ns_active"] is True
    assert json.loads(stdout)["status"] == "ok"
    findings = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    assert any(row["vuln_type"] == "sca:hygiene:lockfile_missing" for row in findings)
