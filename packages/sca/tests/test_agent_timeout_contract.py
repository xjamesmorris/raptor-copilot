"""Regression coverage for the agentic SCA timeout contract."""

from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from core.json import JsonCache
from core.sandbox import SandboxCancelled
from core.sandbox.errors import SandboxSetupError
from core.sandbox.tests.capability import requires_landlock
from core.run.safe_io import write_private_json
from packages.sca import api as sca_api
from packages.sca import agent as sca_agent
from packages.sca.agent import (
    _normalise_direct_sandbox_argv,
    run_sca_subprocess,
)
from packages.sca.diagnostics import (
    DeadlineHttpClient,
    ScaDeadline,
    ScaDeadlineExceeded,
    diagnostic_path,
    finalize_sca_diagnostic,
    read_sca_diagnostic,
)
from packages.sca.pipeline import RunOptions, RunResult, run_sca


@pytest.fixture()
def isolated_sca_paths(tmp_path, monkeypatch):
    from core.config import RaptorConfig
    import packages.sca as sca_package

    monkeypatch.setattr(RaptorConfig, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(
        sca_package,
        "SCA_CACHE_ROOT",
        tmp_path / "cache",
    )
    return tmp_path


@pytest.fixture(autouse=True)
def restore_sandbox_cli_state():
    from core.sandbox import state

    names = (
        "_cli_sandbox_disabled",
        "_cli_sandbox_profile",
        "_cli_sandbox_disable_consent",
        "_cli_sandbox_audit",
        "_cli_sandbox_audit_verbose",
        "_cli_sandbox_audit_budget",
        "_cli_sandbox_readable_paths",
        "_cli_sandbox_tool_paths",
        "_cli_sandbox_floor",
        "_project_sandbox_floor",
    )
    saved = {name: getattr(state, name) for name in names}
    try:
        yield
    finally:
        for name, value in saved.items():
            setattr(state, name, value)


def _completed_result(target: Path, output_dir: Path) -> RunResult:
    return RunResult(
        target=target,
        output_dir=output_dir,
        findings_path=output_dir / "findings.json",
        report_path=output_dir / "report.md",
        sbom_path=output_dir / "sbom.cdx.json",
        sarif_path=output_dir / "findings.sarif",
        deps_analysed=3,
        vuln_findings=1,
        hygiene_findings=0,
        supply_chain_findings=0,
        suppressed_findings=0,
        in_kev=0,
        cache_hits=0,
        cache_misses=3,
    )


def test_offline_fixture_completes_with_success_diagnostic(tmp_path):
    target = tmp_path / "repo"
    output = tmp_path / "out"
    target.mkdir()
    (target / "requirements.txt").write_text(
        "flask==3.1.2\n",
        encoding="utf-8",
    )

    result = run_sca(
        target,
        output,
        RunOptions(
            offline=True,
            enable_llm_review=False,
            enable_triage=False,
            analysis_mode="mechanical",
        ),
        cache=JsonCache(root=tmp_path / "cache"),
    )

    assert result.deps_analysed == 1
    assert result.findings_path.is_file()
    assert result.report_path.is_file()
    diagnostic = read_sca_diagnostic(output)
    assert diagnostic["status"] == "completed"
    assert diagnostic["disposition"] == "success"
    assert diagnostic["mode"] == "mechanical"
    completed = [phase["name"] for phase in diagnostic["completed_phases"]]
    assert completed[0] == "discovery"
    assert completed[-1] == "emit"


def test_large_normal_inventory_is_not_truncated_by_deadline_contract(
    tmp_path,
):
    target = tmp_path / "repo"
    output = tmp_path / "out"
    target.mkdir()
    dependency_count = 1_200
    (target / "requirements.txt").write_text(
        "".join(
            f"normal-package-{index}==1.0.0\n" for index in range(dependency_count)
        ),
        encoding="utf-8",
    )

    result = run_sca(
        target,
        output,
        RunOptions(
            offline=True,
            enable_supply_chain=False,
            enable_license_policy=False,
            enable_reachability=False,
            enable_llm_review=False,
            enable_triage=False,
            deadline_seconds=30,
            analysis_mode="mechanical",
        ),
        cache=JsonCache(root=tmp_path / "cache"),
    )

    assert result.deps_analysed == dependency_count
    diagnostic = read_sca_diagnostic(output)
    assert diagnostic["disposition"] == "success"
    assert diagnostic["status"] == "completed"


def test_normal_completion_uses_mechanical_gates_and_child_deadline(
    isolated_sca_paths,
    monkeypatch,
):
    target = isolated_sca_paths / "repo"
    output = isolated_sca_paths / "out"
    target.mkdir()
    agent = target / "agent.py"
    agent.write_text("# deterministic stub\n", encoding="utf-8")
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["kwargs"] = dict(kwargs)
        return subprocess.CompletedProcess(
            cmd,
            returncode=0,
            stdout='{"status":"ok","deps_analysed":3}\n',
            stderr="",
        )

    def export_consent(child_env):
        child_env["RAPTOR_NO_SANDBOX_NONCE"] = "accepted-parent-token"

    monkeypatch.setattr("core.sandbox.run", fake_run)
    monkeypatch.setattr(
        "core.sandbox.disable_consent.export_disable_consent",
        export_consent,
    )
    supplied_env = {
        "PATH": os.environ.get("PATH", ""),
        "RAPTOR_NO_SANDBOX_NONCE": "caller-smuggled-token",
    }
    rc, stdout, stderr = run_sca_subprocess(
        agent,
        target,
        output,
        env=supplied_env,
        timeout=100,
        cancel_fd=17,
    )

    assert rc == 0
    assert '"status":"ok"' in stdout
    assert stderr == ""
    assert "--skip-review" in captured["cmd"]
    assert "--skip-triage" in captured["cmd"]
    assert "--agentic-worker" in captured["cmd"]
    deadline_index = captured["cmd"].index("--deadline-seconds") + 1
    assert 0 < float(captured["cmd"][deadline_index]) < 100
    assert captured["kwargs"]["timeout"] == 100
    assert captured["kwargs"]["cancel_fd"] == 17
    assert captured["kwargs"]["keep_disable_consent_for_dispatch"] is True
    assert captured["kwargs"]["env"]["RAPTOR_NO_SANDBOX_NONCE"] == (
        "accepted-parent-token"
    )
    assert supplied_env["RAPTOR_NO_SANDBOX_NONCE"] == ("caller-smuggled-token")
    diagnostic = read_sca_diagnostic(output)
    assert diagnostic["disposition"] == "success"
    assert diagnostic["status"] == "completed"
    assert diagnostic["mode"] == "mechanical"


def test_zero_timeout_is_unbounded_for_parent_and_child(
    isolated_sca_paths,
    monkeypatch,
):
    target = isolated_sca_paths / "repo"
    output = isolated_sca_paths / "out"
    target.mkdir()
    agent = target / "agent.py"
    agent.write_text("# deterministic stub\n", encoding="utf-8")
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["kwargs"] = dict(kwargs)
        return subprocess.CompletedProcess(
            cmd,
            returncode=0,
            stdout='{"status":"ok"}\n',
            stderr="",
        )

    monkeypatch.setattr("core.sandbox.run", fake_run)
    rc, _stdout, _stderr = run_sca_subprocess(
        agent,
        target,
        output,
        timeout=0,
    )

    assert rc == 0
    assert "--deadline-seconds" not in captured["cmd"]
    assert captured["kwargs"]["timeout"] is None


def test_api_mechanical_mode_normalizes_deep_defaults_off(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "repo"
    output = tmp_path / "out"
    target.mkdir()
    captured = {}

    def fake_run_sca(*, target, output_dir, options):
        captured["options"] = options
        output_dir.mkdir(parents=True, exist_ok=True)
        return _completed_result(target, output_dir)

    monkeypatch.setattr(sca_api, "run_sca", fake_run_sca)
    result = sca_api.analyse(
        target,
        output,
        deadline_seconds=42,
        analysis_mode="mechanical",
    )

    assert result["status"] == "ok"
    options = captured["options"]
    assert options.enable_llm_review is False
    assert options.enable_triage is False
    assert options.deadline_seconds == 42
    assert options.analysis_mode == "mechanical"


def test_run_options_reject_contradictory_mechanical_deep_gates():
    with pytest.raises(
        ValueError,
        match="mechanical SCA forbids deep/LLM gates",
    ):
        RunOptions(analysis_mode="mechanical")

    options = RunOptions(analysis_mode="deep")
    assert options.enable_llm_review is True
    assert options.enable_triage is True


def test_api_internal_deadline_is_visible_timeout(tmp_path, monkeypatch):
    target = tmp_path / "repo"
    output = tmp_path / "out"
    target.mkdir()

    def deadline_expired(**_kwargs):
        raise ScaDeadlineExceeded(
            "SCA internal deadline exhausted during osv",
        )

    monkeypatch.setattr(sca_api, "run_sca", deadline_expired)
    result = sca_api.analyse(
        target,
        output,
        deadline_seconds=1,
        analysis_mode="mechanical",
    )

    assert result["status"] == "error"
    assert result["timed_out"] is True
    diagnostic = read_sca_diagnostic(output)
    assert diagnostic["status"] == "timed_out"
    assert diagnostic["returncode"] == 124


def test_agent_cli_threads_mechanical_gates_through_nested_sandbox(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "repo"
    output = tmp_path / "out"
    target.mkdir()
    captured = {}

    def fake_sandboxed(**kwargs):
        from core.sandbox import state

        captured.update(kwargs)
        captured["sandbox_floor"] = state._cli_sandbox_floor
        return {"status": "ok"}

    monkeypatch.setattr(sca_agent, "_run_sandboxed", fake_sandboxed)
    rc = sca_agent.main(
        [
            "--repo",
            str(target),
            "--out",
            str(output),
            "--sandbox",
            "full",
            "--sandbox-floor",
            "landlock",
            "--skip-review",
            "--skip-triage",
            "--deadline-seconds",
            "12.5",
        ]
    )

    assert rc == 0
    assert captured["enable_llm_review"] is False
    assert captured["enable_triage"] is False
    assert captured["deadline_seconds"] == 12.5
    assert captured["analysis_mode"] == "mechanical"
    assert captured["sandbox_floor"] == "landlock"


def test_agent_cli_rejects_unknown_direct_options(
    tmp_path,
    monkeypatch,
    capsys,
):
    target = tmp_path / "repo"
    output = tmp_path / "out"
    target.mkdir()
    called = False

    def should_not_run(**_kwargs):
        nonlocal called
        called = True
        return {"status": "ok"}

    monkeypatch.setattr(sca_api, "analyse", should_not_run)
    with pytest.raises(SystemExit) as excinfo:
        sca_agent.main(
            [
                "--repo",
                str(target),
                "--out",
                str(output),
                "--not-a-real-sca-option",
            ]
        )

    assert excinfo.value.code == 2
    assert called is False
    assert "unrecognized arguments" in capsys.readouterr().err


def test_direct_no_sandbox_normalization_preserves_strict_unknowns():
    assert _normalise_direct_sandbox_argv(
        [
            "--sandbox",
            "full",
            "--no-sandbox",
            "--offline",
        ]
    ) == ["--no-sandbox", "--offline"]
    assert _normalise_direct_sandbox_argv(
        [
            "--sandbox=network-only",
            "--no-sandbox",
            "--not-a-real-option",
        ]
    ) == ["--no-sandbox", "--not-a-real-option"]


def test_agentic_worker_disable_still_requires_forwarded_consent(
    tmp_path,
    monkeypatch,
    capsys,
):
    from core.sandbox.disable_consent import NONCE_ENV_VAR

    target = tmp_path / "repo"
    output = tmp_path / "out"
    target.mkdir()
    monkeypatch.delenv(NONCE_ENV_VAR, raising=False)

    with pytest.raises(SystemExit) as excinfo:
        sca_agent.main(
            [
                "--repo",
                str(target),
                "--out",
                str(output),
                "--agentic-worker",
                "--sandbox",
                "none",
                "--offline",
            ]
        )

    assert excinfo.value.code == 2
    assert "refused" in capsys.readouterr().err


def test_deadline_http_client_caps_one_request_and_stops_when_expired():
    calls = []

    class StubHttp:
        def get_json(self, url, **kwargs):
            calls.append((url, kwargs))
            return {}

        def stream_bytes(self, url, **kwargs):
            calls.append((url, kwargs))
            yield b"chunk"

    now = time.monotonic()
    client = DeadlineHttpClient(
        StubHttp(),
        ScaDeadline(now, now + 60, 60),
        per_request_total_timeout=7,
    )
    client.get_json(
        "https://example.invalid/metadata",
        timeout=30,
        total_timeout=600,
    )

    assert calls[0][1]["timeout"] == 7
    assert calls[0][1]["total_timeout"] == 7
    short_now = time.monotonic()
    short = DeadlineHttpClient(
        StubHttp(),
        ScaDeadline(short_now, short_now + 0.5, 0.5),
    )
    short.get_json("https://example.invalid/short")
    assert 0 < calls[1][1]["total_timeout"] < 0.5
    assert calls[1][1]["timeout"] <= calls[1][1]["total_timeout"]

    too_short_now = time.monotonic()
    too_short = DeadlineHttpClient(
        StubHttp(),
        ScaDeadline(too_short_now, too_short_now + 0.01, 0.01),
    )
    with pytest.raises(ScaDeadlineExceeded):
        too_short.get_json("https://example.invalid/no-dispatch")
    assert len(calls) == 2

    stream_now = time.monotonic()
    late_stream = DeadlineHttpClient(
        StubHttp(),
        ScaDeadline(stream_now, stream_now + 0.06, 0.06),
    ).stream_bytes("https://example.invalid/lazy-stream")
    time.sleep(0.07)
    with pytest.raises(ScaDeadlineExceeded):
        next(late_stream)
    assert len(calls) == 2

    expired = DeadlineHttpClient(
        StubHttp(),
        ScaDeadline(now - 2, now - 1, 1),
    )
    with pytest.raises(ScaDeadlineExceeded):
        expired.get_json("https://example.invalid/hang")
    assert len(calls) == 2


def test_timeout_preserves_phase_and_private_sanitized_diagnostics(
    isolated_sca_paths,
    monkeypatch,
):
    target = isolated_sca_paths / "repo"
    output = isolated_sca_paths / "out"
    target.mkdir()
    output.mkdir()
    agent = target / "agent.py"
    agent.write_text("# deterministic stub\n", encoding="utf-8")
    write_private_json(
        diagnostic_path(output),
        {
            "schema_version": 1,
            "status": "running",
            "disposition": None,
            "mode": "mechanical",
            "phase": {
                "name": "llm-review",
                "description": "running LLM behavioural review",
                "status": "running",
            },
            "completed_phases": [],
        },
    )

    def timeout_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd,
            kwargs["timeout"],
            output=b"partial stdout",
            stderr=(b"phase progress token=secret-value-123 \x1b]0;forged-title\x07"),
        )

    monkeypatch.setattr("core.sandbox.run", timeout_run)
    rc, stdout, stderr = run_sca_subprocess(
        agent,
        target,
        output,
        timeout=5,
    )

    assert rc == 124
    assert stdout == "partial stdout"
    assert stderr.endswith("sca-agent timed out after 5s")
    diagnostic = read_sca_diagnostic(output)
    assert diagnostic["status"] == "timed_out"
    assert diagnostic["disposition"] == "failed"
    assert diagnostic["phase"]["name"] == "llm-review"
    rendered = json.dumps(diagnostic)
    assert "secret-value-123" not in rendered
    assert "\x1b" not in rendered
    assert stat.S_IMODE(diagnostic_path(output).stat().st_mode) == 0o600


def test_child_deadline_status_survives_parent_result_collection(
    isolated_sca_paths,
    monkeypatch,
):
    target = isolated_sca_paths / "repo"
    output = isolated_sca_paths / "out"
    target.mkdir()
    agent = target / "agent.py"
    agent.write_text("# deterministic stub\n", encoding="utf-8")

    def deadline_result(cmd, **_kwargs):
        finalize_sca_diagnostic(
            output,
            disposition="failed",
            reason="SCA internal deadline exhausted during osv",
            returncode=124,
            timed_out=True,
            mode="mechanical",
        )
        return subprocess.CompletedProcess(
            cmd,
            returncode=124,
            stdout='{"status":"error","timed_out":true}\n',
            stderr="deadline exhausted",
        )

    monkeypatch.setattr("core.sandbox.run", deadline_result)
    rc, _stdout, _stderr = run_sca_subprocess(
        agent,
        target,
        output,
    )

    assert rc == 124
    diagnostic = read_sca_diagnostic(output)
    assert diagnostic["status"] == "timed_out"
    assert diagnostic["reason"] == "SCA internal deadline exhausted during osv"


def test_cancellation_and_keyboard_interrupt_are_distinct(
    isolated_sca_paths,
    monkeypatch,
):
    target = isolated_sca_paths / "repo"
    output = isolated_sca_paths / "cancelled"
    target.mkdir()
    agent = target / "agent.py"
    agent.write_text("# deterministic stub\n", encoding="utf-8")

    def cancelled_run(cmd, **_kwargs):
        raise SandboxCancelled(
            cmd,
            output=b"partial",
            stderr=b"cancel requested",
        )

    monkeypatch.setattr("core.sandbox.run", cancelled_run)
    rc, stdout, stderr = run_sca_subprocess(
        agent,
        target,
        output,
        cancel_fd=9,
    )
    assert (rc, stdout) == (130, "partial")
    assert stderr.endswith("sca-agent cancelled")
    diagnostic = read_sca_diagnostic(output)
    assert diagnostic["status"] == "cancelled"
    assert diagnostic["disposition"] == "failed"

    interrupted = isolated_sca_paths / "interrupted"

    def interrupted_run(_cmd, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("core.sandbox.run", interrupted_run)
    with pytest.raises(KeyboardInterrupt):
        run_sca_subprocess(agent, target, interrupted)
    interrupt_diagnostic = read_sca_diagnostic(interrupted)
    assert interrupt_diagnostic["status"] == "interrupted"
    assert interrupt_diagnostic["disposition"] == "failed"


def test_diagnostic_permissions_and_sanitization(tmp_path):
    output = tmp_path / "out"
    finalize_sca_diagnostic(
        output,
        disposition="failed",
        reason="token=secret-value-123\x1b]0;spoof\x07",
        stderr="token=stderr-secret-value-456\x00",
        returncode=3,
    )
    path = diagnostic_path(output)
    diagnostic = read_sca_diagnostic(output)
    rendered = json.dumps(diagnostic)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "secret-value-123" not in rendered
    assert "stderr-secret-value-456" not in rendered
    assert "\x1b" not in rendered
    assert "\x00" not in rendered


@pytest.mark.skipif(
    sys.platform != "linux" or not Path("/proc").is_dir(),
    reason="descendant verification uses Linux /proc",
)
def test_real_timeout_reaps_agent_descendant(isolated_sca_paths):
    from core.config import RaptorConfig

    target = isolated_sca_paths / "repo"
    output = isolated_sca_paths / "out"
    target.mkdir()
    marker = f"mvp04-descendant-{os.getpid()}-{time.monotonic_ns()}"
    agent = _write_hanging_agent(target)
    env = RaptorConfig.get_safe_env()
    env["MVP04_DESCENDANT_MARKER"] = marker
    try:
        rc, _stdout, _stderr = run_sca_subprocess(
            agent,
            target,
            output,
            timeout=4,
            env=env,
        )
        assert rc == 124
        assert (output / "ready.txt").read_text(encoding="utf-8") == "ready"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and _marked_pids(marker):
            time.sleep(0.05)
        assert _marked_pids(marker) == []
    finally:
        for pid in _marked_pids(marker):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


@pytest.mark.skipif(
    sys.platform != "linux" or not Path("/proc").is_dir(),
    reason="degraded fallback verification uses Linux sandbox + /proc",
)
@requires_landlock
def test_degraded_nonfork_timeout_reaps_descendant(
    isolated_sca_paths,
    monkeypatch,
):
    from core.config import RaptorConfig
    from core.sandbox import context as sandbox_context

    target = isolated_sca_paths / "repo"
    output = isolated_sca_paths / "out"
    target.mkdir()
    marker = f"mvp04-fallback-{os.getpid()}-{time.monotonic_ns()}"
    agent = _write_hanging_agent(target)
    env = RaptorConfig.get_safe_env()
    env["MVP04_DESCENDANT_MARKER"] = marker
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    monkeypatch.setattr(
        sandbox_context,
        "check_net_available",
        lambda: False,
    )
    monkeypatch.setattr(
        sandbox_context,
        "check_mount_available",
        lambda: False,
    )

    try:
        rc, _stdout, _stderr = run_sca_subprocess(
            agent,
            target,
            output,
            timeout=4,
            env=env,
        )
        assert rc == 124
        assert (output / "ready.txt").is_file()
        assert read_sca_diagnostic(output)["status"] == "timed_out"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and _marked_pids(marker):
            time.sleep(0.05)
        assert _marked_pids(marker) == []
    finally:
        for pid in _marked_pids(marker):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="cancel_fd fallback policy is Linux-specific",
)
@requires_landlock
def test_degraded_nonfork_cancel_fd_refuses_before_child_exec(
    isolated_sca_paths,
    monkeypatch,
):
    from core.config import RaptorConfig
    from core.sandbox import context as sandbox_context

    target = isolated_sca_paths / "repo"
    output = isolated_sca_paths / "out"
    target.mkdir()
    agent = _write_hanging_agent(target)
    env = RaptorConfig.get_safe_env()
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    monkeypatch.setattr(
        sandbox_context,
        "check_net_available",
        lambda: False,
    )
    monkeypatch.setattr(
        sandbox_context,
        "check_mount_available",
        lambda: False,
    )
    cancel_r, cancel_w = os.pipe2(os.O_CLOEXEC)
    try:
        with pytest.raises(SandboxSetupError, match="cancel_fd"):
            run_sca_subprocess(
                agent,
                target,
                output,
                timeout=15,
                cancel_fd=cancel_r,
                env=env,
            )
        assert not (output / "ready.txt").exists()
        diagnostic = read_sca_diagnostic(output)
        assert diagnostic["status"] == "failed"
        assert "cancel_fd" in diagnostic["reason"]
    finally:
        os.close(cancel_r)
        os.close(cancel_w)


@pytest.mark.skipif(
    sys.platform != "linux" or not Path("/proc").is_dir(),
    reason="cancellation verification uses Linux sandbox + /proc",
)
def test_real_cancel_fd_reaps_agent_descendant(isolated_sca_paths):
    from core.config import RaptorConfig

    target = isolated_sca_paths / "repo"
    output = isolated_sca_paths / "out"
    target.mkdir()
    marker = f"mvp04-cancel-{os.getpid()}-{time.monotonic_ns()}"
    agent = _write_hanging_agent(target)
    env = RaptorConfig.get_safe_env()
    env["MVP04_DESCENDANT_MARKER"] = marker
    cancel_r, cancel_w = os.pipe2(os.O_CLOEXEC)

    def request_cancel() -> None:
        ready = output / "ready.txt"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not ready.exists():
            time.sleep(0.02)
        try:
            os.write(cancel_w, b"x")
        except OSError:
            pass

    writer = threading.Thread(target=request_cancel, daemon=True)
    writer.start()
    try:
        rc, _stdout, _stderr = run_sca_subprocess(
            agent,
            target,
            output,
            timeout=15,
            cancel_fd=cancel_r,
            env=env,
        )
        writer.join(timeout=2)
        assert rc == 130
        assert read_sca_diagnostic(output)["status"] == "cancelled"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and _marked_pids(marker):
            time.sleep(0.05)
        assert _marked_pids(marker) == []
    finally:
        os.close(cancel_r)
        os.close(cancel_w)
        for pid in _marked_pids(marker):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


def _write_hanging_agent(target: Path) -> Path:
    agent = target / "hang_agent.py"
    agent.write_text(
        "\n".join(
            [
                "import subprocess",
                "import sys",
                "import time",
                "from pathlib import Path",
                "out = Path(sys.argv[sys.argv.index('--out') + 1])",
                "out.mkdir(parents=True, exist_ok=True)",
                "subprocess.Popen([",
                "    sys.executable, '-c', 'import time; time.sleep(60)'",
                "])",
                "(out / 'ready.txt').write_text('ready', encoding='utf-8')",
                "time.sleep(60)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return agent


def _marked_pids(marker: str) -> list[int]:
    needle = f"MVP04_DESCENDANT_MARKER={marker}".encode()
    found: list[int] = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            environ = (proc / "environ").read_bytes()
        except OSError:
            continue
        if needle in environ:
            found.append(int(proc.name))
    return found
