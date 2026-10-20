"""Backend-neutral frontend preparation and host-claim tests."""

from __future__ import annotations

import os
import signal
import shutil
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from core.startup.host import (
    Frontend,
    FrontendLaunchState,
    FrontendPreparation,
    HostClaimError,
    SessionHostClaim,
    _parse_executable,
    _parse_uint,
    _safe_executable_path,
    _supports_direct_process_claim,
    build_session_host_claim,
    host_process_matches,
    launcher_lines,
    parse_metadata_host_claim,
    parse_session_host_claim,
    prepare_frontend,
)
from core.testing import FakeCLIBehavior, make_hermetic_cli

REPO_ROOT = Path(__file__).resolve().parents[3]
LAUNCHER = REPO_ROOT / "bin" / "raptor"
NATIVE_FIXTURE = Path(__file__).parent / "fixtures" / "native_frontend.c"
NATIVE_FRONTEND_ARGV_FIXTURE = (
    Path(__file__).parent / "fixtures" / "native_frontend_argv.c"
)


def _system_path() -> str:
    dirs = [str(Path(sys.executable).resolve().parent)]
    dirs.extend(
        directory
        for directory in ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
        if Path(directory).is_dir()
    )
    return ":".join(dirs)


def _launcher_env(workspace) -> dict[str, str]:
    env = workspace.child_env()
    env["PATH"] = f"{workspace.bin_dir}:{_system_path()}"
    env["TERM"] = "dumb"
    return env


def _wait_until(predicate, *, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
        except (OSError, ValueError) as exc:
            last_error = exc
        else:
            if value:
                return value
        time.sleep(0.02)
    raise AssertionError(
        f"condition did not become true within {timeout}s"
        + (f": {last_error}" if last_error else "")
    )


def _terminate_owned_process_group(
    process: subprocess.Popen,
) -> tuple[str, str]:
    if process.poll() is None:
        assert os.getpgid(process.pid) == process.pid
        os.killpg(process.pid, signal.SIGTERM)
    try:
        return process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        return process.communicate(timeout=5)


def _compiler() -> str | None:
    for name in ("gcc", "clang", "cc"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _compile_native_fixture(
    destination: Path,
    *,
    source: Path = NATIVE_FIXTURE,
) -> None:
    compiler = _compiler()
    if compiler is None:
        pytest.skip("A9 blocked: no C compiler is available")
    result = subprocess.run(
        [
            compiler,
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(source),
            "-o",
            str(destination),
        ],
        env={
            "HOME": str(destination.parent),
            "PATH": _system_path(),
            "LANG": "C",
            "LC_ALL": "C",
        },
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    destination.chmod(0o700)


def _materialize_launcher_root(workspace) -> Path:
    for name in ("core", "libexec", "plugins"):
        link = workspace.root / name
        link.symlink_to(REPO_ROOT / name, target_is_directory=True)
    (workspace.root / "raptor.py").symlink_to(REPO_ROOT / "raptor.py")
    return workspace.bin_dir / "raptor"


def _run_copied_launcher(
    launcher: Path,
    workspace,
    args: tuple[str, ...],
) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(launcher), *args],
        cwd=workspace.cwd,
        env=_launcher_env(workspace),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _marker_bounded_section(source: str, marker: str) -> str:
    begin = f"# RAPTOR_{marker}_BEGIN"
    end = f"# RAPTOR_{marker}_END"
    assert source.count(begin) == 1
    assert source.count(end) == 1
    start = source.index(begin)
    stop = source.index(end, start)
    return source[start:stop]


def _native_frontend_argv_harness(tmp_path, frontend: str):
    workspace = make_hermetic_cli(tmp_path)
    launcher = _materialize_launcher_root(workspace)
    launcher.write_bytes(LAUNCHER.read_bytes())
    launcher.chmod(0o700)
    _compile_native_fixture(
        workspace.bin_dir / frontend,
        source=NATIVE_FRONTEND_ARGV_FIXTURE,
    )
    capture = workspace.root / f"{frontend}-capture.txt"
    env = _launcher_env(workspace)
    env.update(
        {
            "RAPTOR_REGISTRY_HOME": str(workspace.root / "registry"),
            "RAPTOR_TEST_FRONTEND_CAPTURE": str(capture),
        }
    )
    return workspace, launcher, capture, env


def _read_native_frontend_capture(
    capture: Path,
) -> tuple[list[str], dict[str, str]]:
    argv: list[str] = []
    fields: dict[str, str] = {}
    for line in capture.read_text(encoding="utf-8").splitlines():
        key, value = line.split("=", 1)
        if key.startswith("argv["):
            expected_length, argument = value.split(":", 1)
            assert len(argument) == int(expected_length)
            argv.append(argument)
        else:
            fields[key] = value
    return argv, fields


def _expected_frontend_path_warning(
    frontend: str,
    executable: Path,
) -> str | None:
    directory = executable.parent
    while directory != Path("/"):
        if directory.stat().st_mode & 0o002:
            return (
                f"raptor: WARNING: {frontend} resolves under a "
                f"world-writable tree: {str(executable)[:200]} "
                f"(writable ancestor: {str(directory)[:200]})\n"
            )
        directory = directory.parent
    return None


def _run_native_frontend(
    launcher: Path,
    workspace,
    env: dict[str, str],
    args: tuple[str, ...],
) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(launcher), *args],
        cwd=workspace.cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _create_probe_project(workspace):
    from core.project import ProjectManager

    target = workspace.cwd / "target"
    output_dir = workspace.root / "project-output"
    target.mkdir()
    manager = ProjectManager(workspace.root / "registry" / "projects")
    manager.create("probe", str(target), output_dir=str(output_dir))
    return manager, target


def _expand_target(
    args: tuple[str, ...],
    target: Path,
) -> tuple[str, ...]:
    return tuple(str(target) if arg == "{target}" else arg for arg in args)


def _assert_probe_project_bound(workspace, manager) -> None:
    assert manager.load("probe").trust == {}
    entries = list((workspace.root / "registry" / "sessions.d").glob("[0-9]*"))
    assert len(entries) == 1
    assert "project=probe\n" in entries[0].read_text(encoding="utf-8")


def test_frontend_preparation_keeps_presence_launch_and_provider_separate(
    tmp_path,
):
    workspace = make_hermetic_cli(tmp_path)

    copilot = prepare_frontend("copilot", search_path=str(workspace.bin_dir))
    assert copilot.frontend is Frontend.COPILOT
    assert copilot.installed is True
    assert copilot.launch_state is FrontendLaunchState.GATED
    assert copilot.launchable is False
    assert copilot.provider_usable is None
    assert copilot.session_claim is None

    claude = prepare_frontend("claude", search_path=str(workspace.bin_dir))
    assert claude.frontend is Frontend.CLAUDE
    assert claude.installed is True
    assert claude.launch_state is FrontendLaunchState.READY
    assert claude.launchable is True
    assert claude.provider_usable is None
    # The repository fake is a shebang script. It remains on the legacy
    # Claude identity path instead of receiving an unverifiable native claim.
    assert claude.session_claim is None
    assert launcher_lines(claude).startswith("launch_executable=")


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_native_copilot_preparation_is_ready_with_strong_claim(tmp_path):
    source = Path("/bin/true")
    if not source.is_file():
        pytest.skip("/bin/true unavailable")
    executable = tmp_path / "copilot"
    executable.write_bytes(source.read_bytes())
    executable.chmod(0o755)

    preparation = prepare_frontend("copilot", search_path=str(tmp_path))

    assert preparation.frontend is Frontend.COPILOT
    assert preparation.launch_state is FrontendLaunchState.READY
    assert preparation.launchable is True
    assert preparation.provider_usable is None
    assert preparation.session_claim is not None
    assert preparation.session_claim.frontend is Frontend.COPILOT
    assert preparation.session_claim.executable == executable
    assert "host=copilot" in launcher_lines(preparation)


def test_missing_and_unknown_frontends_are_distinct(tmp_path):
    missing = prepare_frontend("copilot", search_path=str(tmp_path))
    assert missing.launch_state is FrontendLaunchState.MISSING
    assert missing.installed is False
    with pytest.raises(ValueError, match="unknown frontend"):
        prepare_frontend("browser", search_path=str(tmp_path))


@pytest.mark.skipif(sys.platform == "win32", reason="bash launcher")
def test_missing_claude_keeps_legacy_exit_code(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    python_dir = str(Path(sys.executable).resolve().parent)
    env = {
        "PATH": f"{python_dir}:/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "TERM": "dumb",
    }
    # Hide any system/user claude while retaining the launcher's shell tools.
    no_claude = tmp_path / "no-claude"
    no_claude.mkdir()
    env["PATH"] = f"{no_claude}:/usr/bin:/bin"
    if Path("/usr/bin/claude").exists() or Path("/bin/claude").exists():
        pytest.skip("system claude exists on the minimal PATH")
    result = subprocess.run(
        ["bash", str(LAUNCHER)],
        cwd=home,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 1
    assert "claude not found" in result.stderr


def test_host_claim_parser_rejects_partial_unknown_and_noncanonical_fields(
    tmp_path,
):
    executable = Path(sys.executable).resolve()
    claim = build_session_host_claim(Frontend.CLAUDE, executable)
    fields = claim.session_fields()
    assert parse_session_host_claim(fields) == claim
    assert parse_metadata_host_claim(claim.metadata_fields()) == claim

    partial = dict(fields)
    partial.pop("host_exe_ino")
    with pytest.raises(HostClaimError, match="partial host claim"):
        parse_session_host_claim(partial)

    unknown = dict(fields)
    unknown["host_future"] = "1"
    with pytest.raises(HostClaimError, match="unknown host claim"):
        parse_session_host_claim(unknown)

    malformed = dict(fields)
    malformed["host_uid"] = f"0{os.geteuid()}"
    with pytest.raises(HostClaimError, match="canonical decimal"):
        parse_session_host_claim(malformed)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("", "empty or too long"),
        ("x" * 4097, "empty or too long"),
        ("bad\npath", "control bytes"),
    ],
)
def test_a7_safe_executable_rejects_invalid_text(value, expected):
    with pytest.raises(ValueError, match=expected):
        _safe_executable_path(value)


def test_a7_safe_executable_rejects_nonregular_and_nonexecutable(tmp_path):
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(ValueError, match="not a regular file"):
        _safe_executable_path(str(directory))

    plain = tmp_path / "plain"
    plain.write_text("not executable\n", encoding="utf-8")
    plain.chmod(0o600)
    with pytest.raises(ValueError, match="not executable"):
        _safe_executable_path(str(plain))


def test_a7_safe_executable_joins_relative_path_to_cwd(
    tmp_path,
    monkeypatch,
):
    executable = tmp_path / "relative-host"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.chdir(tmp_path)
    assert _safe_executable_path("relative-host") == executable


def test_a7_direct_claim_rejects_shebang_and_unreadable(tmp_path):
    script = tmp_path / "claude"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o700)
    assert _supports_direct_process_claim(script) is False
    with patch.object(
        Path,
        "open",
        side_effect=PermissionError("fixture denied"),
    ):
        assert _supports_direct_process_claim(script) is False


@pytest.mark.parametrize(
    "value,positive,expected",
    [
        ("+1", False, "must be an integer"),
        ("²", False, "must be an integer"),
        ("0x10", False, "must be an integer"),
        (-1, False, "outside the supported range"),
        (2**64, False, "outside the supported range"),
        ("01", False, "canonical decimal"),
        (0, True, "outside the supported range"),
        (True, False, "must be an integer"),
    ],
)
def test_a7_parse_uint_rejects_noncanonical_values(
    value,
    positive,
    expected,
):
    with pytest.raises(HostClaimError, match=expected):
        _parse_uint(value, "field", positive=positive)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("relative/host", "must be absolute"),
        ("/bad\nhost", "empty, too long, or non-printable"),
        ("/" + "x" * 4097, "empty, too long, or non-printable"),
        (123, "must be a string"),
    ],
)
def test_a7_parse_executable_rejects_invalid_values(value, expected):
    with pytest.raises(HostClaimError, match=expected):
        _parse_executable(value, "host executable")


def test_a7_host_process_match_rejects_euid_and_missing_executable():
    claim = SessionHostClaim(
        frontend=Frontend.CLAUDE,
        uid=os.geteuid(),
        executable=Path("/owned/claude"),
        executable_device=10,
        executable_inode=20,
    )
    with patch("core.startup.host.os.geteuid", return_value=claim.uid + 1):
        assert (
            host_process_matches(
                123,
                claim,
                pid_running=lambda _pid: True,
                comm_reader=lambda _pid: "claude",
                uid_reader=lambda _pid: claim.uid,
                executable_identity_reader=lambda _pid: (10, 20),
            )
            is False
        )
    assert (
        host_process_matches(
            123,
            claim,
            pid_running=lambda _pid: True,
            comm_reader=lambda _pid: "claude",
            uid_reader=lambda _pid: claim.uid,
            executable_identity_reader=lambda _pid: None,
        )
        is False
    )


def test_supplemental_a7_rejects_proc_uid_comm_and_exe_gaps():
    claim = SessionHostClaim(
        frontend=Frontend.CLAUDE,
        uid=os.geteuid(),
        executable=Path("/owned/claude"),
        executable_device=10,
        executable_inode=20,
    )
    common = {
        "pid_running": lambda _pid: True,
        "comm_reader": lambda _pid: "claude",
        "uid_reader": lambda _pid: claim.uid,
        "executable_identity_reader": lambda _pid: (10, 20),
    }
    with patch("core.startup.host.os.geteuid", return_value=claim.uid):
        assert (
            host_process_matches(
                123,
                claim,
                **{**common, "uid_reader": lambda _pid: claim.uid + 1},
            )
            is False
        )
        assert (
            host_process_matches(
                123,
                claim,
                **{**common, "comm_reader": lambda _pid: None},
            )
            is False
        )
        assert (
            host_process_matches(
                123,
                claim,
                **{
                    **common,
                    "executable_identity_reader": lambda _pid: None,
                },
            )
            is False
        )


def test_copilot_mainthread_comm_still_requires_exact_executable_identity():
    claim = SessionHostClaim(
        frontend=Frontend.COPILOT,
        uid=os.geteuid(),
        executable=Path("/owned/copilot"),
        executable_device=10,
        executable_inode=20,
    )
    common = {
        "pid_running": lambda _pid: True,
        "comm_reader": lambda _pid: "MainThread",
        "uid_reader": lambda _pid: claim.uid,
    }
    with patch("core.startup.host.os.geteuid", return_value=claim.uid):
        assert (
            host_process_matches(
                123,
                claim,
                **common,
                executable_identity_reader=lambda _pid: (10, 20),
            )
            is True
        )
        assert (
            host_process_matches(
                123,
                claim,
                **common,
                executable_identity_reader=lambda _pid: (10, 21),
            )
            is False
        )

    claude_claim = SessionHostClaim(
        frontend=Frontend.CLAUDE,
        uid=claim.uid,
        executable=Path("/owned/claude"),
        executable_device=10,
        executable_inode=20,
    )
    with patch("core.startup.host.os.geteuid", return_value=claim.uid):
        assert (
            host_process_matches(
                123,
                claude_claim,
                **common,
                executable_identity_reader=lambda _pid: (10, 20),
            )
            is False
        )


def test_a7_launcher_lines_refuses_nonready_preparation(tmp_path):
    preparation = FrontendPreparation(
        frontend=Frontend.COPILOT,
        executable=tmp_path / "copilot",
        launch_state=FrontendLaunchState.GATED,
        provider_usable=None,
        session_claim=None,
        reason="gated",
    )
    with pytest.raises(ValueError, match="not launchable"):
        launcher_lines(preparation)


def test_a6_mapped_executable_identity_ignores_replaced_disk_path(tmp_path):
    executable = tmp_path / "claude"
    executable.write_bytes(b"\x7fELF-old-image")
    executable.chmod(0o700)
    claim = build_session_host_claim(Frontend.CLAUDE, executable)
    mapped_identity = (
        claim.executable_device,
        claim.executable_inode,
    )

    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"\x7fELF-new-image")
    replacement.chmod(0o700)
    os.replace(replacement, executable)
    assert (executable.stat().st_dev, executable.stat().st_ino) != (mapped_identity)

    assert (
        host_process_matches(
            123,
            claim,
            pid_running=lambda _pid: True,
            comm_reader=lambda _pid: "claude",
            uid_reader=lambda _pid: claim.uid,
            executable_identity_reader=lambda _pid: mapped_identity,
        )
        is True
    )


@pytest.mark.skipif(sys.platform == "win32", reason="bash launcher")
def test_explicit_shebang_copilot_is_gated_before_exec_or_session_mutation(
    tmp_path,
):
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "copilot",
        FakeCLIBehavior(stdout="COPILOT_CHILD_RAN\n"),
    )
    target = workspace.cwd / "target"
    target.mkdir()
    (target / ".claude").mkdir()
    (target / ".claude" / "settings.json").write_text(
        '{"hooks":{"SessionStart":[{"hooks":[{"type":"command",'
        '"command":"touch should-not-run"}]}]}}\n',
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "bash",
            str(LAUNCHER),
            "--frontend",
            "copilot",
            "--trust-repo",
            str(target),
        ],
        cwd=workspace.cwd,
        env=_launcher_env(workspace),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 78, (result.stdout, result.stderr)
    assert "live host contract is not verified" in result.stderr
    assert workspace.invocations("copilot") == []
    sessions_dir = workspace.home / ".local" / "share" / "raptor" / "sessions.d"
    assert not sessions_dir.exists()
    assert not tuple(workspace.home.rglob("*.receipt.*"))
    assert not tuple(workspace.home.rglob("*.receipt.lock"))
    assert not (workspace.cwd / "should-not-run").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="bash launcher")
def test_caller_environment_cannot_select_or_unlock_copilot(tmp_path):
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "claude",
        FakeCLIBehavior(stdout="CLAUDE_CHILD_RAN\n"),
    )
    workspace.configure_cli(
        "copilot",
        FakeCLIBehavior(stdout="COPILOT_CHILD_RAN\n"),
    )
    env = _launcher_env(workspace)
    env.update(
        {
            "RAPTOR_HOST": "copilot",
            "COPILOT_FRONTEND": "copilot",
            "RAPTOR_COPILOT_TRANSPORT_DISABLED": "0",
        }
    )
    target = workspace.cwd / "target"
    target.mkdir()

    default_result = subprocess.run(
        [
            "bash",
            str(LAUNCHER),
            "--opaque-frontend-arg",
            str(target),
        ],
        cwd=workspace.cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert default_result.returncode == 0, (
        default_result.stdout,
        default_result.stderr,
    )
    claude_calls = workspace.invocations("claude")
    assert len(claude_calls) == 1
    assert "--opaque-frontend-arg" in claude_calls[0].argv
    assert "--frontend" not in claude_calls[0].argv
    assert claude_calls[0].argv[-1] == f"/raptor {target}"
    assert workspace.invocations("copilot") == []

    gated_result = subprocess.run(
        ["bash", str(LAUNCHER), "--frontend=copilot"],
        cwd=workspace.cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert gated_result.returncode == 78
    assert workspace.invocations("copilot") == []


def test_launcher_gate_and_exec_sections_are_marker_bounded_and_ordered():
    source = LAUNCHER.read_text(encoding="utf-8")
    gate = _marker_bounded_section(source, "FRONTEND_GATE")
    frontend_exec = _marker_bounded_section(source, "FRONTEND_EXEC")

    helper = 'python3 -m core.startup.host "$FRONTEND"'
    shell_guard = 'if [ "$FRONTEND" != "claude" ]; then'
    assert helper in gate
    assert shell_guard not in gate
    assert "raptor-cc-trust-check" not in gate
    assert "raptor-startup-check" not in gate
    assert "PLUGIN_ARGS" not in gate

    gate_start = source.index("# RAPTOR_FRONTEND_GATE_BEGIN")
    trust_start = source.index(
        '"$RAPTOR_DIR/libexec/raptor-cc-trust-check"',
        gate_start,
    )
    project_start = source.index(
        '"$RAPTOR_DIR/libexec/raptor-startup-check"',
        trust_start,
    )
    plugin_start = source.index("PLUGIN_ARGS=()", project_start)
    exec_start = source.index("# RAPTOR_FRONTEND_EXEC_BEGIN", plugin_start)
    assert gate_start < trust_start < project_start < plugin_start < exec_start

    assert '"$FRONTEND_EXECUTABLE" "${PLUGIN_ARGS[@]}"' in frontend_exec
    assert '"${FRONTEND_ARGS[@]}" -i "$INITIAL_PROMPT"' in frontend_exec
    assert '"${FRONTEND_ARGS[@]}" "$INITIAL_PROMPT"' in frontend_exec
    test_source = Path(__file__).read_text(encoding="utf-8")
    assert "BASELINE_" + "HEAD" not in test_source
    assert '"git", ' + '"show"' not in test_source


@pytest.mark.skipif(sys.platform != "linux", reason="Linux registry identity")
def test_launcher_dead_host_v2_cleanup_is_exact(tmp_path):
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "claude",
        FakeCLIBehavior(stdout="CLAUDE_CHILD_RAN\n", read_stdin=False),
    )
    sessions_dir = workspace.home / ".local" / "share" / "raptor" / "sessions.d"
    sessions_dir.mkdir(parents=True)
    dead_pid = 999999999
    digest = "a" * 64
    other_digest = "b" * 64
    boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    pidns = str(Path("/proc/self/ns/pid").stat().st_ino)
    entry = sessions_dir / str(dead_pid)
    entry.write_text(
        "v=2\nproject=-\nsince=2026-09-12T00:00:00+00:00\n"
        f"starttime=1\nboot_id={boot}\npidns={pidns}\n"
        "host_v=2\nhost=copilot\n"
        f"host_receipt_sha256={digest}\n"
        f"host_receipt_sha256={other_digest}\n"
        f"token={'ab' * 16}\nseeded_by=owned_fake\n",
        encoding="utf-8",
    )
    selected = sessions_dir / f"{dead_pid}.receipt.{digest}.json"
    selected.write_bytes(b"selected")
    unrelated = sessions_dir / f"{dead_pid}.receipt.{other_digest}.json"
    unrelated.write_bytes(b"unrelated")
    receipt_lock = sessions_dir / f"{dead_pid}.receipt.lock"
    receipt_lock.write_bytes(b"")
    (sessions_dir / f"{dead_pid}.run").write_text(
        "running 1 run /tmp/run\n",
        encoding="utf-8",
    )
    (sessions_dir / f"{dead_pid}.run.lock").write_bytes(b"")

    result = subprocess.run(
        ["bash", str(LAUNCHER), "--frontend=claude"],
        cwd=workspace.cwd,
        env=_launcher_env(workspace),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert not entry.exists()
    assert not selected.exists()
    assert not (sessions_dir / f"{dead_pid}.run").exists()
    assert not (sessions_dir / f"{dead_pid}.run.lock").exists()
    assert unrelated.exists()
    assert receipt_lock.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux registry identity")
def test_launcher_live_host_v2_is_silent_and_keeps_sidecar(tmp_path):
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "claude",
        FakeCLIBehavior(stdout="CLAUDE_CHILD_RAN\n", read_stdin=False),
    )
    sessions_dir = workspace.home / ".local" / "share" / "raptor" / "sessions.d"
    sessions_dir.mkdir(parents=True)
    pid = os.getpid()
    digest = "c" * 64
    boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    pidns = str(Path("/proc/self/ns/pid").stat().st_ino)
    entry = sessions_dir / str(pid)
    entry.write_text(
        "v=2\nproject=-\nsince=2026-09-12T00:00:00+00:00\n"
        f"starttime=1\nboot_id={boot}\npidns={pidns}\n"
        "host_v=2\nhost=copilot\n"
        f"host_receipt_sha256={digest}\n"
        f"token={'ab' * 16}\nseeded_by=owned_fake\n",
        encoding="utf-8",
    )
    sidecar = sessions_dir / f"{pid}.receipt.{digest}.json"
    sidecar.write_bytes(b"selected")

    result = subprocess.run(
        ["bash", str(LAUNCHER), "--frontend=claude"],
        cwd=workspace.cwd,
        env=_launcher_env(workspace),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert f"session pid {pid}" not in result.stderr
    assert entry.exists()
    assert sidecar.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="bash launcher")
def test_default_and_explicit_claude_argv_match_contract(tmp_path):
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "claude",
        FakeCLIBehavior(stdout="CLAUDE_CHILD_RAN\n", read_stdin=False),
    )
    launcher = _materialize_launcher_root(workspace)
    target = workspace.cwd / "target"
    target.mkdir()
    common = (
        "-m",
        "sonnet",
        "-v",
        "--yolo",
        "--opaque-frontend-arg",
        str(target),
    )

    current = LAUNCHER.read_bytes()
    runs = (
        common,
        ("--frontend", "claude", *common),
        ("--frontend=claude", *common),
    )
    launcher.write_bytes(current)
    launcher.chmod(0o700)
    for args in runs:
        result = _run_copied_launcher(launcher, workspace, args)
        assert result.returncode == 0, (result.stdout, result.stderr)

    invocations = workspace.invocations("claude")
    assert len(invocations) == 3
    expected = (
        "--plugin-dir",
        str(workspace.root / "plugins" / "coverage"),
        "--plugin-dir",
        str(workspace.root / "plugins" / "agents"),
        "-n",
        "RAPTOR",
        "--model",
        "sonnet",
        "--verbose",
        "--yolo",
        "--opaque-frontend-arg",
        f"/raptor {target}",
    )
    for invocation in invocations:
        assert invocation.argv == expected
        assert "--frontend" not in invocation.argv
        assert not any(arg.startswith("--frontend=") for arg in invocation.argv)
        assert "RAPTOR_HOST" not in invocation.env
        assert "COPILOT_FRONTEND" not in invocation.env


_UNLISTED_MODEL = "rhyolite/custom-model:preview@2026"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize(
    ("launcher_args", "frontend_args"),
    (
        (
            (
                "--frontend=copilot",
                "--project",
                "probe",
                "--yolo",
                "--model",
                _UNLISTED_MODEL,
                "{target}",
            ),
            ("--yolo", "--model", _UNLISTED_MODEL),
        ),
        (
            (
                "{target}",
                f"--model={_UNLISTED_MODEL}",
                "--yolo",
                "--project=probe",
                "--frontend",
                "copilot",
            ),
            (f"--model={_UNLISTED_MODEL}", "--yolo"),
        ),
        (
            (
                "--yolo",
                "--frontend",
                "copilot",
                "{target}",
                "--project",
                "probe",
                "--model",
                _UNLISTED_MODEL,
            ),
            ("--yolo", "--model", _UNLISTED_MODEL),
        ),
    ),
    ids=("options-first", "target-first", "interleaved"),
)
def test_native_copilot_new_session_orderings_are_unambiguous(
    tmp_path,
    launcher_args,
    frontend_args,
):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path,
        "copilot",
    )
    manager, target = _create_probe_project(workspace)

    result = _run_native_frontend(
        launcher,
        workspace,
        env,
        _expand_target(launcher_args, target),
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    argv, fields = _read_native_frontend_capture(capture)
    assert argv == [
        str(workspace.bin_dir / "copilot"),
        "--plugin-dir",
        str(workspace.root / "plugins" / "coverage"),
        "--no-auto-update",
        *frontend_args,
        "--name",
        "RAPTOR",
        "-i",
        f"/raptor {target}",
    ]
    assert fields["env.RAPTOR_FRONTEND_MODEL"] == _UNLISTED_MODEL
    assert "--project" not in argv
    assert "--project=probe" not in argv
    assert "probe" not in argv
    _assert_probe_project_bound(workspace, manager)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize(
    ("launcher_args", "frontend_args"),
    (
        (
            (
                "--frontend",
                "copilot",
                "--project",
                "probe",
                "--yolo",
                "--model",
                _UNLISTED_MODEL,
                "--continue",
            ),
            ("--yolo", "--model", _UNLISTED_MODEL, "--continue"),
        ),
        (
            (
                "--continue",
                f"--model={_UNLISTED_MODEL}",
                "--project=probe",
                "--yolo",
                "--frontend=copilot",
            ),
            ("--continue", f"--model={_UNLISTED_MODEL}", "--yolo"),
        ),
        (
            (
                "--yolo",
                "--project",
                "probe",
                "--continue",
                "--frontend",
                "copilot",
                "--model",
                _UNLISTED_MODEL,
            ),
            ("--yolo", "--continue", "--model", _UNLISTED_MODEL),
        ),
    ),
    ids=("options-first", "continue-first", "interleaved"),
)
def test_native_copilot_continuation_orderings_are_unambiguous(
    tmp_path,
    launcher_args,
    frontend_args,
):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path,
        "copilot",
    )
    manager, _ = _create_probe_project(workspace)

    result = _run_native_frontend(
        launcher,
        workspace,
        env,
        launcher_args,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    argv, fields = _read_native_frontend_capture(capture)
    assert argv == [
        str(workspace.bin_dir / "copilot"),
        "--plugin-dir",
        str(workspace.root / "plugins" / "coverage"),
        "--no-auto-update",
        *frontend_args,
    ]
    assert fields["env.RAPTOR_FRONTEND_MODEL"] == _UNLISTED_MODEL
    assert "--project" not in argv
    assert "--project=probe" not in argv
    assert "probe" not in argv
    assert "--name" not in argv
    assert "-i" not in argv
    _assert_probe_project_bound(workspace, manager)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize(
    ("launcher_args", "frontend_args"),
    (
        (
            (
                "--frontend",
                "copilot",
                "--project",
                "probe",
                "--model",
                _UNLISTED_MODEL,
                "--resume",
                "33333333-3333-4333-8333-333333333333",
            ),
            (
                "--model",
                _UNLISTED_MODEL,
                "--session-id=33333333-3333-4333-8333-333333333333",
            ),
        ),
        (
            (
                "--resume=MVP 10 exact session",
                f"--model={_UNLISTED_MODEL}",
                "--project=probe",
                "--frontend=copilot",
            ),
            (
                "--session-id=MVP 10 exact session",
                f"--model={_UNLISTED_MODEL}",
            ),
        ),
        (
            (
                "-r",
                "task-name",
                "--frontend=copilot",
                "--project",
                "probe",
                "--model",
                _UNLISTED_MODEL,
            ),
            (
                "--session-id=task-name",
                "--model",
                _UNLISTED_MODEL,
            ),
        ),
    ),
    ids=("separated-id", "equals-exact-name", "short-name"),
)
def test_native_copilot_explicit_resume_orderings_are_exact_and_isolated(
    tmp_path,
    launcher_args,
    frontend_args,
):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path,
        "copilot",
    )
    manager, _ = _create_probe_project(workspace)

    result = _run_native_frontend(
        launcher,
        workspace,
        env,
        launcher_args,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    argv, fields = _read_native_frontend_capture(capture)
    assert argv == [
        str(workspace.bin_dir / "copilot"),
        "--plugin-dir",
        str(workspace.root / "plugins" / "coverage"),
        "--no-auto-update",
        *frontend_args,
    ]
    assert fields["env.RAPTOR_FRONTEND_MODEL"] == _UNLISTED_MODEL
    assert "--continue" not in argv
    assert "--name" not in argv
    assert "-i" not in argv
    assert not any(arg.startswith("/raptor") for arg in argv)
    _assert_probe_project_bound(workspace, manager)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize(
    ("resume_args", "message"),
    (
        (("--resume",), "--resume requires a session id or name"),
        (("-r",), "-r requires a session id or name"),
        (("--resume=",), "--resume= requires a session id or name"),
        (
            ("--resume", "--model", "gpt-5-mini"),
            "--resume requires a value before the next option",
        ),
        (
            ("--continue", "--resume", "session-1"),
            "--resume cannot be used with --continue",
        ),
        (
            ("--resume", "session-1", "--continue"),
            "--continue cannot be used with --resume",
        ),
        (
            ("--resume", "session-1", "--resume=session-2"),
            "--resume may be specified only once",
        ),
        (
            ("--resume", "session-1", "target"),
            "--resume cannot be combined with a target",
        ),
    ),
    ids=(
        "missing-long",
        "missing-short",
        "empty-equals",
        "before-option",
        "continue-first",
        "resume-first",
        "duplicate",
        "target",
    ),
)
def test_native_copilot_rejects_ambiguous_resume_before_exec(
    tmp_path,
    resume_args,
    message,
):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path,
        "copilot",
    )

    result = _run_native_frontend(
        launcher,
        workspace,
        env,
        ("--frontend", "copilot", *resume_args),
    )

    assert result.returncode == 1, (result.stdout, result.stderr)
    assert message in result.stderr
    assert not capture.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_native_copilot_exec_scrubs_inherited_loader_markers(tmp_path):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path,
        "copilot",
    )
    for name in (
        "COPILOT_CLI_BINARY_VERSION",
        "COPILOT_CLI_RESOLVED_DIST_DIR",
        "COPILOT_LOADER_PID",
    ):
        env[name] = f"parent-{name.lower()}"

    result = _run_native_frontend(
        launcher,
        workspace,
        env,
        ("--frontend", "copilot", "--resume=exact-session"),
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    argv, fields = _read_native_frontend_capture(capture)
    assert "--session-id=exact-session" in argv
    assert fields["env.RAPTOR_SESSION_SERVICE_POLICY"] == "copilot-only"
    for name in (
        "COPILOT_AGENT_SESSION_ID",
        "COPILOT_CLI",
        "COPILOT_CLI_BINARY_VERSION",
        "COPILOT_CLI_RESOLVED_DIST_DIR",
        "COPILOT_LOADER_PID",
    ):
        assert fields[f"env.{name}"] == "<unset>"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize("frontend", ("claude", "copilot"))
@pytest.mark.parametrize("marker", (
    "COPILOT_CLI", "COPILOT_AGENT_SESSION_ID",
    "RAPTOR_FRONTEND", "RAPTOR_SESSION_SERVICE_POLICY",
))
def test_copilot_session_refuses_nested_frontend(tmp_path, frontend, marker):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path, frontend,
    )
    env[marker] = "copilot" if marker == "RAPTOR_FRONTEND" else "fixture-session"
    result = _run_native_frontend(
        launcher, workspace, env, ("--frontend", frontend),
    )
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert "refuses a nested frontend/harness" in result.stderr
    assert not capture.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_native_claude_resume_passthrough_is_unchanged(tmp_path):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path,
        "claude",
    )

    result = _run_native_frontend(
        launcher,
        workspace,
        env,
        ("--frontend", "claude", "--resume=claude-session"),
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    argv, _ = _read_native_frontend_capture(capture)
    assert "--resume=claude-session" in argv
    assert argv[-1] == "/raptor"
    assert "--session-id=claude-session" not in argv


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize(
    ("launcher_args", "frontend_args", "model_label"),
    (
        (
            (
                "--frontend=claude",
                "--project",
                "probe",
                "--yolo",
                "--model",
                "sonnet",
                "{target}",
            ),
            ("--yolo", "--model", "sonnet"),
            "sonnet",
        ),
        (
            (
                "{target}",
                "--model=sonnet",
                "--yolo",
                "--project=probe",
                "--frontend",
                "claude",
            ),
            ("--model=sonnet", "--yolo"),
            "<unset>",
        ),
    ),
    ids=("options-first", "target-first"),
)
def test_native_claude_yolo_stays_on_claude_argv(
    tmp_path,
    launcher_args,
    frontend_args,
    model_label,
):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path,
        "claude",
    )
    manager, target = _create_probe_project(workspace)

    result = _run_native_frontend(
        launcher,
        workspace,
        env,
        _expand_target(launcher_args, target),
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    argv, fields = _read_native_frontend_capture(capture)
    assert argv == [
        str(workspace.bin_dir / "claude"),
        "--plugin-dir",
        str(workspace.root / "plugins" / "coverage"),
        "--plugin-dir",
        str(workspace.root / "plugins" / "agents"),
        "-n",
        "RAPTOR",
        *frontend_args,
        f"/raptor {target}",
    ]
    assert fields["env.RAPTOR_FRONTEND_MODEL"] == model_label
    assert "--project" not in argv
    assert "--project=probe" not in argv
    assert "probe" not in argv
    assert "--no-auto-update" not in argv
    assert "--name" not in argv
    assert "-i" not in argv
    _assert_probe_project_bound(workspace, manager)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_native_copilot_never_enables_yolo_by_default(tmp_path):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path,
        "copilot",
    )

    result = _run_native_frontend(
        launcher,
        workspace,
        env,
        ("--frontend", "copilot"),
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    argv, _ = _read_native_frontend_capture(capture)
    assert "--yolo" not in argv
    assert "--allow-all" not in argv
    assert "--allow-all-tools" not in argv


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize(
    ("model", "model_args"),
    tuple(
        (
            model,
            args,
        )
        for model in (
            "gpt-6-astra",
            "gpt-6-astra",
            _UNLISTED_MODEL,
        )
        for args in (
            ("--model", model),
            (f"--model={model}",),
        )
    ) + (("-vendor/model", ("--model=-vendor/model",)),),
    ids=(
        "listed-separated",
        "listed-equals",
        "unlisted-separated",
        "unlisted-equals",
        "arbitrary-separated",
        "arbitrary-equals",
        "option-looking-equals",
    ),
)
def test_native_copilot_forwards_every_nonempty_model_spelling_exactly(
    tmp_path,
    model,
    model_args,
):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path,
        "copilot",
    )

    result = _run_native_frontend(
        launcher,
        workspace,
        env,
        ("--frontend", "copilot", *model_args),
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    argv, fields = _read_native_frontend_capture(capture)
    if len(model_args) == 1:
        assert model_args[0] in argv
    else:
        model_index = argv.index("--model")
        assert argv[model_index + 1] == model
    assert fields["env.RAPTOR_FRONTEND_MODEL"] == model
    assert argv[-2:] == ["-i", "/raptor"]
    assert "--yolo" not in argv


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize(
    "credit_args",
    (
        ("--max-ai-credits", "30"),
        ("--max-ai-credits", "30.5"),
        ("--max-ai-credits=30",),
        ("--max-ai-credits=30.5",),
    ),
    ids=("floor-separated", "decimal-separated", "floor-equals", "decimal-equals"),
)
def test_native_copilot_forwards_supported_credit_limit_exactly(
    tmp_path,
    credit_args,
):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path,
        "copilot",
    )

    result = _run_native_frontend(
        launcher,
        workspace,
        env,
        ("--frontend", "copilot", *credit_args),
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    argv, _ = _read_native_frontend_capture(capture)
    if len(credit_args) == 1:
        assert credit_args[0] in argv
    else:
        credit_index = argv.index("--max-ai-credits")
        assert argv[credit_index + 1] == credit_args[1]
    assert argv[-2:] == ["-i", "/raptor"]


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize(
    "credit_args",
    (
        ("--max-ai-credits", "1"),
        ("--max-ai-credits", "29.999"),
        ("--max-ai-credits=1.0",),
        ("--max-ai-credits=29",),
    ),
    ids=("one-separated", "decimal-separated", "one-equals", "below-equals"),
)
def test_native_copilot_rejects_credit_limit_below_installed_floor(
    tmp_path,
    credit_args,
):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path,
        "copilot",
    )

    result = _run_native_frontend(
        launcher,
        workspace,
        env,
        ("--frontend", "copilot", *credit_args),
    )

    assert result.returncode == 1, (result.stdout, result.stderr)
    assert (
        "Copilot --max-ai-credits requires at least 30; smaller limits are "
        "unsupported by the installed CLI"
    ) in result.stderr
    assert not capture.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize(
    ("credit_args", "message"),
    (
        (("--max-ai-credits",), "--max-ai-credits requires a value"),
        (
            ("--max-ai-credits", "--yolo"),
            "--max-ai-credits requires a value before the next option",
        ),
        (
            ("--max-ai-credits=",),
            "--max-ai-credits= requires a non-empty value",
        ),
    ),
    ids=("missing", "before-option", "empty-equals"),
)
def test_native_copilot_rejects_missing_credit_limit_before_exec(
    tmp_path,
    credit_args,
    message,
):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path,
        "copilot",
    )

    result = _run_native_frontend(
        launcher,
        workspace,
        env,
        ("--frontend", "copilot", *credit_args),
    )

    assert result.returncode == 1, (result.stdout, result.stderr)
    assert message in result.stderr
    assert not capture.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_native_copilot_leaves_unlisted_repo_model_to_native_config(
    tmp_path,
):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path,
        "copilot",
    )
    settings = workspace.root / ".github" / "copilot" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        '{\n  "model": "gpt-6-astra"\n}\n',
        encoding="utf-8",
    )

    result = _run_native_frontend(
        launcher,
        workspace,
        env,
        ("--frontend", "copilot"),
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    argv, fields = _read_native_frontend_capture(capture)
    assert "--model" not in argv
    assert not any(arg.startswith("--model=") for arg in argv)
    assert fields["env.RAPTOR_FRONTEND_MODEL"] == "<unset>"
    assert fields["cwd"] == str(workspace.root)
    assert "gpt-6-astra" in settings.read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize(
    ("model_args", "message"),
    (
        (("--model",), "--model requires a value"),
        (("-m",), "-m requires a value"),
        (("--model", ""), "--model requires a non-empty value"),
        (("-m", ""), "-m requires a non-empty value"),
        (("--model=",), "--model= requires a non-empty value"),
        (
            ("--model", "--yolo"),
            "--model requires a value before the next option",
        ),
        (
            ("-m", "--continue"),
            "-m requires a value before the next option",
        ),
        (
            ("--model", "--project", "probe"),
            "--model requires a value before the next option",
        ),
        (
            ("--model", "--project=probe"),
            "--model requires a value before the next option",
        ),
    ),
    ids=(
        "missing-long",
        "missing-short",
        "empty-long",
        "empty-short",
        "empty-equals",
        "before-yolo",
        "before-continue",
        "before-project-separated",
        "before-project-equals",
    ),
)
def test_native_copilot_rejects_missing_or_empty_model_before_exec(
    tmp_path,
    model_args,
    message,
):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path,
        "copilot",
    )

    result = _run_native_frontend(
        launcher,
        workspace,
        env,
        ("--frontend", "copilot", *model_args),
    )

    assert result.returncode == 1, (result.stdout, result.stderr)
    assert message in result.stderr
    assert not capture.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize(
    "model_args",
    (
        ("--model", "definitely-not-a-real-model"),
        ("--model=definitely-not-a-real-model",),
    ),
    ids=("separated", "equals"),
)
def test_native_copilot_upstream_model_rejection_is_unchanged(
    tmp_path,
    model_args,
):
    workspace, launcher, capture, env = _native_frontend_argv_harness(
        tmp_path,
        "copilot",
    )
    invalid_model = "definitely-not-a-real-model"
    env["RAPTOR_TEST_FRONTEND_REJECT_MODEL"] = invalid_model

    result = _run_native_frontend(
        launcher,
        workspace,
        env,
        ("--frontend", "copilot", "--yolo", *model_args),
    )

    expected_error = (
        f"native frontend fixture rejected model upstream: {invalid_model}\n"
    )
    assert result.returncode == 64, (result.stdout, result.stderr)
    assert result.stdout == ""
    stderr_lines = result.stderr.splitlines(keepends=True)
    assert stderr_lines[-1] == expected_error
    expected_warning = _expected_frontend_path_warning(
        "copilot",
        workspace.bin_dir / "copilot",
    )
    assert stderr_lines[:-1] == (
        [expected_warning] if expected_warning is not None else []
    )
    argv, fields = _read_native_frontend_capture(capture)
    assert "--yolo" in argv
    if len(model_args) == 1:
        assert model_args[0] in argv
    else:
        model_index = argv.index("--model")
        assert argv[model_index + 1] == invalid_model
    assert fields["env.RAPTOR_FRONTEND_MODEL"] == invalid_model
    assert "gpt-6-astra" not in argv


@pytest.mark.skipif(sys.platform == "win32", reason="bash launcher")
def test_explicit_copilot_scan_cannot_take_login_free_local_route(tmp_path):
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "copilot",
        FakeCLIBehavior(stdout="COPILOT_CHILD_RAN\n"),
    )
    launcher = _materialize_launcher_root(workspace)
    launcher.write_bytes(LAUNCHER.read_bytes())
    launcher.chmod(0o700)

    local_route_marker = workspace.root / "local-route-ran"
    raptor_py = workspace.root / "raptor.py"
    raptor_py.unlink()
    raptor_py.write_text(
        "from pathlib import Path\n"
        f"Path({str(local_route_marker)!r}).write_text('ran', encoding='utf-8')\n"
        "raise SystemExit(42)\n",
        encoding="utf-8",
    )
    target = workspace.cwd / "target"
    target.mkdir()
    env = _launcher_env(workspace)
    env["RAPTOR_NO_CLAUDE"] = "1"

    result = subprocess.run(
        [
            "bash",
            str(launcher),
            "--frontend",
            "copilot",
            "scan",
            str(target),
        ],
        cwd=workspace.cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 78, (result.stdout, result.stderr)
    assert "live host contract is not verified" in result.stderr
    assert not local_route_marker.exists()
    assert workspace.invocations("copilot") == []
    sessions_dir = workspace.home / ".local" / "share" / "raptor" / "sessions.d"
    assert not sessions_dir.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="bash launcher")
@pytest.mark.parametrize(
    "args,expected",
    [
        (("--frontend",), "requires a value"),
        (("--frontend", "browser"), "unknown frontend"),
    ],
)
def test_frontend_selector_rejects_missing_or_unknown_values(
    tmp_path,
    args,
    expected,
):
    workspace = make_hermetic_cli(tmp_path)
    result = subprocess.run(
        ["bash", str(LAUNCHER), *args],
        cwd=workspace.cwd,
        env=_launcher_env(workspace),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode != 0
    assert expected in result.stderr
    assert workspace.invocations("claude") == []
    assert workspace.invocations("copilot") == []


@pytest.mark.skipif(sys.platform == "win32", reason="bash launcher")
def test_path_hardening_precedes_copilot_resolution(tmp_path):
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    marker = tmp_path / "copilot-ran"
    fake = unsafe / "copilot"
    fake.write_text(
        f"#!/bin/sh\nprintf ran > {str(marker)!r}\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    env = {
        "PATH": f"{unsafe}:{_system_path()}",
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "TERM": "dumb",
    }

    result = subprocess.run(
        ["bash", str(LAUNCHER), "--frontend", "copilot"],
        cwd=home,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 127
    assert "dropped unsafe PATH entry" in result.stderr
    assert "copilot not found" in result.stderr
    assert not marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize("frontend", ("claude", "copilot"))
def test_native_frontend_launcher_seeds_strong_claim(tmp_path, frontend):
    source = Path("/bin/true")
    if not source.is_file():
        pytest.skip("/bin/true unavailable")
    host_bin = tmp_path / "bin"
    host_bin.mkdir()
    executable = host_bin / frontend
    executable.write_bytes(source.read_bytes())
    executable.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    env = {
        "PATH": f"{host_bin}:{_system_path()}",
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "TERM": "dumb",
    }

    result = subprocess.run(
        ["bash", str(LAUNCHER), "--frontend", frontend],
        cwd=home,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    entries = list((home / ".local" / "share" / "raptor" / "sessions.d").glob("[0-9]*"))
    assert len(entries) == 1
    text = entries[0].read_text(encoding="utf-8")
    assert "host_v=1\n" in text
    assert f"host={frontend}\n" in text
    assert f"host_uid={os.geteuid()}\n" in text
    assert f"host_exe={executable}\n" in text
    assert "host_exe_dev=" in text
    assert "host_exe_ino=" in text


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize("resume", (False, True), ids=("new", "continue"))
def test_native_copilot_launcher_adapts_argv_and_resolves_owner(tmp_path, resume):
    from core.project import sessions

    host_bin = tmp_path / "bin"
    home = tmp_path / "home"
    tmpdir = tmp_path / "tmp"
    target = tmp_path / "target"
    out_dir = tmp_path / "out"
    for directory in (host_bin, home, tmpdir, target, out_dir):
        directory.mkdir()
    copilot = host_bin / "copilot"
    _compile_native_fixture(copilot)
    marker = home / "native-frontend-ready"
    env = {
        "PATH": f"{host_bin}:{_system_path()}",
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "TERM": "dumb",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "RAPTOR_CONFIG": str(tmp_path / "models.json"),
        "RAPTOR_OUT_DIR": str(out_dir),
        "RAPTOR_CC_TRANSPORT_DISABLED": "1",
        "RAPTOR_COPILOT_TRANSPORT_DISABLED": "1",
    }
    process = subprocess.Popen(
        [
            "bash",
            str(LAUNCHER),
            "--frontend=copilot",
            "--verbose",
            "--model",
            "gpt-6-astra",
            "--reasoning-effort=max",
            "--context=long_context",
            *(["--continue"] if resume else [str(target)]),
        ],
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        _wait_until(marker.exists)
        assert int(marker.read_text(encoding="utf-8").strip()) == process.pid
        argv = [
            item.decode("utf-8")
            for item in Path(f"/proc/{process.pid}/cmdline")
            .read_bytes()
            .split(b"\0")
            if item
        ]
        assert argv[0] == str(copilot)
        assert "--no-auto-update" in argv
        assert argv[argv.index("--log-level") + 1] == "debug"
        assert argv[argv.index("--model") + 1] == "gpt-6-astra"
        assert "--reasoning-effort=max" in argv
        assert "--context=long_context" in argv
        if resume:
            assert "--continue" in argv
            assert "--name" not in argv
            assert "-i" not in argv
        else:
            assert "--continue" not in argv
            assert argv[argv.index("--name") + 1] == "RAPTOR"
            assert argv[argv.index("-i") + 1] == f"/raptor {target}"
        assert "--verbose" not in argv
        process_env = dict(
            item.split(b"=", 1)
            for item in Path(f"/proc/{process.pid}/environ")
            .read_bytes()
            .split(b"\0")
            if b"=" in item
        )
        assert process_env[b"RAPTOR_FRONTEND"] == b"copilot"
        assert process_env[b"RAPTOR_FRONTEND_MODEL"] == b"gpt-6-astra"

        entry = (
            home
            / ".local"
            / "share"
            / "raptor"
            / "sessions.d"
            / str(process.pid)
        )
        fields = _wait_until(lambda: sessions._parse_entry(entry))
        assert fields["host"] == "copilot"
        assert fields["host_exe"] == str(copilot)
        assert len(fields["token"]) == 32
        with (
            patch.object(sessions, "SESSIONS_DIR", entry.parent),
            patch.dict(
                os.environ,
                {
                    sessions.ENV_SESSION_PID: str(process.pid),
                    sessions.ENV_SESSION_TOKEN: fields["token"],
                },
            ),
        ):
            owner = sessions.resolve_session_owner()
        assert owner is not None
        assert owner.pid == process.pid
        assert owner.frontend is Frontend.COPILOT
        assert owner.host_verified is True
    finally:
        stdout, stderr = _terminate_owned_process_group(process)
    assert process.returncode == 0, (stdout, stderr)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_a9_shebang_claude_seeds_legacy_and_resolves(tmp_path):
    from core.project import sessions

    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "claude",
        FakeCLIBehavior(delay_seconds=60, read_stdin=False),
    )
    process = subprocess.Popen(
        ["bash", str(LAUNCHER), "--frontend=claude"],
        cwd=workspace.cwd,
        env=_launcher_env(workspace),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        invocation = _wait_until(
            lambda: calls[-1] if (calls := workspace.invocations("claude")) else None
        )
        assert invocation.pid == process.pid
        entry = (
            workspace.home
            / ".local"
            / "share"
            / "raptor"
            / "sessions.d"
            / str(process.pid)
        )
        fields = _wait_until(lambda: sessions._parse_entry(entry))
        assert not any(key.startswith("host") for key in fields)
        token = fields["token"]
        with (
            patch.object(sessions, "SESSIONS_DIR", entry.parent),
            patch.dict(
                os.environ,
                {
                    sessions.ENV_SESSION_PID: str(process.pid),
                    sessions.ENV_SESSION_TOKEN: token,
                },
            ),
        ):
            owner = sessions.resolve_session_owner()
        assert owner is not None
        assert owner.pid == process.pid
        assert owner.frontend is Frontend.CLAUDE
        assert owner.host_verified is False
    finally:
        stdout, stderr = _terminate_owned_process_group(process)
    assert process.returncode in (0, -signal.SIGTERM), (stdout, stderr)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_a6_a9_native_alias_resolves_and_survives_path_replacement(tmp_path):
    from core.project import sessions

    root = tmp_path / "native"
    host_bin = root / "bin"
    versions = root / "versions"
    home = root / "home"
    tmpdir = root / "tmp"
    out_dir = root / "out"
    for directory in (host_bin, versions, home, tmpdir, out_dir):
        directory.mkdir(parents=True)
    runtime = versions / "claude-runtime"
    _compile_native_fixture(runtime)
    selected = host_bin / "claude"
    selected.symlink_to(runtime)
    marker = home / "native-frontend-ready"
    env = {
        "PATH": f"{host_bin}:{_system_path()}",
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "TERM": "dumb",
        "LANG": "C",
        "LC_ALL": "C",
        "RAPTOR_CONFIG": str(root / "models.json"),
        "RAPTOR_OUT_DIR": str(out_dir),
        "RAPTOR_CC_TRANSPORT_DISABLED": "1",
        "RAPTOR_COPILOT_TRANSPORT_DISABLED": "1",
    }
    process = subprocess.Popen(
        ["bash", str(LAUNCHER), "--frontend=claude"],
        cwd=root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        _wait_until(marker.exists)
        assert int(marker.read_text(encoding="utf-8").strip()) == process.pid
        assert (
            Path(f"/proc/{process.pid}/comm").read_text(encoding="utf-8").strip()
            == "claude"
        )
        mapped = os.stat(f"/proc/{process.pid}/exe")
        runtime_before = runtime.stat()
        assert (mapped.st_dev, mapped.st_ino) == (
            runtime_before.st_dev,
            runtime_before.st_ino,
        )

        entry = home / ".local" / "share" / "raptor" / "sessions.d" / str(process.pid)
        fields = _wait_until(lambda: sessions._parse_entry(entry))
        assert fields["host"] == "claude"
        assert fields["host_exe"] == str(selected)
        assert fields["host_exe_dev"] == str(runtime_before.st_dev)
        assert fields["host_exe_ino"] == str(runtime_before.st_ino)
        assert fields["starttime"] == sessions.proc_starttime(process.pid)
        assert len(fields["token"]) == 32

        with (
            patch.object(sessions, "SESSIONS_DIR", entry.parent),
            patch.dict(
                os.environ,
                {
                    sessions.ENV_SESSION_PID: str(process.pid),
                    sessions.ENV_SESSION_TOKEN: fields["token"],
                },
            ),
        ):
            owner = sessions.resolve_session_owner()
            assert owner is not None
            assert owner.host_verified is True
            assert owner.host_claim is not None
            assert owner.host_claim.executable == selected

            replacement = versions / "replacement"
            true_binary = shutil.which("true")
            if true_binary is None:
                pytest.skip("A6 blocked: true executable is unavailable")
            replacement.write_bytes(Path(true_binary).read_bytes())
            replacement.chmod(0o700)
            os.replace(replacement, runtime)
            assert (runtime.stat().st_dev, runtime.stat().st_ino) != (
                runtime_before.st_dev,
                runtime_before.st_ino,
            )
            mapped_after = os.stat(f"/proc/{process.pid}/exe")
            assert (mapped_after.st_dev, mapped_after.st_ino) == (
                runtime_before.st_dev,
                runtime_before.st_ino,
            )
            assert sessions.resolve_session_owner() == owner
    finally:
        stdout, stderr = _terminate_owned_process_group(process)
    assert process.returncode == 0, (stdout, stderr)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_a13_native_awareness_and_inode_mismatch_silence(tmp_path):
    from core.project import sessions
    from core.project.project import ProjectManager

    root = tmp_path / "awareness"
    existing_dir = root / "existing"
    launch_bin = root / "launch-bin"
    home = root / "home"
    tmpdir = root / "tmp"
    target = root / "target"
    project_out = root / "project-out"
    for directory in (
        existing_dir,
        launch_bin,
        home,
        tmpdir,
        target,
        project_out,
    ):
        directory.mkdir(parents=True)

    existing_executable = existing_dir / "claude"
    _compile_native_fixture(existing_executable)
    launch_executable = launch_bin / "claude"
    true_binary = shutil.which("true", path="/usr/bin:/bin")
    if true_binary is None:
        pytest.skip("A13 blocked: true executable is unavailable")
    launch_executable.write_bytes(Path(true_binary).read_bytes())
    launch_executable.chmod(0o700)

    manager = ProjectManager(projects_dir=home / ".raptor" / "projects")
    manager.create(
        "myapp",
        str(target),
        output_dir=str(project_out),
    )
    manager.set_active("myapp")

    existing = subprocess.Popen(
        [str(existing_executable)],
        cwd=root,
        env={
            "PATH": _system_path(),
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        _wait_until((home / "native-frontend-ready").exists)
        sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
        with patch.object(sessions, "SESSIONS_DIR", sessions_dir):
            token = sessions.mint_token()
            claim = build_session_host_claim(Frontend.CLAUDE, existing_executable)
            assert (
                sessions.record_session(
                    "myapp",
                    pid=existing.pid,
                    token=token,
                    host_claim=claim,
                )
                == existing.pid
            )
        entry = sessions_dir / str(existing.pid)
        env = {
            "PATH": f"{launch_bin}:{_system_path()}",
            "HOME": str(home),
            "TMPDIR": str(tmpdir),
            "TERM": "dumb",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "RAPTOR_CONFIG": str(root / "models.json"),
            "RAPTOR_OUT_DIR": str(root / "out"),
            "RAPTOR_CC_TRANSPORT_DISABLED": "1",
            "RAPTOR_COPILOT_TRANSPORT_DISABLED": "1",
        }

        visible = subprocess.run(
            ["bash", str(LAUNCHER), "--frontend=claude"],
            cwd=target,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert visible.returncode == 0, (visible.stdout, visible.stderr)
        assert (
            f"project myapp is also active in session pid {existing.pid}"
            in visible.stderr
        )

        fields = sessions._parse_entry(entry)
        entry.write_text(
            entry.read_text(encoding="utf-8").replace(
                f"host_exe_ino={fields['host_exe_ino']}",
                f"host_exe_ino={int(fields['host_exe_ino']) + 1}",
            ),
            encoding="utf-8",
        )
        silent = subprocess.run(
            ["bash", str(LAUNCHER), "--frontend=claude"],
            cwd=target,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert silent.returncode == 0, (silent.stdout, silent.stderr)
        assert f"also active in session pid {existing.pid}" not in silent.stderr
        assert "ignoring malformed host claim" not in silent.stderr
        assert entry.exists(), "well-formed live mismatch was pruned"
    finally:
        stdout, stderr = _terminate_owned_process_group(existing)
    assert existing.returncode == 0, (stdout, stderr)
