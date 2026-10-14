"""Behavioural tests for the protocol-neutral fake CLI substrate.

These tests deliberately execute real fixture-owned child processes, matching
the established ``core.startup.tests.test_launcher_hardening`` precedent.
Every executable, config, cwd, environment, and writable path is rooted below
pytest's ``tmp_path``; PATH cannot resolve an operator CLI and no shell is
used.
"""

from __future__ import annotations

import concurrent.futures
import base64
import errno
import json
import os
import signal
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from core.config import RaptorConfig
from core.testing import fake_cli as fake_cli_module
from core.testing.git_hermeticity import (
    GIT_ENV_STRIP,
    GIT_ENV_STRIP_PREFIXES,
)
from core.testing import (
    FAKE_CLI_CONFIG_ERROR,
    FAKE_CLI_GUARD_EXIT,
    FakeCLIBehavior,
    make_hermetic_cli,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="fixture executables use POSIX shebang execution",
)


def _run(
    workspace,
    name: str,
    *args: str,
    input_data: str = "",
    extra_env: dict[str, str] | None = None,
    timeout: float = 5,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [name, *args],
        input=input_data,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        cwd=workspace.cwd,
        env=workspace.child_env(extra_env),
    )


def _assert_below(path: str, root: Path) -> None:
    Path(path).resolve().relative_to(root.resolve())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"stdout": 1},
        {"stdout": "bad\x00value"},
        {"read_stdin": "yes"},
        {"delay_seconds": True},
        {"delay_seconds": float("nan")},
        {"exit_code": True},
        {"exit_code": 256},
        {"descendant_depth": 3},
        {"secret_env_names": []},
        {"secret_env_names": tuple(f"SECRET_{i}" for i in range(65))},
        {"secret_env_names": ("SECRET_A", "SECRET_A")},
        {"secret_env_names": ("bad-name",)},
    ],
)
def test_fake_cli_behavior_rejects_malformed_contracts(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises((TypeError, ValueError)):
        FakeCLIBehavior(**kwargs)


def test_workspace_rejects_relative_or_missing_test_root(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="must be absolute"):
        make_hermetic_cli(Path("relative"))
    with pytest.raises(FileNotFoundError, match="does not exist"):
        make_hermetic_cli(tmp_path / "missing")


def test_workspace_rejects_invalid_behavior_command_and_internal_env(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    with pytest.raises(TypeError, match="FakeCLIBehavior"):
        workspace.configure_cli("bad-cli", object())
    with pytest.raises(TypeError, match="must be a string"):
        workspace.command("copilot", 7)
    with pytest.raises(ValueError, match="reserved"):
        workspace.child_env({"_RAPTOR_FAKE_CLI_TEST": "1"})


def _valid_invocation_payload() -> dict[str, object]:
    return {
        "event": "invocation",
        "cli": "synthetic-cli",
        "argv": ["--flag"],
        "executable": "/fixture/bin/synthetic-cli",
        "cwd": "/fixture/cwd",
        "env": {"SAFE": "value"},
        "secret_env": [
            {
                "name": "SYNTHETIC_SECRET",
                "present": False,
                "length": 0,
                "hmac_sha256": None,
            }
        ],
        "stdin_b64": "",
        "stdin_size": 0,
        "stdin_fd_target": "/fixture/stdin",
        "stdin_fd_access": "read_only",
        "pid": 123,
        "ppid": 122,
    }


@pytest.mark.parametrize(
    "case",
    [
        "event",
        "argv",
        "env",
        "secret-list",
        "secret-entry",
        "secret-name",
        "secret-present",
        "secret-length",
        "secret-digest",
        "secret-mismatch",
        "stdin-size",
        "missing",
    ],
)
def test_invocation_parser_rejects_malformed_event_fields(case: str) -> None:
    payload = _valid_invocation_payload()
    if case == "event":
        payload["event"] = "process"
    elif case == "argv":
        payload["argv"] = ["ok", 7]
    elif case == "env":
        payload["env"] = {"SAFE": 7}
    elif case == "secret-list":
        payload["secret_env"] = {}
    elif case == "secret-entry":
        payload["secret_env"] = ["bad"]
    elif case == "secret-name":
        payload["secret_env"][0]["name"] = "bad-name"
    elif case == "secret-present":
        payload["secret_env"][0]["present"] = "yes"
    elif case == "secret-length":
        payload["secret_env"][0]["length"] = -1
    elif case == "secret-digest":
        payload["secret_env"][0]["hmac_sha256"] = "bad"
    elif case == "secret-mismatch":
        payload["secret_env"][0]["present"] = True
    elif case == "stdin-size":
        payload["stdin_size"] = 1
    else:
        del payload["pid"]

    with pytest.raises(ValueError, match="invalid fake CLI invocation"):
        fake_cli_module._parse_invocation(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {
            "event": "invocation",
            "cli": "synthetic-cli",
            "role": "child",
            "generation": 1,
            "pid": 2,
            "ppid": 1,
        },
        {
            "event": "process",
            "cli": "synthetic-cli",
            "role": "unknown",
            "generation": 1,
            "pid": 2,
            "ppid": 1,
        },
    ],
)
def test_process_parser_rejects_wrong_event_or_role(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="invalid fake CLI process"):
        fake_cli_module._parse_process(payload)


def test_event_reader_rejects_wrong_schema(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    event = workspace.log_dir / "bad-schema.json"
    event.write_text('{"schema_version":2,"event":"invocation"}', encoding="utf-8")
    log_fd = fake_cli_module._open_directory_path(
        workspace.log_dir,
        label="log",
        expected=workspace._log_identity,
    )
    try:
        with pytest.raises(ValueError, match="event schema"):
            fake_cli_module._read_event_at(log_fd, event.name)
    finally:
        os.close(log_fd)


def test_event_reader_rejects_non_object_payload(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    event = workspace.log_dir / "not-an-object.json"
    event.write_text("[]", encoding="utf-8")
    log_fd = fake_cli_module._open_directory_path(
        workspace.log_dir,
        label="log",
        expected=workspace._log_identity,
    )
    try:
        with pytest.raises(ValueError, match="event schema"):
            fake_cli_module._read_event_at(log_fd, event.name)
    finally:
        os.close(log_fd)


def test_generated_configuration_respects_size_cap(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    behavior = FakeCLIBehavior(stdout="x" * (fake_cli_module._MAX_CONFIG_BYTES + 1))
    with pytest.raises(ValueError, match="configuration exceeds"):
        workspace.configure_cli("oversize-generated-config", behavior)


def test_relative_directory_walk_rejects_parent_components(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    root_fd = fake_cli_module._open_directory_path(
        workspace.root,
        label="workspace root",
        expected=workspace._root_identity,
    )
    try:
        with pytest.raises(ValueError, match="invalid relative path"):
            fake_cli_module._open_relative_directory(
                root_fd,
                "xdg/../outside",
                label="synthetic",
            )
    finally:
        os.close(root_fd)


def test_render_rejects_newline_in_python_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    monkeypatch.setattr(fake_cli_module.sys, "executable", "/bin/python\nbad")
    with pytest.raises(ValueError, match="newline"):
        workspace.configure_cli("newline-python", FakeCLIBehavior())


def test_executable_and_raptor_config_must_remain_regular_files(
    tmp_path: Path,
) -> None:
    executable_workspace = make_hermetic_cli(
        tmp_path,
        workspace_name="nonregular-executable",
    )
    executable_workspace.configure_cli("owned-cli", FakeCLIBehavior())
    executable = executable_workspace.executable("owned-cli")
    executable.unlink()
    executable.mkdir()
    with pytest.raises(ValueError, match="not a regular file"):
        executable_workspace.executable("owned-cli")

    config_workspace = make_hermetic_cli(
        tmp_path,
        workspace_name="nonregular-raptor-config",
    )
    config_workspace.raptor_config.unlink()
    config_workspace.raptor_config.mkdir()
    with pytest.raises(ValueError, match="not a regular file"):
        config_workspace.child_env()

    configure_workspace = make_hermetic_cli(
        tmp_path,
        workspace_name="nonregular-configure-target",
    )
    executable = configure_workspace.executable("copilot")
    executable.unlink()
    executable.mkdir()
    with pytest.raises(ValueError, match="not a regular file"):
        configure_workspace.configure_cli("copilot", FakeCLIBehavior())


def test_owned_executable_requires_secret_env_list(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli("owned-cli", FakeCLIBehavior())
    config = json.loads(workspace.config_path("owned-cli").read_text(encoding="utf-8"))
    config["secret_env_names"] = "not-a-list"
    workspace.config_path("owned-cli").write_text(
        json.dumps(config),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="lacks secret_env_names"):
        workspace.owned_executable("owned-cli")


def test_observable_process_shape_and_credential_free_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "RAPTOR_LLM_SOCKET",
        "CLAUDECODE",
        "_RAPTOR_TRUSTED",
    ):
        monkeypatch.setenv(key, f"operator-canary-{key}")
    monkeypatch.setenv("COPILOT_HOME", str(tmp_path / "operator-copilot"))
    monkeypatch.setenv("HOME", str(tmp_path / "operator-home"))

    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "example-cli",
        FakeCLIBehavior(stdout="ok\n", stderr="note\n"),
    )
    result = _run(
        workspace,
        "example-cli",
        "--flag",
        "value",
        input_data="request body",
        extra_env={"SAFE_CANARY": "visible"},
    )

    assert result.returncode == 0
    assert result.stdout == "ok\n"
    assert result.stderr == "note\n"
    (invocation,) = workspace.invocations("example-cli")
    assert invocation.argv == ("--flag", "value")
    assert invocation.cwd == workspace.cwd
    assert invocation.executable == workspace.executable("example-cli")
    assert invocation.stdin == b"request body"
    assert invocation.env["SAFE_CANARY"] == "visible"
    assert invocation.env["PATH"] == str(workspace.bin_dir)
    assert invocation.env["RAPTOR_CC_TRANSPORT_DISABLED"] == "1"
    for key in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "RAPTOR_LLM_SOCKET",
        "CLAUDECODE",
        "_RAPTOR_TRUSTED",
    ):
        assert key not in invocation.env
    for key in (
        "HOME",
        "COPILOT_HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
        "TMPDIR",
        "RAPTOR_CONFIG",
        "RAPTOR_OUT_DIR",
    ):
        _assert_below(invocation.env[key], workspace.root)
    assert workspace.raptor_config.read_text(encoding="utf-8") == ('{"models":[]}\n')


def test_child_imports_cache_production_state_under_isolated_home(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    repo_root = Path(__file__).resolve().parents[3]
    probe = (
        "import json\n"
        "from core.project import sessions\n"
        "from core.project.project import PROJECTS_DIR\n"
        "print(json.dumps({\n"
        "    'sessions': str(sessions.SESSIONS_DIR),\n"
        "    'projects': str(PROJECTS_DIR),\n"
        "}))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
        cwd=repo_root,
        env=workspace.child_env(),
    )
    assert result.returncode == 0, result.stderr
    paths = json.loads(result.stdout)
    _assert_below(paths["sessions"], workspace.root)
    _assert_below(paths["projects"], workspace.root)


def test_binary_stdin_is_captured_without_protocol_assumptions(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli("bytes-cli", FakeCLIBehavior())
    payload = b"\x00request\xff\n"
    result = subprocess.run(
        ["bytes-cli"],
        input=payload,
        capture_output=True,
        timeout=5,
        check=False,
        cwd=workspace.cwd,
        env=workspace.child_env(),
    )
    assert result.returncode == 0
    (invocation,) = workspace.invocations("bytes-cli")
    assert invocation.stdin == payload


def test_secret_env_observation_is_keyed_and_never_records_raw_value(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "secret-cli",
        FakeCLIBehavior(secret_env_names=("COPILOT_GITHUB_TOKEN",)),
    )
    canary = "synthetic-secret-canary"
    env = workspace.child_env()
    env["COPILOT_GITHUB_TOKEN"] = canary

    result = subprocess.run(
        workspace.command("secret-cli"),
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        cwd=workspace.cwd,
        env=env,
    )

    assert result.returncode == 0
    (invocation,) = workspace.invocations("secret-cli")
    assert "COPILOT_GITHUB_TOKEN" not in invocation.env
    assert len(invocation.secret_env) == 1
    observation = invocation.secret_env[0]
    assert observation.name == "COPILOT_GITHUB_TOKEN"
    assert observation.present is True
    assert observation.length == len(canary)
    assert observation.hmac_sha256 == (workspace.secret_observation_hmac(canary))
    encoded = (
        canary.encode(),
        base64.b64encode(canary.encode()),
        base64.urlsafe_b64encode(canary.encode()),
    )
    for event in workspace.log_dir.iterdir():
        payload = event.read_bytes()
        assert all(value not in payload for value in encoded)


def test_owned_executable_capability_rejects_content_and_inode_swaps(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli("owned-cli", FakeCLIBehavior())
    capability = workspace.owned_executable("owned-cli")
    executable = workspace.executable("owned-cli")

    replacement = executable.with_name("replacement")
    shutil.copy2(executable, replacement)
    replacement.chmod(0o700)
    replacement.replace(executable)

    from core.security.fake_executable import verify_owned_fake_executable

    with pytest.raises(ValueError, match="identity"):
        verify_owned_fake_executable(capability)


def test_owned_executable_capability_rejects_symlink_mode_and_size_changes(
    tmp_path: Path,
) -> None:
    from core.security.fake_executable import (
        MAX_OWNED_FAKE_SCRIPT_BYTES,
        verify_owned_fake_executable,
    )

    symlink_workspace = make_hermetic_cli(
        tmp_path,
        workspace_name="symlink-capability",
    )
    symlink_workspace.configure_cli("owned-cli", FakeCLIBehavior())
    symlink_capability = symlink_workspace.owned_executable("owned-cli")
    executable = symlink_workspace.executable("owned-cli")
    moved = executable.with_name("owned-cli-original")
    executable.rename(moved)
    executable.symlink_to(moved)
    with pytest.raises(ValueError, match="opened safely"):
        verify_owned_fake_executable(symlink_capability)

    mode_workspace = make_hermetic_cli(
        tmp_path,
        workspace_name="mode-capability",
    )
    mode_workspace.configure_cli("owned-cli", FakeCLIBehavior())
    mode_capability = mode_workspace.owned_executable("owned-cli")
    mode_executable = mode_workspace.executable("owned-cli")
    mode_executable.chmod(0o720)
    with pytest.raises(ValueError, match="group/world writable"):
        verify_owned_fake_executable(mode_capability)

    size_workspace = make_hermetic_cli(
        tmp_path,
        workspace_name="size-capability",
    )
    size_workspace.configure_cli("owned-cli", FakeCLIBehavior())
    size_capability = size_workspace.owned_executable("owned-cli")
    size_executable = size_workspace.executable("owned-cli")
    size_executable.write_bytes(b"x" * (MAX_OWNED_FAKE_SCRIPT_BYTES + 1))
    size_executable.chmod(0o700)
    with pytest.raises(ValueError, match="exceeds"):
        verify_owned_fake_executable(size_capability)


def test_malformed_owned_executable_capability_is_rejected() -> None:
    from core.security.fake_executable import verify_owned_fake_executable

    with pytest.raises(ValueError, match="not issued"):
        verify_owned_fake_executable(object())


@pytest.mark.parametrize("name", ["copilot", "claude"])
def test_guarded_cli_names_cannot_fall_through_to_operator_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    marker = tmp_path / f"operator-{name}-ran"
    operator_bin = tmp_path / "operator-bin"
    operator_bin.mkdir(exist_ok=True)
    operator_cli = operator_bin / name
    operator_cli.write_text(
        f"#!{Path(sys.executable).resolve()}\n"
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).touch()\n",
        encoding="utf-8",
    )
    operator_cli.chmod(0o700)
    monkeypatch.setenv("PATH", str(operator_bin))

    workspace = make_hermetic_cli(tmp_path)
    env = workspace.child_env()
    assert shutil.which(name, path=env["PATH"]) == str(workspace.executable(name))
    result = _run(workspace, name)

    assert result.returncode == FAKE_CLI_GUARD_EXIT
    assert f"live CLI '{name}' is disabled" in result.stderr
    assert not marker.exists()


def test_partial_output_nonzero_exit_and_flood_are_real_process_effects(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "failure-cli",
        FakeCLIBehavior(
            stdout="partial\n",
            stderr="failed\n",
            exit_code=23,
        ),
    )
    failed = _run(workspace, "failure-cli")
    assert failed.returncode == 23
    assert failed.stdout == "partial\n"
    assert failed.stderr == "failed\n"

    workspace.configure_cli(
        "flood-cli",
        FakeCLIBehavior(
            stdout="x" * 64,
            stderr="y" * 32,
            stdout_repeat=4096,
            stderr_repeat=4096,
        ),
    )
    flooded = _run(workspace, "flood-cli")
    assert flooded.returncode == 0
    assert len(flooded.stdout) == 64 * 4096
    assert len(flooded.stderr) == 32 * 4096


def test_delay_supports_timeout_with_observable_partial_output(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "hanging-cli",
        FakeCLIBehavior(
            stdout="ready\n",
            read_stdin=False,
            delay_seconds=5,
        ),
    )
    with pytest.raises(subprocess.TimeoutExpired) as raised:
        _run(workspace, "hanging-cli", timeout=0.15)
    output = raised.value.stdout
    if isinstance(output, bytes):
        output = output.decode("utf-8")
    assert output == "ready\n"
    (invocation,) = workspace.invocations("hanging-cli")
    with pytest.raises(ProcessLookupError):
        os.kill(invocation.pid, 0)


def test_child_and_grandchild_identities_form_expected_tree(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "tree-cli",
        FakeCLIBehavior(
            read_stdin=False,
            descendant_depth=2,
            descendant_delay_seconds=0.05,
        ),
    )
    result = _run(workspace, "tree-cli")
    assert result.returncode == 0

    (invocation,) = workspace.invocations("tree-cli")
    processes = workspace.processes("tree-cli")
    assert len(processes) == 2
    by_generation = {process.generation: process for process in processes}
    assert by_generation[1].role == "child"
    assert by_generation[1].ppid == invocation.pid
    assert by_generation[2].role == "grandchild"
    assert by_generation[2].ppid == by_generation[1].pid


def test_timeout_cleanup_uses_owned_process_group_not_logged_pids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "timeout-tree-cli",
        FakeCLIBehavior(
            stdout="ready\n",
            read_stdin=False,
            delay_seconds=5,
            descendant_depth=2,
            descendant_delay_seconds=5,
        ),
    )
    monkeypatch.setattr(
        os,
        "kill",
        lambda pid, sig: pytest.fail(
            f"timeout cleanup signaled logged PID {pid} with {sig}"
        ),
    )
    process = subprocess.Popen(
        ["timeout-tree-cli"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=workspace.cwd,
        env=workspace.child_env(),
        start_new_session=True,
    )
    try:
        forged = {
            "schema_version": 1,
            "event": "process",
            "cli": "timeout-tree-cli",
            "role": "child",
            "generation": 1,
            "pid": os.getpid(),
            "ppid": os.getpid(),
        }
        (workspace.log_dir / "process-forged-stale.json").write_text(
            json.dumps(forged),
            encoding="utf-8",
        )
        with pytest.raises(subprocess.TimeoutExpired):
            process.communicate(timeout=0.5)
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=2)
        assert process.returncode == -signal.SIGKILL
        records = workspace.processes("timeout-tree-cli")
        assert any(record.pid == os.getpid() for record in records)
        owned = [record for record in records if record.pid != os.getpid()]
        assert {record.role for record in owned} == {"child", "grandchild"}
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)


@pytest.mark.parametrize(
    "args",
    [
        (),
        ("not-an-integer", "0", "0"),
        ("3", "0", "0"),
        ("1", "2", "0"),
        ("2", "1", "0"),
        ("1", "0", "nan"),
    ],
)
def test_malformed_descendant_inputs_fail_without_spawning(
    tmp_path: Path,
    args: tuple[str, ...],
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli("descendant-input-cli", FakeCLIBehavior())
    env = workspace.child_env()
    env["_RAPTOR_FAKE_CLI_DESCENDANT"] = "1"
    result = subprocess.run(
        [
            str(workspace.executable("descendant-input-cli")),
            "--raptor-fake-cli-descendant",
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=2,
        check=False,
        cwd=workspace.cwd,
        env=env,
    )
    assert result.returncode == FAKE_CLI_CONFIG_ERROR
    assert "invalid descendant" in result.stderr
    assert workspace.processes("descendant-input-cli") == []


def test_malformed_config_fails_loudly_without_running_a_live_cli(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli("broken-cli", FakeCLIBehavior(stdout="unused"))
    workspace.config_path("broken-cli").write_text(
        "{not valid json",
        encoding="utf-8",
    )

    result = _run(workspace, "broken-cli")
    assert result.returncode == FAKE_CLI_CONFIG_ERROR
    assert "configuration error" in result.stderr
    assert result.stdout == ""
    assert workspace.invocations("broken-cli") == []


def test_paths_and_environment_overrides_cannot_escape_fixture_root(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="real directory"):
        make_hermetic_cli(linked_root)
    assert list(outside.iterdir()) == []

    workspace = make_hermetic_cli(tmp_path)
    with pytest.raises(ValueError, match="CLI name"):
        workspace.configure_cli("../escape", FakeCLIBehavior())
    assert not (tmp_path / "escape").exists()
    for key in (
        "HOME",
        "PATH",
        "COPILOT_HOME",
        "RAPTOR_CONFIG",
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "CLAUDECODE",
        "_RAPTOR_TRUSTED",
        "HTTPS_PROXY",
    ):
        with pytest.raises(ValueError, match="reserved|credential"):
            workspace.child_env({key: str(outside)})
    with pytest.raises(ValueError, match="must be absolute"):
        workspace.child_env({"RESULT_FILE": "relative.json"})
    with pytest.raises(ValueError, match="escapes fixture root"):
        workspace.child_env({"RESULT_FILE": str(outside / "result.json")})
    inside_result = workspace.root / "results" / "result.json"
    env = workspace.child_env({"RESULT_FILE": str(inside_result)})
    assert env["RESULT_FILE"] == str(inside_result)
    with pytest.raises(ValueError, match="invalid environment"):
        workspace.child_env({"BAD=NAME": "value"})
    with pytest.raises(ValueError, match="NUL"):
        workspace.child_env({"SAFE_VALUE": "bad\x00value"})
    assert not list(workspace.config_dir.glob("*.tmp"))


def test_canonical_unsafe_environment_families_cannot_be_overridden(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    unsafe = (
        set(RaptorConfig.DANGEROUS_ENV_VARS)
        | set(RaptorConfig.PROXY_ENV_VARS)
        | set(RaptorConfig.TARGET_ENV_STRIP_SET)
        | set(RaptorConfig.LLM_API_KEY_VARS)
        | set(RaptorConfig.LLM_ROUTING_ENV_VARS)
        | set(RaptorConfig.GIT_ENV_VARS)
        | set(GIT_ENV_STRIP)
        | {
            "COPILOT_HOME",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "RAPTOR_LLM_SOCKET",
        }
    )
    for key in sorted(unsafe):
        with pytest.raises(
            ValueError,
            match="reserved|credential|invalid environment",
        ):
            workspace.child_env({key: str(tmp_path / "outside")})
    for prefix in RaptorConfig.LLM_ROUTING_ENV_PREFIXES:
        with pytest.raises(ValueError, match="reserved|credential"):
            workspace.child_env({f"{prefix}TEST": "unsafe"})
    for prefix in GIT_ENV_STRIP_PREFIXES:
        with pytest.raises(ValueError, match="reserved|credential"):
            workspace.child_env({f"{prefix}0": "unsafe"})
    env = workspace.child_env()
    for key, value in RaptorConfig.GIT_ENV_VARS.items():
        assert env[key] == value


@pytest.mark.parametrize(
    ("relative", "label"),
    [
        ("cwd", "working"),
        ("home", "HOME"),
        ("copilot-home", "COPILOT_HOME"),
        ("xdg/config", "XDG config"),
        ("tmp", "temporary"),
        ("raptor/out", "RAPTOR output"),
    ],
)
def test_child_environment_rejects_symlinked_fixture_directories(
    tmp_path: Path,
    relative: str,
    label: str,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    path = workspace.root / relative
    original = path.with_name(f"original-{path.name}")
    path.rename(original)
    outside = tmp_path / f"outside-{relative.replace('/', '-')}"
    outside.mkdir()
    path.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match=label):
        workspace.child_env()
    assert list(outside.iterdir()) == []


def test_child_environment_rejects_symlinked_raptor_config(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    outside = tmp_path / "outside-models.json"
    outside.write_text('{"models":[{"api_key":"canary"}]}\n', encoding="utf-8")
    workspace.raptor_config.unlink()
    workspace.raptor_config.symlink_to(outside)

    with pytest.raises(ValueError, match="RAPTOR config"):
        workspace.child_env()
    assert "canary" in outside.read_text(encoding="utf-8")


def test_bin_directory_replacement_cannot_steer_executable_write(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    original = workspace.root / "original-bin"
    workspace.bin_dir.rename(original)
    outside = tmp_path / "outside-bin"
    outside.mkdir()
    workspace.bin_dir.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="bin directory"):
        workspace.configure_cli("steered-cli", FakeCLIBehavior())
    assert not (outside / "steered-cli").exists()
    assert not (outside / "steered-cli.json").exists()


def test_config_directory_replacement_cannot_steer_config_write(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    original = workspace.root / "original-config"
    workspace.config_dir.rename(original)
    outside = tmp_path / "outside-config"
    outside.mkdir()
    workspace.config_dir.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="config directory"):
        workspace.configure_cli("steered-cli", FakeCLIBehavior())
    assert not (outside / "steered-cli.json").exists()


def test_generated_child_refuses_replaced_config_directory(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "config-root-cli",
        FakeCLIBehavior(stdout="must-not-run\n"),
    )
    env = workspace.child_env()
    original = workspace.root / "original-config"
    workspace.config_dir.rename(original)
    outside = tmp_path / "outside-config"
    outside.mkdir()
    shutil.copyfile(
        original / "config-root-cli.json",
        outside / "config-root-cli.json",
    )
    workspace.config_dir.symlink_to(outside, target_is_directory=True)

    result = subprocess.run(
        ["config-root-cli"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        cwd=workspace.cwd,
        env=env,
    )
    assert result.returncode == FAKE_CLI_CONFIG_ERROR
    assert "configuration error" in result.stderr
    assert result.stdout == ""


def test_generated_child_refuses_replaced_log_directory(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "log-root-cli",
        FakeCLIBehavior(stdout="must-not-run\n"),
    )
    env = workspace.child_env()
    original = workspace.root / "original-logs"
    workspace.log_dir.rename(original)
    outside = tmp_path / "outside-logs"
    outside.mkdir()
    workspace.log_dir.symlink_to(outside, target_is_directory=True)

    result = subprocess.run(
        ["log-root-cli"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        cwd=workspace.cwd,
        env=env,
    )
    assert result.returncode == FAKE_CLI_CONFIG_ERROR
    assert "invocation capture error" in result.stderr
    assert result.stdout == ""
    assert list(outside.iterdir()) == []
    with pytest.raises(ValueError, match="logs directory"):
        workspace.invocations()


def test_non_regular_event_records_are_rejected_without_following_links(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    outside = tmp_path / "outside-event.json"
    outside.write_text('{"operator":"data"}\n', encoding="utf-8")
    (workspace.log_dir / "invocation-forged.json").symlink_to(outside)

    with pytest.raises(ValueError, match="not a regular file|opened safely"):
        workspace.invocations()
    assert outside.read_text(encoding="utf-8") == '{"operator":"data"}\n'


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo unavailable")
def test_fifo_event_is_rejected_without_blocking(tmp_path: Path) -> None:
    workspace = make_hermetic_cli(tmp_path)
    fifo = workspace.log_dir / "invocation-fifo.json"
    os.mkfifo(fifo)
    outcome: list[BaseException] = []

    def read_events() -> None:
        try:
            workspace.invocations()
        except BaseException as exc:  # noqa: BLE001 - captured for assertion
            outcome.append(exc)

    thread = threading.Thread(target=read_events, daemon=True)
    thread.start()
    thread.join(timeout=0.5)
    blocked = thread.is_alive()
    if blocked:
        writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(writer)
        thread.join(timeout=1)
    assert not blocked, "invocations() blocked opening a FIFO"
    assert len(outcome) == 1
    assert isinstance(outcome[0], ValueError)
    assert "not a regular file" in str(outcome[0])


def test_oversized_and_malformed_events_fail_explicitly(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    oversized = workspace.log_dir / "invocation-oversized.json"
    oversized.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="exceeds"):
        workspace.invocations()
    oversized.unlink()

    malformed = workspace.log_dir / "invocation-malformed.json"
    malformed.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid fake CLI event"):
        workspace.invocations()


def test_symlinked_config_is_rejected_without_reading_outside_fixture(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli("linked-cli", FakeCLIBehavior(stdout="unsafe"))
    outside = tmp_path / "outside-config.json"
    outside.write_text(
        json.dumps(FakeCLIBehavior(stdout="escaped").as_config("linked-cli")),
        encoding="utf-8",
    )
    config = workspace.config_path("linked-cli")
    config.unlink()
    config.symlink_to(outside)

    result = _run(workspace, "linked-cli")
    assert result.returncode == FAKE_CLI_CONFIG_ERROR
    assert "configuration error" in result.stderr
    assert result.stdout == ""
    assert outside.read_text(encoding="utf-8").startswith("{")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo unavailable")
def test_fifo_config_is_rejected_without_blocking(tmp_path: Path) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli("fifo-config-cli", FakeCLIBehavior())
    config = workspace.config_path("fifo-config-cli")
    config.unlink()
    os.mkfifo(config)

    result = _run(workspace, "fifo-config-cli", timeout=1)
    assert result.returncode == FAKE_CLI_CONFIG_ERROR
    assert "configuration error" in result.stderr


def test_missing_and_oversized_config_fail_explicitly(tmp_path: Path) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli("bounded-config-cli", FakeCLIBehavior())
    config = workspace.config_path("bounded-config-cli")
    config.unlink()

    missing = _run(workspace, "bounded-config-cli")
    assert missing.returncode == FAKE_CLI_CONFIG_ERROR
    assert "configuration error" in missing.stderr

    config.write_bytes(b" " * (1024 * 1024 + 1))
    oversized = _run(workspace, "bounded-config-cli")
    assert oversized.returncode == FAKE_CLI_CONFIG_ERROR
    assert "exceeds" in oversized.stderr


@pytest.mark.parametrize(
    "marker",
    [
        "__CLI_NAME__",
        "__WORKSPACE_ROOT__",
        "__ROOT_IDENTITY__",
        "__CONFIG_IDENTITY__",
        "__LOG_IDENTITY__",
        "__MAX_CONFIG_BYTES__",
        "__MAX_EVENT_BYTES__",
    ],
)
def test_template_marker_shaped_names_and_paths_are_literal_data(
    tmp_path: Path,
    marker: str,
) -> None:
    test_root = tmp_path / f"path-{marker}"
    test_root.mkdir()
    workspace = make_hermetic_cli(
        test_root,
        workspace_name=f"workspace-{marker}",
    )
    cli_name = f"cli-{marker}"
    workspace.configure_cli(
        cli_name,
        FakeCLIBehavior(stdout=f"{marker}\n"),
    )

    result = _run(workspace, cli_name)
    assert result.returncode == 0
    assert result.stdout == f"{marker}\n"
    (invocation,) = workspace.invocations(cli_name)
    assert marker in str(invocation.executable)


_FD_REUSE_DRIVER = r"""
import errno
import json
import os
import sys
import threading
from pathlib import Path

from core.testing import fake_cli as module

root = Path(sys.argv[1])
failure_label = sys.argv[2]
root.mkdir(mode=0o700)
assert threading.active_count() == 1


def identity(fd):
    st = os.fstat(fd)
    return st.st_dev, st.st_ino


def assert_released(record):
    fd, expected_identity, label = record
    try:
        current_identity = identity(fd)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
    else:
        if current_identity == expected_identity:
            raise AssertionError(f"owned descriptor leaked: {label}")


original_path = module._open_directory_path
original_at = module._open_directory_at
acquired = []


def record(fd, label):
    acquired.append((fd, identity(fd), label))
    return fd


def track_path(path, *, label, expected=None):
    return record(
        original_path(path, label=label, expected=expected),
        label,
    )


sentinel_fd = os.open(
    root / "caller-owned-sentinel",
    os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
    0o600,
)
sentinel_identity = identity(sentinel_fd)
noise_fd = os.open(
    root / "controlled-noise",
    os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
    0o600,
)
noise_identity = identity(noise_fd)
noise_closed = False


def fail_at_label(parent_fd, name, *, label, expected=None):
    global noise_closed
    if label == failure_label:
        os.close(noise_fd)
        noise_closed = True
        raise ValueError(f"forced {label} acquisition failure")
    return record(
        original_at(
            parent_fd,
            name,
            label=label,
            expected=expected,
        ),
        label,
    )


module._open_directory_path = track_path
module._open_directory_at = fail_at_label
try:
    module.make_hermetic_cli(
        root,
        workspace_name=f"driver-failure-{failure_label}",
    )
except ValueError as exc:
    expected_error = f"forced {failure_label} acquisition failure"
    if str(exc) != expected_error:
        raise
else:
    raise AssertionError("construction unexpectedly succeeded")

if not noise_closed:
    raise AssertionError("controlled noise descriptor was not closed")
assert_released((noise_fd, noise_identity, "controlled noise"))
if identity(sentinel_fd) != sentinel_identity:
    raise AssertionError("caller-owned sentinel identity changed")
for acquired_record in acquired:
    assert_released(acquired_record)

target_fd = acquired[-1][0]
reuse_path = root / "owned-reuse-target"
reuse_fds = []
try:
    for _index in range(64):
        fd = os.open(
            reuse_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        reuse_fds.append(fd)
        if fd == target_fd:
            break
        if fd > target_fd:
            raise AssertionError("released descriptor number was not available")
    else:
        raise AssertionError("released descriptor number was not reacquired")

    for acquired_record in acquired:
        assert_released(acquired_record)
    if identity(sentinel_fd) != sentinel_identity:
        raise AssertionError("caller-owned sentinel identity changed after reuse")
finally:
    for fd in reversed(reuse_fds):
        os.close(fd)
    os.close(sentinel_fd)

workspace = root / f"driver-failure-{failure_label}"
if not workspace.is_dir() or not (workspace / "raptor" / "models.json").is_file():
    raise AssertionError("partial diagnostic workspace was not retained")
print(
    json.dumps(
        {
            "acquired_labels": [record[2] for record in acquired],
            "reused_fd": target_fd,
            "status": "ok",
        },
        sort_keys=True,
    )
)
"""


@pytest.mark.parametrize("failure_label", ["bin", "config", "logs"])
def test_create_closes_staged_directory_fds_and_keeps_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_label: str,
) -> None:
    original_path = fake_cli_module._open_directory_path
    original_at = fake_cli_module._open_directory_at
    acquired: list[tuple[int, tuple[int, int], str]] = []

    def identity(fd: int) -> tuple[int, int]:
        st = os.fstat(fd)
        return st.st_dev, st.st_ino

    def assert_resource_released(
        fd: int,
        expected_identity: tuple[int, int],
    ) -> None:
        try:
            current_identity = identity(fd)
        except OSError as exc:
            assert exc.errno == errno.EBADF
        else:
            assert current_identity != expected_identity

    def assert_resource_unchanged(
        fd: int,
        expected_identity: tuple[int, int],
    ) -> None:
        try:
            current_identity = identity(fd)
        except OSError as exc:
            pytest.fail(f"caller-owned sentinel descriptor was closed: {exc}")
        assert current_identity == expected_identity

    def close_if_same_resource(
        fd: int,
        expected_identity: tuple[int, int],
    ) -> None:
        try:
            current_identity = identity(fd)
        except OSError:
            return
        if current_identity == expected_identity:
            os.close(fd)

    def record(fd: int, label: str) -> int:
        acquired.append((fd, identity(fd), label))
        return fd

    def track_path(path, *, label, expected=None):
        return record(
            original_path(path, label=label, expected=expected),
            label,
        )

    def fail_at_label(parent_fd, name, *, label, expected=None):
        if label == failure_label:
            os.close(noise_fd)
            noise_closed.set()
            raise ValueError(f"forced {label} acquisition failure")
        return record(
            original_at(
                parent_fd,
                name,
                label=label,
                expected=expected,
            ),
            label,
        )

    sentinel_path = tmp_path / "caller-owned-sentinel"
    sentinel_fd = os.open(
        sentinel_path,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    sentinel_identity = identity(sentinel_fd)
    noise_path = tmp_path / "unrelated-count-perturbation"
    noise_fd = os.open(
        noise_path,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    noise_identity = identity(noise_fd)
    noise_closed = threading.Event()
    workspace_name = f"fd-failure-{failure_label}"
    try:
        try:
            with monkeypatch.context() as patch:
                patch.setattr(fake_cli_module, "_open_directory_path", track_path)
                patch.setattr(fake_cli_module, "_open_directory_at", fail_at_label)
                with pytest.raises(
                    ValueError,
                    match=f"^forced {failure_label} acquisition failure$",
                ):
                    make_hermetic_cli(tmp_path, workspace_name=workspace_name)
        finally:
            if not noise_closed.is_set():
                close_if_same_resource(noise_fd, noise_identity)

        assert noise_closed.is_set()
        assert_resource_released(noise_fd, noise_identity)
        assert_resource_unchanged(sentinel_fd, sentinel_identity)
        expected_labels = {
            "bin": ["test root", "workspace root", "XDG root", "RAPTOR root"],
            "config": [
                "test root",
                "workspace root",
                "XDG root",
                "RAPTOR root",
                "bin",
            ],
            "logs": [
                "test root",
                "workspace root",
                "XDG root",
                "RAPTOR root",
                "bin",
                "config",
            ],
        }[failure_label]
        assert [label for _fd, _identity, label in acquired] == expected_labels
        for fd, expected_identity, _label in acquired:
            assert_resource_released(fd, expected_identity)

        driver_root = tmp_path / f"fd-reuse-driver-{failure_label}"
        driver_env = RaptorConfig.get_safe_env()
        driver_env["PYTHONDONTWRITEBYTECODE"] = "1"
        driver = subprocess.run(
            [
                sys.executable,
                "-c",
                _FD_REUSE_DRIVER,
                str(driver_root),
                failure_label,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            cwd=Path(__file__).resolve().parents[3],
            env=driver_env,
        )
        assert driver.returncode == 0, driver.stderr
        driver_result = json.loads(driver.stdout)
        assert driver_result["status"] == "ok"
        assert driver_result["acquired_labels"] == expected_labels
        assert_resource_unchanged(sentinel_fd, sentinel_identity)

        workspace = tmp_path / workspace_name
        assert workspace.is_dir()
        assert (workspace / "raptor" / "models.json").is_file()
    finally:
        close_if_same_resource(sentinel_fd, sentinel_identity)


def test_create_failure_never_removes_preexisting_workspace(
    tmp_path: Path,
) -> None:
    existing = tmp_path / "existing-workspace"
    existing.mkdir()
    canary = existing / "keep-me"
    canary.write_text("owned by caller\n", encoding="utf-8")

    with pytest.raises(FileExistsError):
        make_hermetic_cli(tmp_path, workspace_name=existing.name)
    assert canary.read_text(encoding="utf-8") == "owned by caller\n"


def test_create_failure_never_deletes_path_replaced_with_caller_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "rollback-case"
    original_helper_directory = tmp_path / "original-helper-directory"
    caller_directory = tmp_path / "preexisting-sibling"
    caller_directory.mkdir()
    canary = caller_directory / "keep.txt"
    canary.write_text("caller-owned\n", encoding="utf-8")
    original = fake_cli_module._open_directory_at

    def replace_then_fail(parent_fd, name, *, label, expected=None):
        if label == "config":
            workspace.rename(original_helper_directory)
            caller_directory.rename(workspace)
            raise ValueError("forced config acquisition failure")
        return original(
            parent_fd,
            name,
            label=label,
            expected=expected,
        )

    with monkeypatch.context() as patch:
        patch.setattr(
            fake_cli_module,
            "_open_directory_at",
            replace_then_fail,
        )
        with pytest.raises(ValueError, match="forced config"):
            make_hermetic_cli(tmp_path, workspace_name=workspace.name)

    assert (workspace / "keep.txt").read_text(encoding="utf-8") == "caller-owned\n"
    assert original_helper_directory.is_dir()


def test_concurrent_workspaces_do_not_share_binaries_env_or_logs(
    tmp_path: Path,
) -> None:
    first = make_hermetic_cli(tmp_path, workspace_name="first")
    second = make_hermetic_cli(tmp_path, workspace_name="second")
    first.configure_cli("same-name", FakeCLIBehavior(stdout="first\n"))
    second.configure_cli("same-name", FakeCLIBehavior(stdout="second\n"))

    def invoke(workspace, canary):
        return _run(
            workspace,
            "same-name",
            canary,
            extra_env={"CASE_CANARY": canary},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(invoke, first, "one")
        second_future = executor.submit(invoke, second, "two")
        first_result = first_future.result(timeout=10)
        second_result = second_future.result(timeout=10)

    assert first_result.stdout == "first\n"
    assert second_result.stdout == "second\n"
    (first_call,) = first.invocations("same-name")
    (second_call,) = second.invocations("same-name")
    assert first_call.argv == ("one",)
    assert first_call.env["CASE_CANARY"] == "one"
    assert first_call.executable == first.executable("same-name")
    assert second_call.argv == ("two",)
    assert second_call.env["CASE_CANARY"] == "two"
    assert second_call.executable == second.executable("same-name")
    assert first_call.pid != second_call.pid
