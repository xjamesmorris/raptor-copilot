"""Thin coverage shim and retired-helper regression contracts."""

from __future__ import annotations

import ast
import contextlib
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from core.coverage import track_read
from core.coverage.tests.test_track_read_session import (
    _owned_claude,
    _owner_env,
    _write_run,
)
from core.project import sessions
from core.run.host_events import MAX_HOST_EVENT_BYTES

REPO_ROOT = Path(__file__).resolve().parents[3]
HOOK = REPO_ROOT / "plugins" / "coverage" / "libexec" / "raptor-hook-read"
RETIRED_HELPER = REPO_ROOT / "plugins" / "coverage" / "libexec" / "raptor-hook-json"

_TEMPLATE_LINE = re.compile(
    rb"(?:"
    rb"raptor-hook-read: "
    rb"(?:trust marker absent|python3 unavailable|"
    rb"repository root unavailable|coverage helper failed \(rc=\d+\)); "
    rb"coverage read not recorded"
    rb"|raptor-read-hook\[[a-z0-9_]+\]: [ -~]+"
    rb")\n"
)


@contextlib.contextmanager
def _owned_hook_case(tmp_path: Path, monkeypatch, *, strong: bool = False):
    home = tmp_path / "home"
    home.mkdir()
    sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
    monkeypatch.setattr(sessions, "SESSIONS_DIR", sessions_dir)
    with _owned_claude(tmp_path, strong=strong) as (
        process,
        _executable,
        token,
        _claim,
    ):
        target = tmp_path / "target"
        target.mkdir()
        source = target / "a.py"
        source.write_text("x = 1\n")
        run_dir = _write_run(tmp_path, pid=process.pid, name="run1", target=str(target))
        yield {
            "env": _owner_env(home, process.pid, token),
            "source": source,
            "run_dir": run_dir,
        }


def _invoke(
    hook: Path,
    *,
    env: dict[str, str],
    payload: bytes = b"{}",
    stdin=None,
    timeout: float = 10,
) -> subprocess.CompletedProcess:
    kwargs = {
        "env": env,
        "capture_output": True,
        "timeout": timeout,
        "check": False,
    }
    if stdin is None:
        kwargs["input"] = payload
    else:
        kwargs["stdin"] = stdin
    return subprocess.run([str(hook)], **kwargs)


def _assert_template_lines(stderr: bytes, count: int) -> None:
    lines = stderr.splitlines(keepends=True)
    assert len(lines) == count, stderr
    assert all(_TEMPLATE_LINE.fullmatch(line) for line in lines), stderr


def _python_stub(directory: Path, body: str) -> tuple[Path, Path]:
    directory.mkdir(parents=True)
    marker = directory / "python-invoked"
    python = directory / "python3"
    python.write_text(
        f"#!/usr/bin/env bash\nMARKER={str(marker)!r}\n{body}\n",
        encoding="utf-8",
    )
    python.chmod(0o700)
    return python, marker


def _copy_shim_tree(tmp_path: Path, module_source: str) -> tuple[Path, Path]:
    root = tmp_path / "copied-root"
    hook = root / "plugins" / "coverage" / "libexec" / "raptor-hook-read"
    hook.parent.mkdir(parents=True)
    hook.write_bytes(HOOK.read_bytes())
    hook.chmod(0o700)
    for package in ("core", "core/coverage"):
        package_dir = root / package
        package_dir.mkdir(parents=True, exist_ok=True)
        (package_dir / "__init__.py").write_text("", encoding="utf-8")
    module = root / "core" / "coverage" / "track_read.py"
    module.write_text(module_source, encoding="utf-8")
    return root, hook


def test_n7_shim_static_contract_and_helper_retirement():
    text = HOOK.read_text(encoding="utf-8")
    code_lines = [
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    ]
    code = "\n".join(code_lines)

    assert "set -euo pipefail" in code
    assert "umask 077" in code
    assert 'cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/../../..' in code
    assert '$(dirname -- "${BASH_SOURCE[0]}")/../.."' not in code
    assert '[ -f "$REPO_ROOT/core/coverage/track_read.py" ]' in code
    assert code.count("python3 -E -s -m core.coverage.track_read 1>&2 2>/dev/null") == 1
    assert "exec python3" not in code
    assert "jq" not in code
    assert "tool_input" not in code
    assert "file_path" not in code
    assert "python3 -c" not in code
    assert "<<" not in code
    assert re.search(r"(^|[;&|]\s*)read(?:\s|$)", code, re.MULTILINE) is None
    assert "exit 0" in code
    assert not RETIRED_HELPER.exists()


def test_n7_track_read_has_only_stdlib_module_imports():
    tree = ast.parse(
        (REPO_ROOT / "core" / "coverage" / "track_read.py").read_text(encoding="utf-8")
    )
    imports = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports.extend(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append((node.module or "").split(".", 1)[0])

    assert set(imports) <= {
        "__future__",
        "dataclasses",
        "json",
        "logging",
        "os",
        "pathlib",
        "stat",
        "sys",
        "types",
        "typing",
    }


def test_n7_hook_contract_tests_do_not_require_git_history() -> None:
    source = Path(__file__).read_text(encoding="utf-8")

    for forbidden in (
        "git" + " show",
        "BASELINE_" + "HEAD",
        '["git", ' + '"show"',
    ):
        assert forbidden not in source


def test_n7_marker_gate_prevents_child_spawn(tmp_path):
    bindir = tmp_path / "bin"
    _python, marker = _python_stub(
        bindir,
        'printf invoked >"$MARKER"\nexit 0',
    )
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(tmp_path)}

    proc = _invoke(HOOK, env=env)

    assert proc.returncode == 0
    assert proc.stdout == b""
    _assert_template_lines(proc.stderr, 1)
    assert b"trust marker absent" in proc.stderr
    assert not marker.exists()


def test_e31_python_absent_is_one_fixed_line(tmp_path):
    empty_path = tmp_path / "empty-bin"
    empty_path.mkdir()
    env = {
        "PATH": str(empty_path),
        "HOME": str(tmp_path),
        "_RAPTOR_TRUSTED": "1",
    }

    proc = subprocess.run(
        ["/usr/bin/bash", str(HOOK)],
        input=b"{}",
        env=env,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert proc.returncode == 0
    assert proc.stdout == b""
    _assert_template_lines(proc.stderr, 1)
    assert b"python3 unavailable" in proc.stderr


def test_n7_relocated_shim_fails_before_child_spawn(tmp_path):
    root = tmp_path / "relocated"
    relocated = root / "plugins" / "coverage" / "libexec" / HOOK.name
    relocated.parent.mkdir(parents=True)
    relocated.write_bytes(HOOK.read_bytes())
    relocated.chmod(0o700)
    bindir = tmp_path / "bin"
    _python, marker = _python_stub(
        bindir,
        'printf invoked >"$MARKER"\nexit 0',
    )
    env = {
        "PATH": f"{bindir}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "_RAPTOR_TRUSTED": "1",
    }

    proc = _invoke(relocated, env=env)

    assert proc.returncode == 0
    assert proc.stdout == b""
    _assert_template_lines(proc.stderr, 1)
    assert b"repository root unavailable" in proc.stderr
    assert not marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_n7_real_and_directory_symlinked_hook_paths_run_module(
    tmp_path,
    monkeypatch,
):
    for through_symlink in (False, True):
        case_root = tmp_path / f"case-{through_symlink}"
        case_root.mkdir()
        with _owned_hook_case(case_root, monkeypatch) as case:
            selected = HOOK
            if through_symlink:
                plugin_link = case_root / "plugin-link"
                plugin_link.symlink_to(
                    REPO_ROOT / "plugins" / "coverage",
                    target_is_directory=True,
                )
                selected = plugin_link / "libexec" / HOOK.name
            proc = _invoke(
                selected,
                env=case["env"],
                payload=json.dumps(
                    {
                        "tool_input": {"file_path": str(case["source"])},
                    }
                ).encode(),
            )
            manifest = case["run_dir"] / track_read.MANIFEST_NAME

        assert proc.returncode == 0
        assert proc.stdout == b""
        assert proc.stderr == b""
        assert manifest.read_bytes() == (str(case["source"].resolve()) + "\n").encode()


def test_n7_hostile_pythonpath_is_ignored(tmp_path):
    evil = tmp_path / "evil"
    module = evil / "core" / "coverage" / "track_read.py"
    module.parent.mkdir(parents=True)
    (evil / "core" / "__init__.py").write_text("", encoding="utf-8")
    (evil / "core" / "coverage" / "__init__.py").write_text("", encoding="utf-8")
    marker = tmp_path / "hijacked"
    module.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
        encoding="utf-8",
    )
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path),
        "PYTHONPATH": str(evil),
        "_RAPTOR_TRUSTED": "1",
    }

    proc = _invoke(HOOK, env=env, payload=b"{not json")

    assert proc.returncode == 0
    assert proc.stdout == b""
    _assert_template_lines(proc.stderr, 1)
    assert not marker.exists()


@pytest.mark.parametrize(
    "error",
    [
        OSError("SECRET expected os error"),
        ValueError("SECRET expected value error"),
    ],
    ids=["oserror", "valueerror"],
)
def test_t2_entry_expected_errors_emit_once_and_restore_logging(
    monkeypatch,
    capsys,
    error,
):
    previous_disable = logging.root.manager.disable

    def fail():
        raise error

    monkeypatch.setattr(track_read, "_run_hook", fail)
    result = track_read._entry()
    captured = capsys.readouterr()

    assert result == 0
    assert captured.out == (
        "raptor-read-hook[hook_failed]: coverage helper failed safely\n"
    )
    assert captured.err == ""
    assert "SECRET" not in captured.out
    assert logging.root.manager.disable == previous_disable


def test_ambiguous_diagnostic_is_specific(capsys):
    track_read._diag("ambiguous")
    captured = capsys.readouterr()
    assert captured.out == (
        "raptor-read-hook[ambiguous]: "
        "multiple owned running runs are active\n"
    )
    assert captured.err == ""


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_t3_idle_owned_session_real_shim_is_silent(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
    monkeypatch.setattr(sessions, "SESSIONS_DIR", sessions_dir)
    with _owned_claude(tmp_path, strong=False) as (
        process,
        _executable,
        token,
        _claim,
    ):
        source = tmp_path / "source.py"
        source.write_text("x = 1\n")
        proc = _invoke(
            HOOK,
            env=_owner_env(home, process.pid, token),
            payload=json.dumps({"tool_input": {"file_path": str(source)}}).encode(),
        )

    assert proc.returncode == 0
    assert proc.stdout == b""
    assert proc.stderr == b""
    assert list(tmp_path.rglob(track_read.MANIFEST_NAME)) == []


def test_e31_pre_entry_python_failure_suppresses_child_text(tmp_path):
    bindir = tmp_path / "bin"
    _python_stub(
        bindir,
        "printf 'SECRET fake traceback\\n' >&2\nexit 1",
    )
    env = {
        "PATH": f"{bindir}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "_RAPTOR_TRUSTED": "1",
    }

    proc = _invoke(HOOK, env=env)

    assert proc.returncode == 0
    assert proc.stdout == b""
    _assert_template_lines(proc.stderr, 1)
    assert b"coverage helper failed (rc=1)" in proc.stderr
    assert b"SECRET" not in proc.stderr


def test_e31_post_entry_core_import_failure_is_sanitized(tmp_path):
    source = (REPO_ROOT / "core" / "coverage" / "track_read.py").read_text(
        encoding="utf-8"
    )
    root, hook = _copy_shim_tree(tmp_path, source)
    run_pkg = root / "core" / "run"
    run_pkg.mkdir()
    (run_pkg / "__init__.py").write_text("", encoding="utf-8")
    (run_pkg / "host_events.py").write_text(
        "raise ImportError('SECRET import path')\n",
        encoding="utf-8",
    )
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path),
        "_RAPTOR_TRUSTED": "1",
    }

    proc = _invoke(hook, env=env)

    assert proc.returncode == 0
    assert proc.stdout == b""
    _assert_template_lines(proc.stderr, 1)
    assert b"core_import_failed" in proc.stderr
    assert b"SECRET" not in proc.stderr


@pytest.mark.parametrize(
    "payload",
    [
        b"{not json",
        b"x" * (1024 * 1024 + 1),
        b"",
    ],
    ids=["malformed", "oversize", "eof"],
)
def test_e31_malformed_oversize_and_eof_are_one_template_line(
    tmp_path,
    payload,
):
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path),
        "_RAPTOR_TRUSTED": "1",
    }

    proc = _invoke(HOOK, env=env, payload=payload)

    assert proc.returncode == 0
    assert proc.stdout == b""
    _assert_template_lines(proc.stderr, 1)


def test_e31_devnull_stdin_is_one_template_line(tmp_path):
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path),
        "_RAPTOR_TRUSTED": "1",
    }

    proc = _invoke(HOOK, env=env, stdin=subprocess.DEVNULL)

    assert proc.returncode == 0
    assert proc.stdout == b""
    _assert_template_lines(proc.stderr, 1)


@pytest.mark.parametrize(
    "payload",
    [
        {
            "session_id": "SECRET-session\n",
            "tool_input": {"file_path": "/owned/a.py"},
        },
        {
            "tool_input": {
                "file_path": "SECRET-/very/long/path\ninjected.py",
            },
        },
    ],
)
def test_n5_shim_diagnostics_never_echo_payload_canaries(tmp_path, payload):
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path),
        "_RAPTOR_TRUSTED": "1",
    }

    proc = _invoke(HOOK, env=env, payload=json.dumps(payload).encode())

    assert proc.returncode == 0
    assert proc.stdout == b""
    _assert_template_lines(proc.stderr, 1)
    assert b"SECRET" not in proc.stderr
    assert b"injected.py" not in proc.stderr


def test_e31_closed_stdin_is_one_template_line(tmp_path):
    wrapper = tmp_path / "close-stdin.py"
    wrapper.write_text(
        "import os, sys\n"
        "os.close(0)\n"
        "os.execve(sys.argv[1], [sys.argv[1], sys.argv[2]], os.environ)\n",
        encoding="utf-8",
    )
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path),
        "_RAPTOR_TRUSTED": "1",
    }

    proc = subprocess.run(
        [sys.executable, str(wrapper), "/usr/bin/bash", str(HOOK)],
        env=env,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert proc.returncode == 0
    assert proc.stdout == b""
    _assert_template_lines(proc.stderr, 1)


def test_e31_unforeseen_child_failure_is_one_shell_line(tmp_path):
    root, hook = _copy_shim_tree(
        tmp_path,
        "raise TypeError('SECRET unforeseen failure')\n",
    )
    assert root.is_dir()
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path),
        "_RAPTOR_TRUSTED": "1",
    }

    proc = _invoke(hook, env=env)

    assert proc.returncode == 0
    assert proc.stdout == b""
    _assert_template_lines(proc.stderr, 1)
    assert b"coverage helper failed (rc=1)" in proc.stderr
    assert b"SECRET" not in proc.stderr


def test_e31_unforeseen_after_emission_is_two_template_lines(tmp_path):
    _root, hook = _copy_shim_tree(
        tmp_path,
        "import sys\n"
        "sys.stdout.write('raptor-read-hook[io_refused]: "
        "coverage evidence write was refused\\n')\n"
        "sys.stdout.flush()\n"
        "raise TypeError('SECRET after emission')\n",
    )
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path),
        "_RAPTOR_TRUSTED": "1",
    }

    proc = _invoke(hook, env=env)

    assert proc.returncode == 0
    assert proc.stdout == b""
    _assert_template_lines(proc.stderr, 2)
    assert b"SECRET" not in proc.stderr


def test_e31_entry_propagates_unforeseen_errors(monkeypatch):
    def fail():
        raise TypeError("unforeseen")

    monkeypatch.setattr(track_read, "_run_hook", fail)
    with pytest.raises(TypeError, match="unforeseen"):
        track_read._entry()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
def test_t7_tool_response_counts_toward_real_shim_payload_budget(
    tmp_path,
    monkeypatch,
):
    with _owned_hook_case(tmp_path, monkeypatch) as case:
        in_budget = json.dumps(
            {
                "tool_input": {"file_path": str(case["source"])},
                "tool_response": "x" * (900 * 1024),
            }
        ).encode()
        assert 900 * 1024 < len(in_budget) < MAX_HOST_EVENT_BYTES
        positive = _invoke(HOOK, env=case["env"], payload=in_budget)
        manifest = case["run_dir"] / track_read.MANIFEST_NAME
        assert manifest.read_text(encoding="utf-8") == (
            str(case["source"].resolve()) + "\n"
        )
        manifest.unlink()

        over_budget = json.dumps(
            {
                "tool_input": {"file_path": str(case["source"])},
                "tool_response": "x" * MAX_HOST_EVENT_BYTES,
            }
        ).encode()
        assert len(over_budget) > MAX_HOST_EVENT_BYTES
        refused = _invoke(HOOK, env=case["env"], payload=over_budget)

    assert positive.returncode == 0
    assert positive.stdout == b""
    assert positive.stderr == b""
    assert refused.returncode == 0
    assert refused.stdout == b""
    _assert_template_lines(refused.stderr, 1)
    assert b"raptor-read-hook[budget]" in refused.stderr
    assert not manifest.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process identity")
@pytest.mark.parametrize("strong", [False, True], ids=["legacy", "strong"])
def test_e32_shim_writes_claude_manifest_contract_bytes(
    tmp_path,
    monkeypatch,
    strong,
):
    with _owned_hook_case(tmp_path, monkeypatch, strong=strong) as case:
        payload = json.dumps(
            {
                "tool_input": {"file_path": str(case["source"])},
            }
        ).encode()
        expected = (str(case["source"].resolve()) + "\n").encode()
        manifest = case["run_dir"] / track_read.MANIFEST_NAME
        result = _invoke(HOOK, env=case["env"], payload=payload)

    assert result.returncode == 0
    assert result.stdout == b""
    assert result.stderr == b""
    assert manifest.read_bytes() == expected
