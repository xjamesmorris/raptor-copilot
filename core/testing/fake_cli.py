"""Protocol-neutral fake CLI processes for hermetic tests.

The helper creates real executable children under a caller-owned pytest
temporary directory.  It intentionally knows nothing about Claude or Copilot
wire formats: tests configure raw stdin/stdout/stderr/process behaviour, then
assert on recorded argv, cwd, environment, input, and process identities.

The child environment is built from scratch rather than copied from
``os.environ``.  ``PATH`` contains only fixture-owned executables, and loud
default guards occupy the ``claude`` and ``copilot`` names.  Thus ambient
credentials are not inherited and a missing fake cannot fall through to an
operator's installed CLI. Caller-supplied opaque canary values remain the
caller's responsibility. Absolute-path production spawn guards remain the
responsibility of the provider adapter that owns that spawn boundary.
Configured ``secret_env_names`` are removed from the captured environment and
represented only by name, presence, length, and an HMAC under a fixture-random
observation key. ``_root_identity`` remains the workspace device/inode tuple;
a separate random nonce identifies the generating fixture instance.

The generated program uses ``subprocess.Popen`` only for its optional,
fixture-owned child/grandchild process shape.  Direct execution of the fake in
tests follows the established launcher-test precedent: the executable,
configuration, cwd, environment, and all writable paths are confined to the
pytest temporary root, and no shell is involved.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from core.config import RaptorConfig
from core.security.fake_executable import (
    FAKE_EXECUTABLE_FACTORY_ID,
    OwnedFakeExecutable,
    _issue_owned_fake_executable,
)
from core.testing.git_hermeticity import (
    GIT_ENV_STRIP,
    GIT_ENV_STRIP_PREFIXES,
)

FAKE_CLI_CONFIG_ERROR = 94
FAKE_CLI_SPAWN_ERROR = 95
FAKE_CLI_GUARD_EXIT = 97

_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_EVENT_BYTES = 4 * 1024 * 1024

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_PROTECTED_ENV_KEYS = frozenset({
    "HOME",
    "COPILOT_HOME",
    "PATH",
    "PYTHONHOME",
    "PYTHONPATH",
    "RAPTOR_CONFIG",
    "RAPTOR_OUT_DIR",
    "RAPTOR_DIR",
    "RAPTOR_TEST_LIVE_LLM",
    "RAPTOR_CC_TRANSPORT_DISABLED",
    "TMPDIR",
    "VIRTUAL_ENV",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_STATE_HOME",
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "_RAPTOR_TRUSTED",
})
_CANONICAL_UNSAFE_ENV_KEYS = frozenset(
    key.upper()
    for key in (
        set(RaptorConfig.DANGEROUS_ENV_VARS)
        | set(RaptorConfig.PROXY_ENV_VARS)
        | set(RaptorConfig.TARGET_ENV_STRIP_SET)
        | set(RaptorConfig.LLM_API_KEY_VARS)
        | set(RaptorConfig.LLM_ROUTING_ENV_VARS)
        | set(RaptorConfig.GIT_ENV_VARS)
        | set(GIT_ENV_STRIP)
        | {
            "COPILOT_HOME",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "RAPTOR_LLM_SOCKET",
            "RAPTOR_LLM_TOKEN_FD",
            "SSH_AUTH_SOCK",
        }
    )
)
_CANONICAL_UNSAFE_ENV_PREFIXES = tuple(
    prefix.upper()
    for prefix in (
        *RaptorConfig.LLM_ROUTING_ENV_PREFIXES,
        *GIT_ENV_STRIP_PREFIXES,
    )
)
_SECRET_ENV_SUFFIXES = (
    "_API_KEY",
    "_CREDENTIAL",
    "_CREDENTIALS",
    "_PASSWORD",
    "_SECRET",
    "_TOKEN",
)
_PATH_ENV_SUFFIXES = (
    "_DIR",
    "_FILE",
    "_HOME",
    "_PATH",
    "_SOCKET",
)
_INTERNAL_ENV_PREFIX = "_RAPTOR_FAKE_CLI_"
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)

_SCRIPT_BODY = r'''
import base64
import fcntl
import hashlib
import hmac
import json
import math
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

CONFIG_ERROR_EXIT = 94
SPAWN_ERROR_EXIT = 95
INTERNAL_MARKER = "_RAPTOR_FAKE_CLI_DESCENDANT"
INTERNAL_ARG = "--raptor-fake-cli-descendant"
DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def _secret_observations(env, names):
    key = base64.b64decode(SECRET_OBSERVATION_KEY_B64, validate=True)
    observations = []
    for name in names:
        value = env.pop(name, None)
        present = value is not None
        encoded = (
            value.encode("utf-8", errors="surrogateescape")
            if present else b""
        )
        observations.append({
            "name": name,
            "present": present,
            "length": len(encoded),
            "hmac_sha256": (
                hmac.new(key, encoded, hashlib.sha256).hexdigest()
                if present else None
            ),
        })
    return observations


def _stdin_descriptor():
    try:
        target = os.readlink("/proc/self/fd/0")
    except OSError:
        target = ""
    try:
        access = fcntl.fcntl(0, fcntl.F_GETFL) & os.O_ACCMODE
    except OSError:
        return target, "unknown"
    if access == os.O_RDONLY:
        return target, "read_only"
    if access == os.O_WRONLY:
        return target, "write_only"
    return target, "read_write"


def _fail(message, code):
    sys.stderr.write("RAPTOR fake CLI: " + message + "\n")
    sys.stderr.flush()
    return code


def _number(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(field + " must be a finite number")
    value = float(value)
    if not math.isfinite(value) or value < 0 or value > 86400:
        raise ValueError(field + " must be between 0 and 86400")
    return value


def _integer(value, field, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(field + " must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(
            field + " must be between " + str(minimum) + " and "
            + str(maximum)
        )
    return value


def _identity(st):
    return st.st_dev, st.st_ino


def _open_workspace_dir(name, label, expected):
    try:
        root_fd = os.open(WORKSPACE_ROOT, DIRECTORY_FLAGS)
    except OSError as exc:
        raise ValueError(
            "workspace root directory cannot be opened safely: " + str(exc)
        ) from exc
    try:
        if _identity(os.fstat(root_fd)) != ROOT_IDENTITY:
            raise ValueError("workspace root directory identity changed")
        try:
            fd = os.open(name, DIRECTORY_FLAGS, dir_fd=root_fd)
        except OSError as exc:
            raise ValueError(
                label + " directory cannot be opened safely: " + str(exc)
            ) from exc
    finally:
        os.close(root_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or _identity(st) != expected:
            raise ValueError(label + " directory identity changed")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_capped_at(dir_fd, name, max_bytes, label):
    try:
        fd = os.open(name, READ_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        raise ValueError(label + " cannot be opened safely: " + str(exc)) \
            from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(label + " is not a regular file")
        if st.st_size > max_bytes:
            raise ValueError(
                label + " exceeds " + str(max_bytes) + " bytes"
            )
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(
                label + " exceeds " + str(max_bytes) + " bytes"
            )
        return data
    finally:
        os.close(fd)


def _load_config():
    config_fd = _open_workspace_dir(
        "config", "config", CONFIG_IDENTITY
    )
    try:
        raw = _read_capped_at(
            config_fd,
            CLI_NAME + ".json",
            MAX_CONFIG_BYTES,
            "configuration",
        )
    finally:
        os.close(config_fd)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("configuration is not valid UTF-8 JSON") from exc
    required = {
        "schema_version",
        "name",
        "stdout",
        "stderr",
        "exit_code",
        "read_stdin",
        "delay_seconds",
        "stdout_repeat",
        "stderr_repeat",
        "descendant_depth",
        "descendant_delay_seconds",
        "secret_env_names",
    }
    if not isinstance(data, dict) or set(data) != required:
        raise ValueError("configuration fields do not match schema v2")
    if data["schema_version"] != 2:
        raise ValueError("unsupported configuration schema")
    if data["name"] != CLI_NAME:
        raise ValueError("name does not match the executable")
    if not isinstance(data["stdout"], str):
        raise ValueError("stdout must be a string")
    if not isinstance(data["stderr"], str):
        raise ValueError("stderr must be a string")
    data["exit_code"] = _integer(data["exit_code"], "exit_code", 0, 255)
    if not isinstance(data["read_stdin"], bool):
        raise ValueError("read_stdin must be a boolean")
    data["delay_seconds"] = _number(
        data["delay_seconds"], "delay_seconds"
    )
    data["stdout_repeat"] = _integer(
        data["stdout_repeat"], "stdout_repeat", 0, 1000000
    )
    data["stderr_repeat"] = _integer(
        data["stderr_repeat"], "stderr_repeat", 0, 1000000
    )
    data["descendant_depth"] = _integer(
        data["descendant_depth"], "descendant_depth", 0, 2
    )
    data["descendant_delay_seconds"] = _number(
        data["descendant_delay_seconds"], "descendant_delay_seconds"
    )
    names = data["secret_env_names"]
    if not isinstance(names, list) or not all(
        isinstance(name, str) and name
        for name in names
    ):
        raise ValueError("secret_env_names must be a string list")
    if len(set(names)) != len(names):
        raise ValueError("secret_env_names must not contain duplicates")
    return data


def _write_event(kind, payload):
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_EVENT_BYTES:
        raise ValueError(
            "event exceeds " + str(MAX_EVENT_BYTES) + " bytes"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    log_fd = _open_workspace_dir("logs", "logs", LOG_IDENTITY)
    try:
        for attempt in range(100):
            name = (
                kind + "-" + str(time.time_ns()) + "-" + str(os.getpid())
                + "-" + str(attempt) + ".json"
            )
            try:
                fd = os.open(name, flags, 0o600, dir_fd=log_fd)
            except FileExistsError:
                continue
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
            return
        raise OSError("could not allocate a unique event record")
    finally:
        os.close(log_fd)


def _sleep_while_parent_alive(delay, parent_pid):
    deadline = time.monotonic() + delay
    while True:
        if os.getppid() != parent_pid:
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return True
        time.sleep(min(remaining, 0.05))


def _descendant(config, generation, remaining, delay):
    parent_pid = os.getppid()
    role = "child" if generation == 1 else "grandchild"
    _write_event("process", {
        "schema_version": 1,
        "event": "process",
        "cli": config["name"],
        "role": role,
        "generation": generation,
        "pid": os.getpid(),
        "ppid": os.getppid(),
    })
    child = None
    if remaining:
        env = dict(os.environ)
        env[INTERNAL_MARKER] = "1"
        child = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                INTERNAL_ARG,
                str(generation + 1),
                str(remaining - 1),
                str(delay),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            close_fds=True,
        )
    if delay and not _sleep_while_parent_alive(delay, parent_pid):
        return 0
    if child is not None:
        child.wait()
    return 0


def _emit(stream, text, repeat):
    for _ in range(repeat):
        stream.write(text)
    stream.flush()


def main():
    try:
        config = _load_config()
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return _fail("configuration error: " + str(exc), CONFIG_ERROR_EXIT)

    if os.environ.get(INTERNAL_MARKER) == "1":
        if len(sys.argv) != 5 or sys.argv[1] != INTERNAL_ARG:
            return _fail("invalid descendant arguments", CONFIG_ERROR_EXIT)
        try:
            generation = _integer(
                int(sys.argv[2]), "generation", 1, 2
            )
            remaining = _integer(
                int(sys.argv[3]), "remaining", 0, 1
            )
            delay = _number(float(sys.argv[4]), "delay")
            if remaining > 2 - generation:
                raise ValueError("remaining exceeds descendant depth")
        except ValueError:
            return _fail("invalid descendant values", CONFIG_ERROR_EXIT)
        try:
            return _descendant(config, generation, remaining, delay)
        except (OSError, ValueError) as exc:
            return _fail("descendant error: " + str(exc), SPAWN_ERROR_EXIT)

    try:
        stdin_data = (
            sys.stdin.buffer.read() if config["read_stdin"] else b""
        )
        env = dict(sorted(os.environ.items()))
        secret_env = _secret_observations(
            env,
            config["secret_env_names"],
        )
        stdin_fd_target, stdin_fd_access = _stdin_descriptor()
        _write_event("invocation", {
            "schema_version": 1,
            "event": "invocation",
            "cli": config["name"],
            "argv": sys.argv[1:],
            "executable": str(Path(sys.argv[0]).resolve()),
            "cwd": os.getcwd(),
            "env": env,
            "secret_env": secret_env,
            "stdin_b64": base64.b64encode(stdin_data).decode("ascii"),
            "stdin_size": len(stdin_data),
            "stdin_fd_target": stdin_fd_target,
            "stdin_fd_access": stdin_fd_access,
            "pid": os.getpid(),
            "ppid": os.getppid(),
        })
    except (OSError, ValueError) as exc:
        return _fail("invocation capture error: " + str(exc), CONFIG_ERROR_EXIT)

    child = None
    if config["descendant_depth"]:
        env = dict(os.environ)
        env[INTERNAL_MARKER] = "1"
        try:
            child = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    INTERNAL_ARG,
                    "1",
                    str(config["descendant_depth"] - 1),
                    str(config["descendant_delay_seconds"]),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
                close_fds=True,
            )
        except OSError as exc:
            return _fail("could not spawn descendant: " + str(exc),
                         SPAWN_ERROR_EXIT)

    _emit(sys.stdout, config["stdout"], config["stdout_repeat"])
    _emit(sys.stderr, config["stderr"], config["stderr_repeat"])
    if config["delay_seconds"]:
        time.sleep(config["delay_seconds"])
    if child is not None:
        child.wait()
    return config["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _validate_name(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not _NAME_RE.fullmatch(value):
        raise ValueError(
            f"{field} must match {_NAME_RE.pattern!r}; got {value!r}"
        )
    if value in {".", ".."}:
        raise ValueError(f"{field} cannot be {value!r}")
    return value


def _validate_text(value: str, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    if "\x00" in value:
        raise ValueError(f"{field} cannot contain NUL")
    return value


def _validate_number(value: float, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field} must be a number")
    value = float(value)
    if not math.isfinite(value) or not 0 <= value <= 86400:
        raise ValueError(f"{field} must be between 0 and 86400")
    return value


def _validate_integer(
    value: int,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(
            f"{field} must be between {minimum} and {maximum}"
        )
    return value


@dataclass(frozen=True)
class FakeCLIBehavior:
    """Raw process behaviour for one fake executable."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    read_stdin: bool = True
    delay_seconds: float = 0.0
    stdout_repeat: int = 1
    stderr_repeat: int = 1
    descendant_depth: int = 0
    descendant_delay_seconds: float = 0.0
    secret_env_names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_text(self.stdout, field="stdout")
        _validate_text(self.stderr, field="stderr")
        _validate_integer(
            self.exit_code, field="exit_code", minimum=0, maximum=255
        )
        if not isinstance(self.read_stdin, bool):
            raise TypeError("read_stdin must be a boolean")
        _validate_number(self.delay_seconds, field="delay_seconds")
        _validate_integer(
            self.stdout_repeat,
            field="stdout_repeat",
            minimum=0,
            maximum=1_000_000,
        )
        _validate_integer(
            self.stderr_repeat,
            field="stderr_repeat",
            minimum=0,
            maximum=1_000_000,
        )
        _validate_integer(
            self.descendant_depth,
            field="descendant_depth",
            minimum=0,
            maximum=2,
        )
        _validate_number(
            self.descendant_delay_seconds,
            field="descendant_delay_seconds",
        )
        if not isinstance(self.secret_env_names, tuple):
            raise TypeError("secret_env_names must be a tuple")
        if len(self.secret_env_names) > 64:
            raise ValueError(
                "secret_env_names cannot contain more than 64 names"
            )
        if len(set(self.secret_env_names)) != len(self.secret_env_names):
            raise ValueError("secret_env_names must not contain duplicates")
        for name in self.secret_env_names:
            if not isinstance(name, str) or not _ENV_NAME_RE.fullmatch(name):
                raise ValueError(
                    f"invalid secret environment variable name: {name!r}"
                )

    def as_config(self, name: str) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "name": name,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "read_stdin": self.read_stdin,
            "delay_seconds": self.delay_seconds,
            "stdout_repeat": self.stdout_repeat,
            "stderr_repeat": self.stderr_repeat,
            "descendant_depth": self.descendant_depth,
            "descendant_delay_seconds": self.descendant_delay_seconds,
            "secret_env_names": list(self.secret_env_names),
        }


@dataclass(frozen=True)
class FakeCLISecretObservation:
    """Keyed observation of one secret environment variable."""

    name: str
    present: bool
    length: int
    hmac_sha256: str | None


@dataclass(frozen=True)
class FakeCLIInvocation:
    """One captured top-level fake CLI invocation."""

    cli: str
    argv: tuple[str, ...]
    executable: Path
    cwd: Path
    env: dict[str, str]
    secret_env: tuple[FakeCLISecretObservation, ...]
    stdin: bytes
    stdin_fd_target: str
    stdin_fd_access: str
    pid: int
    ppid: int


@dataclass(frozen=True)
class FakeCLIProcess:
    """One captured fake child or grandchild identity."""

    cli: str
    role: str
    generation: int
    pid: int
    ppid: int


def _identity(st: os.stat_result) -> tuple[int, int]:
    return st.st_dev, st.st_ino


def _open_directory_path(
    path: Path,
    *,
    label: str,
    expected: tuple[int, int] | None = None,
) -> int:
    try:
        fd = os.open(str(path), _DIRECTORY_FLAGS)
    except OSError as exc:
        raise ValueError(
            f"{label} directory cannot be opened safely: {exc}"
        ) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError(f"{label} directory is not a directory")
        if expected is not None and _identity(st) != expected:
            raise ValueError(f"{label} directory identity changed")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_directory_at(
    parent_fd: int,
    name: str,
    *,
    label: str,
    expected: tuple[int, int] | None = None,
) -> int:
    try:
        fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise ValueError(
            f"{label} directory cannot be opened safely: {exc}"
        ) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError(f"{label} directory is not a directory")
        if expected is not None and _identity(st) != expected:
            raise ValueError(f"{label} directory identity changed")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_relative_directory(
    root_fd: int,
    relative: str,
    *,
    label: str,
) -> int:
    """Open a fixture-relative directory one component at a time."""
    current = os.dup(root_fd)
    try:
        for component in relative.split("/"):
            if not component or component in {".", ".."}:
                raise ValueError(
                    f"{label} directory has an invalid relative path"
                )
            nxt = _open_directory_at(current, component, label=label)
            os.close(current)
            current = nxt
        return current
    except BaseException:
        os.close(current)
        raise


def _write_new_file_at(
    dir_fd: int,
    name: str,
    data: bytes,
    mode: int,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    fd = os.open(name, flags, mode, dir_fd=dir_fd)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _write_atomic_json_at(
    dir_fd: int,
    name: str,
    payload: Mapping[str, Any],
) -> None:
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if len(encoded) > _MAX_CONFIG_BYTES:
        raise ValueError(
            f"fake CLI configuration exceeds {_MAX_CONFIG_BYTES} bytes"
        )
    temporary = f".{name}.{uuid.uuid4().hex}.tmp"
    try:
        _write_new_file_at(dir_fd, temporary, encoded, 0o600)
        os.replace(
            temporary,
            name,
            src_dir_fd=dir_fd,
            dst_dir_fd=dir_fd,
        )
    finally:
        try:
            os.unlink(temporary, dir_fd=dir_fd)
        except FileNotFoundError:
            pass


def _read_capped_at(
    dir_fd: int,
    name: str,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    """Directory-FD variant of ``core.security.capped_read.read_capped``.

    The shared helper establishes the required O_NONBLOCK/O_NOFOLLOW,
    descriptor-level regular-file check, and max+1 read. This local variant
    adds ``dir_fd`` so a replaced parent component cannot redirect the read.
    """
    try:
        fd = os.open(name, _READ_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        raise ValueError(f"{label} cannot be opened safely: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{label} is not a regular file")
        if st.st_size > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} bytes")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} bytes")
        return data
    finally:
        os.close(fd)


def _read_event_at(dir_fd: int, name: str) -> dict[str, Any]:
    raw = _read_capped_at(
        dir_fd,
        name,
        max_bytes=_MAX_EVENT_BYTES,
        label=f"fake CLI event {name}",
    )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid fake CLI event {name}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError(f"invalid fake CLI event schema: {name}")
    return payload


def _parse_invocation(payload: Mapping[str, Any]) -> FakeCLIInvocation:
    try:
        if payload["event"] != "invocation":
            raise ValueError("wrong event kind")
        argv = payload["argv"]
        env = payload["env"]
        secret_env = payload["secret_env"]
        if not isinstance(argv, list) or not all(
            isinstance(item, str) for item in argv
        ):
            raise ValueError("argv is not a string list")
        if not isinstance(env, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in env.items()
        ):
            raise ValueError("env is not a string mapping")
        if not isinstance(secret_env, list):
            raise ValueError("secret_env is not a list")
        parsed_secret_env = []
        for observation in secret_env:
            if not isinstance(observation, dict):
                raise ValueError("secret_env entry is not an object")
            name = observation["name"]
            present = observation["present"]
            length = observation["length"]
            digest = observation["hmac_sha256"]
            if not isinstance(name, str) or not _ENV_NAME_RE.fullmatch(name):
                raise ValueError("secret_env name is invalid")
            if not isinstance(present, bool):
                raise ValueError("secret_env present is not boolean")
            if type(length) is not int or length < 0:
                raise ValueError("secret_env length is invalid")
            if digest is not None and (
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise ValueError("secret_env hmac_sha256 is invalid")
            if present != (digest is not None):
                raise ValueError("secret_env presence and digest disagree")
            parsed_secret_env.append(
                FakeCLISecretObservation(
                    name=name,
                    present=present,
                    length=length,
                    hmac_sha256=digest,
                )
            )
        stdin = base64.b64decode(payload["stdin_b64"], validate=True)
        if len(stdin) != payload["stdin_size"]:
            raise ValueError("stdin size does not match payload")
        return FakeCLIInvocation(
            cli=str(payload["cli"]),
            argv=tuple(argv),
            executable=Path(payload["executable"]),
            cwd=Path(payload["cwd"]),
            env=dict(env),
            secret_env=tuple(parsed_secret_env),
            stdin=stdin,
            stdin_fd_target=str(payload["stdin_fd_target"]),
            stdin_fd_access=str(payload["stdin_fd_access"]),
            pid=int(payload["pid"]),
            ppid=int(payload["ppid"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid fake CLI invocation: {exc}") from exc


def _parse_process(payload: Mapping[str, Any]) -> FakeCLIProcess:
    try:
        if payload["event"] != "process":
            raise ValueError("wrong event kind")
        role = payload["role"]
        if role not in {"child", "grandchild"}:
            raise ValueError("unknown process role")
        return FakeCLIProcess(
            cli=str(payload["cli"]),
            role=role,
            generation=int(payload["generation"]),
            pid=int(payload["pid"]),
            ppid=int(payload["ppid"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid fake CLI process event: {exc}") from exc


def _extra_env_key_allowed(key: str) -> bool:
    upper = key.upper()
    if key in _PROTECTED_ENV_KEYS:
        return False
    if key.startswith(_INTERNAL_ENV_PREFIX):
        return False
    if upper in _CANONICAL_UNSAFE_ENV_KEYS:
        return False
    if upper.startswith(_CANONICAL_UNSAFE_ENV_PREFIXES):
        return False
    return not upper.endswith(_SECRET_ENV_SUFFIXES)


@dataclass(frozen=True)
class HermeticCLIWorkspace:
    """Fixture-owned fake executables plus an isolated child environment."""

    root: Path
    bin_dir: Path
    config_dir: Path
    log_dir: Path
    cwd: Path
    home: Path
    copilot_home: Path
    xdg_config_home: Path
    xdg_cache_home: Path
    xdg_data_home: Path
    xdg_state_home: Path
    xdg_runtime_dir: Path
    tmp_dir: Path
    raptor_out_dir: Path
    raptor_config: Path
    _root_identity: tuple[int, int]
    _bin_identity: tuple[int, int]
    _config_identity: tuple[int, int]
    _log_identity: tuple[int, int]
    _factory_nonce: str
    _secret_observation_key: bytes

    @classmethod
    def create(
        cls,
        test_root: Path,
        *,
        workspace_name: str = "hermetic-cli",
        guarded_commands: Sequence[str] = ("copilot", "claude"),
    ) -> "HermeticCLIWorkspace":
        """Create a fresh workspace below an existing, non-symlink root.

        On failure, opened descriptors are closed but partially created files
        are intentionally retained for diagnostics. The caller owns
        ``test_root`` (normally pytest's ``tmp_path``) and therefore owns its
        eventual cleanup. This method never recursively deletes a mutable
        pathname during error handling.
        """
        workspace_name = _validate_name(
            workspace_name, field="workspace_name"
        )
        test_root = Path(test_root)
        if not test_root.is_absolute():
            raise ValueError("test_root must be absolute")
        try:
            root_stat = test_root.lstat()
        except FileNotFoundError as exc:
            raise FileNotFoundError(
                f"test_root does not exist: {test_root}"
            ) from exc
        if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(
            root_stat.st_mode
        ):
            raise ValueError("test_root must be a real directory, not a link")
        test_root = test_root.resolve(strict=True)
        root = test_root / workspace_name
        test_root_fd = _open_directory_path(test_root, label="test root")
        try:
            os.mkdir(workspace_name, 0o700, dir_fd=test_root_fd)
            root_fd = _open_directory_at(
                test_root_fd,
                workspace_name,
                label="workspace root",
            )
        finally:
            os.close(test_root_fd)
        try:
            for name in (
                "bin",
                "config",
                "logs",
                "cwd",
                "home",
                "copilot-home",
                "tmp",
                "xdg",
                "raptor",
            ):
                os.mkdir(name, 0o700, dir_fd=root_fd)

            xdg_fd = _open_directory_at(
                root_fd, "xdg", label="XDG root"
            )
            try:
                for name in ("config", "cache", "data", "state", "runtime"):
                    os.mkdir(name, 0o700, dir_fd=xdg_fd)
            finally:
                os.close(xdg_fd)

            raptor_fd = _open_directory_at(
                root_fd, "raptor", label="RAPTOR root"
            )
            try:
                os.mkdir("out", 0o700, dir_fd=raptor_fd)
                _write_new_file_at(
                    raptor_fd,
                    "models.json",
                    b'{"models":[]}\n',
                    0o600,
                )
            finally:
                os.close(raptor_fd)

            with contextlib.ExitStack() as stack:
                bin_fd = _open_directory_at(
                    root_fd, "bin", label="bin"
                )
                stack.callback(os.close, bin_fd)
                config_fd = _open_directory_at(
                    root_fd, "config", label="config"
                )
                stack.callback(os.close, config_fd)
                log_fd = _open_directory_at(
                    root_fd, "logs", label="logs"
                )
                stack.callback(os.close, log_fd)
                root_identity = _identity(os.fstat(root_fd))
                bin_identity = _identity(os.fstat(bin_fd))
                config_identity = _identity(os.fstat(config_fd))
                log_identity = _identity(os.fstat(log_fd))
        finally:
            os.close(root_fd)

        directories = {
            "bin_dir": root / "bin",
            "config_dir": root / "config",
            "log_dir": root / "logs",
            "cwd": root / "cwd",
            "home": root / "home",
            "copilot_home": root / "copilot-home",
            "xdg_config_home": root / "xdg" / "config",
            "xdg_cache_home": root / "xdg" / "cache",
            "xdg_data_home": root / "xdg" / "data",
            "xdg_state_home": root / "xdg" / "state",
            "xdg_runtime_dir": root / "xdg" / "runtime",
            "tmp_dir": root / "tmp",
            "raptor_out_dir": root / "raptor" / "out",
        }
        raptor_config = root / "raptor" / "models.json"
        workspace = cls(
            root=root,
            raptor_config=raptor_config,
            _root_identity=root_identity,
            _bin_identity=bin_identity,
            _config_identity=config_identity,
            _log_identity=log_identity,
            _factory_nonce=secrets.token_hex(16),
            _secret_observation_key=secrets.token_bytes(32),
            **directories,
        )
        for command in guarded_commands:
            name = _validate_name(command, field="guarded command")
            workspace.configure_cli(
                name,
                FakeCLIBehavior(
                    stderr=(
                        "RAPTOR TEST GUARD: live CLI "
                        f"{name!r} is disabled; configure an explicit fake.\n"
                    ),
                    exit_code=FAKE_CLI_GUARD_EXIT,
                    read_stdin=False,
                ),
            )
        return workspace

    def _open_root_dir(self) -> int:
        return _open_directory_path(
            self.root,
            label="workspace root",
            expected=self._root_identity,
        )

    def _open_owned_dir(
        self,
        name: str,
        *,
        label: str,
        expected: tuple[int, int],
    ) -> int:
        root_fd = self._open_root_dir()
        try:
            return _open_directory_at(
                root_fd,
                name,
                label=label,
                expected=expected,
            )
        finally:
            os.close(root_fd)

    def _render_script(self, name: str) -> bytes:
        python = str(Path(sys.executable).resolve())
        if "\n" in python or "\r" in python:
            raise ValueError("Python executable path contains a newline")
        prelude = (
            f"#!{python}\n"
            "from __future__ import annotations\n\n"
            f"CLI_NAME = {name!r}\n"
            f"FAKE_CLI_FACTORY_ID = {FAKE_EXECUTABLE_FACTORY_ID!r}\n"
            f"FACTORY_NONCE = {self._factory_nonce!r}\n"
            "SECRET_OBSERVATION_KEY_B64 = "
            f"{base64.b64encode(self._secret_observation_key).decode('ascii')!r}\n"
            f"WORKSPACE_ROOT = {str(self.root)!r}\n"
            f"ROOT_IDENTITY = {self._root_identity!r}\n"
            f"CONFIG_IDENTITY = {self._config_identity!r}\n"
            f"LOG_IDENTITY = {self._log_identity!r}\n"
            f"MAX_CONFIG_BYTES = {_MAX_CONFIG_BYTES}\n"
            f"MAX_EVENT_BYTES = {_MAX_EVENT_BYTES}\n\n"
        )
        return f"{prelude}{_SCRIPT_BODY.lstrip()}".encode("utf-8")

    def config_path(self, name: str) -> Path:
        name = _validate_name(name, field="CLI name")
        config_fd = self._open_owned_dir(
            "config",
            label="config",
            expected=self._config_identity,
        )
        os.close(config_fd)
        return self.config_dir / f"{name}.json"

    def executable(self, name: str) -> Path:
        name = _validate_name(name, field="CLI name")
        bin_fd = self._open_owned_dir(
            "bin",
            label="bin",
            expected=self._bin_identity,
        )
        try:
            try:
                fd = os.open(name, _READ_FLAGS, dir_fd=bin_fd)
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f"fake CLI is not installed: {name}"
                ) from exc
            except OSError as exc:
                raise ValueError(
                    f"fake CLI cannot be opened safely: {name}: {exc}"
                ) from exc
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ValueError(
                        f"fake CLI is not a regular file: {name}"
                    )
            finally:
                os.close(fd)
        finally:
            os.close(bin_fd)
        return self.bin_dir / name

    def command(self, name: str, *args: str) -> list[str]:
        for arg in args:
            _validate_text(arg, field="CLI argument")
        return [str(self.executable(name)), *args]

    def owned_executable(self, name: str) -> OwnedFakeExecutable:
        """Return the opaque execution capability for a configured fake."""
        name = _validate_name(name, field="CLI name")
        executable = self.executable(name)
        config_fd = self._open_owned_dir(
            "config",
            label="config",
            expected=self._config_identity,
        )
        try:
            config = _read_capped_at(
                config_fd,
                f"{name}.json",
                max_bytes=_MAX_CONFIG_BYTES,
                label="configuration",
            )
        finally:
            os.close(config_fd)
        try:
            payload = json.loads(config.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("fake CLI configuration is invalid") from exc
        secret_env_names = payload.get("secret_env_names")
        if not isinstance(secret_env_names, list):
            raise ValueError("fake CLI configuration lacks secret_env_names")
        return _issue_owned_fake_executable(
            path=executable,
            workspace_root=self.root,
            config_path=self.config_path(name),
            log_dir=self.log_dir,
            executable_name=name,
            expected_script=self._render_script(name),
            expected_config=config,
            factory_nonce=self._factory_nonce,
            observation_key=self._secret_observation_key,
            root_identity=self._root_identity,
            bin_identity=self._bin_identity,
            config_identity=self._config_identity,
            log_identity=self._log_identity,
            secret_env_names=tuple(secret_env_names),
        )

    def secret_observation_hmac(self, value: str) -> str:
        """Return the HMAC the fake records for ``value``."""
        _validate_text(value, field="secret observation value")
        return hmac.new(
            self._secret_observation_key,
            value.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def configure_cli(
        self,
        name: str,
        behavior: FakeCLIBehavior,
    ) -> Path:
        """Install or atomically reconfigure one fixture-owned executable."""
        name = _validate_name(name, field="CLI name")
        if not isinstance(behavior, FakeCLIBehavior):
            raise TypeError("behavior must be a FakeCLIBehavior")
        bin_fd = self._open_owned_dir(
            "bin",
            label="bin",
            expected=self._bin_identity,
        )
        try:
            config_fd = self._open_owned_dir(
                "config",
                label="config",
                expected=self._config_identity,
            )
        except BaseException:
            os.close(bin_fd)
            raise
        try:
            try:
                fd = os.open(name, _READ_FLAGS, dir_fd=bin_fd)
            except FileNotFoundError:
                _write_new_file_at(
                    bin_fd,
                    name,
                    self._render_script(name),
                    0o700,
                )
            except OSError as exc:
                raise ValueError(
                    f"fake CLI cannot be opened safely: {name}: {exc}"
                ) from exc
            else:
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        raise ValueError(
                            f"fake CLI is not a regular file: {name}"
                        )
                finally:
                    os.close(fd)
            _write_atomic_json_at(
                config_fd,
                f"{name}.json",
                behavior.as_config(name),
            )
        finally:
            os.close(config_fd)
            os.close(bin_fd)
        return self.bin_dir / name

    def child_env(
        self,
        extra_env: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        """Return a non-inheriting environment rooted in this workspace.

        Ambient variables never enter the mapping. Caller overrides are
        screened against RAPTOR's canonical dangerous/proxy/target/LLM
        families and the fixture's pinned roots. Arbitrary permitted canary
        names and values remain caller-owned test data; this helper cannot
        infer whether a deliberately supplied opaque value is a secret.
        """
        for name, label, expected in (
            ("bin", "bin", self._bin_identity),
            ("config", "config", self._config_identity),
            ("logs", "logs", self._log_identity),
        ):
            fd = self._open_owned_dir(
                name,
                label=label,
                expected=expected,
            )
            os.close(fd)
        root_fd = self._open_root_dir()
        try:
            for relative, label in (
                ("cwd", "working"),
                ("home", "HOME"),
                ("copilot-home", "COPILOT_HOME"),
                ("xdg/config", "XDG config"),
                ("xdg/cache", "XDG cache"),
                ("xdg/data", "XDG data"),
                ("xdg/state", "XDG state"),
                ("xdg/runtime", "XDG runtime"),
                ("tmp", "temporary"),
                ("raptor/out", "RAPTOR output"),
            ):
                fd = _open_relative_directory(
                    root_fd,
                    relative,
                    label=label,
                )
                os.close(fd)
            raptor_fd = _open_relative_directory(
                root_fd,
                "raptor",
                label="RAPTOR config",
            )
            try:
                config_fd = os.open(
                    "models.json",
                    _READ_FLAGS,
                    dir_fd=raptor_fd,
                )
                try:
                    if not stat.S_ISREG(os.fstat(config_fd).st_mode):
                        raise ValueError(
                            "RAPTOR config is not a regular file"
                        )
                finally:
                    os.close(config_fd)
            except OSError as exc:
                raise ValueError(
                    f"RAPTOR config cannot be opened safely: {exc}"
                ) from exc
            finally:
                os.close(raptor_fd)
        finally:
            os.close(root_fd)
        env = {
            "PATH": str(self.bin_dir),
            "HOME": str(self.home),
            "COPILOT_HOME": str(self.copilot_home),
            "XDG_CONFIG_HOME": str(self.xdg_config_home),
            "XDG_CACHE_HOME": str(self.xdg_cache_home),
            "XDG_DATA_HOME": str(self.xdg_data_home),
            "XDG_STATE_HOME": str(self.xdg_state_home),
            "XDG_RUNTIME_DIR": str(self.xdg_runtime_dir),
            "TMPDIR": str(self.tmp_dir),
            "RAPTOR_CONFIG": str(self.raptor_config),
            "RAPTOR_OUT_DIR": str(self.raptor_out_dir),
            "RAPTOR_CC_TRANSPORT_DISABLED": "1",
            **RaptorConfig.GIT_ENV_VARS,
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUNBUFFERED": "1",
        }
        for key, value in (extra_env or {}).items():
            if not isinstance(key, str) or not _ENV_NAME_RE.fullmatch(key):
                raise ValueError(f"invalid environment variable name: {key!r}")
            if not _extra_env_key_allowed(key):
                raise ValueError(
                    f"environment variable is reserved or credential-shaped: "
                    f"{key}"
                )
            value = _validate_text(value, field=f"environment {key}")
            if key.upper().endswith(_PATH_ENV_SUFFIXES):
                candidate = Path(value)
                if not candidate.is_absolute():
                    raise ValueError(
                        f"path-shaped environment variable must be absolute: "
                        f"{key}"
                    )
                try:
                    candidate.resolve(strict=False).relative_to(self.root)
                except ValueError as exc:
                    raise ValueError(
                        f"path-shaped environment variable escapes fixture "
                        f"root: {key}"
                    ) from exc
            env[key] = value
        return env

    def invocations(self, name: str | None = None) -> list[FakeCLIInvocation]:
        if name is not None:
            name = _validate_name(name, field="CLI name")
        log_fd = self._open_owned_dir(
            "logs",
            label="logs",
            expected=self._log_identity,
        )
        try:
            events = []
            for filename in sorted(os.listdir(log_fd)):
                if not (
                    filename.startswith("invocation-")
                    and filename.endswith(".json")
                ):
                    continue
                invocation = _parse_invocation(
                    _read_event_at(log_fd, filename)
                )
                if name is None or invocation.cli == name:
                    events.append(invocation)
            return events
        finally:
            os.close(log_fd)

    def processes(self, name: str | None = None) -> list[FakeCLIProcess]:
        if name is not None:
            name = _validate_name(name, field="CLI name")
        log_fd = self._open_owned_dir(
            "logs",
            label="logs",
            expected=self._log_identity,
        )
        try:
            events = []
            for filename in sorted(os.listdir(log_fd)):
                if not (
                    filename.startswith("process-")
                    and filename.endswith(".json")
                ):
                    continue
                process = _parse_process(_read_event_at(log_fd, filename))
                if name is None or process.cli == name:
                    events.append(process)
            return events
        finally:
            os.close(log_fd)


def make_hermetic_cli(
    test_root: Path,
    *,
    workspace_name: str = "hermetic-cli",
    guarded_commands: Sequence[str] = ("copilot", "claude"),
) -> HermeticCLIWorkspace:
    """Convenience constructor for pytest ``tmp_path`` fixtures."""
    return HermeticCLIWorkspace.create(
        test_root,
        workspace_name=workspace_name,
        guarded_commands=guarded_commands,
    )


__all__ = [
    "FAKE_CLI_CONFIG_ERROR",
    "FAKE_CLI_GUARD_EXIT",
    "FAKE_CLI_SPAWN_ERROR",
    "FakeCLIBehavior",
    "FakeCLIInvocation",
    "FakeCLIProcess",
    "FakeCLISecretObservation",
    "HermeticCLIWorkspace",
    "OwnedFakeExecutable",
    "make_hermetic_cli",
]
