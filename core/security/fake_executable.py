"""Narrow issuer and verifier for repository-owned fake executables.

This is a trusted in-process test boundary, not same-UID hard isolation.
Callers cannot promote a path or a receipt string into execution authority:
the fixture issuer binds an opaque object to the generated script, config,
workspace directories, and a process-local issuer MAC. The verifier then
reopens every path without following symlinks and checks the exact bytes and
inode identities again immediately before use.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

FAKE_EXECUTABLE_FACTORY_ID = "core.testing.fake_cli:v1"
MAX_OWNED_FAKE_SCRIPT_BYTES = 512 * 1024
MAX_OWNED_FAKE_CONFIG_BYTES = 1024 * 1024

_ISSUER_KEY = secrets.token_bytes(32)
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_DIR_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_CANARY_CONTEXT = b"raptor-copilot-level-a-canary-v1\0"


@dataclass(frozen=True, init=False, repr=False)
class OwnedFakeExecutable:
    """Opaque evidence that ``core.testing.fake_cli`` minted an executable."""

    path: Path
    workspace_root: Path
    config_path: Path
    log_dir: Path
    executable_name: str
    factory_id: str
    executable_device: int
    executable_inode: int
    executable_size: int
    executable_sha256: str
    config_device: int
    config_inode: int
    config_size: int
    config_sha256: str
    root_identity: tuple[int, int]
    bin_identity: tuple[int, int]
    config_identity: tuple[int, int]
    log_identity: tuple[int, int]
    secret_env_names: tuple[str, ...]
    _factory_nonce: str = field(repr=False)
    _observation_key: bytes = field(repr=False)
    _issuer_mac: str = field(repr=False)

    def __repr__(self) -> str:
        return (
            "OwnedFakeExecutable("
            f"path={self.path!r}, "
            f"factory_id={self.factory_id!r}, "
            f"sha256={self.executable_sha256!r})"
        )


def _identity(st: os.stat_result) -> tuple[int, int]:
    return st.st_dev, st.st_ino


def _open_dir(path: Path, *, label: str, expected: tuple[int, int]) -> int:
    try:
        fd = os.open(str(path), _DIR_FLAGS)
    except OSError as exc:
        raise ValueError(f"owned fake {label} cannot be opened safely: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError(f"owned fake {label} is not a directory")
        if _identity(st) != expected:
            raise ValueError(f"owned fake {label} identity changed")
        if st.st_uid != os.geteuid():
            raise ValueError(f"owned fake {label} is not caller-owned")
        if stat.S_IMODE(st.st_mode) & 0o022:
            raise ValueError(f"owned fake {label} is group/world writable")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_dir_at(
    parent_fd: int,
    name: str,
    *,
    label: str,
    expected: tuple[int, int],
) -> int:
    try:
        fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise ValueError(f"owned fake {label} cannot be opened safely: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError(f"owned fake {label} is not a directory")
        if _identity(st) != expected:
            raise ValueError(f"owned fake {label} identity changed")
        if st.st_uid != os.geteuid():
            raise ValueError(f"owned fake {label} is not caller-owned")
        if stat.S_IMODE(st.st_mode) & 0o022:
            raise ValueError(f"owned fake {label} is group/world writable")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_regular_at(
    dir_fd: int,
    name: str,
    *,
    label: str,
    max_bytes: int,
) -> tuple[bytes, os.stat_result]:
    try:
        fd = os.open(name, _READ_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        raise ValueError(f"owned fake {label} cannot be opened safely: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"owned fake {label} is not a regular file")
        if st.st_uid != os.geteuid():
            raise ValueError(f"owned fake {label} is not caller-owned")
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o022:
            raise ValueError(f"owned fake {label} is group/world writable")
        if st.st_size > max_bytes:
            raise ValueError(f"owned fake {label} exceeds {max_bytes} bytes")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"owned fake {label} exceeds {max_bytes} bytes")
        return data, st
    finally:
        os.close(fd)


def _proof_payload(capability: OwnedFakeExecutable) -> bytes:
    payload = {
        "bin_identity": list(capability.bin_identity),
        "config_device": capability.config_device,
        "config_identity": list(capability.config_identity),
        "config_inode": capability.config_inode,
        "config_path": str(capability.config_path),
        "config_sha256": capability.config_sha256,
        "config_size": capability.config_size,
        "executable_device": capability.executable_device,
        "executable_inode": capability.executable_inode,
        "executable_name": capability.executable_name,
        "executable_sha256": capability.executable_sha256,
        "executable_size": capability.executable_size,
        "factory_id": capability.factory_id,
        "factory_nonce": capability._factory_nonce,
        "log_dir": str(capability.log_dir),
        "log_identity": list(capability.log_identity),
        "observation_key_sha256": hashlib.sha256(
            capability._observation_key
        ).hexdigest(),
        "path": str(capability.path),
        "root_identity": list(capability.root_identity),
        "secret_env_names": list(capability.secret_env_names),
        "workspace_root": str(capability.workspace_root),
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _issuer_mac(capability: OwnedFakeExecutable) -> str:
    return hmac.new(
        _ISSUER_KEY,
        _proof_payload(capability),
        hashlib.sha256,
    ).hexdigest()


def _new_capability(**values) -> OwnedFakeExecutable:
    capability = object.__new__(OwnedFakeExecutable)
    for name, value in values.items():
        object.__setattr__(capability, name, value)
    object.__setattr__(capability, "_issuer_mac", "")
    object.__setattr__(capability, "_issuer_mac", _issuer_mac(capability))
    return capability


def _issue_owned_fake_executable(
    *,
    path: Path,
    workspace_root: Path,
    config_path: Path,
    log_dir: Path,
    executable_name: str,
    expected_script: bytes,
    expected_config: bytes,
    factory_nonce: str,
    observation_key: bytes,
    root_identity: tuple[int, int],
    bin_identity: tuple[int, int],
    config_identity: tuple[int, int],
    log_identity: tuple[int, int],
    secret_env_names: Sequence[str],
) -> OwnedFakeExecutable:
    """Issue the capability used by ``HermeticCLIWorkspace``.

    The leading underscore is deliberate: this is a trusted-code seam for the
    repository fixture, not a general caller-facing capability factory.
    """
    if not _NONCE_RE.fullmatch(factory_nonce):
        raise ValueError("owned fake factory nonce is malformed")
    if len(observation_key) != 32:
        raise ValueError("owned fake observation key must be 32 bytes")
    if len(expected_script) > MAX_OWNED_FAKE_SCRIPT_BYTES:
        raise ValueError("owned fake generated script exceeds the size cap")
    if len(expected_config) > MAX_OWNED_FAKE_CONFIG_BYTES:
        raise ValueError("owned fake generated config exceeds the size cap")
    workspace_root = Path(workspace_root)
    path = Path(path)
    config_path = Path(config_path)
    log_dir = Path(log_dir)
    if not workspace_root.is_absolute():
        raise ValueError("owned fake workspace root must be absolute")
    if path != workspace_root / "bin" / executable_name:
        raise ValueError("owned fake executable path is outside its bin")
    if config_path != workspace_root / "config" / f"{executable_name}.json":
        raise ValueError("owned fake config path is outside its config dir")
    if log_dir != workspace_root / "logs":
        raise ValueError("owned fake log path is outside its workspace")

    root_fd = _open_dir(
        workspace_root,
        label="workspace root",
        expected=root_identity,
    )
    bin_fd = config_fd = logs_fd = -1
    try:
        bin_fd = _open_dir_at(
            root_fd,
            "bin",
            label="bin directory",
            expected=bin_identity,
        )
        config_fd = _open_dir_at(
            root_fd,
            "config",
            label="config directory",
            expected=config_identity,
        )
        logs_fd = _open_dir_at(
            root_fd,
            "logs",
            label="log directory",
            expected=log_identity,
        )
        script, script_st = _read_regular_at(
            bin_fd,
            executable_name,
            label="executable",
            max_bytes=MAX_OWNED_FAKE_SCRIPT_BYTES,
        )
        config, config_st = _read_regular_at(
            config_fd,
            f"{executable_name}.json",
            label="config",
            max_bytes=MAX_OWNED_FAKE_CONFIG_BYTES,
        )
    finally:
        for fd in (logs_fd, config_fd, bin_fd):
            if fd >= 0:
                os.close(fd)
        os.close(root_fd)

    if script != expected_script:
        raise ValueError("owned fake executable content is not factory output")
    if config != expected_config:
        raise ValueError("owned fake config content changed during issuance")
    if not script.startswith(b"#!"):
        raise ValueError("owned fake executable lacks the fixture shebang")
    factory_line = f"FAKE_CLI_FACTORY_ID = {FAKE_EXECUTABLE_FACTORY_ID!r}\n".encode()
    nonce_line = f"FACTORY_NONCE = {factory_nonce!r}\n".encode()
    observation_line = (
        "SECRET_OBSERVATION_KEY_B64 = "
        f"{base64.b64encode(observation_key).decode('ascii')!r}\n"
    ).encode()
    for marker in (factory_line, nonce_line, observation_line):
        if marker not in script:
            raise ValueError("owned fake executable is missing its factory identity")
    if not stat.S_IMODE(script_st.st_mode) & stat.S_IXUSR:
        raise ValueError("owned fake executable is not owner-executable")

    capability = _new_capability(
        path=path,
        workspace_root=workspace_root,
        config_path=config_path,
        log_dir=log_dir,
        executable_name=executable_name,
        factory_id=FAKE_EXECUTABLE_FACTORY_ID,
        executable_device=script_st.st_dev,
        executable_inode=script_st.st_ino,
        executable_size=script_st.st_size,
        executable_sha256=hashlib.sha256(script).hexdigest(),
        config_device=config_st.st_dev,
        config_inode=config_st.st_ino,
        config_size=config_st.st_size,
        config_sha256=hashlib.sha256(config).hexdigest(),
        root_identity=root_identity,
        bin_identity=bin_identity,
        config_identity=config_identity,
        log_identity=log_identity,
        secret_env_names=tuple(secret_env_names),
        _factory_nonce=factory_nonce,
        _observation_key=bytes(observation_key),
    )
    return verify_owned_fake_executable(capability)


def verify_owned_fake_executable(
    capability: object,
) -> OwnedFakeExecutable:
    """Revalidate an opaque fake-executable capability without path following."""
    if type(capability) is not OwnedFakeExecutable:
        raise ValueError(
            "owned fake executable capability was not issued by the fixture"
        )
    if capability.factory_id != FAKE_EXECUTABLE_FACTORY_ID:
        raise ValueError("owned fake executable factory identity is invalid")
    expected_mac = _issuer_mac(capability)
    if not hmac.compare_digest(capability._issuer_mac, expected_mac):
        raise ValueError("owned fake executable issuer proof is invalid")

    root_fd = _open_dir(
        capability.workspace_root,
        label="workspace root",
        expected=capability.root_identity,
    )
    bin_fd = config_fd = logs_fd = -1
    try:
        bin_fd = _open_dir_at(
            root_fd,
            "bin",
            label="bin directory",
            expected=capability.bin_identity,
        )
        config_fd = _open_dir_at(
            root_fd,
            "config",
            label="config directory",
            expected=capability.config_identity,
        )
        logs_fd = _open_dir_at(
            root_fd,
            "logs",
            label="log directory",
            expected=capability.log_identity,
        )
        script, script_st = _read_regular_at(
            bin_fd,
            capability.executable_name,
            label="executable",
            max_bytes=MAX_OWNED_FAKE_SCRIPT_BYTES,
        )
        config, config_st = _read_regular_at(
            config_fd,
            f"{capability.executable_name}.json",
            label="config",
            max_bytes=MAX_OWNED_FAKE_CONFIG_BYTES,
        )
    finally:
        for fd in (logs_fd, config_fd, bin_fd):
            if fd >= 0:
                os.close(fd)
        os.close(root_fd)

    if _identity(script_st) != (
        capability.executable_device,
        capability.executable_inode,
    ):
        raise ValueError("owned fake executable identity changed")
    if not stat.S_IMODE(script_st.st_mode) & stat.S_IXUSR:
        raise ValueError("owned fake executable is not owner-executable")
    if script_st.st_size != capability.executable_size:
        raise ValueError("owned fake executable size changed")
    if hashlib.sha256(script).hexdigest() != capability.executable_sha256:
        raise ValueError("owned fake executable content changed")
    if _identity(config_st) != (
        capability.config_device,
        capability.config_inode,
    ):
        raise ValueError("owned fake config identity changed")
    if config_st.st_size != capability.config_size:
        raise ValueError("owned fake config size changed")
    if hashlib.sha256(config).hexdigest() != capability.config_sha256:
        raise ValueError("owned fake config content changed")
    if not script.startswith(b"#!"):
        raise ValueError("owned fake executable lacks the fixture shebang")
    factory_line = f"FAKE_CLI_FACTORY_ID = {capability.factory_id!r}\n".encode()
    nonce_line = f"FACTORY_NONCE = {capability._factory_nonce!r}\n".encode()
    if factory_line not in script or nonce_line not in script:
        raise ValueError("owned fake executable factory identity changed")
    return capability


def _derive_synthetic_canary(
    observation_key: bytes,
    session_id: str,
) -> str:
    digest = hmac.new(
        observation_key,
        _CANARY_CONTEXT + session_id.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


def owned_fake_synthetic_canary(
    capability: object,
    session_id: str,
) -> str:
    verified = verify_owned_fake_executable(capability)
    return _derive_synthetic_canary(
        verified._observation_key,
        session_id,
    )


def owned_fake_secret_observation_hmac(
    capability: object,
    value: str,
) -> str:
    verified = verify_owned_fake_executable(capability)
    return hmac.new(
        verified._observation_key,
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


__all__ = [
    "FAKE_EXECUTABLE_FACTORY_ID",
    "MAX_OWNED_FAKE_SCRIPT_BYTES",
    "OwnedFakeExecutable",
    "owned_fake_secret_observation_hmac",
    "owned_fake_synthetic_canary",
    "verify_owned_fake_executable",
]
