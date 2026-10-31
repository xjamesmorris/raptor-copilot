"""Authority and tamper tests for repository-owned fake executables."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from core.security import fake_executable as fake_module
from core.testing import FakeCLIBehavior, make_hermetic_cli


def _owned(tmp_path: Path, *, workspace_name: str = "owned-fake"):
    workspace = make_hermetic_cli(
        tmp_path,
        workspace_name=workspace_name,
    )
    workspace.configure_cli(
        "owned-cli",
        FakeCLIBehavior(secret_env_names=("FAKE_SECRET_TOKEN",)),
    )
    return workspace, workspace.owned_executable("owned-cli")


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("factory_id", "other.factory:v1", "factory identity"),
        ("_issuer_mac", "0" * 64, "issuer proof"),
    ],
)
def test_verifier_rejects_tampered_authority_fields(
    tmp_path: Path,
    field: str,
    value: object,
    match: str,
) -> None:
    _workspace, capability = _owned(
        tmp_path,
        workspace_name=f"authority-{field.strip('_')}",
    )
    object.__setattr__(capability, field, value)

    with pytest.raises(ValueError, match=match):
        fake_module.verify_owned_fake_executable(capability)


@pytest.mark.parametrize(
    ("component", "mutation", "match"),
    [
        ("root", "mode", "group/world writable"),
        ("bin", "replace", "identity changed"),
        ("config", "mode", "group/world writable"),
        ("logs", "replace", "identity changed"),
    ],
)
def test_verifier_rejects_parent_directory_tampering(
    tmp_path: Path,
    component: str,
    mutation: str,
    match: str,
) -> None:
    workspace, capability = _owned(
        tmp_path,
        workspace_name=f"parent-{component}-{mutation}",
    )
    path = workspace.root if component == "root" else workspace.root / component
    if mutation == "mode":
        path.chmod(0o720)
    else:
        backup = path.with_name(path.name + "-original")
        path.rename(backup)
        path.mkdir(mode=0o700)

    with pytest.raises(ValueError, match=match):
        fake_module.verify_owned_fake_executable(capability)


@pytest.mark.parametrize(
    ("target", "mutation", "match"),
    [
        ("executable", "content", "content changed"),
        ("executable", "size", "size changed"),
        ("executable", "mode", "not owner-executable"),
        ("config", "content", "content changed"),
        ("config", "size", "config size changed"),
        ("config", "replace", "config identity changed"),
        ("config", "directory", "not a regular file"),
    ],
)
def test_verifier_rejects_leaf_tampering(
    tmp_path: Path,
    target: str,
    mutation: str,
    match: str,
) -> None:
    workspace, capability = _owned(
        tmp_path,
        workspace_name=f"leaf-{target}-{mutation}",
    )
    path = (
        workspace.executable("owned-cli")
        if target == "executable"
        else workspace.config_path("owned-cli")
    )
    if mutation == "content":
        original = path.read_bytes()
        replacement = bytes([original[0] ^ 1]) + original[1:]
        path.write_bytes(replacement)
        if target == "executable":
            path.chmod(0o700)
    elif mutation == "size":
        path.write_bytes(path.read_bytes() + b"x")
        if target == "executable":
            path.chmod(0o700)
    elif mutation == "mode":
        path.chmod(0o600)
    elif mutation == "replace":
        replacement = path.with_name(path.name + "-replacement")
        shutil.copy2(path, replacement)
        replacement.replace(path)
    else:
        path.unlink()
        path.mkdir(mode=0o700)

    with pytest.raises(ValueError, match=match):
        fake_module.verify_owned_fake_executable(capability)


def _issuer_kwargs(workspace) -> dict[str, object]:
    executable = workspace.executable("owned-cli")
    config = workspace.config_path("owned-cli")
    return {
        "path": executable,
        "workspace_root": workspace.root,
        "config_path": config,
        "log_dir": workspace.log_dir,
        "executable_name": "owned-cli",
        "expected_script": executable.read_bytes(),
        "expected_config": config.read_bytes(),
        "factory_nonce": workspace._factory_nonce,
        "observation_key": workspace._secret_observation_key,
        "root_identity": workspace._root_identity,
        "bin_identity": workspace._bin_identity,
        "config_identity": workspace._config_identity,
        "log_identity": workspace._log_identity,
        "secret_env_names": ("FAKE_SECRET_TOKEN",),
    }


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("factory_nonce", "bad", "nonce"),
        ("observation_key", b"short", "32 bytes"),
        (
            "expected_script",
            b"x" * (fake_module.MAX_OWNED_FAKE_SCRIPT_BYTES + 1),
            "script exceeds",
        ),
        (
            "expected_config",
            b"x" * (fake_module.MAX_OWNED_FAKE_CONFIG_BYTES + 1),
            "config exceeds",
        ),
        ("workspace_root", Path("relative"), "must be absolute"),
        ("path", Path("/tmp/outside-owned-bin"), "outside its bin"),
        (
            "config_path",
            Path("/tmp/outside-owned-config"),
            "outside its config",
        ),
        ("log_dir", Path("/tmp/outside-owned-log"), "outside its workspace"),
    ],
)
def test_issuer_rejects_malformed_structural_inputs(
    tmp_path: Path,
    field: str,
    value: object,
    match: str,
) -> None:
    workspace, _capability = _owned(
        tmp_path,
        workspace_name=f"issuer-{field}",
    )
    kwargs = _issuer_kwargs(workspace)
    kwargs[field] = value

    with pytest.raises(ValueError, match=match):
        fake_module._issue_owned_fake_executable(**kwargs)


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        ("script-mismatch", "executable content"),
        ("config-mismatch", "config content"),
        ("no-shebang", "lacks the fixture shebang"),
        ("missing-marker", "missing its factory identity"),
        ("not-executable", "not owner-executable"),
    ],
)
def test_issuer_rejects_nonfactory_file_content(
    tmp_path: Path,
    mutation: str,
    match: str,
) -> None:
    workspace, _capability = _owned(
        tmp_path,
        workspace_name=f"issuer-content-{mutation}",
    )
    kwargs = _issuer_kwargs(workspace)
    executable = workspace.executable("owned-cli")
    if mutation == "script-mismatch":
        kwargs["expected_script"] = b"different"
    elif mutation == "config-mismatch":
        kwargs["expected_config"] = b"different"
    elif mutation == "no-shebang":
        content = executable.read_bytes()
        content = b"xx" + content[2:]
        executable.write_bytes(content)
        executable.chmod(0o700)
        kwargs["expected_script"] = content
    elif mutation == "missing-marker":
        content = executable.read_bytes().replace(
            b"core.testing.fake_cli:v1",
            b"core.testing.fake_cli:v0",
        )
        executable.write_bytes(content)
        executable.chmod(0o700)
        kwargs["expected_script"] = content
    else:
        executable.chmod(0o600)

    with pytest.raises(ValueError, match=match):
        fake_module._issue_owned_fake_executable(**kwargs)


@pytest.mark.parametrize("fail_call", [2, 3])
def test_issuer_closes_real_staged_descriptors_after_open_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_call: int,
) -> None:
    workspace, _capability = _owned(
        tmp_path,
        workspace_name=f"issuer-open-failure-{fail_call}",
    )
    kwargs = _issuer_kwargs(workspace)
    opened_fds: list[int] = []
    open_at_calls = 0
    real_open_dir = fake_module._open_dir
    real_open_dir_at = fake_module._open_dir_at

    def record_root(*args, **call_kwargs):
        fd = real_open_dir(*args, **call_kwargs)
        opened_fds.append(fd)
        return fd

    def fail_staged_open(*args, **call_kwargs):
        nonlocal open_at_calls
        open_at_calls += 1
        if open_at_calls == fail_call:
            raise OSError(f"injected owned open failure {fail_call}")
        fd = real_open_dir_at(*args, **call_kwargs)
        opened_fds.append(fd)
        return fd

    monkeypatch.setattr(fake_module, "_open_dir", record_root)
    monkeypatch.setattr(fake_module, "_open_dir_at", fail_staged_open)

    with pytest.raises(
        OSError,
        match=f"injected owned open failure {fail_call}",
    ):
        fake_module._issue_owned_fake_executable(**kwargs)

    assert open_at_calls == fail_call
    assert len(opened_fds) == fail_call
    for fd in opened_fds:
        with pytest.raises(OSError):
            os.fstat(fd)
