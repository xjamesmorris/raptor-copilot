from __future__ import annotations

import copy
import json
import os
import pickle
import stat
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import pytest

from core.project import sessions
from core.startup.runtime_receipt.launch import (
    LaunchCancellation,
    LaunchFailure,
    LaunchReason,
    MonotonicDeadline,
    OwnedFakeLaunchHandle,
    OwnedFakeRuntimeCapability,
    _close_owned_runtime_fake,
    _launch_owned_runtime_fake,
)
from core.startup.runtime_receipt.profile import DEFAULT_PROFILE_DIRECTORY
from core.startup.runtime_receipt import persistence as persistence_module
from core.testing import runtime_receipt_fake as fake_module
from core.testing.runtime_receipt_fake import (
    FakeRuntimeBehavior,
    FakeRuntimeUnsupported,
    build_runtime_receipt_document,
    forbid_receipt_sidecar_reads,
    make_owned_runtime_receipt_fake,
    resign_runtime_receipt_document,
    runtime_receipt_verification_now,
)


@dataclass(frozen=True)
class _OwnedRoots:
    outer: Path
    test_root: Path
    registry_guard: Path


@pytest.fixture
def owned_roots(monkeypatch: pytest.MonkeyPatch):
    with tempfile.TemporaryDirectory(
        prefix=".raptor-stage3b-test-",
        dir=Path.home(),
    ) as raw:
        outer = Path(raw)
        outer.chmod(0o700)
        test_root = outer / "caller-root"
        test_root.mkdir(mode=0o700)
        registry_guard = outer / "real-sessions"
        registry_guard.mkdir(mode=0o700)
        monkeypatch.setattr(sessions, "SESSIONS_DIR", registry_guard)
        yield _OwnedRoots(outer, test_root, registry_guard)


def _make(
    roots: _OwnedRoots,
    *,
    behavior: FakeRuntimeBehavior = FakeRuntimeBehavior(),
) -> tuple[OwnedFakeRuntimeCapability, Path]:
    before = set(roots.test_root.iterdir())
    capability = make_owned_runtime_receipt_fake(
        roots.test_root,
        behavior=behavior,
    )
    if isinstance(capability, FakeRuntimeUnsupported):
        pytest.skip(capability.reason)
    created = set(roots.test_root.iterdir()) - before
    assert len(created) == 1
    bundle = created.pop()
    return capability, bundle


def _bind_registry(monkeypatch: pytest.MonkeyPatch, bundle: Path) -> None:
    monkeypatch.setattr(
        sessions,
        "SESSIONS_DIR",
        bundle / "registry/sessions.d",
    )


def _launch(
    capability: object,
    *,
    seconds: float = 10,
):
    cancellation = LaunchCancellation()
    result = _launch_owned_runtime_fake(
        capability,
        deadline=MonotonicDeadline.after(seconds),
        cancellation=cancellation,
    )
    return cancellation, result


def test_stable_receipt_builders_and_sidecar_denial_helper() -> None:
    document = build_runtime_receipt_document()
    original = document["receipt_sha256"]
    assert original != "0" * 64
    assert runtime_receipt_verification_now().isoformat() == (
        "2026-09-12T08:30:00+00:00"
    )

    mutated = copy.deepcopy(document)
    mutated["launch_binding"]["receipt_nonce"] = "f" * 32
    assert resign_runtime_receipt_document(mutated) is mutated
    assert mutated["receipt_sha256"] != original

    with forbid_receipt_sidecar_reads("deny-only consumer"):
        with pytest.raises(AssertionError, match="deny-only consumer"):
            persistence_module.read_receipt_sidecar(None, None)  # type: ignore[arg-type]
        with pytest.raises(AssertionError, match="deny-only consumer"):
            persistence_module.read_receipt_sidecar_bytes_for_registry(
                None,
                None,
            )


def test_builder_creates_exact_private_native_bundle(
    owned_roots: _OwnedRoots,
) -> None:
    capability, bundle = _make(owned_roots)
    expected = {
        "bin/owned-runtime-host",
        "bin/owned-runtime-host-alt",
        "issuer/launcher-marker",
        "dist/package.json",
        "dist/index.js",
        "dist/npm-loader.js",
        "dist/sea-loader.js",
        "dist/app.js",
        "dist/sdk/index.js",
        "dist/changelog.json",
        "dist/prebuilds/linux-x64/runtime.node",
        "dist/prebuilds/linux-x64/cli-native.node",
        "dist/schemas/session-events.schema.json",
        "dist/schemas/api.schema.json",
        "dist/.extraction-complete",
        "build-manifest.json",
    }
    files = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    assert files == expected
    assert type(capability) is OwnedFakeRuntimeCapability
    assert capability.factory_id == "core.testing.runtime_receipt_fake:v1"
    assert len(capability.bundle_sha256) == 64
    assert len(capability.compiler_sha256) == 64
    assert str(bundle) not in repr(capability)
    assert "issuer_mac" not in repr(capability)
    for relative in (
        "bin/owned-runtime-host",
        "bin/owned-runtime-host-alt",
        "dist/prebuilds/linux-x64/runtime.node",
        "dist/prebuilds/linux-x64/cli-native.node",
    ):
        assert stat.S_IMODE((bundle / relative).stat().st_mode) == 0o500
    assert (bundle / "bin/owned-runtime-host").read_bytes().count(
        b"RAPTOR_OWNED_RUNTIME_FAKE_SEA_LOADER_V1"
    ) == 1
    assert (bundle / "bin/owned-runtime-host-alt").read_bytes().count(
        b"RAPTOR_OWNED_RUNTIME_FAKE_SEA_LOADER_V1"
    ) == 1
    manifest = json.loads((bundle / "build-manifest.json").read_text())
    assert manifest["schema"] == "raptor.owned_runtime_fake_build/v1"
    assert manifest["behavior"] == {
        "descendants": 0,
        "ready_delay_seconds": 0,
        "reexec": 0,
        "scenario": 1,
    }
    assert all("<bundle>" in " ".join(argv) for argv in manifest["argv"])
    assert all("--version" not in argv for argv in manifest["argv"])


def test_builder_uses_only_fixed_compiler_argv_and_environment(
    owned_roots: _OwnedRoots,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
    original = fake_module.subprocess.run
    with fake_module._BUILD_CACHE_LOCK:
        fake_module._BUILD_CACHE.clear()

    def recording_run(argv, **kwargs):
        calls.append((tuple(argv), dict(kwargs["env"])))
        assert kwargs.get("shell") is None
        assert kwargs["stdin"] is fake_module.subprocess.DEVNULL
        return original(argv, **kwargs)

    monkeypatch.setattr(fake_module.subprocess, "run", recording_run)
    _make(owned_roots)
    assert calls
    compiler = calls[0][0][0]
    assert all(argv[0] == compiler for argv, _env in calls)
    assert all(
        env
        == {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "SOURCE_DATE_EPOCH": "0",
        }
        for _argv, env in calls
    )
    assert all("--version" not in argv and "git" not in argv for argv, _env in calls)


def test_reused_compiled_images_are_reverified_and_deterministic(
    owned_roots: _OwnedRoots,
) -> None:
    _first, first_bundle = _make(owned_roots)
    _second, second_bundle = _make(owned_roots)
    for relative in (
        "bin/owned-runtime-host",
        "bin/owned-runtime-host-alt",
        "dist/prebuilds/linux-x64/runtime.node",
        "dist/prebuilds/linux-x64/cli-native.node",
    ):
        assert (first_bundle / relative).read_bytes() == (
            second_bundle / relative
        ).read_bytes()


def test_missing_or_untrusted_compiler_is_typed(
    owned_roots: _OwnedRoots,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fake_module, "_COMPILER_CANDIDATES", ())
    result = make_owned_runtime_receipt_fake(owned_roots.test_root)
    assert type(result) is FakeRuntimeUnsupported
    assert result.reason == "approved_c_compiler_missing"
    with pytest.raises(TypeError):
        bool(result)


@pytest.mark.parametrize(
    "root_selector",
    (
        lambda roots: roots.registry_guard,
        lambda _roots: DEFAULT_PROFILE_DIRECTORY,
        lambda _roots: Path(__file__).resolve().parents[3],
        lambda _roots: Path(__file__).resolve().parents[3] / "core",
        lambda _roots: Path(tempfile.gettempdir()),
    ),
)
def test_builder_refuses_forbidden_roots_before_writing(
    owned_roots: _OwnedRoots,
    root_selector,
) -> None:
    root = root_selector(owned_roots)
    before = set(root.iterdir()) if root.is_dir() else set()
    with pytest.raises(ValueError):
        make_owned_runtime_receipt_fake(root)
    if root.is_dir():
        assert set(root.iterdir()) == before


@pytest.mark.parametrize(
    "mutation",
    (
        "content",
        "mode",
        "hardlink",
        "unexpected",
        "replace_executable",
        "replace_directory",
    ),
)
def test_capability_revalidation_rejects_bundle_tampering(
    owned_roots: _OwnedRoots,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    capability, bundle = _make(owned_roots)
    if mutation == "content":
        path = bundle / "dist/app.js"
        path.chmod(0o600)
        path.write_bytes(b"changed\n")
        path.chmod(0o400)
    elif mutation == "mode":
        (bundle / "dist/index.js").chmod(0o600)
    elif mutation == "hardlink":
        os.link(bundle / "dist/app.js", bundle / "dist/app-copy.js")
    elif mutation == "unexpected":
        (bundle / "dist/unexpected").write_bytes(b"x")
    elif mutation == "replace_executable":
        primary = bundle / "bin/owned-runtime-host"
        replacement = bundle / "bin/replacement"
        replacement.write_bytes((bundle / "bin/owned-runtime-host-alt").read_bytes())
        replacement.chmod(0o500)
        primary.rename(bundle / "bin/original")
        replacement.rename(primary)
    else:
        issuer = bundle / "issuer"
        issuer.rename(bundle / "issuer-original")
        issuer.symlink_to(bundle / "issuer-original", target_is_directory=True)
    _bind_registry(monkeypatch, bundle)
    with LaunchCancellation() as cancellation:
        result = _launch_owned_runtime_fake(
            capability,
            deadline=MonotonicDeadline.after(5),
            cancellation=cancellation,
        )
    assert type(result) is LaunchFailure
    assert result.reason_codes[0] is LaunchReason.INVALID_CAPABILITY


def test_capability_copy_deepcopy_and_concurrent_reuse_are_single_use(
    owned_roots: _OwnedRoots,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability, bundle = _make(owned_roots)
    _bind_registry(monkeypatch, bundle)
    copies = (capability, copy.copy(capability), copy.deepcopy(capability))
    barrier = threading.Barrier(3)

    def invoke(item: object):
        with LaunchCancellation() as cancellation:
            barrier.wait()
            return _launch_owned_runtime_fake(
                item,
                deadline=MonotonicDeadline.after(10),
                cancellation=cancellation,
            )

    with ThreadPoolExecutor(max_workers=3) as executor:
        results = tuple(executor.map(invoke, copies))
    handles = [item for item in results if type(item) is OwnedFakeLaunchHandle]
    failures = [item for item in results if type(item) is LaunchFailure]
    assert len(handles) == 1
    assert len(failures) == 2
    assert all(
        item.reason_codes[0] is LaunchReason.CAPABILITY_REUSED for item in failures
    )
    closed = _close_owned_runtime_fake(
        handles[0],
        deadline=MonotonicDeadline.after(10),
    )
    assert type(closed).__name__ == "LaunchClosed"
    assert list(owned_roots.test_root.iterdir()) == []


def test_capability_is_process_local_across_fork(
    owned_roots: _OwnedRoots,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability, bundle = _make(owned_roots)
    _bind_registry(monkeypatch, bundle)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        with LaunchCancellation() as cancellation:
            result = _launch_owned_runtime_fake(
                capability,
                deadline=MonotonicDeadline.after(5),
                cancellation=cancellation,
            )
        reason = (
            result.reason_codes[0].value
            if isinstance(result, LaunchFailure)
            else "unexpected_success"
        )
        os.write(write_fd, reason.encode("ascii"))
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    observed = os.read(read_fd, 128).decode("ascii")
    os.close(read_fd)
    waited, status = os.waitpid(pid, 0)
    assert waited == pid
    assert os.WIFEXITED(status)
    assert observed == LaunchReason.INVALID_CAPABILITY.value
    with LaunchCancellation() as cancellation:
        handle = _launch_owned_runtime_fake(
            capability,
            deadline=MonotonicDeadline.after(10),
            cancellation=cancellation,
        )
    assert type(handle) is OwnedFakeLaunchHandle
    assert (
        type(
            _close_owned_runtime_fake(
                handle,
                deadline=MonotonicDeadline.after(10),
            )
        ).__name__
        == "LaunchClosed"
    )


def test_capability_is_frozen_redacted_non_authorizing_and_non_pickleable(
    owned_roots: _OwnedRoots,
) -> None:
    capability, bundle = _make(owned_roots)
    with pytest.raises(TypeError):
        bool(capability)
    with pytest.raises(TypeError):
        pickle.dumps(capability)
    with pytest.raises(TypeError):

        class CapabilitySubclass(OwnedFakeRuntimeCapability):
            pass

    with pytest.raises((AttributeError, TypeError)):
        capability.bundle_sha256 = "0" * 64
    text = repr(capability)
    assert str(bundle) not in text
    assert "token" not in text.lower()
    assert "path=" not in text.lower()
    assert "descriptor" not in text.lower()
