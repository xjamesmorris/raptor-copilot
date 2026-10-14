"""Hermetic builder for the private owned runtime-receipt native fake."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import os
import platform
import secrets
import stat
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Iterator, Mapping, NoReturn, cast
from unittest.mock import patch

from core.json.utils import dumps_canonical, load_json
from core.source import read_bytes_gated

if TYPE_CHECKING:
    from core.startup.runtime_receipt.launch import OwnedFakeRuntimeCapability

_FACTORY_PREFIX = "runtime-receipt-fake-"
_SEA_LOADER_BYTES = b"RAPTOR_OWNED_RUNTIME_FAKE_SEA_LOADER_V1"
_BUILD_MANIFEST_MAX_BYTES = 1_048_576
_COMPILER_CANDIDATES = (
    "/usr/bin/cc",
    "/usr/bin/clang",
    "/usr/bin/gcc",
    "/bin/cc",
    "/bin/clang",
    "/bin/gcc",
    "/usr/local/bin/clang",
    "/usr/local/bin/gcc",
)
_COMPILER_ENV: Mapping[str, str] = MappingProxyType(
    {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "SOURCE_DATE_EPOCH": "0",
    }
)
_BUILD_CACHE_LOCK = threading.Lock()
_RECEIPT_CASES_PATH = (
    Path(__file__).resolve().parents[1]
    / "startup/tests/fixtures/runtime_receipt/cases.json"
)
_RECEIPT_DOCUMENT_PATH = (
    Path(__file__).resolve().parent / "fixtures/runtime-receipt-document-v1.json"
)


class FakeRuntimeScenario(int, Enum):
    READY = 1
    DELAYED_READY = 2
    EXIT_BEFORE_READY = 3
    EXIT_AFTER_READY = 4
    ACTIVATION_FAILURE = 5
    SKIP_RUNTIME_MODULE = 6
    EXTRA_DISTRIBUTION_MAPPING = 7
    WRONG_MODULE_ROLE = 8
    MALFORMED_READY = 9
    DUPLICATE_READY = 10
    CONTROL_EOF = 11


class FakeDescendantShape(int, Enum):
    NONE = 0
    ONE_CHILD = 1
    CHILD_AND_GRANDCHILD = 2


class FakeReexecMode(int, Enum):
    NONE = 0
    SAME_BEFORE_CAS = 1
    DIFFERENT_BEFORE_CAS = 2
    SAME_AFTER_CAS = 3
    DIFFERENT_AFTER_CAS = 4


@dataclass(frozen=True, slots=True)
class FakeRuntimeBehavior:
    scenario: FakeRuntimeScenario = FakeRuntimeScenario.READY
    descendants: FakeDescendantShape = FakeDescendantShape.NONE
    ready_delay_seconds: int = 0
    reexec: FakeReexecMode = FakeReexecMode.NONE

    def __post_init__(self) -> None:
        if type(self.scenario) is not FakeRuntimeScenario:
            raise TypeError("scenario must be FakeRuntimeScenario")
        if type(self.descendants) is not FakeDescendantShape:
            raise TypeError("descendants must be FakeDescendantShape")
        if type(self.reexec) is not FakeReexecMode:
            raise TypeError("reexec must be FakeReexecMode")
        if (
            type(self.ready_delay_seconds) is not int
            or not 0 <= self.ready_delay_seconds <= 3600
        ):
            raise ValueError("ready delay must be an integer from 0 to 3600")
        if (
            self.scenario is FakeRuntimeScenario.DELAYED_READY
            and self.ready_delay_seconds <= 30
        ):
            raise ValueError("delayed READY fixtures must exceed 30 seconds")
        if (
            self.scenario is not FakeRuntimeScenario.DELAYED_READY
            and self.ready_delay_seconds != 0
        ):
            raise ValueError("only delayed READY fixtures carry a delay")
        if (
            self.reexec is not FakeReexecMode.NONE
            and self.descendants is not FakeDescendantShape.NONE
        ):
            raise ValueError("re-exec fixtures cannot retain descendants")


@dataclass(frozen=True, slots=True, repr=False)
class FakeRuntimeUnsupported:
    reason: str

    def __post_init__(self) -> None:
        if (
            not self.reason
            or not self.reason.isascii()
            or not self.reason.isprintable()
            or len(self.reason) > 128
        ):
            raise ValueError("unsupported reason is outside its bound")

    def __repr__(self) -> str:
        return f"FakeRuntimeUnsupported(reason={self.reason!r})"

    def __bool__(self) -> bool:
        raise TypeError("unsupported fixture results are not truth values")

    def __reduce__(self) -> NoReturn:
        raise TypeError("FakeRuntimeUnsupported cannot be pickled")

    def __init_subclass__(cls) -> None:
        raise TypeError("FakeRuntimeUnsupported cannot be subclassed")


@dataclass(frozen=True, slots=True)
class _Compiler:
    path: Path
    device: int
    inode: int
    size: int
    sha256: str
    family: str


@dataclass(frozen=True, slots=True)
class _CompiledImages:
    files: tuple[tuple[str, bytes], ...]
    argv: tuple[tuple[str, ...], ...]


_BUILD_CACHE: dict[tuple[object, ...], _CompiledImages] = {}


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1_048_576)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def _resolve_compiler() -> _Compiler | None:
    seen: set[tuple[int, int]] = set()
    for text in _COMPILER_CANDIDATES:
        candidate = Path(text)
        try:
            resolved = candidate.resolve(strict=True)
            value = resolved.stat()
        except OSError:
            continue
        identity = (value.st_dev, value.st_ino)
        if identity in seen:
            continue
        seen.add(identity)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(value.st_mode) & 0o022
            or not os.access(resolved, os.X_OK)
        ):
            continue
        name = resolved.name.lower()
        family = "clang" if "clang" in name else "gcc"
        return _Compiler(
            path=resolved,
            device=value.st_dev,
            inode=value.st_ino,
            size=value.st_size,
            sha256=_hash_file(resolved),
            family=family,
        )
    return None


def _verify_compiler(compiler: _Compiler) -> None:
    value = compiler.path.stat()
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(value.st_mode) & 0o022
        or (value.st_dev, value.st_ino, value.st_size)
        != (compiler.device, compiler.inode, compiler.size)
        or _hash_file(compiler.path) != compiler.sha256
    ):
        raise RuntimeError("owned runtime fixture compiler identity changed")


def _write_new(path: Path, raw: bytes, mode: int) -> None:
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise OSError("short owned fake fixture write")
            offset += written
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _run_compiler(argv: tuple[str, ...], *, cwd: Path) -> None:
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=dict(_COMPILER_ENV),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr[:4096].decode("utf-8", errors="replace")
        raise RuntimeError(
            f"owned runtime fixture compiler failed ({result.returncode}): {stderr}"
        )


def _normalise_argv(argv: tuple[str, ...], bundle_root: Path) -> tuple[str, ...]:
    prefix = str(bundle_root)
    return tuple(item.replace(prefix, "<bundle>") for item in argv)


def _compile_images(
    compiler: _Compiler,
    *,
    bundle_root: Path,
    host_source: Path,
    module_source: Path,
) -> _CompiledImages:
    source_hashes = (_hash_file(host_source), _hash_file(module_source))
    cache_key = (
        str(compiler.path),
        compiler.device,
        compiler.inode,
        compiler.size,
        compiler.sha256,
        compiler.family,
        *source_hashes,
    )
    with _BUILD_CACHE_LOCK:
        cached = _BUILD_CACHE.get(cache_key)
    if cached is not None:
        return cached

    work = bundle_root / "work"
    prefix_flags = (
        f"-ffile-prefix-map={bundle_root}=.",
        f"-fmacro-prefix-map={bundle_root}=.",
    )
    common_compile = (
        str(compiler.path),
        "-std=c11",
        "-O2",
        "-g0",
        "-pipe",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fno-ident",
        "-fno-record-gcc-switches",
        *prefix_flags,
    )
    link_hardening = (
        "-Wl,--build-id=sha1",
        "-Wl,-z,relro",
        "-Wl,-z,now",
        "-Wl,-z,noexecstack",
    )
    commands: list[tuple[str, ...]] = []
    outputs: dict[str, Path] = {}

    for image_name, image_id in (
        ("owned-runtime-host", "1"),
        ("owned-runtime-host-alt", "2"),
    ):
        object_path = work / f"{image_name}.o"
        output_path = work / image_name
        compile_argv = (
            *common_compile,
            "-fPIE",
            f"-DOWNED_IMAGE_ID={image_id}",
            "-c",
            str(host_source),
            "-o",
            str(object_path),
        )
        link_argv = (
            str(compiler.path),
            "-pie",
            str(object_path),
            "-o",
            str(output_path),
            *link_hardening,
            "-ldl",
        )
        _run_compiler(compile_argv, cwd=bundle_root)
        _run_compiler(link_argv, cwd=bundle_root)
        commands.extend((compile_argv, link_argv))
        outputs[f"bin/{image_name}"] = output_path

    for output_name, role in (
        ("runtime.node", "runtime.node"),
        ("cli-native.node", "cli-native.node"),
        ("extra-owned.node", "extra-owned.node"),
    ):
        object_path = work / f"{output_name}.o"
        output_path = work / output_name
        compile_argv = (
            *common_compile,
            "-fPIC",
            f'-DOWNED_MODULE_ROLE="{role}"',
            "-c",
            str(module_source),
            "-o",
            str(object_path),
        )
        link_argv = (
            str(compiler.path),
            "-shared",
            str(object_path),
            "-o",
            str(output_path),
            *link_hardening,
            f"-Wl,-soname,{output_name}",
        )
        _run_compiler(compile_argv, cwd=bundle_root)
        _run_compiler(link_argv, cwd=bundle_root)
        commands.extend((compile_argv, link_argv))
        outputs[f"dist/prebuilds/linux-x64/{output_name}"] = output_path

    files = tuple(
        (relative, output.read_bytes()) for relative, output in sorted(outputs.items())
    )
    for path in work.iterdir():
        path.unlink()
    compiled = _CompiledImages(
        files=files,
        argv=tuple(_normalise_argv(item, bundle_root) for item in commands),
    )
    with _BUILD_CACHE_LOCK:
        _BUILD_CACHE.setdefault(cache_key, compiled)
        return _BUILD_CACHE[cache_key]


def _artifact_bytes(relative: str) -> bytes:
    if relative == "index.js":
        return b"export const ownedRuntimeFake = true;\n"
    if relative == "npm-loader.js":
        return b"import './index.js';\n"
    if relative == "sea-loader.js":
        return _SEA_LOADER_BYTES
    if relative == "app.js":
        return b"export const app = 'owned-runtime-fake';\n"
    if relative == "sdk/index.js":
        return b"owned-runtime-fake-sdk\n"
    if relative == "changelog.json":
        return b'{"version":"0.0.0-owned"}\n'
    if relative == "schemas/session-events.schema.json":
        return b'{"properties":{"type":{"type":"string"}},"type":"object"}\n'
    if relative == "schemas/api.schema.json":
        return b'{"properties":{"ok":{"type":"boolean"}},"type":"object"}\n'
    if relative == ".extraction-complete":
        return b""
    raise ValueError("unknown owned fake artifact")


def _create_bundle_root(test_root: Path) -> Path:
    root_fd = os.open(
        test_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        for _attempt in range(32):
            name = f"{_FACTORY_PREFIX}{secrets.token_hex(32)}"
            try:
                os.mkdir(name, 0o700, dir_fd=root_fd)
            except FileExistsError:
                continue
            return test_root / name
    finally:
        os.close(root_fd)
    raise RuntimeError("could not allocate an owned runtime fixture directory")


def _ancestor_identities(path: Path) -> set[tuple[int, int]]:
    identities: set[tuple[int, int]] = set()
    current = path
    while True:
        value = current.stat()
        identities.add((value.st_dev, value.st_ino))
        if current.parent == current:
            return identities
        current = current.parent


def _validate_test_root(test_root: Path) -> None:
    from core.project.sessions import SESSIONS_DIR
    from core.startup.runtime_receipt.profile import DEFAULT_PROFILE_DIRECTORY

    if not test_root.is_absolute():
        raise ValueError("owned fake test root must be absolute")
    value = test_root.lstat()
    if (
        test_root.is_symlink()
        or not stat.S_ISDIR(value.st_mode)
        or value.st_uid != os.geteuid()
        or stat.S_IMODE(value.st_mode) & 0o022
    ):
        raise ValueError("owned fake test root is unsafe")
    test_ancestors = _ancestor_identities(test_root)
    temporary = Path(tempfile.gettempdir())
    if temporary.exists() and (value.st_dev, value.st_ino) == (
        temporary.stat().st_dev,
        temporary.stat().st_ino,
    ):
        raise ValueError("system temporary directory cannot be the fixture root")
    for forbidden in (
        Path(__file__).resolve().parents[2],
        DEFAULT_PROFILE_DIRECTORY,
        SESSIONS_DIR,
    ):
        try:
            forbidden_value = forbidden.stat()
        except OSError:
            continue
        if (forbidden_value.st_dev, forbidden_value.st_ino) in test_ancestors:
            raise ValueError("owned fake test root is inside a forbidden tree")


def _make_directories(bundle_root: Path) -> None:
    for relative in (
        "bin",
        "issuer",
        "dist",
        "dist/sdk",
        "dist/prebuilds",
        "dist/prebuilds/linux-x64",
        "dist/schemas",
        "registry",
        "registry/sessions.d",
        "runs",
        "work",
        "logs",
    ):
        path = bundle_root / relative
        path.mkdir(mode=0o700)
        path.chmod(0o700)


def _write_distribution(
    bundle_root: Path, compiled: _CompiledImages, *, extra: bool
) -> None:
    from core.startup.runtime_receipt.schema import ArtifactName

    compiled_files = dict(compiled.files)
    for relative in (
        "bin/owned-runtime-host",
        "bin/owned-runtime-host-alt",
        "dist/prebuilds/linux-x64/runtime.node",
        "dist/prebuilds/linux-x64/cli-native.node",
    ):
        _write_new(bundle_root / relative, compiled_files[relative], 0o500)
    if extra:
        relative = "dist/prebuilds/linux-x64/extra-owned.node"
        _write_new(bundle_root / relative, compiled_files[relative], 0o500)
    for name in ArtifactName:
        if name.value.endswith(".node"):
            continue
        _write_new(
            bundle_root / "dist" / name.value, _artifact_bytes(name.value), 0o400
        )
    package = (
        dumps_canonical(
            {
                "bin": {"copilot": "npm-loader.js"},
                "name": "@github/copilot",
                "type": "module",
                "version": "0.0.0-owned",
            }
        ).encode("utf-8")
        + b"\n"
    )
    _write_new(bundle_root / "dist/package.json", package, 0o400)
    _write_new(
        bundle_root / "issuer/launcher-marker",
        b"raptor-owned-runtime-fake-launcher-v1\n",
        0o400,
    )


def _write_build_manifest(
    bundle_root: Path,
    *,
    compiler: _Compiler,
    compiled: _CompiledImages,
    source_hashes: tuple[str, str],
    behavior: FakeRuntimeBehavior,
) -> bytes:
    files = []
    for path in sorted(bundle_root.rglob("*")):
        if path.is_file():
            files.append(
                {
                    "path": path.relative_to(bundle_root).as_posix(),
                    "sha256": _hash_file(path),
                    "size": path.stat().st_size,
                }
            )
    raw = (
        dumps_canonical(
            {
                "schema": "raptor.owned_runtime_fake_build/v1",
                "compiler": {
                    "device": compiler.device,
                    "family": compiler.family,
                    "inode": compiler.inode,
                    "real_path": str(compiler.path),
                    "sha256": compiler.sha256,
                    "size": compiler.size,
                },
                "argv": compiled.argv,
                "source_hashes": source_hashes,
                "behavior": {
                    "scenario": behavior.scenario.value,
                    "descendants": behavior.descendants.value,
                    "ready_delay_seconds": behavior.ready_delay_seconds,
                    "reexec": behavior.reexec.value,
                },
                "files": files,
            }
        ).encode("utf-8")
        + b"\n"
    )
    manifest_path = bundle_root / "build-manifest.json"
    _write_new(manifest_path, raw, 0o400)
    return raw


def _read_build_manifest(bundle_root: Path) -> bytes:
    return read_bytes_gated(
        bundle_root / "build-manifest.json",
        _BUILD_MANIFEST_MAX_BYTES,
        follow_symlinks=False,
    )


def _verify_build_manifest(bundle_root: Path, expected: bytes) -> None:
    if _read_build_manifest(bundle_root) != expected:
        raise RuntimeError("owned runtime fake build manifest changed")


def _runtime_receipt_seed() -> dict[str, Any]:
    value = load_json(_RECEIPT_CASES_PATH)
    assert isinstance(value, dict)
    return cast(dict[str, Any], copy.deepcopy(value))


def resign_runtime_receipt_document(
    document: dict[str, Any],
) -> dict[str, Any]:
    """Recompute every canonical digest on a mutable test receipt."""

    from core.startup.runtime_receipt.canonical import (
        canonical_bytes,
        receipt_sha256,
        sha256_hex,
    )

    document["stable_identity_sha256"] = sha256_hex(
        canonical_bytes(document["stable_identity"])
    )
    document["launch_instance_sha256"] = sha256_hex(
        canonical_bytes(document["launch_instance"])
    )
    document["launch_binding"]["stable_identity_sha256"] = document[
        "stable_identity_sha256"
    ]
    document["launch_binding"]["launch_instance_sha256"] = document[
        "launch_instance_sha256"
    ]
    document["launch_binding_sha256"] = sha256_hex(
        canonical_bytes(document["launch_binding"])
    )
    document["process_corroboration_sha256"] = sha256_hex(
        canonical_bytes(document["process_corroboration"])
    )
    document["receipt_sha256"] = receipt_sha256(
        document["stable_identity_sha256"],
        document["launch_instance_sha256"],
        document["launch_binding_sha256"],
        document["process_corroboration_sha256"],
    )
    return document


def build_runtime_receipt_document() -> dict[str, Any]:
    """Load a fresh copy of the canonical fixed receipt test document."""

    value = load_json(_RECEIPT_DOCUMENT_PATH)
    if not isinstance(value, dict):
        raise TypeError("runtime receipt fixture must be an object")
    return cast(dict[str, Any], copy.deepcopy(value))


def runtime_receipt_verification_now() -> datetime:
    """Return the fixture timestamp used for deterministic verification."""
    value = _runtime_receipt_seed()["verification_now_utc"]
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@contextlib.contextmanager
def forbid_receipt_sidecar_reads(message: str) -> Iterator[None]:
    """Fail if a deny-only consumer attempts to read receipt sidecar bytes."""

    persistence = "core.startup.runtime_receipt.persistence"
    targets = (
        f"{persistence}.read_receipt_sidecar",
        f"{persistence}.read_receipt_sidecar_bytes_for_registry",
    )
    with contextlib.ExitStack() as stack:
        for target in targets:
            stack.enter_context(
                patch(target, side_effect=AssertionError(f"{message}: {target}"))
            )
        yield


def make_owned_runtime_receipt_fake(
    test_root: Path,
    *,
    behavior: FakeRuntimeBehavior = FakeRuntimeBehavior(),
) -> OwnedFakeRuntimeCapability | FakeRuntimeUnsupported:
    """Build and issue one fixed native fake below a caller-owned test root."""

    from core.startup.runtime_receipt.launch import (
        _issue_owned_fake_runtime_capability,
    )

    if type(behavior) is not FakeRuntimeBehavior:
        raise TypeError("behavior must be FakeRuntimeBehavior")
    test_root = Path(test_root)
    _validate_test_root(test_root)
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        return FakeRuntimeUnsupported("linux_x86_64_required")
    compiler = _resolve_compiler()
    if compiler is None:
        return FakeRuntimeUnsupported("approved_c_compiler_missing")
    source_root = (
        Path(__file__).resolve().parents[1] / "startup/tests/fixtures/runtime_receipt"
    )
    host_source = source_root / "owned_host.c"
    module_source = source_root / "owned_module.c"
    source_hashes = (_hash_file(host_source), _hash_file(module_source))
    bundle_root = _create_bundle_root(test_root)
    _make_directories(bundle_root)
    compiled = _compile_images(
        compiler,
        bundle_root=bundle_root,
        host_source=host_source,
        module_source=module_source,
    )
    _verify_compiler(compiler)
    extra = behavior.scenario is FakeRuntimeScenario.EXTRA_DISTRIBUTION_MAPPING
    _write_distribution(bundle_root, compiled, extra=extra)
    manifest_raw = _write_build_manifest(
        bundle_root,
        compiler=compiler,
        compiled=compiled,
        source_hashes=source_hashes,
        behavior=behavior,
    )
    _verify_build_manifest(bundle_root, manifest_raw)
    return _issue_owned_fake_runtime_capability(
        test_root=test_root,
        bundle_root=bundle_root,
        registry_root=bundle_root / "registry/sessions.d",
        behavior_code=behavior.scenario.value,
        descendant_code=behavior.descendants.value,
        ready_delay_seconds=behavior.ready_delay_seconds,
        reexec_mode=behavior.reexec.value,
        compiler_identity=(
            str(compiler.path),
            compiler.device,
            compiler.inode,
            compiler.size,
            compiler.sha256,
            compiler.family,
        ),
        compiler_argv=compiled.argv,
        source_hashes=source_hashes,
    )


__all__ = [
    "FakeDescendantShape",
    "FakeReexecMode",
    "FakeRuntimeBehavior",
    "FakeRuntimeScenario",
    "FakeRuntimeUnsupported",
    "build_runtime_receipt_document",
    "forbid_receipt_sidecar_reads",
    "make_owned_runtime_receipt_fake",
    "resign_runtime_receipt_document",
    "runtime_receipt_verification_now",
]
