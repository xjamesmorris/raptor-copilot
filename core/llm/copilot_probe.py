"""Synthetic-only Copilot CLI probe boundary.

Level A executes only an opaque, repository-owned fake executable through the
ordinary strict networked sandbox. There is deliberately no real executable,
provider, launcher, discovery, credential lookup, or production branch here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import urllib.parse
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path

from core.config import RaptorConfig
from core.llm.copilot_protocol import (
    CANDIDATE_SOURCE_CLI_VERSION,
    CandidateCompletion,
    CandidateRequestedSettings,
    CandidateStreamLimits,
    CandidateTranscript,
    CandidateTranscriptOutcome,
    CopilotCandidateAdmissionError,
    CopilotCandidateProtocolError,
    admit_candidate_completion,
    parse_candidate_transcript,
)
from core.sandbox import (
    SandboxCancelled,
    SandboxSetupError,
    run_untrusted_networked,
)
from core.security.fake_executable import (
    FAKE_EXECUTABLE_FACTORY_ID,
    OwnedFakeExecutable,
    owned_fake_secret_observation_hmac,
    owned_fake_synthetic_canary,
    verify_owned_fake_executable,
)

COPILOT_TRANSPORT_DISABLED_ENV = "RAPTOR_COPILOT_TRANSPORT_DISABLED"
SYNTHETIC_SECRET_ENV = "COPILOT_GITHUB_TOKEN"
SYNTHETIC_PROXY_HOSTS = ("synthetic.invalid",)
RAW_EVIDENCE_CLASSIFICATION = "prompt-bearing_potentially-secret-bearing"

_MAX_PROMPT_BYTES = 1024 * 1024
_MAX_RETENTION_SECONDS = 30 * 24 * 60 * 60
_MAX_SCAN_FILE_BYTES = 4 * 1024 * 1024
_MAX_SCAN_FILES = 1024
_OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/+ -]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_ENV = frozenset(
    {
        "COPILOT_CLI_DIST_DIR",
        "COPILOT_PKG_CACHE_HOME",
        "COPILOT_MODEL",
        "COPILOT_ALLOW_ALL",
        "GH_TOKEN",
        "GITHUB_TOKEN",
    }
)
_DIR_FLAGS = (
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


class CopilotProbeRefused(RuntimeError):
    """A synthetic probe request failed a pre-spawn authority gate."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class CopilotProbeCaptureMode(str, Enum):
    RECORD_ONLY = "record_only"
    CANDIDATE_ADMISSION = "candidate_admission"


class CopilotProbeStatus(str, Enum):
    RECORDED = "recorded"
    CANDIDATE_ADMITTED = "candidate_admitted"
    CANDIDATE_COMPLETE_UNEVIDENCED = "candidate_complete_unevidenced"
    CANDIDATE_REJECTED = "candidate_rejected"
    CAPTURE_INCOMPLETE = "capture_incomplete"
    PROCESS_FAILED = "process_failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    EVIDENCE_CONTAMINATED = "evidence_contaminated"
    SANDBOX_POSTURE_REJECTED = "sandbox_posture_rejected"


@dataclass(frozen=True)
class CopilotRuntimeReceipt:
    """Sanitized Level-A runtime identity; never execution authority."""

    executable: Path
    cli_version: str
    executable_sha256: str
    executable_size: int
    executable_device: int
    executable_inode: int
    origin: str
    factory_id: str


@dataclass(frozen=True)
class CopilotProbeCapture:
    enabled: bool
    stdout_truncated: bool | None
    stderr_truncated: bool | None
    stdout_bytes_kept: int | None
    stderr_bytes_kept: int | None


@dataclass(frozen=True)
class CopilotSandboxPosture:
    backend: str | None
    mount_ns_active: bool | None
    restrict_reads: bool | None
    proxy_enforcement: str | None
    degrade_waiver_honored: bool | None


@dataclass(frozen=True)
class CopilotParserDiagnostic:
    status: str
    error_type: str | None = None
    error_code: str | None = None


@dataclass(frozen=True)
class CopilotRawEvidenceRef:
    """Private raw evidence reference; the bytes are not in this object."""

    stdout_path: Path
    stderr_path: Path
    manifest_path: Path
    stdout_sha256: str
    stderr_sha256: str
    classification: str
    owner: str
    expires_at: str
    quarantined: bool
    contamination_encodings: tuple[str, ...]


@dataclass(frozen=True)
class CopilotProbePlan:
    """Non-spawning, prompt-free Level-A execution plan."""

    capture_mode: CopilotProbeCaptureMode
    runtime_receipt: CopilotRuntimeReceipt
    requested_settings: CandidateRequestedSettings
    session_id: str
    argv: tuple[str, ...]
    private_root: Path
    cwd: Path
    home: Path
    copilot_home: Path
    xdg_config_home: Path
    xdg_cache_home: Path
    xdg_data_home: Path
    xdg_state_home: Path
    xdg_runtime_dir: Path
    copilot_cache_home: Path
    log_dir: Path
    usage_output_path: Path
    evidence_root: Path
    execution_marker: Path
    proxy_hosts: tuple[str, ...]
    secret_env_names: tuple[str, ...]
    timeout_s: float
    stream_limits: CandidateStreamLimits
    prompt_bytes: int
    prompt_sha256: str
    evidence_owner: str | None
    evidence_retention_seconds: int | None
    no_degrade: bool = field(default=True, init=False)
    level: str = field(default="A-synthetic", init=False)


@dataclass(frozen=True)
class CopilotProbeExecution:
    """Execution metadata.

    ``candidate_transcript`` and ``candidate_completion`` can contain model
    output and are therefore excluded from repr; callers must treat them as
    sensitive response data, not as sanitized diagnostics.
    """

    status: CopilotProbeStatus
    capture_mode: CopilotProbeCaptureMode
    returncode: int | None
    timed_out: bool
    cancelled: bool
    capture: CopilotProbeCapture
    sandbox: CopilotSandboxPosture
    parser_diagnostic: CopilotParserDiagnostic
    raw_evidence: CopilotRawEvidenceRef | None
    synthetic_secret_challenge_hmac: str
    candidate_transcript: CandidateTranscript | None = field(
        default=None,
        repr=False,
    )
    candidate_completion: CandidateCompletion | None = field(
        default=None,
        repr=False,
    )


@dataclass(frozen=True)
class _ProbePrivateState:
    capability: OwnedFakeExecutable
    session_id: str
    dir_identities: dict[str, tuple[int, int]]


def _transport_disabled() -> bool:
    value = os.environ.get(COPILOT_TRANSPORT_DISABLED_ENV, "1")
    return value.strip() not in ("", "0")


def _receipt(capability: OwnedFakeExecutable) -> CopilotRuntimeReceipt:
    return CopilotRuntimeReceipt(
        executable=capability.path,
        cli_version=CANDIDATE_SOURCE_CLI_VERSION,
        executable_sha256=capability.executable_sha256,
        executable_size=capability.executable_size,
        executable_device=capability.executable_device,
        executable_inode=capability.executable_inode,
        origin="repository_owned_fake",
        factory_id=capability.factory_id,
    )


def _relative_dirs(session_id: str) -> dict[str, tuple[str, ...]]:
    return {
        "cwd": ("cwd",),
        "home": (".home",),
        "xdg_config_home": (".home", ".config"),
        "xdg_cache_home": (".home", ".cache"),
        "home_local": (".home", ".local"),
        "xdg_data_home": (".home", ".local", "share"),
        "xdg_state_home": (".home", ".local", "state"),
        "copilot_home": ("copilot-home",),
        "copilot_cache_home": ("copilot-home", "cache"),
        "xdg_root": ("xdg",),
        "xdg_runtime_dir": ("xdg", "runtime"),
        "raptor_root": ("raptor",),
        "out": ("raptor", "out"),
        "log_dir": ("raptor", "out", f"copilot-logs-{session_id}"),
        "evidence_root": (
            "raptor",
            "out",
            f"copilot-evidence-{session_id}",
        ),
        "capability_log_dir": ("logs",),
    }


def _paths(
    capability: OwnedFakeExecutable,
    session_id: str,
) -> dict[str, Path]:
    root = capability.workspace_root
    relative = _relative_dirs(session_id)
    home = root.joinpath(*relative["home"])
    out = root.joinpath(*relative["out"])
    return {
        "private_root": root,
        "cwd": root.joinpath(*relative["cwd"]),
        "home": home,
        "copilot_home": root.joinpath(*relative["copilot_home"]),
        "xdg_config_home": root.joinpath(*relative["xdg_config_home"]),
        "xdg_cache_home": root.joinpath(*relative["xdg_cache_home"]),
        "xdg_data_home": root.joinpath(*relative["xdg_data_home"]),
        "xdg_state_home": root.joinpath(*relative["xdg_state_home"]),
        "xdg_runtime_dir": root.joinpath(*relative["xdg_runtime_dir"]),
        "copilot_cache_home": root.joinpath(*relative["copilot_cache_home"]),
        "log_dir": root.joinpath(*relative["log_dir"]),
        "usage_output_path": out / f"copilot-usage-{session_id}.json",
        "evidence_root": root.joinpath(*relative["evidence_root"]),
        "execution_marker": out / f".copilot-probe-{session_id}.started",
    }


def _command(
    *,
    executable: Path,
    requested: CandidateRequestedSettings,
    session_id: str,
    cwd: Path,
    usage_output_path: Path,
    log_dir: Path,
) -> tuple[str, ...]:
    return (
        str(executable),
        "--model",
        requested.model,
        "--effort",
        requested.reasoning_effort or "",
        "--context",
        requested.context_tier or "",
        "--session-id",
        session_id,
        "--output-format",
        "json",
        "--usage-output-file",
        str(usage_output_path),
        "--log-dir",
        str(log_dir),
        "--log-level",
        "none",
        "--secret-env-vars",
        SYNTHETIC_SECRET_ENV,
        "--no-auto-update",
        "--no-custom-instructions",
        "--no-ask-user",
        "--no-remote-export",
        "--available-tools=",
        "--deny-tool=shell",
        "--deny-tool=write",
        "--deny-tool=url",
        "--deny-tool=memory",
        "--disable-builtin-mcps",
        "--disallow-temp-dir",
        "--no-bash-env",
        "-C",
        str(cwd),
    )


def _capture_mode(value: CopilotProbeCaptureMode) -> CopilotProbeCaptureMode:
    if not isinstance(value, CopilotProbeCaptureMode):
        raise TypeError("capture_mode must be CopilotProbeCaptureMode")
    return value


def _canonical_session_id(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("session_id must be a string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError("session_id must be a canonical UUID") from exc
    if str(parsed) != value or parsed.version != 4:
        raise ValueError("session_id must be a canonical UUID v4")
    return value


def _validate_timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("timeout_s must be a finite number")
    value = float(value)
    if not math.isfinite(value) or not 0 < value <= 3600:
        raise ValueError("timeout_s must be between 0 and 3600 seconds")
    return value


def _validate_prompt(prompt: bytes) -> bytes:
    if not isinstance(prompt, bytes):
        raise TypeError("prompt must be bytes")
    if not prompt:
        raise ValueError("prompt must not be empty")
    if len(prompt) > _MAX_PROMPT_BYTES:
        raise ValueError(f"prompt exceeds the {_MAX_PROMPT_BYTES}-byte Level-A limit")
    return prompt


def _validate_cancel_fd(cancel_fd: int | None) -> None:
    if cancel_fd is None:
        return
    if type(cancel_fd) is not int or cancel_fd < 3:
        raise CopilotProbeRefused(
            "cancel_fd_invalid",
            "cancel_fd must be an open non-stdio file descriptor",
        )
    try:
        os.fstat(cancel_fd)
        inheritable = os.get_inheritable(cancel_fd)
    except OSError:
        raise CopilotProbeRefused(
            "cancel_fd_invalid",
            "cancel_fd must be an open non-stdio file descriptor",
        ) from None
    if inheritable:
        raise CopilotProbeRefused(
            "cancel_fd_invalid",
            "cancel_fd must be close-on-exec",
        )


def _validate_retention(
    mode: CopilotProbeCaptureMode,
    owner: str | None,
    seconds: int | None,
) -> tuple[str | None, int | None]:
    if mode is CopilotProbeCaptureMode.CANDIDATE_ADMISSION:
        if owner is not None or seconds is not None:
            raise ValueError("candidate_admission does not retain raw evidence")
        return None, None
    if not isinstance(owner, str) or _OWNER_RE.fullmatch(owner) is None:
        raise ValueError("record_only requires a bounded evidence_owner string")
    if type(seconds) is not int or seconds <= 0 or seconds > _MAX_RETENTION_SECONDS:
        raise ValueError(
            "record_only requires evidence_retention_seconds between "
            f"1 and {_MAX_RETENTION_SECONDS}"
        )
    return owner, seconds


def build_copilot_probe_plan(
    *,
    synthetic_capability: object,
    prompt: bytes,
    model: str,
    reasoning_effort: str,
    context_tier: str,
    session_id: str,
    capture_mode: CopilotProbeCaptureMode,
    timeout_s: float,
    stream_limits: CandidateStreamLimits | None = None,
    evidence_owner: str | None = None,
    evidence_retention_seconds: int | None = None,
) -> CopilotProbePlan:
    """Build and validate a non-spawning Level-A synthetic probe plan."""
    capability = verify_owned_fake_executable(synthetic_capability)
    if capability.factory_id != FAKE_EXECUTABLE_FACTORY_ID:
        raise ValueError("owned fake factory identity is unsupported")
    if capability.secret_env_names != (SYNTHETIC_SECRET_ENV,):
        raise ValueError("owned fake must redact exactly COPILOT_GITHUB_TOKEN")
    prompt = _validate_prompt(prompt)
    mode = _capture_mode(capture_mode)
    owner, retention = _validate_retention(
        mode,
        evidence_owner,
        evidence_retention_seconds,
    )
    requested = CandidateRequestedSettings(
        model=model,
        reasoning_effort=reasoning_effort,
        context_tier=context_tier,
    )
    if requested.reasoning_effort is None:
        raise ValueError("reasoning_effort must be explicit")
    if requested.context_tier is None:
        raise ValueError("context_tier must be explicit")
    session_id = _canonical_session_id(session_id)
    timeout = _validate_timeout(timeout_s)
    limits = stream_limits or CandidateStreamLimits()
    if not isinstance(limits, CandidateStreamLimits):
        raise TypeError("stream_limits must be CandidateStreamLimits")
    paths = _paths(capability, session_id)
    argv = _command(
        executable=capability.path,
        requested=requested,
        session_id=session_id,
        cwd=paths["cwd"],
        usage_output_path=paths["usage_output_path"],
        log_dir=paths["log_dir"],
    )
    return CopilotProbePlan(
        capture_mode=mode,
        runtime_receipt=_receipt(capability),
        requested_settings=requested,
        session_id=session_id,
        argv=argv,
        proxy_hosts=SYNTHETIC_PROXY_HOSTS,
        secret_env_names=(SYNTHETIC_SECRET_ENV,),
        timeout_s=timeout,
        stream_limits=limits,
        prompt_bytes=len(prompt),
        prompt_sha256=hashlib.sha256(prompt).hexdigest(),
        evidence_owner=owner,
        evidence_retention_seconds=retention,
        **paths,
    )


def _revalidate_plan_contract(
    plan: CopilotProbePlan,
    capability: OwnedFakeExecutable,
) -> None:
    """Re-run every public plan value contract before any mutation."""
    try:
        mode = _capture_mode(plan.capture_mode)
        session_id = _canonical_session_id(plan.session_id)
        timeout = _validate_timeout(plan.timeout_s)
        if type(plan.requested_settings) is not CandidateRequestedSettings:
            raise TypeError("requested_settings must be CandidateRequestedSettings")
        requested = CandidateRequestedSettings(
            model=plan.requested_settings.model,
            reasoning_effort=plan.requested_settings.reasoning_effort,
            context_tier=plan.requested_settings.context_tier,
        )
        if requested.reasoning_effort is None or requested.context_tier is None:
            raise ValueError("requested settings must be explicit")
        if type(plan.stream_limits) is not CandidateStreamLimits:
            raise TypeError("stream_limits must be CandidateStreamLimits")
        limits = CandidateStreamLimits(
            max_total_bytes=plan.stream_limits.max_total_bytes,
            max_line_bytes=plan.stream_limits.max_line_bytes,
            max_events=plan.stream_limits.max_events,
        )
        if type(plan.prompt_bytes) is not int:
            raise TypeError("prompt_bytes must be an integer")
        if not 0 < plan.prompt_bytes <= _MAX_PROMPT_BYTES:
            raise ValueError("prompt_bytes is outside the Level-A limit")
        if not isinstance(plan.prompt_sha256, str) or not _SHA256_RE.fullmatch(
            plan.prompt_sha256
        ):
            raise ValueError("prompt_sha256 is malformed")
        _validate_retention(
            mode,
            plan.evidence_owner,
            plan.evidence_retention_seconds,
        )
        if type(plan.argv) is not tuple or not all(
            isinstance(value, str) for value in plan.argv
        ):
            raise TypeError("argv must be a tuple of strings")
        if type(plan.runtime_receipt) is not CopilotRuntimeReceipt:
            raise TypeError("runtime_receipt must be CopilotRuntimeReceipt")
        if type(plan.no_degrade) is not bool or plan.no_degrade is not True:
            raise TypeError("no_degrade must be true")
        if type(plan.level) is not str or plan.level != "A-synthetic":
            raise ValueError("level must be A-synthetic")
        for name in _paths(capability, session_id):
            value = getattr(plan, name)
            if not isinstance(value, Path) or not value.is_absolute():
                raise TypeError(f"{name} must be an absolute Path")
    except AttributeError:
        raise CopilotProbeRefused(
            "plan_invalid",
            "the probe plan contains malformed settings or limits",
        ) from None
    except (TypeError, ValueError) as exc:
        raise CopilotProbeRefused(
            "plan_invalid",
            f"the probe plan contract is invalid: {exc}",
        ) from None

    if (
        mode is not plan.capture_mode
        or session_id != plan.session_id
        or timeout != float(plan.timeout_s)
        or requested != plan.requested_settings
        or limits != plan.stream_limits
    ):
        raise CopilotProbeRefused(
            "plan_invalid",
            "the probe plan is not in canonical form",
        )


def _validate_plan(
    plan: CopilotProbePlan,
    capability: OwnedFakeExecutable,
) -> None:
    if type(plan) is not CopilotProbePlan:
        raise CopilotProbeRefused(
            "plan_invalid",
            "plan must be CopilotProbePlan",
        )
    _revalidate_plan_contract(plan, capability)
    if plan.runtime_receipt != _receipt(capability):
        raise CopilotProbeRefused(
            "runtime_receipt_mismatch",
            "the plan runtime receipt does not match the verified owned fake",
        )
    if plan.private_root != capability.workspace_root:
        raise CopilotProbeRefused(
            "private_root_mismatch",
            "the plan private root is not the owned fake workspace",
        )
    if plan.proxy_hosts != SYNTHETIC_PROXY_HOSTS:
        raise CopilotProbeRefused(
            "proxy_policy_mismatch",
            "Level A uses only the fixed synthetic proxy allowlist",
        )
    if plan.secret_env_names != (SYNTHETIC_SECRET_ENV,):
        raise CopilotProbeRefused(
            "secret_policy_mismatch",
            "Level A uses only the internal synthetic secret variable",
        )
    if not plan.no_degrade or plan.level != "A-synthetic":
        raise CopilotProbeRefused(
            "level_mismatch",
            "the plan does not carry the Level-A no-degrade policy",
        )
    expected_paths = _paths(capability, plan.session_id)
    for name, expected in expected_paths.items():
        if getattr(plan, name) != expected:
            raise CopilotProbeRefused(
                "private_path_mismatch",
                f"the plan {name} path was modified",
            )
    expected_argv = _command(
        executable=capability.path,
        requested=plan.requested_settings,
        session_id=plan.session_id,
        cwd=plan.cwd,
        usage_output_path=plan.usage_output_path,
        log_dir=plan.log_dir,
    )
    if plan.argv != expected_argv:
        raise CopilotProbeRefused(
            "command_policy_mismatch",
            "the protected Level-A command was modified",
        )
    if not _SHA256_RE.fullmatch(plan.prompt_sha256):
        raise CopilotProbeRefused(
            "prompt_digest_invalid",
            "the prompt digest in the plan is invalid",
        )
    _validate_retention(
        plan.capture_mode,
        plan.evidence_owner,
        plan.evidence_retention_seconds,
    )


def _identity(st: os.stat_result) -> tuple[int, int]:
    return st.st_dev, st.st_ino


def _private_component(name: str) -> str:
    if not name or name in (".", "..") or "/" in name or "\\" in name:
        raise CopilotProbeRefused(
            "private_path_unsafe",
            "private path contains an invalid component",
        )
    return name


def _validate_private_dir(
    fd: int,
    *,
    label: str,
    expected: tuple[int, int] | None = None,
) -> tuple[int, int]:
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode):
        raise CopilotProbeRefused(
            "private_path_unsafe",
            f"{label} is not a directory",
        )
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise CopilotProbeRefused(
            "private_path_permissions",
            f"{label} is not caller-owned private state",
        )
    identity = _identity(st)
    if expected is not None and identity != expected:
        raise CopilotProbeRefused(
            "private_path_identity",
            f"{label} identity changed",
        )
    return identity


def _open_workspace_root(capability: OwnedFakeExecutable) -> int:
    try:
        fd = os.open(str(capability.workspace_root), _DIR_FLAGS)
    except OSError:
        raise CopilotProbeRefused(
            "private_path_unsafe",
            "the verified workspace root cannot be opened safely",
        ) from None
    try:
        _validate_private_dir(
            fd,
            label="workspace root",
            expected=capability.root_identity,
        )
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_relative_dir(
    root_fd: int,
    components: tuple[str, ...],
    *,
    label: str,
    create: bool,
    expected: tuple[int, int] | None = None,
) -> int:
    current_fd = os.dup(root_fd)
    try:
        for index, raw_name in enumerate(components):
            name = _private_component(raw_name)
            if create:
                try:
                    os.mkdir(name, mode=0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
                except OSError:
                    raise CopilotProbeRefused(
                        "private_path_unsafe",
                        f"{label} cannot be created safely",
                    ) from None
            try:
                next_fd = os.open(name, _DIR_FLAGS, dir_fd=current_fd)
            except OSError:
                raise CopilotProbeRefused(
                    "private_path_unsafe",
                    f"{label} cannot be opened safely",
                ) from None
            os.close(current_fd)
            current_fd = next_fd
            _validate_private_dir(
                current_fd,
                label=label,
                expected=(expected if index == len(components) - 1 else None),
            )
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _write_private_at(
    parent_fd: int,
    name: str,
    data: bytes,
    *,
    label: str,
    exists_code: str = "private_path_unsafe",
) -> None:
    name = _private_component(name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
    except FileExistsError:
        raise CopilotProbeRefused(
            exists_code,
            f"{label} already exists",
        ) from None
    except OSError:
        raise CopilotProbeRefused(
            "private_path_unsafe",
            f"{label} cannot be created safely",
        ) from None
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) & 0o077
        ):
            raise CopilotProbeRefused(
                "private_path_permissions",
                f"{label} is not a caller-owned private file",
            )
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(data)
    finally:
        os.close(fd)


def _require_absent_at(parent_fd: int, name: str, *, label: str) -> None:
    name = _private_component(name)
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        raise CopilotProbeRefused(
            "private_path_unsafe",
            f"{label} cannot be checked safely",
        ) from None
    raise CopilotProbeRefused(
        "private_path_unsafe",
        f"{label} must not exist before execution",
    )


def _prepare_private_state(
    plan: CopilotProbePlan,
    capability: OwnedFakeExecutable,
) -> _ProbePrivateState:
    relative = _relative_dirs(plan.session_id)
    identities: dict[str, tuple[int, int]] = {
        "private_root": capability.root_identity,
    }
    root_fd = _open_workspace_root(capability)
    try:
        state_directories = [
            "cwd",
            "home",
            "xdg_config_home",
            "xdg_cache_home",
            "home_local",
            "xdg_data_home",
            "xdg_state_home",
            "copilot_home",
            "copilot_cache_home",
            "xdg_root",
            "xdg_runtime_dir",
            "raptor_root",
            "out",
            "log_dir",
        ]
        if plan.capture_mode is CopilotProbeCaptureMode.RECORD_ONLY:
            state_directories.append("evidence_root")
        for name in state_directories:
            fd = _open_relative_dir(
                root_fd,
                relative[name],
                label=name,
                create=True,
            )
            try:
                identities[name] = _identity(os.fstat(fd))
            finally:
                os.close(fd)
        capability_log_fd = _open_relative_dir(
            root_fd,
            relative["capability_log_dir"],
            label="capability_log_dir",
            create=False,
            expected=capability.log_identity,
        )
        try:
            identities["capability_log_dir"] = _identity(os.fstat(capability_log_fd))
        finally:
            os.close(capability_log_fd)

        out_fd = _open_relative_dir(
            root_fd,
            relative["out"],
            label="out",
            create=False,
            expected=identities["out"],
        )
        try:
            _require_absent_at(
                out_fd,
                plan.usage_output_path.name,
                label="usage output",
            )
            _write_private_at(
                out_fd,
                plan.execution_marker.name,
                b"level=A-synthetic\n",
                label="execution marker",
                exists_code="plan_already_executed",
            )
        finally:
            os.close(out_fd)

        copilot_home_fd = _open_relative_dir(
            root_fd,
            relative["copilot_home"],
            label="copilot_home",
            create=False,
            expected=identities["copilot_home"],
        )
        try:
            settings = {
                "askUser": False,
                "continueOnAutoMode": False,
                "disableAllHooks": True,
                "remote": "off",
                "remoteExport": False,
            }
            _write_private_at(
                copilot_home_fd,
                "settings.json",
                (
                    json.dumps(
                        settings,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8"),
                label="Copilot settings",
            )
        finally:
            os.close(copilot_home_fd)
    finally:
        os.close(root_fd)
    return _ProbePrivateState(
        capability=capability,
        session_id=plan.session_id,
        dir_identities=identities,
    )


def _open_state_dir(state: _ProbePrivateState, name: str) -> int:
    root_fd = _open_workspace_root(state.capability)
    try:
        return _open_relative_dir(
            root_fd,
            _relative_dirs_for_state(state, name),
            label=name,
            create=False,
            expected=state.dir_identities[name],
        )
    finally:
        os.close(root_fd)


def _relative_dirs_for_state(
    state: _ProbePrivateState,
    name: str,
) -> tuple[str, ...]:
    if name == "private_root":
        return ()
    return _relative_dirs(state.session_id)[name]


def _child_env(
    plan: CopilotProbePlan,
    *,
    canary: str,
) -> dict[str, str]:
    env = RaptorConfig.get_safe_env()
    for name in tuple(env):
        if (
            name in _FORBIDDEN_ENV
            or name.startswith("COPILOT_")
            or name in RaptorConfig.LLM_API_KEY_VARS
            or name in RaptorConfig.LLM_ROUTING_ENV_VARS
            or name.startswith(RaptorConfig.LLM_ROUTING_ENV_PREFIXES)
        ):
            env.pop(name, None)
    for name in (
        "RAPTOR_CONFIG",
        "RAPTOR_DIR",
        "RAPTOR_OUT_DIR",
        "RAPTOR_SESSION_PID",
        "RAPTOR_SESSION_TOKEN",
        "CLAUDECODE",
        "_RAPTOR_TRUSTED",
    ):
        env.pop(name, None)
    env.update(
        {
            "PATH": "/usr/bin:/bin",
            "HOME": str(plan.home),
            "COPILOT_HOME": str(plan.copilot_home),
            "COPILOT_CACHE_HOME": str(plan.copilot_cache_home),
            "COPILOT_AUTO_UPDATE": "false",
            "XDG_CONFIG_HOME": str(plan.xdg_config_home),
            "XDG_CACHE_HOME": str(plan.xdg_cache_home),
            "XDG_DATA_HOME": str(plan.xdg_data_home),
            "XDG_STATE_HOME": str(plan.xdg_state_home),
            "XDG_RUNTIME_DIR": str(plan.xdg_runtime_dir),
            "TMPDIR": "/tmp",
            "RAPTOR_NONINTERACTIVE": "1",
            "RAPTOR_CC_TRANSPORT_DISABLED": "1",
            COPILOT_TRANSPORT_DISABLED_ENV: "1",
            SYNTHETIC_SECRET_ENV: canary,
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUNBUFFERED": "1",
        }
    )
    return env


def _capture_from(result_or_error) -> CopilotProbeCapture:
    info = dict(getattr(result_or_error, "sandbox_info", {}) or {})
    capture = dict(info.get("capture") or {})
    return CopilotProbeCapture(
        enabled=bool(capture.get("enabled", False)),
        stdout_truncated=capture.get("stdout_truncated"),
        stderr_truncated=capture.get("stderr_truncated"),
        stdout_bytes_kept=capture.get("stdout_bytes_kept"),
        stderr_bytes_kept=capture.get("stderr_bytes_kept"),
    )


def _posture_from(result_or_error) -> CopilotSandboxPosture:
    info = dict(getattr(result_or_error, "sandbox_info", {}) or {})
    return CopilotSandboxPosture(
        backend=info.get("backend"),
        mount_ns_active=info.get("mount_ns_active"),
        restrict_reads=info.get("restrict_reads"),
        proxy_enforcement=info.get("proxy_enforcement"),
        degrade_waiver_honored=info.get("degrade_waiver_honored"),
    )


def _captured_prefix(
    value,
    bytes_kept: int | None,
) -> bytes:
    if not isinstance(value, bytes):
        return b""
    if bytes_kept is None:
        return b""
    return value[:bytes_kept]


def _raw_streams(result_or_error) -> tuple[bytes, bytes]:
    capture = _capture_from(result_or_error)
    stdout_value = getattr(
        result_or_error,
        "stdout",
        getattr(result_or_error, "output", None),
    )
    stderr_value = getattr(result_or_error, "stderr", None)
    return (
        _captured_prefix(stdout_value, capture.stdout_bytes_kept),
        _captured_prefix(stderr_value, capture.stderr_bytes_kept),
    )


def _contamination_variants(canary: bytes) -> dict[str, bytes]:
    return {
        "exact": canary,
        "base64": base64.b64encode(canary),
        "base64url": base64.urlsafe_b64encode(canary),
        "percent": urllib.parse.quote_from_bytes(canary).encode("ascii"),
    }


def _scan_known_files(
    plan: CopilotProbePlan,
    state: _ProbePrivateState,
    variants: dict[str, bytes],
) -> set[str]:
    matches: set[str] = set()
    if not _private_state_stable(state):
        matches.add("unscannable")

    out_fd = _try_open_state_dir(state, "out", matches)
    if out_fd is not None:
        try:
            _scan_file_at(
                out_fd,
                plan.usage_output_path.name,
                variants,
                matches,
                missing_ok=True,
            )
            _scan_file_at(
                out_fd,
                plan.execution_marker.name,
                variants,
                matches,
                missing_ok=False,
            )
        finally:
            os.close(out_fd)

    copilot_home_fd = _try_open_state_dir(
        state,
        "copilot_home",
        matches,
    )
    if copilot_home_fd is not None:
        try:
            _scan_file_at(
                copilot_home_fd,
                "settings.json",
                variants,
                matches,
                missing_ok=False,
            )
        finally:
            os.close(copilot_home_fd)

    for name in ("log_dir", "capability_log_dir"):
        directory_fd = _try_open_state_dir(state, name, matches)
        if directory_fd is None:
            continue
        try:
            _scan_directory_files(
                directory_fd,
                variants,
                matches,
            )
        finally:
            os.close(directory_fd)
    return matches


def _private_state_stable(state: _ProbePrivateState) -> bool:
    try:
        root_fd = _open_workspace_root(state.capability)
    except CopilotProbeRefused:
        return False
    try:
        for name, expected in state.dir_identities.items():
            if name == "private_root":
                continue
            try:
                fd = _open_relative_dir(
                    root_fd,
                    _relative_dirs_for_state(state, name),
                    label=name,
                    create=False,
                    expected=expected,
                )
            except CopilotProbeRefused:
                return False
            else:
                os.close(fd)
        return True
    finally:
        os.close(root_fd)


def _try_open_state_dir(
    state: _ProbePrivateState,
    name: str,
    matches: set[str],
) -> int | None:
    try:
        return _open_state_dir(state, name)
    except CopilotProbeRefused:
        matches.add("unscannable")
        return None


def _scan_directory_files(
    directory_fd: int,
    variants: dict[str, bytes],
    matches: set[str],
) -> None:
    try:
        entries = os.scandir(directory_fd)
    except OSError:
        matches.add("unscannable")
        return
    with entries:
        for index, entry in enumerate(entries):
            if index >= _MAX_SCAN_FILES:
                matches.add("unscannable")
                break
            _scan_file_at(
                directory_fd,
                entry.name,
                variants,
                matches,
                missing_ok=False,
            )


def _scan_file_at(
    directory_fd: int,
    name: str,
    variants: dict[str, bytes],
    matches: set[str],
    *,
    missing_ok: bool,
) -> None:
    try:
        safe_name = _private_component(name)
    except CopilotProbeRefused:
        matches.add("unscannable")
        return
    try:
        fd = os.open(safe_name, _READ_FLAGS, dir_fd=directory_fd)
    except FileNotFoundError:
        if not missing_ok:
            matches.add("unscannable")
        return
    except OSError:
        matches.add("unscannable")
        return
    data = b""
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) & 0o077
            or st.st_size > _MAX_SCAN_FILE_BYTES
        ):
            matches.add("unscannable")
            return
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(_MAX_SCAN_FILE_BYTES + 1)
        if len(data) > _MAX_SCAN_FILE_BYTES:
            matches.add("unscannable")
            return
    except OSError:
        matches.add("unscannable")
        return
    finally:
        os.close(fd)
    for label, needle in variants.items():
        if needle and needle in data:
            matches.add(label)


def _contamination_matches(
    *,
    plan: CopilotProbePlan,
    private_state: _ProbePrivateState,
    canary: bytes,
    stdout: bytes,
    stderr: bytes,
) -> tuple[str, ...]:
    variants = _contamination_variants(canary)
    matches = {
        label
        for label, needle in variants.items()
        if needle and (needle in stdout or needle in stderr)
    }
    matches.update(_scan_known_files(plan, private_state, variants))
    return tuple(sorted(matches))


def _write_raw_evidence(
    *,
    plan: CopilotProbePlan,
    private_state: _ProbePrivateState,
    stdout: bytes,
    stderr: bytes,
    capture: CopilotProbeCapture,
    contamination: tuple[str, ...],
    started_at: datetime,
    returncode: int | None,
    timed_out: bool,
    cancelled: bool,
    parser_diagnostic: CopilotParserDiagnostic,
    sandbox: CopilotSandboxPosture,
) -> CopilotRawEvidenceRef:
    if plan.evidence_owner is None or plan.evidence_retention_seconds is None:
        raise RuntimeError("record_only plan lacks retention policy")
    quarantined = bool(contamination)
    bucket_name = "quarantine" if quarantined else "raw"
    bucket = plan.evidence_root / bucket_name
    stdout_path = bucket / "stdout.bin"
    stderr_path = bucket / "stderr.bin"
    manifest_path = bucket / "manifest.json"
    stdout_sha256 = hashlib.sha256(stdout).hexdigest()
    stderr_sha256 = hashlib.sha256(stderr).hexdigest()
    expires_at = (
        started_at + timedelta(seconds=plan.evidence_retention_seconds)
    ).isoformat()
    manifest = {
        "capture": {
            "stderr_bytes_kept": capture.stderr_bytes_kept,
            "stderr_truncated": capture.stderr_truncated,
            "stdout_bytes_kept": capture.stdout_bytes_kept,
            "stdout_truncated": capture.stdout_truncated,
        },
        "classification": RAW_EVIDENCE_CLASSIFICATION,
        "contamination_encodings": list(contamination),
        "expires_at": expires_at,
        "owner": plan.evidence_owner,
        "parser": {
            "error_code": parser_diagnostic.error_code,
            "error_type": parser_diagnostic.error_type,
            "status": parser_diagnostic.status,
        },
        "process": {
            "cancelled": cancelled,
            "returncode": returncode,
            "timed_out": timed_out,
        },
        "quarantined": quarantined,
        "runtime": {
            "executable_sha256": plan.runtime_receipt.executable_sha256,
            "factory_id": plan.runtime_receipt.factory_id,
            "level": plan.level,
            "origin": plan.runtime_receipt.origin,
        },
        "sandbox": {
            "backend": sandbox.backend,
            "degrade_waiver_honored": sandbox.degrade_waiver_honored,
            "mount_ns_active": sandbox.mount_ns_active,
            "proxy_enforcement": sandbox.proxy_enforcement,
            "restrict_reads": sandbox.restrict_reads,
        },
        "stderr_sha256": stderr_sha256,
        "stdout_sha256": stdout_sha256,
    }
    evidence_fd = _open_state_dir(private_state, "evidence_root")
    bucket_fd = -1
    try:
        bucket_fd = _open_relative_dir(
            evidence_fd,
            (bucket_name,),
            label="evidence_bucket",
            create=True,
        )
        bucket_identity = _identity(os.fstat(bucket_fd))
        _write_private_at(
            bucket_fd,
            stdout_path.name,
            stdout,
            label="raw stdout evidence",
        )
        _write_private_at(
            bucket_fd,
            stderr_path.name,
            stderr,
            label="raw stderr evidence",
        )
        _write_private_at(
            bucket_fd,
            manifest_path.name,
            (
                json.dumps(
                    manifest,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
            label="raw evidence manifest",
        )
    finally:
        if bucket_fd >= 0:
            os.close(bucket_fd)
        os.close(evidence_fd)

    root_fd = _open_workspace_root(private_state.capability)
    verify_evidence_fd = verify_bucket_fd = -1
    try:
        verify_evidence_fd = _open_relative_dir(
            root_fd,
            _relative_dirs(plan.session_id)["evidence_root"],
            label="evidence_root",
            create=False,
            expected=private_state.dir_identities["evidence_root"],
        )
        verify_bucket_fd = _open_relative_dir(
            verify_evidence_fd,
            (bucket_name,),
            label="evidence_bucket",
            create=False,
            expected=bucket_identity,
        )
    finally:
        if verify_bucket_fd >= 0:
            os.close(verify_bucket_fd)
        if verify_evidence_fd >= 0:
            os.close(verify_evidence_fd)
        os.close(root_fd)
    return CopilotRawEvidenceRef(
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        manifest_path=manifest_path,
        stdout_sha256=stdout_sha256,
        stderr_sha256=stderr_sha256,
        classification=RAW_EVIDENCE_CLASSIFICATION,
        owner=plan.evidence_owner,
        expires_at=expires_at,
        quarantined=quarantined,
        contamination_encodings=contamination,
    )


def _diagnose_candidate(
    payload: bytes,
    limits: CandidateStreamLimits,
    expected_session_id: str,
) -> tuple[CopilotParserDiagnostic, CandidateTranscript | None]:
    try:
        transcript = parse_candidate_transcript(payload, limits=limits)
    except CopilotCandidateProtocolError as exc:
        return (
            CopilotParserDiagnostic(
                status="rejected",
                error_type=type(exc).__name__,
            ),
            None,
        )
    if transcript.session_id != expected_session_id:
        return (
            CopilotParserDiagnostic(
                status="rejected",
                error_type="CopilotProbeSessionMismatch",
                error_code="session_id_mismatch",
            ),
            transcript,
        )
    return CopilotParserDiagnostic(status="accepted"), transcript


def _with_path_contamination_diagnostic(
    diagnostic: CopilotParserDiagnostic,
    contamination: tuple[str, ...],
) -> CopilotParserDiagnostic:
    if "unscannable" not in contamination:
        return diagnostic
    return CopilotParserDiagnostic(
        status="incomplete",
        error_type="CopilotProbePrivateState",
        error_code="unscannable_private_state",
    )


def _posture_is_level_a(posture: CopilotSandboxPosture) -> bool:
    return (
        posture.backend == "linux-fork-mount-pid-netns"
        and posture.mount_ns_active is True
        and posture.restrict_reads is True
        and posture.proxy_enforcement == "netns"
        and posture.degrade_waiver_honored is False
    )


def _execution(
    *,
    status: CopilotProbeStatus,
    plan: CopilotProbePlan,
    result_or_error,
    returncode: int | None,
    timed_out: bool,
    cancelled: bool,
    parser_diagnostic: CopilotParserDiagnostic,
    raw_evidence: CopilotRawEvidenceRef | None,
    secret_hmac: str,
    transcript: CandidateTranscript | None = None,
    completion: CandidateCompletion | None = None,
) -> CopilotProbeExecution:
    return CopilotProbeExecution(
        status=status,
        capture_mode=plan.capture_mode,
        returncode=returncode,
        timed_out=timed_out,
        cancelled=cancelled,
        capture=_capture_from(result_or_error),
        sandbox=_posture_from(result_or_error),
        parser_diagnostic=parser_diagnostic,
        raw_evidence=raw_evidence,
        synthetic_secret_challenge_hmac=secret_hmac,
        candidate_transcript=transcript,
        candidate_completion=completion,
    )


def execute_copilot_probe(
    plan: CopilotProbePlan,
    *,
    prompt: bytes,
    synthetic_capability: object | None = None,
    cancel_fd: int | None = None,
    allow_live: bool = False,
) -> CopilotProbeExecution:
    """Execute one verified Level-A fake through the guarded chokepoint."""
    if _transport_disabled():
        raise CopilotProbeRefused(
            "transport_disabled",
            f"{COPILOT_TRANSPORT_DISABLED_ENV} keeps Copilot transport disabled",
        )
    if allow_live:
        raise CopilotProbeRefused(
            "live_not_implemented",
            "this implementation is Level A synthetic only; allow_live "
            "cannot grant real execution authority",
        )
    if synthetic_capability is None:
        raise CopilotProbeRefused(
            "synthetic_capability_required",
            "Level A execution requires a fixture-issued owned fake",
        )
    capability = verify_owned_fake_executable(synthetic_capability)
    _validate_plan(plan, capability)
    prompt = _validate_prompt(prompt)
    _validate_cancel_fd(cancel_fd)
    if (
        len(prompt) != plan.prompt_bytes
        or hashlib.sha256(prompt).hexdigest() != plan.prompt_sha256
    ):
        raise CopilotProbeRefused(
            "prompt_mismatch",
            "execution prompt does not match the prompt-free plan digest",
        )

    private_state = _prepare_private_state(plan, capability)
    canary = owned_fake_synthetic_canary(
        capability,
        plan.session_id,
    )
    secret_hmac = owned_fake_secret_observation_hmac(
        capability,
        canary,
    )
    env = _child_env(plan, canary=canary)
    bind_identities = {
        str(capability.path): (
            capability.executable_device,
            capability.executable_inode,
        ),
        str(capability.config_path): (
            capability.config_device,
            capability.config_inode,
        ),
    }
    started_at = datetime.now(timezone.utc)
    try:
        result = run_untrusted_networked(
            list(plan.argv),
            output=str(plan.private_root),
            proxy_hosts=list(plan.proxy_hosts),
            restrict_reads=True,
            readable_paths=[
                str(capability.path),
                str(capability.config_path),
            ],
            writable_paths=[str(plan.private_root)],
            fake_home=True,
            env=env,
            cwd=str(plan.cwd),
            timeout=plan.timeout_s,
            capture_output=True,
            text=False,
            input=prompt,
            caller_label="copilot-synthetic-probe",
            tool_paths=[str(capability.path)],
            cancel_fd=cancel_fd,
            bind_source_identities=bind_identities,
            no_degrade=True,
        )
    except subprocess.TimeoutExpired as error:
        capture = _capture_from(error)
        posture = _posture_from(error)
        stdout, stderr = _raw_streams(error)
        contamination = _contamination_matches(
            plan=plan,
            private_state=private_state,
            canary=canary.encode(),
            stdout=stdout,
            stderr=stderr,
        )
        diagnostic = _with_path_contamination_diagnostic(
            CopilotParserDiagnostic(status="not_attempted"),
            contamination,
        )
        evidence = (
            _write_raw_evidence(
                plan=plan,
                private_state=private_state,
                stdout=stdout,
                stderr=stderr,
                capture=capture,
                contamination=contamination,
                started_at=started_at,
                returncode=None,
                timed_out=True,
                cancelled=False,
                parser_diagnostic=diagnostic,
                sandbox=posture,
            )
            if (
                plan.capture_mode is CopilotProbeCaptureMode.RECORD_ONLY
                and "unscannable" not in contamination
            )
            else None
        )
        status = (
            CopilotProbeStatus.EVIDENCE_CONTAMINATED
            if contamination
            else CopilotProbeStatus.TIMED_OUT
        )
        return _execution(
            status=status,
            plan=plan,
            result_or_error=error,
            returncode=None,
            timed_out=True,
            cancelled=False,
            parser_diagnostic=diagnostic,
            raw_evidence=evidence,
            secret_hmac=secret_hmac,
        )
    except SandboxCancelled as error:
        capture = _capture_from(error)
        posture = _posture_from(error)
        stdout, stderr = _raw_streams(error)
        contamination = _contamination_matches(
            plan=plan,
            private_state=private_state,
            canary=canary.encode(),
            stdout=stdout,
            stderr=stderr,
        )
        diagnostic = _with_path_contamination_diagnostic(
            CopilotParserDiagnostic(status="not_attempted"),
            contamination,
        )
        evidence = (
            _write_raw_evidence(
                plan=plan,
                private_state=private_state,
                stdout=stdout,
                stderr=stderr,
                capture=capture,
                contamination=contamination,
                started_at=started_at,
                returncode=None,
                timed_out=False,
                cancelled=True,
                parser_diagnostic=diagnostic,
                sandbox=posture,
            )
            if (
                plan.capture_mode is CopilotProbeCaptureMode.RECORD_ONLY
                and "unscannable" not in contamination
            )
            else None
        )
        status = (
            CopilotProbeStatus.EVIDENCE_CONTAMINATED
            if contamination
            else CopilotProbeStatus.CANCELLED
        )
        return _execution(
            status=status,
            plan=plan,
            result_or_error=error,
            returncode=None,
            timed_out=False,
            cancelled=True,
            parser_diagnostic=diagnostic,
            raw_evidence=evidence,
            secret_hmac=secret_hmac,
        )
    except SandboxSetupError as error:
        return _execution(
            status=CopilotProbeStatus.PROCESS_FAILED,
            plan=plan,
            result_or_error=error,
            returncode=None,
            timed_out=False,
            cancelled=False,
            parser_diagnostic=CopilotParserDiagnostic(status="not_attempted"),
            raw_evidence=None,
            secret_hmac=secret_hmac,
        )

    capture = _capture_from(result)
    posture = _posture_from(result)
    stdout, stderr = _raw_streams(result)
    contamination = _contamination_matches(
        plan=plan,
        private_state=private_state,
        canary=canary.encode(),
        stdout=stdout,
        stderr=stderr,
    )
    if plan.capture_mode is CopilotProbeCaptureMode.RECORD_ONLY:
        capture_complete = (
            capture.enabled
            and capture.stdout_truncated is False
            and capture.stderr_truncated is False
        )
        diagnostic = (
            CopilotParserDiagnostic(status="not_attempted")
            if not capture_complete
            else _diagnose_candidate(
                stdout,
                plan.stream_limits,
                plan.session_id,
            )[0]
        )
        diagnostic = _with_path_contamination_diagnostic(
            diagnostic,
            contamination,
        )
        evidence = (
            _write_raw_evidence(
                plan=plan,
                private_state=private_state,
                stdout=stdout,
                stderr=stderr,
                capture=capture,
                contamination=contamination,
                started_at=started_at,
                returncode=result.returncode,
                timed_out=False,
                cancelled=False,
                parser_diagnostic=diagnostic,
                sandbox=posture,
            )
            if "unscannable" not in contamination
            else None
        )
        return _execution(
            status=(
                CopilotProbeStatus.EVIDENCE_CONTAMINATED
                if contamination
                else (
                    CopilotProbeStatus.RECORDED
                    if _posture_is_level_a(posture)
                    else CopilotProbeStatus.SANDBOX_POSTURE_REJECTED
                )
            ),
            plan=plan,
            result_or_error=result,
            returncode=result.returncode,
            timed_out=False,
            cancelled=False,
            parser_diagnostic=diagnostic,
            raw_evidence=evidence,
            secret_hmac=secret_hmac,
        )

    if contamination:
        return _execution(
            status=CopilotProbeStatus.EVIDENCE_CONTAMINATED,
            plan=plan,
            result_or_error=result,
            returncode=result.returncode,
            timed_out=False,
            cancelled=False,
            parser_diagnostic=_with_path_contamination_diagnostic(
                CopilotParserDiagnostic(status="not_attempted"),
                contamination,
            ),
            raw_evidence=None,
            secret_hmac=secret_hmac,
        )
    if not _posture_is_level_a(posture):
        return _execution(
            status=CopilotProbeStatus.SANDBOX_POSTURE_REJECTED,
            plan=plan,
            result_or_error=result,
            returncode=result.returncode,
            timed_out=False,
            cancelled=False,
            parser_diagnostic=CopilotParserDiagnostic(status="not_attempted"),
            raw_evidence=None,
            secret_hmac=secret_hmac,
        )
    if (
        not capture.enabled
        or capture.stdout_truncated is not False
        or capture.stderr_truncated is not False
    ):
        return _execution(
            status=CopilotProbeStatus.CAPTURE_INCOMPLETE,
            plan=plan,
            result_or_error=result,
            returncode=result.returncode,
            timed_out=False,
            cancelled=False,
            parser_diagnostic=CopilotParserDiagnostic(status="not_attempted"),
            raw_evidence=None,
            secret_hmac=secret_hmac,
        )
    if result.returncode != 0:
        return _execution(
            status=CopilotProbeStatus.PROCESS_FAILED,
            plan=plan,
            result_or_error=result,
            returncode=result.returncode,
            timed_out=False,
            cancelled=False,
            parser_diagnostic=CopilotParserDiagnostic(status="not_attempted"),
            raw_evidence=None,
            secret_hmac=secret_hmac,
        )

    diagnostic, transcript = _diagnose_candidate(
        stdout,
        plan.stream_limits,
        plan.session_id,
    )
    if transcript is None:
        return _execution(
            status=CopilotProbeStatus.CANDIDATE_REJECTED,
            plan=plan,
            result_or_error=result,
            returncode=result.returncode,
            timed_out=False,
            cancelled=False,
            parser_diagnostic=diagnostic,
            raw_evidence=None,
            secret_hmac=secret_hmac,
        )
    if diagnostic.error_code == "session_id_mismatch":
        return _execution(
            status=CopilotProbeStatus.CANDIDATE_REJECTED,
            plan=plan,
            result_or_error=result,
            returncode=result.returncode,
            timed_out=False,
            cancelled=False,
            parser_diagnostic=diagnostic,
            raw_evidence=None,
            secret_hmac=secret_hmac,
            transcript=transcript,
        )
    if transcript.outcome is (
        CandidateTranscriptOutcome.CANDIDATE_COMPLETE_UNEVIDENCED
    ):
        return _execution(
            status=CopilotProbeStatus.CANDIDATE_COMPLETE_UNEVIDENCED,
            plan=plan,
            result_or_error=result,
            returncode=result.returncode,
            timed_out=False,
            cancelled=False,
            parser_diagnostic=diagnostic,
            raw_evidence=None,
            secret_hmac=secret_hmac,
            transcript=transcript,
        )
    try:
        completion = admit_candidate_completion(
            transcript,
            plan.requested_settings,
        )
    except CopilotCandidateAdmissionError as exc:
        return _execution(
            status=CopilotProbeStatus.CANDIDATE_REJECTED,
            plan=plan,
            result_or_error=result,
            returncode=result.returncode,
            timed_out=False,
            cancelled=False,
            parser_diagnostic=CopilotParserDiagnostic(
                status="rejected",
                error_type=type(exc).__name__,
                error_code=exc.code,
            ),
            raw_evidence=None,
            secret_hmac=secret_hmac,
            transcript=transcript,
        )
    return _execution(
        status=CopilotProbeStatus.CANDIDATE_ADMITTED,
        plan=plan,
        result_or_error=result,
        returncode=result.returncode,
        timed_out=False,
        cancelled=False,
        parser_diagnostic=diagnostic,
        raw_evidence=None,
        secret_hmac=secret_hmac,
        transcript=transcript,
        completion=completion,
    )


__all__ = [
    "COPILOT_TRANSPORT_DISABLED_ENV",
    "RAW_EVIDENCE_CLASSIFICATION",
    "SYNTHETIC_SECRET_ENV",
    "CopilotParserDiagnostic",
    "CopilotProbeCapture",
    "CopilotProbeCaptureMode",
    "CopilotProbeExecution",
    "CopilotProbePlan",
    "CopilotProbeRefused",
    "CopilotProbeStatus",
    "CopilotRawEvidenceRef",
    "CopilotRuntimeReceipt",
    "CopilotSandboxPosture",
    "build_copilot_probe_plan",
    "execute_copilot_probe",
]
