"""Shared coverage ingestion for host read-tool events.

The production hook and tests use this one implementation. Host-event parsing
does not grant authority: a read is recorded only for a verified current
Claude owner and the sole eligible running run in that owner's ledger.

The no-credential ``.active`` lookup remains solely as the pre-series Claude
compatibility route. Reserved launch-evidence markers are ineligible both at
discovery and at the fd-bound pre-append recheck. A present but invalid
credential never reaches the fallback.
Symlinked run directories retain the existing same-uid behavior: ownership,
not directory isolation, is the gate. The manifest is evidence only; it never
grants run ownership or review depth.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

MANIFEST_NAME = ".reads-manifest"

_MAX_STDIN_BYTES = 1 * 1024 * 1024
_MAX_METADATA_BYTES = 1 * 1024 * 1024
_MAX_PROJECT_BYTES = 1 * 1024 * 1024
_MAX_REPORTED_PATH = 16 * 1024

_SOURCE_EXTENSIONS = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".cc",
        ".cxx",
        ".java",
        ".go",
        ".rs",
        ".rb",
        ".php",
        ".cs",
        ".swift",
        ".kt",
        ".scala",
        ".sh",
        ".bash",
        ".zsh",
        ".zig",
        ".nim",
        ".cr",
        ".sol",
        ".dart",
        ".m",
        ".mm",
        ".lua",
        ".pl",
        ".pm",
        ".jl",
        ".ex",
        ".exs",
        ".erl",
        ".hrl",
        ".fs",
        ".fsi",
        ".fsx",
        ".ml",
        ".mli",
        ".clj",
        ".cljs",
        ".cljc",
        ".groovy",
        ".gradle",
        ".r",
        ".hs",
        ".elm",
        ".vue",
        ".svelte",
        ".astro",
        ".tf",
        ".tofu",
        ".nix",
    }
)


@dataclass(frozen=True)
class ReadArgumentContract:
    """Native argument key for a canonical read tool."""

    canonical_tool_name: str
    path_key: str


@dataclass(frozen=True)
class ReadObservation:
    """A reported read path, not yet attributed to a run."""

    event: Any
    reported_path: str


@dataclass(frozen=True)
class ReadObservationResult:
    """Non-throwing read-argument extraction result."""

    disposition: Any
    observation: ReadObservation | None
    reason_code: str
    detail: str


@dataclass(frozen=True)
class ReadTarget:
    """The sole run eligible to receive one read observation."""

    run_dir: Path
    target_path: Path | None
    session_pid: int | None
    run_id: str
    route: str


@dataclass(frozen=True)
class ReadTargetResult:
    """Owner/run resolution result."""

    target: ReadTarget | None
    disposition: Any | None
    reason_code: str
    detail: str
    route: str


@dataclass(frozen=True)
class ReadIngestResult:
    """Complete parser-to-filesystem outcome for one hook invocation."""

    parse_disposition: Any
    effect_disposition: Any | None
    reason_code: str
    detail: str
    route: str | None = None
    event: Any | None = None
    observation: ReadObservation | None = None
    target: ReadTarget | None = None
    recorded_path: Path | None = None


_DIAGNOSTICS = MappingProxyType(
    dict(
        (
            ("bad_identifier", "hook event identifier is invalid"),
            ("bad_env_pid", "session credential pid is invalid"),
            ("bad_file_path", "hook event read path is invalid"),
            ("bad_reason", "hook event reason is invalid"),
            ("bad_success", "hook event success value is invalid"),
            ("bad_tool_args", "hook event tool arguments are invalid"),
            ("bad_tool_name", "hook event tool name is invalid"),
            ("budget", "hook event exceeds the byte budget"),
            ("core_import_failed", "coverage hook core import failed"),
            ("depth", "hook event nesting exceeds the parser limit"),
            ("duplicate_key", "hook event contains a duplicate object key"),
            ("ambiguous", "multiple owned running runs are active"),
            ("hook_failed", "coverage helper failed safely"),
            ("invalid_target", "run target metadata is invalid"),
            ("integer_out_of_range", "hook event contains an unsupported integer"),
            ("io_refused", "coverage evidence write was refused"),
            ("malformed_json", "hook event is not valid JSON"),
            ("missing_file_path", "hook event read path is missing"),
            ("missing_tool_args", "hook event tool arguments are missing"),
            ("no_candidate", "no owned running run is available"),
            ("no_owner", "no verified session owner is available"),
            ("no_stdin", "hook event input could not be read"),
            ("non_finite", "hook event contains a non-finite number"),
            ("non_object_root", "hook event root is not an object"),
            ("not_bytes", "hook event input is not bytes"),
            ("not_utf8", "hook event is not strict UTF-8"),
            ("owner_mismatch", "session owner does not match the credential pid"),
            ("profile_mismatch", "session owner frontend does not match the hook"),
            (
                "registration_mismatch",
                ("hook event does not match the fixed registration"),
            ),
            ("unsupported_kind", "hook event registration kind is unsupported"),
            ("unsupported_profile", "hook event profile is unsupported"),
            ("unsupported_tool", "hook event tool is unsupported"),
        )
    )
)


def _diag(code: str, **values: int) -> None:
    """Write one fixed-template diagnostic to stdout."""
    del values
    safe_code = code if code in _DIAGNOSTICS else "hook_failed"
    detail = _DIAGNOSTICS[safe_code]
    sys.stdout.write(f"raptor-read-hook[{safe_code}]: {detail}\n")
    sys.stdout.flush()


def _read_argument_contract(profile: Any) -> ReadArgumentContract:
    from core.run.host_events import HostEventProfileId

    if profile is HostEventProfileId.CLAUDE_LEGACY_V1:
        return ReadArgumentContract(
            canonical_tool_name="Read",
            path_key="file_path",
        )
    return ReadArgumentContract(
        canonical_tool_name="Read",
        path_key="path",
    )


def extract_read_observation(
    event: Any,
    contract: ReadArgumentContract,
) -> ReadObservationResult:
    """Extract one host-native read argument without renaming any key."""
    from core.run.host_events import HostEventParseDisposition, _diag as detail

    if (
        event.raw_tool_name is not None
        and event.canonical_tool_name != contract.canonical_tool_name
    ):
        return ReadObservationResult(
            disposition=HostEventParseDisposition.UNSUPPORTED,
            observation=None,
            reason_code="unsupported_tool",
            detail=detail("unsupported_tool"),
        )
    if event.tool_args is None:
        return ReadObservationResult(
            disposition=HostEventParseDisposition.INVALID,
            observation=None,
            reason_code="missing_tool_args",
            detail=detail("missing_tool_args"),
        )
    if contract.path_key not in event.tool_args:
        return ReadObservationResult(
            disposition=HostEventParseDisposition.INVALID,
            observation=None,
            reason_code="missing_file_path",
            detail=detail("missing_file_path"),
        )
    reported_path = event.tool_args[contract.path_key]
    if (
        not isinstance(reported_path, str)
        or not reported_path
        or len(reported_path) > _MAX_REPORTED_PATH
        or not reported_path.isprintable()
    ):
        return ReadObservationResult(
            disposition=HostEventParseDisposition.INVALID,
            observation=None,
            reason_code="bad_file_path",
            detail=detail("bad_file_path"),
        )
    return ReadObservationResult(
        disposition=HostEventParseDisposition.PARSED,
        observation=ReadObservation(
            event=event,
            reported_path=reported_path,
        ),
        reason_code="parsed",
        detail=detail("parsed"),
    )


def _read_regular_json_at(
    name: str,
    *,
    dir_fd: int | None = None,
    path: Path | None = None,
    max_bytes: int,
) -> dict | None:
    """Open first, then validate and parse one bounded regular JSON file."""
    from core.json import loads_bounded

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        return None
    flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        if dir_fd is None:
            if path is None:
                return None
            fd = os.open(str(path), flags)
        else:
            fd = os.open(name, flags, dir_fd=dir_fd)
    except (OSError, TypeError, NotImplementedError):
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            return None
        try:
            text = raw.decode("utf-8-sig")
            parsed = loads_bounded(
                text,
                max_bytes=max_bytes,
                reject_duplicate_keys=True,
            )
        except (UnicodeDecodeError, ValueError, RecursionError):
            return None
        return parsed if isinstance(parsed, dict) else None
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _read_run_metadata(run_dir: Path) -> dict | None:
    return _read_regular_json_at(
        ".raptor-run.json",
        path=run_dir / ".raptor-run.json",
        max_bytes=_MAX_METADATA_BYTES,
    )


def _valid_run_dir(value: object) -> Path | None:
    if not isinstance(value, str) or not value.isprintable():
        return None
    path = Path(value)
    return path if path.is_absolute() else None


def _target_from_metadata(
    meta: Mapping[str, object],
) -> tuple[bool, Path | None]:
    if "target_path" not in meta:
        return True, None
    raw = meta["target_path"]
    if (
        not isinstance(raw, str)
        or not raw
        or not raw.isprintable()
        or not os.path.isabs(raw)
    ):
        return False, None
    try:
        resolved = Path(os.path.realpath(raw))
    except (OSError, ValueError):
        return False, None
    if (
        not str(resolved).isprintable()
        or resolved == Path(resolved.anchor)
        or not resolved.is_dir()
    ):
        return False, None
    return True, resolved


def _owner_target(
    environ: Mapping[str, str],
) -> ReadTargetResult:
    from core.project import sessions
    from core.run.host_events import HostEventEffectDisposition, _diag as detail
    from core.startup.host import Frontend

    pid_present = sessions.ENV_SESSION_PID in environ
    token_present = sessions.ENV_SESSION_TOKEN in environ
    credential_present = pid_present or token_present
    if not credential_present:
        global_run_dir, global_target = _find_global_run()
        if global_run_dir is None:
            return ReadTargetResult(
                target=None,
                disposition=HostEventEffectDisposition.NO_CANDIDATE,
                reason_code="no_candidate",
                detail=detail("no_candidate"),
                route="legacy_global_fallback",
            )
        run_path = Path(global_run_dir)
        valid_target, resolved_target = _target_from_legacy_project(global_target)
        if not valid_target:
            return ReadTargetResult(
                target=None,
                disposition=HostEventEffectDisposition.INVALID_TARGET,
                reason_code="invalid_target",
                detail=detail("invalid_target"),
                route="legacy_global_fallback",
            )
        return ReadTargetResult(
            target=ReadTarget(
                run_dir=run_path,
                target_path=resolved_target,
                session_pid=None,
                run_id=run_path.name,
                route="legacy_global_fallback",
            ),
            disposition=None,
            reason_code="parsed",
            detail=detail("parsed"),
            route="legacy_global_fallback",
        )

    owner = sessions.resolve_session_owner()
    raw_pid = environ.get(sessions.ENV_SESSION_PID, "")
    if (
        not pid_present
        or not token_present
        or len(raw_pid) > 20
        or not raw_pid.isascii()
        or not raw_pid.isdigit()
    ):
        return ReadTargetResult(
            target=None,
            disposition=HostEventEffectDisposition.NO_OWNER,
            reason_code="bad_env_pid" if pid_present else "no_owner",
            detail=detail("bad_env_pid" if pid_present else "no_owner"),
            route="session_owner",
        )
    expected_pid = int(raw_pid)
    if owner is None:
        return ReadTargetResult(
            target=None,
            disposition=HostEventEffectDisposition.NO_OWNER,
            reason_code="no_owner",
            detail=detail("no_owner"),
            route="session_owner",
        )
    if owner.pid != expected_pid:
        return ReadTargetResult(
            target=None,
            disposition=HostEventEffectDisposition.NO_OWNER,
            reason_code="owner_mismatch",
            detail=detail("owner_mismatch"),
            route="session_owner",
        )
    if owner.frontend is not Frontend.CLAUDE:
        return ReadTargetResult(
            target=None,
            disposition=HostEventEffectDisposition.EFFECTS_DISABLED,
            reason_code="profile_mismatch",
            detail=detail("profile_mismatch"),
            route="session_owner",
        )

    from core.run.metadata import (
        RUN_METADATA_FILE,
        STATUS_RUNNING,
        _metadata_owned_by_session,
        _run_recently_active,
        worker_liveness_for_meta,
    )

    candidates: list[tuple[dict, dict, Path]] = []
    seen: set[tuple[str, str]] = set()
    try:
        records = sessions.ledger_runs(pid=owner.pid, status="running")
    except (OSError, ValueError):
        records = []
    for record in records:
        run_id = record.get("run_id")
        candidate_run_dir = _valid_run_dir(record.get("run_dir"))
        if not isinstance(run_id, str) or not run_id or candidate_run_dir is None:
            continue
        key = (run_id, str(candidate_run_dir))
        if key in seen:
            continue
        seen.add(key)
        meta = _read_regular_json_at(
            RUN_METADATA_FILE,
            path=candidate_run_dir / RUN_METADATA_FILE,
            max_bytes=_MAX_METADATA_BYTES,
        )
        if (
            not isinstance(meta, dict)
            or meta.get("status") != STATUS_RUNNING
            or not _metadata_owned_by_session(meta, owner.pid)
        ):
            continue
        tool_pid = meta.get("tool_pid")
        if (
            isinstance(tool_pid, int)
            and not isinstance(tool_pid, bool)
            and tool_pid > 0
        ):
            worker_alive, _worker_detail = worker_liveness_for_meta(meta)
            if not worker_alive and not _run_recently_active(candidate_run_dir):
                # A dead worker plus an idle run directory is the same
                # abandonment proof used by the lifecycle sweep. Excluding
                # it here prevents one Esc-cancelled multi-turn run from
                # disabling read coverage for every later run in the session.
                continue
        candidates.append((record, meta, candidate_run_dir))

    route = "session_owner_strong" if owner.host_verified else "session_owner_legacy"
    if not candidates:
        return ReadTargetResult(
            target=None,
            disposition=HostEventEffectDisposition.NO_CANDIDATE,
            reason_code="no_candidate",
            detail=detail("no_candidate"),
            route=route,
        )
    if len(candidates) != 1:
        return ReadTargetResult(
            target=None,
            disposition=HostEventEffectDisposition.AMBIGUOUS,
            reason_code="ambiguous",
            detail=detail("ambiguous"),
            route=route,
        )
    record, meta, candidate_run_dir = candidates[0]
    valid_target, target_path = _target_from_metadata(meta)
    if not valid_target:
        return ReadTargetResult(
            target=None,
            disposition=HostEventEffectDisposition.INVALID_TARGET,
            reason_code="invalid_target",
            detail=detail("invalid_target"),
            route=route,
        )
    return ReadTargetResult(
        target=ReadTarget(
            run_dir=candidate_run_dir,
            target_path=target_path,
            session_pid=owner.pid,
            run_id=record["run_id"],
            route=route,
        ),
        disposition=None,
        reason_code="parsed",
        detail=detail("parsed"),
        route=route,
    )


def resolve_read_target(
    *,
    environ: Mapping[str, str] | None = None,
) -> ReadTargetResult:
    """Resolve the sole eligible run without consulting event-supplied paths."""
    return _owner_target(os.environ if environ is None else environ)


def _target_from_legacy_project(
    target: object,
) -> tuple[bool, Path | None]:
    if target is None or target == "":
        return True, None
    return _target_from_metadata({"target_path": target})


def _find_global_run() -> tuple[str | None, object | None]:
    """Legacy machine-global discovery used only when both credentials are absent."""
    from core.project import registry_home
    from core.run.metadata import _metadata_allows_legacy_attribution

    try:
        active_link = registry_home.active_link()
    except ValueError:
        return None, None
    if not active_link.is_symlink():
        return None, None

    try:
        link_target = os.readlink(active_link)
        if (
            not link_target
            or "/" in link_target
            or ".." in link_target
            or link_target.startswith(".")
        ):
            return None, None
        project_file = active_link.parent / link_target
        data = _read_regular_json_at(
            project_file.name,
            path=project_file,
            max_bytes=_MAX_PROJECT_BYTES,
        )
        if not isinstance(data, dict):
            return None, None
        project_dir = data.get("output_dir")
        target = data.get("target")
        if (
            not isinstance(project_dir, str)
            or not project_dir.isprintable()
            or not os.path.isabs(project_dir)
            or not Path(project_dir).is_dir()
        ):
            return None, None

        entries: list[tuple[float, Path]] = []
        for candidate in Path(project_dir).iterdir():
            if not candidate.is_dir() or candidate.name.startswith((".", "_")):
                continue
            try:
                mtime = candidate.stat().st_mtime
            except OSError:
                continue
            entries.append((mtime, candidate))
        for _mtime, candidate in sorted(
            entries, key=lambda item: item[0], reverse=True
        ):
            meta = _read_run_metadata(candidate)
            if (
                isinstance(meta, dict)
                and meta.get("status") == "running"
                and _metadata_allows_legacy_attribution(meta)
            ):
                return str(candidate), target
    except (
        OSError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        ValueError,
        TypeError,
        RecursionError,
    ):
        pass
    return None, None


def _resolve_source_path(
    reported_path: str,
    target_path: Path | None,
) -> Path | None:
    if os.path.isdir(reported_path):
        return None
    suffix = Path(reported_path).suffix.casefold()
    if suffix not in _SOURCE_EXTENSIONS:
        return None
    try:
        resolved = Path(os.path.realpath(reported_path))
    except (OSError, ValueError):
        return None
    if not str(resolved).isprintable() or not Path(resolved.parent).is_dir():
        return None
    if target_path is not None:
        try:
            if os.path.commonpath((str(resolved), str(target_path))) != str(
                target_path
            ):
                return None
        except ValueError:
            return None
    return resolved


def _metadata_still_owned(dfd: int, target: ReadTarget) -> bool:
    from core.run.metadata import (
        RUN_METADATA_FILE,
        STATUS_RUNNING,
        _metadata_allows_legacy_attribution,
        _metadata_owned_by_session,
    )

    meta = _read_regular_json_at(
        RUN_METADATA_FILE,
        dir_fd=dfd,
        max_bytes=_MAX_METADATA_BYTES,
    )
    if not isinstance(meta, dict) or meta.get("status") != STATUS_RUNNING:
        return False
    if not _metadata_allows_legacy_attribution(meta):
        return False
    if target.session_pid is not None:
        return _metadata_owned_by_session(meta, target.session_pid)
    return True


def record_read(
    target: ReadTarget,
    observation: ReadObservation,
) -> tuple[Any, str, Path | None]:
    """Append one path through fd-bound checks; never retry a short write."""
    from core.run.host_events import HostEventEffectDisposition

    resolved = _resolve_source_path(
        observation.reported_path,
        target.target_path,
    )
    if resolved is None:
        return (
            HostEventEffectDisposition.INVALID_TARGET,
            "invalid_target",
            None,
        )
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        return HostEventEffectDisposition.IO_REFUSED, "io_refused", None
    dir_flags = os.O_RDONLY | directory | getattr(os, "O_CLOEXEC", 0)
    try:
        dfd = os.open(str(target.run_dir), dir_flags)
    except OSError:
        return HostEventEffectDisposition.IO_REFUSED, "io_refused", None
    try:
        dst = os.fstat(dfd)
        if not stat.S_ISDIR(dst.st_mode) or dst.st_uid != os.geteuid():
            return HostEventEffectDisposition.IO_REFUSED, "io_refused", None
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_APPEND
            | nofollow
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            fd = os.open(MANIFEST_NAME, flags, 0o600, dir_fd=dfd)
        except (OSError, TypeError, NotImplementedError):
            return HostEventEffectDisposition.IO_REFUSED, "io_refused", None
        try:
            mst = os.fstat(fd)
            if (
                not stat.S_ISREG(mst.st_mode)
                or mst.st_uid != os.geteuid()
                or mst.st_nlink != 1
            ):
                return (
                    HostEventEffectDisposition.IO_REFUSED,
                    "io_refused",
                    None,
                )
            if not _metadata_still_owned(dfd, target):
                return (
                    HostEventEffectDisposition.NO_CANDIDATE,
                    "no_candidate",
                    None,
                )
            encoded = (str(resolved) + "\n").encode("utf-8")
            try:
                written = os.write(fd, encoded)
            except OSError:
                return (
                    HostEventEffectDisposition.IO_REFUSED,
                    "io_refused",
                    None,
                )
            if written != len(encoded):
                return (
                    HostEventEffectDisposition.IO_REFUSED,
                    "io_refused",
                    None,
                )
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
    finally:
        try:
            os.close(dfd)
        except OSError:
            pass
    return HostEventEffectDisposition.APPLIED, "parsed", resolved


def process_read_event(
    raw: bytes,
    *,
    profile: Any | None = None,
    environ: Mapping[str, str] | None = None,
) -> ReadIngestResult:
    """Parse and, only for an enabled profile, record one read event."""
    from core.run.host_events import (
        HostEventEffectDisposition,
        HostEventKind,
        HostEventParseDisposition,
        HostEventProfileId,
        PROFILE_META,
        _diag as detail,
        normalize_host_event,
    )

    if profile is None:
        profile = HostEventProfileId.CLAUDE_LEGACY_V1
    parsed = normalize_host_event(
        raw,
        profile=profile,
        registration_kind=HostEventKind.TOOL_SUCCESS,
    )
    if (
        parsed.disposition is not HostEventParseDisposition.PARSED
        or parsed.event is None
    ):
        return ReadIngestResult(
            parse_disposition=parsed.disposition,
            effect_disposition=None,
            reason_code=parsed.reason_code,
            detail=parsed.detail,
        )

    contract = _read_argument_contract(profile)
    observed = extract_read_observation(parsed.event, contract)
    if (
        observed.disposition is not HostEventParseDisposition.PARSED
        or observed.observation is None
    ):
        return ReadIngestResult(
            parse_disposition=observed.disposition,
            effect_disposition=None,
            reason_code=observed.reason_code,
            detail=observed.detail,
            event=parsed.event,
        )
    if not PROFILE_META[profile].effects_enabled:
        return ReadIngestResult(
            parse_disposition=HostEventParseDisposition.PARSED,
            effect_disposition=HostEventEffectDisposition.EFFECTS_DISABLED,
            reason_code="profile_mismatch",
            detail=detail("profile_mismatch"),
            event=parsed.event,
            observation=observed.observation,
        )

    target_result = resolve_read_target(environ=environ)
    if target_result.target is None:
        return ReadIngestResult(
            parse_disposition=HostEventParseDisposition.PARSED,
            effect_disposition=target_result.disposition,
            reason_code=target_result.reason_code,
            detail=target_result.detail,
            route=target_result.route,
            event=parsed.event,
            observation=observed.observation,
        )
    effect, code, recorded_path = record_read(
        target_result.target,
        observed.observation,
    )
    return ReadIngestResult(
        parse_disposition=HostEventParseDisposition.PARSED,
        effect_disposition=effect,
        reason_code=code,
        detail=detail(code),
        route=target_result.route,
        event=parsed.event,
        observation=observed.observation,
        target=target_result.target,
        recorded_path=recorded_path,
    )


def _read_stdin_bytes() -> tuple[bytes | None, str | None]:
    if sys.stdin is None:
        return None, "no_stdin"
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    if stream is None:
        return None, "no_stdin"
    try:
        raw = stream.read(_MAX_STDIN_BYTES + 1)
    except (OSError, ValueError):
        return None, "stdin_closed"
    if isinstance(raw, str):
        try:
            return raw.encode("utf-8"), None
        except UnicodeEncodeError:
            return None, "not_utf8"
    return raw, None


def _run_hook() -> None:
    try:
        from core.run.host_events import (
            HostEventEffectDisposition,
            HostEventProfileId,
        )
    except ImportError:
        _diag("core_import_failed")
        return

    raw, _read_error = _read_stdin_bytes()
    if raw is None:
        _diag("no_stdin")
        return
    result = process_read_event(
        raw,
        profile=HostEventProfileId.CLAUDE_LEGACY_V1,
    )
    if (
        result.effect_disposition is not HostEventEffectDisposition.APPLIED
        and result.reason_code not in {"no_candidate"}
    ):
        _diag(result.reason_code)


def _entry() -> int:
    previous_disable = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        try:
            _run_hook()
        # JsonBudgetExceededError is a ValueError subclass, so the lazy core
        # parser's budget refusal is covered without a module-level core import.
        except (OSError, ValueError, UnicodeDecodeError, ImportError, RecursionError):
            _diag("hook_failed")
    finally:
        logging.disable(previous_disable)
    return 0


def main() -> int:
    """Compatibility entrypoint for direct in-process callers."""
    return _entry()


if __name__ == "__main__":
    raise SystemExit(_entry())
