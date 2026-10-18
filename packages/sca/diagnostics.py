"""Bounded SCA progress, deadlines, and private diagnostic receipts."""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.http import (
    DEFAULT_MAX_BYTES,
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT,
    DEFAULT_TOTAL_TIMEOUT,
)
from core.json import load_json
from core.progress import HackerProgressBar, last_stage_name
from core.run.safe_io import write_private_json
from core.security.log_sanitisation import escape_nonprintable
from core.security.redaction import redact_secrets

from .pipeline_phases import describe_phase


DIAGNOSTIC_FILENAME = "diagnostics.json"
_DIAGNOSTIC_MAX_BYTES = 64 * 1024
_COMPLETED_PHASE_CAP = 32
_STDERR_LINE_CAP = 20
_STDERR_LINE_CHARS = 500
_SUMMARY_CHARS = 300
_REQUEST_TOTAL_TIMEOUT_SECONDS = 30
_HTTP_DISPATCH_RESERVE_SECONDS = 0.05
_DISPOSITIONS = frozenset({"success", "failed", "skipped", "unsupported"})


class ScaDeadlineExceeded(TimeoutError):
    """Raised when the SCA child exhausts its propagated run budget."""


@dataclass(frozen=True)
class ScaDeadline:
    """Monotonic deadline shared by progress and HTTP dispatch."""

    started_at: float
    expires_at: float
    budget_seconds: float

    @classmethod
    def from_seconds(cls, seconds: float | None) -> ScaDeadline | None:
        if seconds is None:
            return None
        budget = float(seconds)
        if budget <= 0:
            raise ValueError("SCA deadline must be greater than zero")
        now = time.monotonic()
        return cls(now, now + budget, budget)

    def remaining(self) -> float:
        return max(0.0, self.expires_at - time.monotonic())

    @staticmethod
    def _raise_exhausted(phase: str | None = None) -> None:
        active = phase or last_stage_name() or "startup"
        description = describe_phase(active)
        detail = f" ({description})" if description else ""
        raise ScaDeadlineExceeded(
            f"SCA internal deadline exhausted during {active}{detail}"
        )

    def check(
        self,
        phase: str | None = None,
        *,
        minimum_remaining: float = 0.0,
    ) -> None:
        if self.remaining() > minimum_remaining:
            return
        self._raise_exhausted(phase)

    def bounded_timeouts(
        self,
        *,
        timeout: int | float,
        total_timeout: int | float,
        per_request_cap: int | float,
    ) -> tuple[float, float]:
        remaining = self.remaining()
        if remaining <= _HTTP_DISPATCH_RESERVE_SECONDS:
            self._raise_exhausted()
        remaining -= _HTTP_DISPATCH_RESERVE_SECONDS
        bounded_total = min(
            float(total_timeout),
            float(per_request_cap),
            remaining,
        )
        bounded_attempt = min(float(timeout), bounded_total)
        return bounded_attempt, bounded_total


class DeadlineHttpClient:
    """HttpClient adapter that keeps one request inside the run deadline."""

    def __init__(
        self,
        inner,
        deadline: ScaDeadline,
        *,
        per_request_total_timeout: int | float = (_REQUEST_TOTAL_TIMEOUT_SECONDS),
    ) -> None:
        self._inner = inner
        self._deadline = deadline
        self._per_request_total_timeout = max(
            0.001,
            float(per_request_total_timeout),
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def _timeouts(
        self,
        timeout: int | float,
        total_timeout: int | float,
    ) -> tuple[float, float]:
        return self._deadline.bounded_timeouts(
            timeout=timeout,
            total_timeout=total_timeout,
            per_request_cap=self._per_request_total_timeout,
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
        total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        follow_redirects: bool = True,
        stream: bool = False,
        raise_on_status: bool = True,
    ):
        timeout, total_timeout = self._timeouts(timeout, total_timeout)
        return self._inner.request(
            method,
            url,
            body=body,
            headers=headers,
            timeout=timeout,
            max_bytes=max_bytes,
            total_timeout=total_timeout,
            retries=retries,
            follow_redirects=follow_redirects,
            stream=stream,
            raise_on_status=raise_on_status,
        )

    def post_json(
        self,
        url: str,
        body: dict[str, Any],
        timeout: int = DEFAULT_TIMEOUT,
        *,
        headers: dict[str, str] | None = None,
        total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        follow_redirects: bool = True,
    ) -> dict[str, Any]:
        timeout, total_timeout = self._timeouts(timeout, total_timeout)
        return self._inner.post_json(
            url,
            body,
            timeout=timeout,
            headers=headers,
            total_timeout=total_timeout,
            retries=retries,
            follow_redirects=follow_redirects,
        )

    def get_json(
        self,
        url: str,
        timeout: int = DEFAULT_TIMEOUT,
        *,
        headers: dict[str, str] | None = None,
        total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        follow_redirects: bool = True,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> dict[str, Any]:
        timeout, total_timeout = self._timeouts(timeout, total_timeout)
        return self._inner.get_json(
            url,
            timeout=timeout,
            headers=headers,
            total_timeout=total_timeout,
            retries=retries,
            follow_redirects=follow_redirects,
            max_bytes=max_bytes,
        )

    def get_bytes(
        self,
        url: str,
        timeout: int = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
        *,
        headers: dict[str, str] | None = None,
        total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        follow_redirects: bool = True,
    ) -> bytes:
        timeout, total_timeout = self._timeouts(timeout, total_timeout)
        return self._inner.get_bytes(
            url,
            timeout=timeout,
            max_bytes=max_bytes,
            headers=headers,
            total_timeout=total_timeout,
            retries=retries,
            follow_redirects=follow_redirects,
        )

    def stream_bytes(
        self,
        url: str,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
        headers: dict[str, str] | None = None,
        total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
        retries: int = 0,
    ) -> Iterator[bytes]:
        def _bounded_stream() -> Iterator[bytes]:
            bounded_timeout, bounded_total = self._timeouts(
                timeout,
                total_timeout,
            )
            yield from self._inner.stream_bytes(
                url,
                timeout=bounded_timeout,
                max_bytes=max_bytes,
                headers=headers,
                total_timeout=bounded_total,
                retries=retries,
            )

        return _bounded_stream()


def diagnostic_path(output_dir: Path | str) -> Path:
    return Path(output_dir) / DIAGNOSTIC_FILENAME


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_text(value: object, *, max_chars: int = _SUMMARY_CHARS) -> str:
    text = redact_secrets(str(value or ""))
    text = escape_nonprintable(text)
    if len(text) > max_chars:
        return text[:max_chars] + f"...[+{len(text) - max_chars} chars]"
    return text


def _safe_stderr_tail(stderr: object) -> str:
    text = redact_secrets(str(stderr or ""))
    lines = text.splitlines()[-_STDERR_LINE_CAP:]
    safe_lines = [_safe_text(line, max_chars=_STDERR_LINE_CHARS) for line in lines]
    return "\n".join(safe_lines)


def read_sca_diagnostic(output_dir: Path | str) -> dict[str, Any]:
    path = diagnostic_path(output_dir)
    if not path.is_file():
        return {}
    try:
        data = load_json(
            path,
            strict=True,
            max_bytes=_DIAGNOSTIC_MAX_BYTES,
        )
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_record(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(f".{path.name}.next")
    write_private_json(pending, record)
    os.replace(pending, path)
    path.chmod(0o600)


def finalize_sca_diagnostic(
    output_dir: Path | str,
    *,
    disposition: str,
    reason: object = "",
    returncode: int | None = None,
    timed_out: bool = False,
    cancelled: bool = False,
    interrupted: bool = False,
    stderr: object = "",
    mode: str | None = None,
    summary: dict[str, Any] | None = None,
) -> Path:
    """Merge a terminal result into the private SCA receipt."""
    if disposition not in _DISPOSITIONS:
        raise ValueError(f"unsupported SCA disposition: {disposition}")
    output_dir = Path(output_dir)
    path = diagnostic_path(output_dir)
    record = read_sca_diagnostic(output_dir)
    record.setdefault("schema_version", 1)
    record.setdefault("started_at", _utc_now())
    record["updated_at"] = _utc_now()
    record["disposition"] = disposition
    if mode:
        record["mode"] = _safe_text(mode, max_chars=32)
    if timed_out:
        status = "timed_out"
    elif cancelled:
        status = "cancelled"
    elif interrupted:
        status = "interrupted"
    elif disposition == "success":
        status = "completed"
    elif disposition in {"skipped", "unsupported"}:
        status = disposition
    else:
        prior_status = record.get("status")
        status = (
            prior_status
            if prior_status in {"timed_out", "cancelled", "interrupted"}
            else "failed"
        )
    record["status"] = status
    if returncode is not None:
        record["returncode"] = int(returncode)
    safe_reason = _safe_text(reason)
    if safe_reason:
        record["reason"] = safe_reason
    stderr_tail = _safe_stderr_tail(stderr)
    if stderr_tail:
        record["stderr_tail"] = stderr_tail
    if summary:
        safe_summary: dict[str, Any] = {}
        for key, value in summary.items():
            if not (isinstance(value, (bool, int, float, str)) or value is None):
                continue
            safe_summary[_safe_text(key, max_chars=64)] = (
                _safe_text(value, max_chars=500) if isinstance(value, str) else value
            )
        record["summary"] = safe_summary
    phase = record.get("phase")
    if isinstance(phase, dict) and phase.get("status") == "running":
        phase["status"] = status
        phase["finished_at"] = _utc_now()
        record["phase"] = phase
    _write_record(path, record)
    return path


class ScaProgress:
    """Progress-bar adapter that persists a bounded private phase receipt."""

    def __init__(
        self,
        *,
        target: str,
        output_dir: Path,
        diagnostics_path: Path | None = None,
        disabled: bool | None,
        mode: str,
        deadline: ScaDeadline | None,
    ) -> None:
        self._bar = HackerProgressBar(
            target=target,
            disabled=disabled,
        )
        self._path = diagnostics_path or diagnostic_path(output_dir)
        self._deadline = deadline
        self._mode = mode
        self._phase_started_monotonic: float | None = None
        self._active_phase: str | None = None
        self._last_tick_write = 0.0
        self._record: dict[str, Any] = {
            "schema_version": 1,
            "status": "running",
            "disposition": None,
            "mode": _safe_text(mode, max_chars=32),
            "started_at": _utc_now(),
            "updated_at": _utc_now(),
            "deadline_seconds": (
                round(deadline.budget_seconds, 3) if deadline is not None else None
            ),
            "phase": None,
            "completed_phases": [],
        }
        _write_record(self._path, self._record)

    def _write(self) -> None:
        self._record["updated_at"] = _utc_now()
        if self._deadline is not None:
            self._record["deadline_remaining_seconds"] = round(
                self._deadline.remaining(),
                3,
            )
        _write_record(self._path, self._record)

    def stage(self, name: str, total: int | None = None) -> None:
        if self._deadline is not None:
            self._deadline.check(name)
        self._bar.stage(name, total=total)
        self._active_phase = name
        self._phase_started_monotonic = time.monotonic()
        self._record["phase"] = {
            "name": _safe_text(name, max_chars=64),
            "description": _safe_text(
                describe_phase(name) or name,
                max_chars=160,
            ),
            "status": "running",
            "started_at": _utc_now(),
            "done": 0,
            "total": int(total) if total is not None else None,
        }
        self._write()

    def tick(self, done: int | None = None, detail: str = "") -> None:
        if self._deadline is not None:
            self._deadline.check(self._active_phase)
        self._bar.tick(done=done, detail=detail)
        phase = self._record.get("phase")
        if not isinstance(phase, dict):
            return
        phase["done"] = (
            int(done)
            if done is not None
            else int(
                phase.get("done", 0),
            )
            + 1
        )
        if detail:
            phase["detail"] = _safe_text(detail)
        now = time.monotonic()
        if now - self._last_tick_write >= 1.0:
            self._last_tick_write = now
            self._write()

    def flash(self, severity: str, message: str) -> None:
        self._bar.flash(severity, message)

    def done(self, summary: str = "") -> None:
        self._bar.done(summary)
        phase = self._record.get("phase")
        if isinstance(phase, dict):
            phase["status"] = "completed"
            phase["finished_at"] = _utc_now()
            if self._phase_started_monotonic is not None:
                phase["elapsed_seconds"] = round(
                    time.monotonic() - self._phase_started_monotonic,
                    3,
                )
            if summary:
                phase["summary"] = _safe_text(summary)
            completed = self._record.setdefault("completed_phases", [])
            if isinstance(completed, list):
                completed.append(dict(phase))
                del completed[:-_COMPLETED_PHASE_CAP]
        self._write()

    def end(self, summary: str = "") -> None:
        self._bar.end(summary)
        self._record["status"] = "completed"
        self._record["disposition"] = "success"
        if summary:
            self._record["result_summary"] = _safe_text(summary)
        self._write()
