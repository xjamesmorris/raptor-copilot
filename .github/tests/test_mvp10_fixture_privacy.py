"""Keep MVP-10 fixtures shape-faithful without retaining live identifiers."""

from __future__ import annotations

import re
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]

_FIXTURE_AND_DOC_SURFACES = (
    "CONTRIBUTING.md",
    "README-Copilot.md",
    "README.md",
    "core/coverage/tests/test_shared_host_event_fixtures.py",
    "core/coverage/tests/test_track_read_session.py",
    "core/run/tests/test_host_events.py",
    "core/run/tests/test_lifecycle_hook.py",
    "core/run/tests/test_metadata.py",
    "core/startup/tests/test_host.py",
    "core/testing/fixtures/README.md",
    "core/testing/host_events.py",
    "core/testing/tests/test_host_events.py",
    "docs/agent-security.md",
    "docs/architecture.md",
    "docs/ci-controls.md",
    "docs/concepts.md",
    "docs/developers.md",
)
_TIMESTAMP_SURFACES = (
    "core/run/tests/test_lifecycle_hook.py",
    "core/testing/host_events.py",
    "core/testing/tests/test_host_events.py",
)

_UUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b"
)
_OPERATOR_HOME_RE = re.compile(
    r"(?:/(?:home|Users)/[^/\s\"'`]+|[A-Za-z]:\\Users\\[^\\\s\"'`]+)"
)
_ISO_TIMESTAMP_RE = re.compile(
    r"\b20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\b"
)
_EPOCH_MS_RE = re.compile(r"""["']timestamp["']\s*:\s*(\d{12,13})""")
_DEVICE_INODE_RE = re.compile(
    r"""(?:_?host_)?executable_(?:device|inode)["']?\s*(?:=|:)\s*(\d+)"""
)
_UID_RE = re.compile(r"""(?:host_)?uid["']?\s*(?:=|:)\s*(\d+)""")

_SYNTHETIC_UUIDS = {
    "00000000-0000-4000-8000-000000000000",
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
    "99999999-8888-4777-8666-555555555555",
    "aaaaaaaa-1111-2222-3333-444444444444",
    "bbbbbbbb-1111-2222-3333-444444444444",
    "bbbbbbbb-5555-6666-7777-888888888888",
}
_SYNTHETIC_TIMESTAMPS = {
    "2000-01-02T03:04:05.678Z",
    "2026-05-03T12:00:00+00:00",
    "2026-05-03T13:00:00+00:00",
    "2026-09-11T00:00:00+00:00",
    "2026-09-12T00:00:00+00:00",
}
_SYNTHETIC_EPOCH_MS = {"946782245678"}
_SYNTHETIC_DEVICE_INODE_VALUES = {"10", "20", "30", "40"}
_SYNTHETIC_UID_VALUES = {"0", "1000"}


def _read(relative: str) -> str:
    return (REPO / relative).read_text(encoding="utf-8")


def _unexpected_matches(
    surfaces: tuple[str, ...],
    pattern: re.Pattern[str],
    allowed: set[str],
) -> dict[str, list[str]]:
    unexpected: dict[str, list[str]] = {}
    allowed_folded = {value.casefold() for value in allowed}
    for relative in surfaces:
        values = {
            match.group(1) if match.lastindex else match.group(0)
            for match in pattern.finditer(_read(relative))
        }
        extra = sorted(
            value for value in values if value.casefold() not in allowed_folded
        )
        if extra:
            unexpected[relative] = extra
    return unexpected


def test_mvp10_session_ids_are_reviewed_synthetic_values() -> None:
    assert not _unexpected_matches(
        _FIXTURE_AND_DOC_SURFACES,
        _UUID_RE,
        _SYNTHETIC_UUIDS,
    )


def test_mvp10_surfaces_do_not_embed_operator_home_paths() -> None:
    assert not _unexpected_matches(
        _FIXTURE_AND_DOC_SURFACES,
        _OPERATOR_HOME_RE,
        set(),
    )


def test_mvp10_evidence_timestamps_are_reviewed_synthetic_values() -> None:
    assert not _unexpected_matches(
        _TIMESTAMP_SURFACES,
        _ISO_TIMESTAMP_RE,
        _SYNTHETIC_TIMESTAMPS,
    )
    assert not _unexpected_matches(
        _TIMESTAMP_SURFACES,
        _EPOCH_MS_RE,
        _SYNTHETIC_EPOCH_MS,
    )


def test_mvp10_machine_identity_values_are_synthetic_sentinels() -> None:
    assert not _unexpected_matches(
        _FIXTURE_AND_DOC_SURFACES,
        _DEVICE_INODE_RE,
        _SYNTHETIC_DEVICE_INODE_VALUES,
    )
    assert not _unexpected_matches(
        _FIXTURE_AND_DOC_SURFACES,
        _UID_RE,
        _SYNTHETIC_UID_VALUES,
    )


def test_raw_mvp10_evidence_roots_stay_ignored() -> None:
    rules = {
        line.strip()
        for line in _read(".gitignore").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert {"out/", ".mvp10-state/"} <= rules
