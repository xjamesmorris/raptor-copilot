"""Every build system the detector can emit must be validatable.

Regression: ``BUILD_SYSTEMS["cpp"]`` emits ``autotools`` and ``meson``
but ``_VALIDATION_COMMANDS`` had no entry for either, so
``validate_build_command`` returned False for every detected
``./configure && make`` / meson command and the CodeQL caller silently
downgraded those targets to no-build mode on every run — the detected
command was ALWAYS discarded, never a "tool missing" signal.

The completeness assertion below enumerates both maps so a build
system added to BUILD_SYSTEMS without a validation probe fails loudly
here instead of shipping the same silent-discard behaviour.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from core.build.build_detector import BuildDetector


def test_every_detectable_type_has_a_validation_probe():
    emitted = {
        build_type
        for per_language in BuildDetector.BUILD_SYSTEMS.values()
        for build_type in per_language
    }
    missing = emitted - set(BuildDetector._VALIDATION_COMMANDS)
    assert not missing, (
        f"BUILD_SYSTEMS emits types with no _VALIDATION_COMMANDS "
        f"probe — validate_build_command returns False for them and "
        f"the CodeQL caller silently discards the detected command "
        f"into no-build mode: {sorted(missing)}"
    )


def _ok_probe():
    return mock.patch(
        "core.build.build_detector._run_trusted",
        return_value=SimpleNamespace(returncode=0),
    )


# Detection fixture → expected (type, probe argv) per build system the
# regression shipped for, driven end-to-end: real file layout →
# detect_build_system → validate_build_command with the probe mocked.
_DETECT_CASES = [
    pytest.param(
        "cpp", {"configure.ac": "AC_INIT([x], [1])\n"},
        "autotools", ["make", "--version"], id="autotools",
    ),
    pytest.param(
        "cpp", {"meson.build": "project('x', 'c')\n"},
        "meson", ["meson", "--version"], id="meson",
    ),
    pytest.param(
        "ruby", {"Rakefile": "task :build\n"},
        "rake", ["rake", "--version"], id="rake",
    ),
    pytest.param(
        "rust", {"Cargo.toml": '[package]\nname = "fixture"\nversion = "0.1.0"\n'},
        "cargo", ["cargo", "--version"], id="cargo",
    ),
]


@pytest.mark.parametrize(
    ("language", "files", "expected_type", "expected_probe"), _DETECT_CASES,
)
def test_detected_system_survives_validation(
    tmp_path: Path,
    language: str,
    files: dict[str, str],
    expected_type: str,
    expected_probe: list[str],
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    for name, content in files.items():
        (repo / name).write_text(content)

    detector = BuildDetector(repo)
    bs = detector.detect_build_system(language)
    assert bs is not None
    assert bs.type == expected_type

    with _ok_probe() as run:
        assert detector.validate_build_command(bs) is True
    assert run.call_args.args[0] == expected_probe


@pytest.mark.parametrize(
    ("language", "files", "expected_type", "expected_probe"), _DETECT_CASES,
)
def test_detected_system_tool_missing_reports_unvalidated(
    tmp_path: Path,
    language: str,
    files: dict[str, str],
    expected_type: str,
    expected_probe: list[str],
) -> None:
    """Other direction: with the probe failing (tool genuinely absent)
    validation still returns False — the new entries report tool
    availability, they don't rubber-stamp."""
    repo = tmp_path / "repo"
    repo.mkdir()
    for name, content in files.items():
        (repo / name).write_text(content)

    detector = BuildDetector(repo)
    bs = detector.detect_build_system(language)
    assert bs is not None and bs.type == expected_type

    with mock.patch(
        "core.build.build_detector._run_trusted",
        side_effect=FileNotFoundError(expected_probe[0]),
    ):
        assert detector.validate_build_command(bs) is False
