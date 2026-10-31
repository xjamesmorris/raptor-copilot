"""Tree-class tagging for audit findings and gaps.

Assigns every file one of three tree classes so consumers can present
and weigh findings by WHERE they live, without ever filtering them:

* ``production``      — first-party production source (the default)
* ``vendored-compat`` — vendored / generated third-party code and
                        portability shim trees (``vendor/``,
                        ``openbsd-compat/``-shaped compat dirs,
                        generated protobuf output, …)
* ``test-harness``    — test suites, regression trees, fuzz drivers,
                        and fixture paths

A tag, never a filter: findings in non-production trees are legitimate
detections (a fuzz-harness overflow is still an overflow) — the tag
exists so reports list production findings first and priority scoring
can apply a MILD demotion, not so anything gets dropped.

The classifier reuses the existing per-file signal sources instead of
inventing parallel heuristics:

* vendored/generated — :mod:`core.audit.vendored_detector` (prep-time
  verdicts when the caller has them; the same detector's path/filename
  signals in path-only mode otherwise), plus the compat-shim directory
  shape the detector's vendored-path vocabulary does not carry
  (``compat`` / ``*-compat`` / ``*_compat`` segments — the
  openbsd-compat convention);
* test-harness — :func:`core.inventory.fixture_detection.is_fixture_path`
  plus the regress-tree directory segments (the OpenBSD/openssh
  ``regress/`` convention test discovery already understands).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import PurePosixPath
from typing import Any

from core.inventory.fixture_detection import is_fixture_path

from .vendored_detector import classify_file as _vendored_classify_file

TREE_CLASS_PRODUCTION = "production"
TREE_CLASS_VENDORED = "vendored-compat"
TREE_CLASS_TEST = "test-harness"

#: The classes priority scoring may mildly demote and reports group
#: after production findings. Never a skip class.
NON_PRODUCTION_TREE_CLASSES = frozenset({
    TREE_CLASS_VENDORED, TREE_CLASS_TEST,
})

# Test-tree directory conventions the fixture path patterns don't
# cover: OpenBSD-style ``regress/`` trees. Directory segments only —
# a file named ``regress.c`` is production code. (Moved from
# core.audit.findings_export, which now delegates here.)
TEST_TREE_SEGMENTS = frozenset({"regress", "regression", "regressions"})

# Portability/compat shim tree shape: a directory segment that IS
# ``compat`` or ends in ``-compat`` / ``_compat`` (openssh's
# ``openbsd-compat/`` is the motivating convention). Shape-based on
# purpose — per-project names never get listed; if the family grows
# past a couple of suffix shapes, route it through pack data instead.
# The vocabulary gate (check_vocab_lists) does not scan dash-prefixed
# suffix strings, so the seed-count discipline for this list is
# MANUAL — the cap above is enforced by review, not by CI.
_COMPAT_SEGMENT = "compat"
_COMPAT_SEGMENT_SUFFIXES = ("-compat", "_compat")


def is_test_tree_path(file_path: str) -> bool:
    """Test-tree membership: the shared fixture-path conventions
    (``core.inventory.fixture_detection``) plus regress-tree directory
    segments."""
    if is_fixture_path(file_path)[0]:
        return True
    parts = PurePosixPath(file_path.replace("\\", "/")).parts
    return any(p.lower() in TEST_TREE_SEGMENTS for p in parts[:-1])


def _is_compat_tree_path(file_path: str) -> bool:
    parts = PurePosixPath(file_path.replace("\\", "/")).parts
    for part in parts[:-1]:  # directory segments only
        lowered = part.lower()
        if lowered == _COMPAT_SEGMENT or lowered.endswith(
            _COMPAT_SEGMENT_SUFFIXES,
        ):
            return True
    return False


def classify_tree_class(
    file_path: str,
    vendor_verdicts: dict[str, Any] | None = None,
) -> str:
    """Tree class for one file path.

    ``vendor_verdicts`` is the prep-time per-file map from
    :func:`core.audit.vendored_detector.detect_vendored_files` when the
    caller has one; without it the same detector runs in path-only mode
    (path segments + generated-filename conventions — banner and
    structural signals need file content and are covered by the
    verdict map when threaded in). Unknown paths default to
    ``production`` — the tag must never demote code it cannot place.
    """
    if not file_path:
        return TREE_CLASS_PRODUCTION
    if vendor_verdicts and vendor_verdicts.get(file_path) is not None:
        return TREE_CLASS_VENDORED
    if _vendored_classify_file(file_path, "") is not None:
        return TREE_CLASS_VENDORED
    if _is_compat_tree_path(file_path):
        return TREE_CLASS_VENDORED
    if is_test_tree_path(file_path):
        return TREE_CLASS_TEST
    return TREE_CLASS_PRODUCTION


def tree_class_map(
    file_paths: Iterable[str],
    vendor_verdicts: dict[str, Any] | None = None,
) -> dict[str, str]:
    """``{file: tree_class}`` for every distinct path in *file_paths*."""
    result: dict[str, str] = {}
    for file_path in file_paths:
        if file_path and file_path not in result:
            result[file_path] = classify_tree_class(
                file_path, vendor_verdicts,
            )
    return result
