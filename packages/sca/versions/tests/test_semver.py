"""Tests for the semver version comparator.

Semver (https://semver.org/) is used by npm, Cargo, and Go (with
leading ``v`` tolerated for Go's convention). The spec is cleaner
than PEP 440 / Maven but has two real gotchas:

  * Numeric pre-release identifiers compare NUMERICALLY (so
    ``1.0.0-2 < 1.0.0-10``), while alphanumeric ones compare
    lexically. The split is per-identifier, not per-pre-release.
  * Numeric identifiers always sort BELOW alphanumeric ones at
    the same position — ``1.0.0-1 < 1.0.0-alpha`` rather than
    the other way around. Counter-intuitive but spec-mandated.
  * Build metadata (``+...``) is IGNORED for ordering per spec.
    Three otherwise-identical versions with different build
    metadata sort as equal.

Tests in this file pin those gotchas + the everyday cases.

The semver comparator also tolerates Go's ``v``-prefixed format
and the pseudo-version form ``v0.0.0-<timestamp>-<short_sha>``,
which Go's module system uses for unreleased commits. Those are
covered explicitly.
"""

from __future__ import annotations

import pytest

from packages.sca.versions import compare as dispatch_compare
from packages.sca.versions import in_range
from packages.sca.versions.semver import compare as cmp
from packages.sca.versions.semver import parse

# ---------------------------------------------------------------------------
# Basic ordering.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("a, b, expected", [
    ("1.0.0", "1.0.1", -1),
    ("1.0.1", "1.0.0", 1),
    ("1.0.0", "1.0.0", 0),
    ("1.0.0", "1.1.0", -1),
    ("1.0.0", "2.0.0", -1),
    ("0.9.9", "1.0.0", -1),
    ("10.0.0", "9.0.0", 1),     # numeric, not lex
    ("1.10.0", "1.9.0", 1),     # same: numeric compare on minor
])
def test_basic_ordering(a, b, expected) -> None:
    assert cmp(a, b) == expected


def test_identical_short_circuit() -> None:
    """Identical strings short-circuit to 0 without parsing."""
    assert cmp("1.0.0", "1.0.0") == 0
    assert cmp("1.0.0-alpha", "1.0.0-alpha") == 0


# ---------------------------------------------------------------------------
# Pre-release ordering — the spec's core complexity.
# ---------------------------------------------------------------------------

def test_pre_release_below_release() -> None:
    """Pre-releases sort BELOW the bare release per spec §11."""
    assert cmp("1.0.0-alpha", "1.0.0") == -1
    assert cmp("1.0.0-rc.1", "1.0.0") == -1
    assert cmp("1.0.0", "1.0.0-alpha") == 1


def test_pre_release_label_order() -> None:
    """Common pre-release label progression (lex-sorted since
    none are pure numeric)."""
    assert cmp("1.0.0-alpha", "1.0.0-beta") == -1
    assert cmp("1.0.0-beta", "1.0.0-rc.1") == -1


def test_numeric_pre_compares_as_int_not_lex() -> None:
    """The headline gotcha: numeric pre-release identifiers
    compare NUMERICALLY, not lexically. ``1.0.0-2`` < ``1.0.0-10``
    because both pre-release segments are pure numeric — int
    compare wins over lex compare here."""
    assert cmp("1.0.0-2", "1.0.0-10") == -1
    assert cmp("1.0.0-10", "1.0.0-2") == 1


def test_alphanumeric_pre_compares_as_string() -> None:
    """The COUNTERPART gotcha: alphanumeric pre-release
    identifiers compare LEXICALLY, NOT numerically. So
    ``1.0.0-rc11 < 1.0.0-rc2`` because "rc11" < "rc2" in
    string comparison. This is genuinely counter-intuitive
    but spec-mandated — operators who want numeric ordering
    on rcN must separate the rc from the number with a dot
    (``1.0.0-rc.11`` > ``1.0.0-rc.2``)."""
    assert cmp("1.0.0-rc11", "1.0.0-rc2") == -1
    # The fix: separate with a dot so they become two identifiers.
    assert cmp("1.0.0-rc.2", "1.0.0-rc.11") == -1


def test_numeric_below_alphanumeric_in_pre() -> None:
    """Per spec §11.4.3: numeric identifiers always sort BELOW
    alphanumeric ones at the same position. ``1.0.0-1`` <
    ``1.0.0-alpha`` because the first identifier of the LHS is
    numeric (1) and of the RHS is alphanumeric (alpha)."""
    assert cmp("1.0.0-1", "1.0.0-alpha") == -1
    assert cmp("1.0.0-alpha", "1.0.0-1") == 1


def test_pre_chain_length_tiebreak() -> None:
    """Per spec §11.4.4: when shared prefix matches, longer pre-
    release chain wins. ``1.0.0-alpha < 1.0.0-alpha.1`` because
    the extra ``.1`` identifier extends the chain."""
    assert cmp("1.0.0-alpha", "1.0.0-alpha.1") == -1
    assert cmp("1.0.0-alpha.1", "1.0.0-alpha") == 1
    assert cmp("1.0.0-alpha.1", "1.0.0-alpha.beta") == -1


# ---------------------------------------------------------------------------
# Build metadata — explicitly ignored.
# ---------------------------------------------------------------------------

def test_build_metadata_ignored_for_ordering() -> None:
    """Per spec §10: build metadata MUST be ignored when
    determining version precedence. Three versions identical
    except for build metadata sort as equal."""
    assert cmp("1.0.0+a", "1.0.0+b") == 0
    assert cmp("1.0.0+build.1", "1.0.0+build.2") == 0
    assert cmp("1.0.0", "1.0.0+a") == 0


def test_build_metadata_with_pre_release() -> None:
    """Build metadata can co-exist with pre-release. The
    pre-release segment still orders normally; only the build
    metadata is ignored."""
    assert cmp("1.0.0-alpha+build1", "1.0.0-beta+build1") == -1
    assert cmp("1.0.0-alpha+build1", "1.0.0-alpha+build2") == 0


# ---------------------------------------------------------------------------
# Short forms + v-prefix tolerance (Go).
# ---------------------------------------------------------------------------

def test_short_forms_default_to_zero() -> None:
    """Missing minor / patch components default to 0 in this
    comparator. Real-world advisory data + Go pseudo-versions
    use short forms; rejecting them would miss findings."""
    assert parse("1") == (1, 0, 0, None)
    assert parse("1.2") == (1, 2, 0, None)
    assert parse("1.2.3") == (1, 2, 3, None)
    # Comparison is equal across these:
    assert cmp("1", "1.0") == 0
    assert cmp("1.0", "1.0.0") == 0


def test_leading_v_tolerated() -> None:
    """Go's convention is ``v1.2.3``; npm accepts plain ``1.2.3``.
    The comparator tolerates either form, so Go advisory data
    against an npm-style installed version still matches."""
    assert cmp("v1.0.0", "1.0.0") == 0
    assert cmp("v1.0.0", "v1.0.1") == -1
    assert cmp("v2.0.0", "1.0.0") == 1


def test_go_pseudo_version_parses() -> None:
    """Go's pseudo-version form
    ``v0.0.0-<timestamp>-<short_sha>`` is used for unreleased
    commits. The comparator parses it (treating the
    timestamp-sha as a pre-release identifier) so range
    matching against go.mod versions works."""
    major, minor, patch, pre = parse("v0.0.0-20210320205559-abc123")
    assert (major, minor, patch) == (0, 0, 0)
    assert pre is not None
    assert pre[0] == "20210320205559-abc123"


def test_go_pseudo_version_order() -> None:
    """Two pseudo-versions sort by their timestamp segment
    (lexicographic since the format puts the largest unit
    first)."""
    older = "v0.0.0-20200101000000-aaaaaa"
    newer = "v0.0.0-20210320205559-bbbbbb"
    assert cmp(older, newer) == -1


# ---------------------------------------------------------------------------
# Edge cases — malformed / boundary inputs.
# ---------------------------------------------------------------------------

def test_invalid_raises_value_error() -> None:
    """Bad inputs raise ``ValueError`` — not a silent default."""
    with pytest.raises(ValueError):
        parse("not-a-version")
    with pytest.raises(ValueError):
        parse("@@@@")


def test_empty_pre_after_dash_does_not_match() -> None:
    """``1.0.0-`` (dash with nothing after) is malformed.
    Don't silently succeed."""
    with pytest.raises(ValueError):
        parse("1.0.0-")


def test_multiple_dashes_in_pre() -> None:
    """Only the FIRST ``-`` is the pre-release delimiter — the
    rest are part of the pre-release identifier. Common in
    Go pseudo-versions."""
    _, _, _, pre = parse("1.0.0-alpha-1.snapshot")
    assert pre == ["alpha-1", "snapshot"]


# ---------------------------------------------------------------------------
# Dispatcher integration.
# ---------------------------------------------------------------------------

def test_dispatch_routes_npm_to_semver() -> None:
    """``versions.compare("npm", ...)`` routes to the semver
    comparator."""
    assert dispatch_compare("npm", "1.0.0", "1.0.1") == -1
    assert dispatch_compare("npm", "1.0.0-alpha", "1.0.0") == -1


def test_dispatch_routes_cargo_to_semver() -> None:
    """``versions.compare("Cargo", ...)`` also routes here."""
    assert dispatch_compare("Cargo", "1.0.0", "1.0.1") == -1


def test_dispatch_routes_go_to_semver() -> None:
    """Go modules use semver too (with ``v`` prefix tolerated)."""
    assert dispatch_compare("Go", "v1.0.0", "v1.0.1") == -1


def test_in_range_semver_smoke() -> None:
    """End-to-end OSV range matching."""
    events = [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
    assert in_range("npm", "1.5.0", events) is True
    assert in_range("npm", "2.0.0", events) is False
    # Pre-release of 2.0 still < 2.0 per spec, so still in range.
    assert in_range("npm", "2.0.0-rc.1", events) is True


def test_in_range_multiple_intervals_in_one_events_list() -> None:
    """Two introduced/fixed pairs in one range object — both intervals
    must match."""
    events = [
        {"introduced": "1.0.0"}, {"fixed": "1.5.0"},
        {"introduced": "2.0.0"}, {"fixed": "2.5.0"},
    ]
    assert in_range("npm", "1.2.0", events) is True
    assert in_range("npm", "1.7.0", events) is False
    assert in_range("npm", "2.2.0", events) is True
    assert in_range("npm", "3.0.0", events) is False


def test_in_range_consecutive_introduced_keeps_first_interval() -> None:
    """A second ``introduced`` while one interval is open used to
    overwrite the first, silently dropping its vulnerable range. The
    first now closes as open-ended (conservative, mirroring a dangling
    introduced)."""
    events = [
        {"introduced": "1.0.0"},
        {"introduced": "2.0.0"}, {"fixed": "2.5.0"},
    ]
    # In the first (now open-ended) interval — was False pre-fix.
    assert in_range("npm", "1.2.0", events) is True
    # In the second interval.
    assert in_range("npm", "2.2.0", events) is True
    # Below every introduced bound.
    assert in_range("npm", "0.9.0", events) is False


def test_in_range_dangling_introduced_open_ended() -> None:
    events = [{"introduced": "1.0.0"}]
    assert in_range("npm", "99.0.0", events) is True
    assert in_range("npm", "0.1.0", events) is False


# ---------------------------------------------------------------------------
# Fork-tag prerelease detection.
# ---------------------------------------------------------------------------

from packages.sca.versions.semver import is_fork_tag


class TestIsForkTag:
    """Distinguish org/fork suffixes from genuine prereleases."""

    def test_fork_tags(self) -> None:
        assert is_fork_tag(["succinct"]) is True
        assert is_fork_tag(["tokio"]) is True
        assert is_fork_tag(["facebook"]) is True
        assert is_fork_tag(["myorg"]) is True

    def test_fork_tags_with_hyphens(self) -> None:
        assert is_fork_tag(["tokio-rs"]) is True

    def test_genuine_prereleases(self) -> None:
        assert is_fork_tag(["alpha"]) is False
        assert is_fork_tag(["beta"]) is False
        assert is_fork_tag(["rc", "1"]) is False
        assert is_fork_tag(["dev"]) is False
        assert is_fork_tag(["preview"]) is False
        assert is_fork_tag(["canary"]) is False
        assert is_fork_tag(["nightly"]) is False

    def test_expanded_keywords(self) -> None:
        assert is_fork_tag(["hotfix"]) is False
        assert is_fork_tag(["patch"]) is False
        assert is_fork_tag(["test"]) is False
        assert is_fork_tag(["build"]) is False
        assert is_fork_tag(["wip"]) is False
        assert is_fork_tag(["fix"]) is False

    def test_digit_bearing_identifiers(self) -> None:
        """Identifiers containing digits are version markers, not org names."""
        assert is_fork_tag(["pre1"]) is False
        assert is_fork_tag(["patch1"]) is False
        assert is_fork_tag(["0alpha"]) is False
        assert is_fork_tag(["v2"]) is False
        assert is_fork_tag(["build123"]) is False

    def test_numeric_identifiers(self) -> None:
        assert is_fork_tag(["20250522"]) is False
        assert is_fork_tag(["0"]) is False
        assert is_fork_tag(["1"]) is False

    def test_single_char_not_fork_tag(self) -> None:
        assert is_fork_tag(["a"]) is False
        assert is_fork_tag(["b"]) is False

    def test_mixed_with_keyword(self) -> None:
        assert is_fork_tag(["alpha", "succinct"]) is False
        assert is_fork_tag(["succinct", "beta"]) is False

    def test_mixed_with_numeric(self) -> None:
        assert is_fork_tag(["succinct", "1"]) is False

    def test_empty(self) -> None:
        assert is_fork_tag([]) is False


# ---------------------------------------------------------------------------
# Fork-tag false-positive avoidance in in_range.
# ---------------------------------------------------------------------------

class TestForkTagInRange:
    """A version like ``0.4.3-succinct`` should NOT match a range
    ``[introduced, fixed=0.4.3)`` because the ``-succinct`` suffix is
    an org/fork tag, not a genuine prerelease."""

    def test_fork_tag_at_fix_not_in_range(self) -> None:
        events = [{"introduced": "0"}, {"fixed": "0.4.3"}]
        assert in_range("Cargo", "0.4.3-succinct", events) is False
        assert in_range("npm", "0.4.3-succinct", events) is False

    def test_fork_tag_via_crates_io_alias(self) -> None:
        """Real OSV data uses ``crates.io``, not ``Cargo``."""
        events = [{"introduced": "0"}, {"fixed": "0.4.3"}]
        assert in_range("crates.io", "0.4.3-succinct", events) is False

    def test_genuine_prerelease_at_fix_still_in_range(self) -> None:
        events = [{"introduced": "0"}, {"fixed": "2.0.0"}]
        assert in_range("npm", "2.0.0-rc.1", events) is True
        assert in_range("npm", "2.0.0-alpha", events) is True
        assert in_range("npm", "2.0.0-beta.1", events) is True
        assert in_range("Cargo", "2.0.0-dev", events) is True

    def test_digit_bearing_prerelease_at_fix_still_in_range(self) -> None:
        """pre1, hotfix1, 0alpha — contain digits, not fork tags."""
        events = [{"introduced": "0"}, {"fixed": "2.0.0"}]
        assert in_range("Cargo", "2.0.0-pre1", events) is True
        assert in_range("Cargo", "2.0.0-hotfix", events) is True
        assert in_range("Cargo", "2.0.0-0alpha", events) is True
        assert in_range("npm", "2.0.0-patch1", events) is True

    def test_fork_tag_below_fix_still_in_range(self) -> None:
        """Fork at a base version BELOW the fix: genuinely affected."""
        events = [{"introduced": "0"}, {"fixed": "0.5.0"}]
        assert in_range("Cargo", "0.4.3-succinct", events) is True

    def test_fork_tag_at_fix_go_excluded(self) -> None:
        """Go uses prerelease for pseudo-versions — skip the heuristic."""
        events = [{"introduced": "0"}, {"fixed": "0.4.3"}]
        assert in_range("Go", "v0.4.3-succinct", events) is True

    def test_fork_tag_at_fix_last_affected_inclusive(self) -> None:
        """last_affected is inclusive — fork-tag bypass only applies to
        exclusive upper bounds (fixed versions)."""
        events = [{"introduced": "0"}, {"last_affected": "0.4.3"}]
        assert in_range("Cargo", "0.4.3-succinct", events) is True

    def test_fork_tag_version_above_fix(self) -> None:
        """Fork base above the fix: not in range regardless."""
        events = [{"introduced": "0"}, {"fixed": "0.4.3"}]
        assert in_range("Cargo", "0.5.0-succinct", events) is False


class TestBranchSnapshotGuard:
    """Upstream branch/channel tokens are NOT fork tags — the guard
    lives in ``is_fork_tag`` itself so both the live post-filter and
    the offline ``in_range`` path share it."""

    def test_branch_tokens_are_not_fork_tags(self) -> None:
        assert is_fork_tag(["master"]) is False
        assert is_fork_tag(["develop"]) is False
        assert is_fork_tag(["latest"]) is False
        assert is_fork_tag(["myorg", "main"]) is False

    def test_in_range_keeps_branch_snapshot_match(self) -> None:
        """Offline-DB path: a vulnerable ``1.0.0-master`` pin matching
        ``[introduced, 1.0.0)`` must stay reported — it is an upstream
        branch snapshot, not a fork.  This was the offline/live
        asymmetry: the live path's post-filter kept the match while
        ``in_range`` silently dropped it."""
        events = [{"introduced": "0"}, {"fixed": "1.0.0"}]
        assert in_range("npm", "1.0.0-master", events) is True
        assert in_range("Cargo", "1.0.0-develop", events) is True

    def test_in_range_still_prunes_true_fork_tag_at_fix(self) -> None:
        """The fork-tag suppression itself is retained: a fork tagged
        exactly at the fix version stays pruned."""
        events = [{"introduced": "0"}, {"fixed": "0.4.3"}]
        assert in_range("Cargo", "0.4.3-succinct", events) is False
