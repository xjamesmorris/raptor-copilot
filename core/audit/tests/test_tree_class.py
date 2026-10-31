"""Tests for tree-class tagging — classifier, priority weighting,
finding/export field, report grouping, and /validate selection
preference. Tags order and weigh; nothing is ever filtered."""

from __future__ import annotations

from types import SimpleNamespace

from core.audit.findings import emit_finding, load_findings
from core.audit.findings_export import build_graded_finding, export_findings
from core.audit.priority import SCORE_NON_PRODUCTION_TREE, score_functions
from core.audit.report import _format_summary, write_markdown_report
from core.audit.tree_class import (
    NON_PRODUCTION_TREE_CLASSES,
    TREE_CLASS_PRODUCTION,
    TREE_CLASS_TEST,
    TREE_CLASS_VENDORED,
    classify_tree_class,
    tree_class_map,
)
from core.audit.vendored_detector import VendorVerdict
from core.orchestration.skill_dispatch import truncate_findings_by_signal


class TestClassifier:
    def test_compat_shim_tree_is_vendored(self):
        # The openssh-shaped compat tree that motivated the tag.
        assert classify_tree_class(
            "openbsd-compat/bsd-getpeereid.c",
        ) == TREE_CLASS_VENDORED

    def test_plain_compat_segment_is_vendored(self):
        assert classify_tree_class(
            "kernel/compat/syscalls.c",
        ) == TREE_CLASS_VENDORED

    def test_regress_tree_is_test_harness(self):
        assert classify_tree_class(
            "regress/unittests/sshkey/test_sshkey.c",
        ) == TREE_CLASS_TEST

    def test_fuzz_harness_under_regress_is_test_harness(self):
        assert classify_tree_class(
            "regress/misc/fuzz-harness/ssh-sk-null.cc",
        ) == TREE_CLASS_TEST

    def test_tests_dir_is_test_harness(self):
        assert classify_tree_class(
            "tests/fuzz_harness.c",
        ) == TREE_CLASS_TEST

    def test_root_level_file_is_production(self):
        assert classify_tree_class("ssh.c") == TREE_CLASS_PRODUCTION

    def test_nested_production_file(self):
        assert classify_tree_class(
            "src/net/parser.c",
        ) == TREE_CLASS_PRODUCTION

    def test_vendor_dir_is_vendored(self):
        assert classify_tree_class(
            "vendor/zlib/inflate.c",
        ) == TREE_CLASS_VENDORED

    def test_generated_filename_is_vendored(self):
        assert classify_tree_class("proto/api_pb2.py") == TREE_CLASS_VENDORED

    def test_filename_segments_never_match_dir_conventions(self):
        # regress.c / compat.c are files, not tree segments.
        assert classify_tree_class("src/regress.c") == TREE_CLASS_PRODUCTION
        assert classify_tree_class("src/compat.c") == TREE_CLASS_PRODUCTION

    def test_vendor_verdict_map_refines_classification(self):
        # A prep-time detector verdict (e.g. banner-based) classifies
        # a path the path-only signals cannot.
        verdicts = {
            "src/mlkem.c": VendorVerdict(
                kind="generated", signal="banner", detail="banner",
            ),
        }
        assert classify_tree_class(
            "src/mlkem.c", verdicts,
        ) == TREE_CLASS_VENDORED
        assert classify_tree_class("src/mlkem.c") == TREE_CLASS_PRODUCTION

    def test_empty_path_is_production(self):
        assert classify_tree_class("") == TREE_CLASS_PRODUCTION

    def test_map_dedups_and_skips_empty(self):
        m = tree_class_map(["ssh.c", "ssh.c", "", "regress/t.c"])
        assert m == {
            "ssh.c": TREE_CLASS_PRODUCTION,
            "regress/t.c": TREE_CLASS_TEST,
        }

    def test_non_production_set(self):
        assert NON_PRODUCTION_TREE_CLASSES == {
            TREE_CLASS_VENDORED, TREE_CLASS_TEST,
        }
        assert TREE_CLASS_PRODUCTION not in NON_PRODUCTION_TREE_CLASSES


def _gap(file, name, sloc=10):
    return {
        "file": file,
        "name": name,
        "line_start": 1,
        "line_end": sloc + 1,
        "priority": 0,
        "strategies": [],
        "sloc": sloc,
        "metadata": None,
    }


class TestPriorityWeight:
    def test_non_production_gap_demoted(self):
        gaps = [
            _gap("ssh.c", "main"),
            _gap("openbsd-compat/bsd-misc.c", "strlcpy"),
            _gap("regress/t.c", "t_main"),
        ]
        tree_classes = tree_class_map(g["file"] for g in gaps)
        scored = {
            g["name"]: g["priority_score"]
            for g in score_functions(gaps, tree_classes=tree_classes)
        }
        assert scored["main"] == 0
        assert scored["strlcpy"] == SCORE_NON_PRODUCTION_TREE
        assert scored["t_main"] == SCORE_NON_PRODUCTION_TREE

    def test_equal_signal_non_production_sorts_strictly_below(self):
        # Two-direction bound, low side: the demotion must be a real
        # demotion — an equal-signal non-production function scores
        # strictly below its production peer (a zero weight makes the
        # scores equal and fails here).
        gaps = [
            _gap("openbsd-compat/bsd-misc.c", "strlcpy", sloc=50),
            _gap("ssh.c", "main", sloc=50),
        ]
        result = score_functions(
            gaps, tree_classes=tree_class_map(g["file"] for g in gaps),
        )
        assert [g["name"] for g in result] == ["main", "strlcpy"]
        scores = {g["name"]: g["priority_score"] for g in result}
        assert scores["strlcpy"] < scores["main"]

    def test_vendored_entry_point_outranks_trivial_production(self):
        # Two-direction bound, high side: "mild" means the demotion
        # magnitude stays below SCORE_ENTRY_POINT — a vendored parser
        # that IS the attack surface must still outrank signal-free
        # production code (a weight at or beyond -SCORE_ENTRY_POINT
        # flips this ordering and fails here).
        context_map = {
            "entry_points": [
                {"file": "openbsd-compat/bsd-net.c", "name": "recv_frame"},
            ],
        }
        gaps = [
            _gap("openbsd-compat/bsd-net.c", "recv_frame", sloc=10),
            _gap("ssh.c", "helper", sloc=10),
        ]
        result = score_functions(
            gaps, context_map=context_map,
            tree_classes=tree_class_map(g["file"] for g in gaps),
        )
        scores = {g["name"]: g["priority_score"] for g in result}
        assert scores["recv_frame"] > scores["helper"]
        assert result[0]["name"] == "recv_frame"

    def test_demotion_is_weighting_never_a_skip(self):
        gaps = [_gap("openbsd-compat/bsd-misc.c", "strlcpy")]
        result = score_functions(
            gaps, tree_classes=tree_class_map(["openbsd-compat/bsd-misc.c"]),
        )
        assert len(result) == 1  # still scheduled

    def test_weight_off_knob_restores_prior_behavior(self):
        gaps = [
            _gap("ssh.c", "main"),
            _gap("openbsd-compat/bsd-misc.c", "strlcpy"),
        ]
        baseline = score_functions([dict(g) for g in gaps])
        knob_off = score_functions([dict(g) for g in gaps], tree_classes=None)
        assert [(g["name"], g["priority_score"]) for g in baseline] == \
            [(g["name"], g["priority_score"]) for g in knob_off]
        assert all(g["priority_score"] == 0 for g in knob_off)


class TestFindingField:
    def test_emit_finding_stamps_tree_class(self, tmp_path):
        emit_finding(
            out_dir=tmp_path,
            file_path="openbsd-compat/bsd-misc.c",
            function_name="strlcpy",
            line=10,
            title="t",
            description="d",
        )
        emit_finding(
            out_dir=tmp_path,
            file_path="ssh.c",
            function_name="main",
            line=5,
            title="t2",
            description="d2",
        )
        by_file = {f["file"]: f for f in load_findings(tmp_path)}
        assert by_file["openbsd-compat/bsd-misc.c"]["tree_class"] == \
            TREE_CLASS_VENDORED
        assert by_file["ssh.c"]["tree_class"] == TREE_CLASS_PRODUCTION

    def test_emit_finding_explicit_tree_class_wins(self, tmp_path):
        emit_finding(
            out_dir=tmp_path,
            file_path="src/mlkem.c",
            function_name="f",
            line=1,
            title="t",
            description="d",
            tree_class=TREE_CLASS_VENDORED,
        )
        assert load_findings(tmp_path)[0]["tree_class"] == \
            TREE_CLASS_VENDORED


def _outcome(file, function="f", status="finding"):
    return SimpleNamespace(
        file=file, function=function, line=3, status=status,
        hypothesis="overflow", review_result={}, evidence_tool="",
        depth="L1",
    )


class TestGradedExport:
    def test_build_graded_finding_carries_tree_class(self):
        finding = build_graded_finding(_outcome("regress/t.c"))
        assert finding["tree_class"] == TREE_CLASS_TEST
        production = build_graded_finding(_outcome("ssh.c"))
        assert production["tree_class"] == TREE_CLASS_PRODUCTION

    def test_export_findings_threads_vendor_verdicts(self):
        verdicts = {
            "src/mlkem.c": VendorVerdict(
                kind="generated", signal="banner", detail="banner",
            ),
        }
        export = export_findings(
            [_outcome("src/mlkem.c")], vendor_verdicts=verdicts,
        )
        assert export["findings"][0]["tree_class"] == TREE_CLASS_VENDORED


def _report_finding(fid, file, title="Bug", tree_class=None):
    f = {
        "id": fid, "title": title, "file": file, "line": 1,
        "severity": "medium", "evidence_tier": "heuristic",
    }
    if tree_class is not None:
        f["tree_class"] = tree_class
    return f


class TestReportGrouping:
    _FINDINGS = [
        # Emission order deliberately buries the production finding.
        _report_finding("F-1", "openbsd-compat/bsd-misc.c",
                        tree_class=TREE_CLASS_VENDORED),
        # No tree_class field: path fallback must group it (pre-tag
        # findings.json records).
        _report_finding("F-2", "regress/t.c"),
        _report_finding("F-3", "ssh.c", tree_class=TREE_CLASS_PRODUCTION),
    ]

    def test_markdown_production_first_groups_labeled(self, tmp_path):
        report = {"stats": {"reviewed": 3}, "findings": list(self._FINDINGS)}
        path = write_markdown_report(report, tmp_path)
        text = path.read_text(encoding="utf-8")
        assert text.index("F-3") < text.index("F-1") < text.index("F-2")
        assert "### Vendored / compat tree findings (1)" in text
        assert "### Test-harness tree findings (1)" in text

    def test_summary_production_first_groups_counted(self):
        report = {
            "stats": {"reviewed": 3},
            "findings": list(self._FINDINGS),
            "findings_count": 3,
            "gaps_remaining": 0,
        }
        summary = _format_summary(report)
        assert summary.index("(ssh.c:1)") < summary.index(
            "openbsd-compat/bsd-misc.c",
        )
        assert "Vendored / compat tree (1):" in summary
        assert "Test-harness tree (1):" in summary

    def test_all_production_renders_unchanged_shape(self, tmp_path):
        report = {
            "stats": {"reviewed": 1},
            "findings": [_report_finding("F-9", "ssh.c")],
        }
        text = write_markdown_report(report, tmp_path).read_text(
            encoding="utf-8",
        )
        assert "### F-9: Bug (Heuristic)" in text
        assert "tree findings" not in text


class TestValidateSelectionPreference:
    def test_truncation_prefers_production_on_signal_tie(self):
        findings = [
            {"id": "V-1", "tree_class": TREE_CLASS_VENDORED},
            {"id": "T-1", "tree_class": TREE_CLASS_TEST},
            {"id": "P-1", "tree_class": TREE_CLASS_PRODUCTION},
            {"id": "L-1"},  # untagged legacy record ranks as production
        ]
        kept = {f["id"] for f in truncate_findings_by_signal(findings, 2)}
        assert kept == {"P-1", "L-1"}

    def test_exploitability_signal_still_wins_over_tree_class(self):
        findings = [
            {"id": "P-1", "tree_class": TREE_CLASS_PRODUCTION},
            {"id": "V-1", "tree_class": TREE_CLASS_VENDORED,
             "is_exploitable": True},
        ]
        kept = truncate_findings_by_signal(findings, 1)
        assert kept[0]["id"] == "V-1"
