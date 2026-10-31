"""Precision gate for the Java CWE-1333 (ReDoS) rules.

The fixture harness (test_rule_fixtures.py) asserts "fires somewhere /
stays silent"; catastrophic-backtracking detection lives or dies on the
exact line set, so this gate is stricter:

  - every fixture line tagged ``// redos-tp`` fires — and NOTHING else
    in the positive fixtures fires (each tag is one vulnerable shape
    from the taxonomy: nested unbounded quantifiers, self-repetition
    alternation, unbounded wildcard runs, tainted pattern position);
  - the negative fixtures (linear look-alikes: possessive/atomic
    forms, bounded repetition, required-delimiter groups, anchored
    everyday idioms) produce ZERO findings.

The real semgrep binary adjudicates the end-to-end assertions; the
shape-regex unit assertions below run hermetically without it.

All fixtures are synthetic — written for this test, no real-world code.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

_RULES_FILE = (
    Path(__file__).resolve().parents[1] / "rules" / "injection" / "regex-dos.yaml"
)
_FIXTURES = Path(__file__).resolve().parent / "fixtures"

_LITERAL_RULE = "raptor.injection.regex-dos.literal.java"
_TAINT_RULE = "raptor.injection.regex-dos.taint.java"

# rule id → (positive fixture whose tagged lines must ALL fire, and
# nothing else; negative fixture that must stay fully silent)
_PRECISION_CASES = {
    _LITERAL_RULE: ("redos_java_literal_pos.java", "redos_java_literal_neg.java"),
    _TAINT_RULE: ("redos_java_taint_pos.java", "redos_java_taint_neg.java"),
}

_TP_MARKER = re.compile(r"//\s*redos-tp\s*$")


def _tagged_lines(fixture: Path) -> set[int]:
    return {
        n
        for n, line in enumerate(fixture.read_text().splitlines(), start=1)
        if _TP_MARKER.search(line)
    }


def _semgrep_lines_by_rule(targets: list[Path]) -> dict[str, dict[str, set[int]]]:
    """rule id → fixture name → set of fired line numbers."""
    proc = subprocess.run(
        [
            "semgrep",
            "scan",
            "--config",
            str(_RULES_FILE),
            "--quiet",
            "--metrics",
            "off",
            "--json",
            *[str(t) for t in targets],
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0, f"semgrep failed: {proc.stderr[:500]}"
    out: dict[str, dict[str, set[int]]] = {}
    for result in json.loads(proc.stdout)["results"]:
        rule = result["check_id"]
        # semgrep prefixes check_id with the config path; keep the tail
        for known in _PRECISION_CASES:
            if rule.endswith(known):
                rule = known
        fixture = Path(result["path"]).name
        out.setdefault(rule, {}).setdefault(fixture, set()).add(
            result["start"]["line"]
        )
    return out


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_exact_tp_lines_fire_and_tn_fixtures_stay_silent():
    targets = sorted({f for pair in _PRECISION_CASES.values() for f in pair})
    fired = _semgrep_lines_by_rule([_FIXTURES / t for t in targets])
    for rule, (pos_name, neg_name) in _PRECISION_CASES.items():
        expected = _tagged_lines(_FIXTURES / pos_name)
        assert expected, f"{pos_name} has no // redos-tp tags"
        got = fired.get(rule, {}).get(pos_name, set())
        assert got == expected, (
            f"{rule} on {pos_name}: missed TP lines {sorted(expected - got)}, "
            f"unexpected extra lines {sorted(got - expected)}"
        )
        neg_hits = fired.get(rule, {}).get(neg_name, set())
        assert not neg_hits, (
            f"{rule} fired on clean fixture {neg_name} lines {sorted(neg_hits)}"
        )
    # No OTHER rule in the file may claim the java fixtures either —
    # a python/js sibling matching java would be a language-key bug.
    for rule, by_fixture in fired.items():
        assert rule in _PRECISION_CASES, (
            f"unexpected rule {rule} fired on {sorted(by_fixture)}"
        )


def _collect_metavariable_regexes(node: object, out: list[str]) -> None:
    if isinstance(node, dict):
        if "metavariable-regex" in node:
            out.append(node["metavariable-regex"]["regex"])
        for value in node.values():
            _collect_metavariable_regexes(value, out)
    elif isinstance(node, list):
        for item in node:
            _collect_metavariable_regexes(item, out)


def _literal_shape_regexes() -> tuple[re.Pattern[str], re.Pattern[str]]:
    """(main shape regex, COMMENTS-flag-argument core) from the rule."""
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load(_RULES_FILE.read_text())
    (rule,) = [r for r in doc["rules"] if r["id"] == _LITERAL_RULE]
    regexes: list[str] = []
    _collect_metavariable_regexes(rule["patterns"], regexes)
    assert len(regexes) == 2, f"expected 2 metavariable-regex clauses, got {len(regexes)}"
    main, comments_arg = regexes  # YAML order: normal-mode clause first
    assert len(main) > len(comments_arg), "clause order changed in the rule file"
    return re.compile(main), re.compile(comments_arg)


def test_shape_regex_compiles_and_matches_taxonomy():
    """Hermetic mirror of the semgrep assertion: the shape regex itself
    classifies the TP/TN taxonomy correctly on the Java SOURCE form of
    each pattern (regex backslashes doubled, as they appear inside a
    string literal — which is the text semgrep binds to the metavariable).
    Anchored ``.match`` mirrors semgrep's metavariable-regex semantics.
    """
    shape, comments_core = _literal_shape_regexes()
    vulnerable = [
        r"(a+)+", r"^(a+)+$", r"(\d+)*", r"([a-z]+)*$", r"(\w+\s?)*",
        r"(a{2,})+", r"(x+){3,}", r"(a|aa)+", r"(ab|abab)*", r"(a|a)*",
        r"(.*,)+", r"(a.+b)*", r"(?:\d+)+", r"(a+?)+", r"(\s*\w+)*$",
        r"(a+b?)+",
        # alternate group spellings and escape forms
        r"(?<g>a+)+", r"(?i:a+)+", r"((?i)a+)+", r"(?x)( a+ )+",
        r"\\(a+)+", r"(\.+)+",
    ]
    linear = [
        r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$", r"^\d{4}-\d{2}-\d{2}$",
        r"(a++)+", r"(a+)++", r"(a+)*+", r"(?>a+)+", r"(a|b)+",
        r"(cat|dog)*", r"(foo|bar){1,3}", r"(a+){1,4}", r"(a{1,5})+",
        r"\(x+\)+", r"([^,]*,)+", r"(https?|ftp)://", r"(\d+)", r"[.*]+",
        r"(a+b)+", r"(\d+\.\d+)?", r"^(\d+)$", r"(?i)^(rc4.*|des.*|.*-ecb)$",
        r"([A-Z][a-z]+ )+[A-Z][a-z]+", r"(0x[0-9a-f]+,)*0x[0-9a-f]+",
        r"^\w+(\.\w+)*$", r"^[+-]?(\d+\.?\d*|\.\d+)$", r"(19|20)\d{2}",
        r"^(\w+)=(\S+)$", r"(;[^;]+)*$",
        # group-spelling look-alikes: prefixes admitted, still linear
        r"(a?b)+", r"(\d+,\d+)+", r"(https?://[a-z0-9.-]+/?)+",
        r"(foo|foobar)+", r"(a+){2,4}", r"(?<name>\d+)", r"(?i:[a-z]+)",
        r"((?m)^\w+$)", r"(?<g>\.\w+)*",
    ]
    java_source = lambda p: p.replace("\\", "\\\\")  # noqa: E731
    missed = [p for p in vulnerable if not shape.match(java_source(p))]
    assert not missed, f"shape regex misses vulnerable patterns: {missed}"
    false_hits = [p for p in linear if shape.match(java_source(p))]
    assert not false_hits, f"shape regex flags linear patterns: {false_hits}"
    # COMMENTS-flag-argument core: whitespace-insignificant nesting fires,
    # delimiter-terminated groups stay silent.
    assert comments_core.match(java_source(r"( a+ )+"))
    assert not comments_core.match(java_source(r"( a+ b )+"))
    assert not comments_core.match(java_source(r"( [a-z]+ , )+"))


def test_shape_regex_is_not_itself_catastrophic():
    """The shape regex runs inside semgrep over arbitrary repo string
    literals — it must stay effectively linear on adversarial inputs
    (unclosed groups, backslash walls, near-miss alternations).
    Generous wallclock bound: exponential blowup on these probes would
    take minutes-to-forever, not seconds.
    """
    shape, comments_core = _literal_shape_regexes()
    probes = [
        "(" + "a?" * 4000,
        "(" + "a" * 8000 + "|",
        "(" + "ab" * 3000 + "|" + "ab" * 2999,
        "\\\\" * 4000 + "(a+)+",
        "(" * 2000 + "a+" + ")" * 2000,
        "(" + "." * 6000,
        "(?x" + " a+" * 2000,
        "(?x)" + "( a" * 1500,
    ]
    for probe in probes:
        for rx in (shape, comments_core):
            start = time.monotonic()
            rx.match(probe)
            assert time.monotonic() - start < 5.0, (
                f"shape regex superlinear on probe of len {len(probe)}"
            )
