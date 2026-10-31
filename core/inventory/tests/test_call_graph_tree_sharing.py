"""Tests for the shared-parse-tree seam between the inventory builder
and the call-graph extractors.

``extract_items`` already tree-sitter-parses every file; the
``extract_call_graph_*`` functions accept that tree via ``_tree`` so a
build parses each file once instead of twice. These tests pin both
directions of the contract:

  * a pre-parsed tree is USED — no second grammar import / parse
    happens (proven by making the module's own parse path fail), and
    the resulting graph matches the self-parsed one exactly;
  * without ``_tree`` the extractors keep their original
    parse-it-themselves behavior.
"""

from __future__ import annotations

import pytest

from core.inventory import call_graph as cg
from core.inventory.extractors import _ts_parser_for

pytest.importorskip("tree_sitter")


C_SOURCE = """\
#include <stdio.h>

static void helper(int x) {
    printf("%d", x);
}

int main(void) {
    helper(42);
    return 0;
}
"""

JS_SOURCE = """\
const fs = require('fs');

function run(path) {
    return fs.readFileSync(path);
}

run('x');
"""

GO_SOURCE = """\
package main

import "fmt"

func main() {
    fmt.Println("hi")
}
"""


def _pre_parsed(lang: str, source: str):
    """Parse *source* the way the inventory builder does (the
    extractors module's parser), skipping when the grammar is absent."""
    parser = _ts_parser_for(lang)
    if parser is None:
        pytest.skip(f"tree-sitter grammar for {lang} not installed")
    return parser.parse(source.encode())


def _break_own_parse_path(monkeypatch):
    """Make the module's own grammar-import/parse path unusable so any
    graph that still comes out MUST have been walked from ``_tree``."""
    def _boom(*_a, **_kw):
        raise AssertionError("call_graph re-parsed despite _tree")
    monkeypatch.setattr(cg, "_import_grammar", _boom)
    monkeypatch.setattr(cg, "_get_ts_parser", _boom)


@pytest.mark.parametrize(
    ("lang", "source", "extract"),
    [
        ("c", C_SOURCE, cg.extract_call_graph_c),
        ("javascript", JS_SOURCE, cg.extract_call_graph_javascript),
        ("go", GO_SOURCE, cg.extract_call_graph_go),
    ],
)
def test_pre_parsed_tree_is_used_and_equivalent(monkeypatch, lang, source,
                                                extract):
    expected = extract(source).to_dict()
    assert expected["calls"], "fixture must produce call sites"

    tree = _pre_parsed(lang, source)
    _break_own_parse_path(monkeypatch)
    got = extract(source, _tree=tree).to_dict()
    assert got == expected


def test_without_tree_extractor_parses_itself():
    pytest.importorskip("tree_sitter_c")
    g = cg.extract_call_graph_c(C_SOURCE)
    assert [c.chain for c in g.calls] == [["printf"], ["helper"]]


def test_builder_shares_the_extractors_parse(monkeypatch, tmp_path):
    """End-to-end: a sequential inventory build must never take the
    call-graph module's own parse path for a language whose grammar the
    extractors already parsed — and the shared tree must still yield a
    populated call graph."""
    pytest.importorskip("tree_sitter_c")
    from core.inventory import build_inventory

    src = tmp_path / "proj"
    src.mkdir()
    (src / "main.c").write_text(C_SOURCE)
    out = tmp_path / "out"

    _break_own_parse_path(monkeypatch)
    inv = build_inventory(str(src), output_dir=str(out), parallel=False)

    (record,) = inv["files"]
    graph = record["call_graph"]
    chains = [c["chain"] for c in graph["calls"]]
    assert ["helper"] in chains
    assert ["printf"] in chains
