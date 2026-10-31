"""Tests for core.audit.decompiler_sanitise.

``sanitise`` feeds Ghidra decompiler output to Semgrep's C parser
(the binary semgrep path); each rewrite rule below keeps a construct
Semgrep would choke on out of the scanned text while preserving the
identifiers and call shapes the rules match on. ``sanitise`` is the
module's whole surface: it is safe (and idempotent) on text that
needs no rewriting, so callers apply it unconditionally — a separate
needs-rewriting gate would have to mirror every rule here and drifts
the moment one is added.
"""

from __future__ import annotations

from core.audit.decompiler_sanitise import sanitise


class TestSanitise:
    def test_scoped_static(self):
        out = sanitise("FuncName(int)::localVar = 1;")
        assert "::" not in out
        assert "__static_FuncName__localVar" in out

    def test_class_member(self):
        out = sanitise("Widget::count++;")
        assert out == "Widget__count++;"

    def test_nested_class_member_chain(self):
        out = sanitise("a::b::c = 0;")
        assert "::" not in out

    def test_concat_preserves_both_operands(self):
        out = sanitise("x = CONCAT44(hi, lo);")
        assert "CONCAT" not in out
        assert "hi" in out and "lo" in out

    def test_sub_sext_zext_unwrap(self):
        out = sanitise("y = SUB41(expr, 2) + SEXT14(a) + ZEXT14(b);")
        assert "SUB41" not in out
        assert "SEXT14" not in out
        assert "ZEXT14" not in out
        assert "expr" in out and "(a)" in out and "(b)" in out

    def test_calling_convention_keywords_dropped(self):
        out = sanitise("void __thiscall f(void);")
        assert "__thiscall" not in out
        assert "f(void)" in out

    def test_plain_c_unchanged(self):
        src = "int main(void) { return memcpy(dst, src, n) != 0; }"
        assert sanitise(src) == src

    def test_idempotent(self):
        src = "Widget::run(CONCAT44(a, b))::state;"
        once = sanitise(src)
        assert sanitise(once) == once
