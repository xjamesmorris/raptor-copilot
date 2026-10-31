"""Integer-truncation checker: xref-concatenation seam behavior.

The checker searches the primary decompile plus an optional xref blob
(caller/callee decompilations). The two are joined with a newline
sentinel: a truncated decompile ending mid-token must not glue to the
xref's first line and mint a cast/alloc/copy chain that exists in
neither function.
"""

from core.audit.integer_truncation_checker import check_integer_truncation


class TestPrimaryFunction:
    def test_classic_truncation_chain_found(self):
        source = (
            "void f(uint32_t wide_len) {\n"
            "    uint16_t trunc_val = (uint16_t)wide_len;\n"
            "    char *buf = malloc(trunc_val);\n"
            "    memcpy(buf, src, wide_len);\n"
            "}\n"
        )
        findings = check_integer_truncation("f", source)
        assert len(findings) == 1
        assert findings[0].wide_var == "wide_len"
        assert findings[0].narrow_var == "trunc_val"
        assert "[cross-function]" not in findings[0].evidence

    def test_no_narrowing_no_finding(self):
        source = (
            "void f(uint32_t n) {\n"
            "    char *buf = malloc(n);\n"
            "    memcpy(buf, src, n);\n"
            "}\n"
        )
        assert check_integer_truncation("f", source) == []


class TestXrefSeam:
    def test_cross_function_chain_found(self):
        primary = (
            "void g(uint32_t wide_len) {\n"
            "    uint16_t trunc_val = (uint16_t)wide_len;\n"
            "    do_copy(trunc_val, wide_len);\n"
            "}\n"
        )
        xref = (
            "// --- callee: do_copy ---\n"
            "void do_copy(uint16_t trunc_val, uint32_t wide_len) {\n"
            "    char *buf = malloc(trunc_val);\n"
            "    memcpy(buf, src, wide_len);\n"
            "}\n"
        )
        findings = check_integer_truncation("g", primary, xref_source=xref)
        assert len(findings) == 1
        assert findings[0].confidence == "medium"
        assert "[cross-function]" in findings[0].evidence

    def test_seam_glue_mints_no_identifier(self):
        # Primary ends mid-token (a decompiler cut): without the
        # newline sentinel "…(uint16_t)wide" + "_len;…" glued into
        # "(uint16_t)wide_len", a narrowing assignment that exists in
        # neither function, chaining with the xref's alloc/copy into
        # a fabricated finding.
        primary = "void f(void) { uint16_t trunc_val = (uint16_t)wide"
        xref = "_len; buf = malloc(trunc_val); memcpy(buf, p, wide_len); }"
        assert check_integer_truncation(
            "f", primary, xref_source=xref,
        ) == []
