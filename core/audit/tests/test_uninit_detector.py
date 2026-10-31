"""Tests for uninit_detector and inject-mode prompt rendering."""

from __future__ import annotations

from core.audit.uninit_detector import detect_uninit_leak


class TestUninitLeakBasic:
    def test_classic_copy_to_user(self):
        src = """\
int io_uring_setup(unsigned entries, struct io_uring_params __user *params)
{
    struct io_uring_params p;
    p.sq_entries = entries;
    p.cq_entries = entries * 2;
    if (copy_to_user(params, &p, sizeof(p)))
        return -EFAULT;
    return 0;
}
"""
        results = detect_uninit_leak(src)
        assert len(results) == 1
        assert results[0].struct_var == "p"
        assert results[0].sink_call == "copy_to_user"
        assert "info leak" in results[0].description

    def test_zeroed_struct_no_finding(self):
        src = """\
int safe_func(struct my_struct __user *dst)
{
    struct my_struct s;
    memset(&s, 0, sizeof(s));
    s.field = 42;
    if (copy_to_user(dst, &s, sizeof(s)))
        return -EFAULT;
    return 0;
}
"""
        results = detect_uninit_leak(src)
        assert len(results) == 0

    def test_brace_zero_init_no_finding(self):
        src = """\
int safe_func(struct my_struct __user *dst)
{
    struct my_struct s = {0};
    s.field = 42;
    if (copy_to_user(dst, &s, sizeof(s)))
        return -EFAULT;
    return 0;
}
"""
        results = detect_uninit_leak(src)
        assert len(results) == 0

    def test_empty_brace_init_no_finding(self):
        src = """\
int safe_func(struct my_struct __user *dst)
{
    struct my_struct s = {};
    s.field = 42;
    if (copy_to_user(dst, &s, sizeof(s)))
        return -EFAULT;
    return 0;
}
"""
        results = detect_uninit_leak(src)
        assert len(results) == 0

    def test_no_sink_no_finding(self):
        src = """\
void helper(struct foo *out)
{
    struct bar b;
    b.x = 1;
    out->inner = b;
}
"""
        results = detect_uninit_leak(src)
        assert len(results) == 0

    def test_no_struct_no_finding(self):
        src = """\
int simple_copy(void __user *dst, int value)
{
    if (put_user(value, dst))
        return -EFAULT;
    return 0;
}
"""
        results = detect_uninit_leak(src)
        assert len(results) == 0


class TestUninitLeakSinks:
    def test_nla_put(self):
        src = """\
int fill_info(struct sk_buff *skb)
{
    struct my_data d;
    d.type = 1;
    nla_put(skb, ATTR_DATA, sizeof(d), &d);
    return 0;
}
"""
        results = detect_uninit_leak(src)
        assert len(results) == 1
        assert results[0].sink_call == "nla_put"

    def test_put_user(self):
        src = """\
int get_info(struct info __user *u)
{
    struct info i;
    i.version = 1;
    put_user(&i, u);
    return 0;
}
"""
        results = detect_uninit_leak(src)
        assert len(results) == 1
        assert results[0].sink_call == "put_user"


class TestUninitLeakEdgeCases:
    def test_memcpy_counts_as_init(self):
        src = """\
int func(struct dst __user *u, struct src *s)
{
    struct dst d;
    memcpy(&d, s, sizeof(d));
    copy_to_user(u, &d, sizeof(d));
    return 0;
}
"""
        results = detect_uninit_leak(src)
        assert len(results) == 0

    def test_designated_init_is_partial(self):
        src = """\
int func(struct params __user *u)
{
    struct params p = {.version = 1};
    copy_to_user(u, &p, sizeof(p));
    return 0;
}
"""
        results = detect_uninit_leak(src)
        assert len(results) == 0

    def test_multiple_structs(self):
        src = """\
int func(void __user *u)
{
    struct safe s;
    struct unsafe us;
    memset(&s, 0, sizeof(s));
    s.x = 1;
    us.y = 2;
    copy_to_user(u, &us, sizeof(us));
    return 0;
}
"""
        results = detect_uninit_leak(src)
        assert len(results) == 1
        assert results[0].struct_var == "us"


class TestUninitLeakCpgFallback:
    def test_falls_back_to_regex_when_no_server(self):
        src = """\
int func(struct params __user *u)
{
    struct params p;
    p.sq_entries = 1;
    copy_to_user(u, &p, sizeof(p));
    return 0;
}
"""
        results = detect_uninit_leak(src, "func", joern_server=None)
        assert len(results) == 1
        assert results[0].tier == "regex"

    def test_falls_back_to_regex_on_cpg_error(self):
        class BrokenServer:
            def query(self, *a, **kw):
                raise RuntimeError("boom")

        src = """\
int func(struct params __user *u)
{
    struct params p;
    p.sq_entries = 1;
    copy_to_user(u, &p, sizeof(p));
    return 0;
}
"""
        results = detect_uninit_leak(src, "func", joern_server=BrokenServer())
        assert len(results) == 1
        assert results[0].tier == "regex"


class TestInjectModePromptRendering:
    def test_mechanical_detector_findings_rendered(self):
        from core.audit.context import format_context_for_prompt

        ctx = {
            "file": "test.c",
            "function": "foo",
            "source": "void foo(void) {}",
            "line_start": 1,
            "mechanical_detector_findings": [
                {
                    "detector": "smt:check-lock-domain",
                    "line": 42,
                    "description": "lock-domain mismatch: field `count` ...",
                },
                {
                    "detector": "uninit_leak",
                    "line": 55,
                    "description": "stack struct `p` partially initialised ...",
                },
            ],
        }
        prompt = format_context_for_prompt(ctx)
        assert "Pre-loop mechanical findings" in prompt
        assert "smt:check-lock-domain" in prompt
        assert "uninit_leak" in prompt
        assert "L42" in prompt
        assert "L55" in prompt
        assert "leads, not proof" in prompt

    def test_no_findings_no_section(self):
        from core.audit.context import format_context_for_prompt

        ctx = {
            "file": "test.c",
            "function": "foo",
            "source": "void foo(void) {}",
            "line_start": 1,
        }
        prompt = format_context_for_prompt(ctx)
        assert "Pre-loop mechanical findings" not in prompt


class TestCpgQueryAndReporting:
    def test_underscored_sink_not_reported_under_plain_name(self, monkeypatch):
        """"copy_to_user" is a substring of "__copy_to_user" — tuple
        order used to misreport the underscored sink."""
        import core.audit.uninit_detector as ud

        def fake_run_query(server, query):
            return [["buf___copy_to_user", "struct x", [10], False]]

        monkeypatch.setattr(ud, "_run_query", fake_run_query)
        results = ud.detect_uninit_leak_cpg("func", object())
        assert len(results) == 1
        assert results[0].sink_call == "__copy_to_user"

    def test_local_name_never_interpolated_into_regex(self, monkeypatch):
        """A variable name with regex metacharacters used to blow up
        the Scala .matches at query runtime (whole CPG tier lost)."""
        import core.audit.uninit_detector as ud
        captured: dict[str, str] = {}

        def fake_run_query(server, query):
            captured["query"] = query
            return []

        monkeypatch.setattr(ud, "_run_query", fake_run_query)
        ud.detect_uninit_leak_cpg("func", object())
        assert '".*" + local.name' not in captured["query"]
        assert ".contains(local.name)" in captured["query"]
