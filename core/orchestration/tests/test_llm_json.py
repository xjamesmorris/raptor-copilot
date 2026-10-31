"""Unit tests for the shared LLM-JSON helpers.

strip_json_fences replaced seven per-module fence-strip copies whose
edge behavior had drifted (filter-all-fence-lines vs first-block vs
strip-backticks); these tests pin the one shared shape.
"""

from core.orchestration.llm_json import dict_rows, list_at, strip_json_fences


class TestStripJsonFences:
    def test_plain_json_passes_through(self):
        assert strip_json_fences('  {"a": 1}\n') == '{"a": 1}'

    def test_language_tagged_fence(self):
        assert strip_json_fences('```json\n{"a": 1}\n```') == '{"a": 1}'

    def test_bare_fence(self):
        assert strip_json_fences('```\n{"a": 1}\n```') == '{"a": 1}'

    def test_multiline_payload_kept(self):
        raw = '```json\n{"a": 1}\n{"b": 2}\n```'
        assert strip_json_fences(raw) == '{"a": 1}\n{"b": 2}'

    def test_unclosed_fence_keeps_rest(self):
        assert strip_json_fences('```json\n{"a": 1}') == '{"a": 1}'

    def test_trailing_prose_after_close_dropped(self):
        raw = '```json\n{"a": 1}\n```\nHope that helps!'
        assert strip_json_fences(raw) == '{"a": 1}'

    def test_mid_text_fence_not_triggered(self):
        # Leading-fence detection only: callers that tolerate prose
        # before the fence slice it off first (core/iris/specs.py) or
        # use core.json.tolerant.parse_llm_json's full ladder.
        raw = 'Here you go:\n```json\n{"a": 1}\n```'
        assert strip_json_fences(raw) == raw.strip()

    def test_empty_and_fence_only(self):
        assert strip_json_fences("") == ""
        assert strip_json_fences("```json\n```") == ""


class TestListAt:
    def test_non_dict_container(self):
        assert list_at(None, "k") == []
        assert list_at(42, "k") == []

    def test_non_list_value(self):
        assert list_at({"k": "scalar"}, "k") == []
        assert list_at({"k": None}, "k") == []

    def test_list_value(self):
        assert list_at({"k": [1, 2]}, "k") == [1, 2]


class TestDictRows:
    def test_non_dict_rows_skipped(self):
        d = {"k": [{"a": 1}, "prose row", None, {"b": 2}]}
        assert dict_rows(d, "k") == [{"a": 1}, {"b": 2}]
