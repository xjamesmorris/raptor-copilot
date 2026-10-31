"""Shared strict from_dict checks (core.dataflow._schema_checks).

finding, label, and sanitizer_evidence each carried a byte-identical
copy; one implementation now serves all three. The identity test pins
the sharing so a module can't quietly grow its own variant back.
"""

from __future__ import annotations

import pytest

from core.dataflow import finding, label, sanitizer_evidence
from core.dataflow._schema_checks import check_extra_fields, require_nonempty


def test_value_modules_share_one_implementation():
    for mod in (finding, label, sanitizer_evidence):
        assert mod._check_extra_fields is check_extra_fields, mod.__name__
        assert mod._require_nonempty is require_nonempty, mod.__name__


def test_extra_fields_rejected_with_sorted_names():
    with pytest.raises(ValueError, match=r"\['b_extra', 'z_extra'\]"):
        check_extra_fields(
            "Step", {"ok": 1, "z_extra": 2, "b_extra": 3},
            frozenset({"ok"}),
        )


def test_allowed_fields_pass():
    check_extra_fields("Step", {"ok": 1}, frozenset({"ok", "opt"}))


@pytest.mark.parametrize("bad", ["", "   ", None, 7, b"x"])
def test_require_nonempty_rejects(bad):
    with pytest.raises(ValueError, match="non-empty string"):
        require_nonempty("field", bad)


def test_require_nonempty_accepts_real_string():
    require_nonempty("field", " x ")
