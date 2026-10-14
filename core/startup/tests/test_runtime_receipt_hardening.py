"""Regression coverage required before real identity collection is accepted."""

from __future__ import annotations

from datetime import datetime

import pytest

from core.startup.runtime_receipt import (
    ReceiptRejection,
    load_profile_store,
    verify_receipt_static,
)
from core.startup.tests.test_runtime_receipt import (
    _expected,
    _parse_document,
    _receipt_document,
)


def test_verify_receipt_rejects_timezone_naive_now_as_programming_error() -> None:
    receipt = _parse_document(_receipt_document())
    assert not isinstance(receipt, ReceiptRejection)
    profiles = load_profile_store()
    assert not isinstance(profiles, ReceiptRejection)

    with pytest.raises(ValueError, match="timezone-aware"):
        verify_receipt_static(
            receipt,
            profiles=profiles,
            expected=_expected(),
            now=datetime(2026, 9, 12, 12, 0, 0),
        )
