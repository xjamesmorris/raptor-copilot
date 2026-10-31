"""Compose-spec rendering: recv_le64 parses target-controlled hex
under a budget.

The recv_le64 chunk parses the first token of a prior recv — bytes
the TARGET wrote, up to the daemon's capture cap — as a hex int. Hex
parsing is exempt from CPython's int_max_str_digits guard (the same
hazard ``_parse_bytes_to_int`` documents and budgets), so a hostile
target printing megabytes of hex used to cost a multi-megabit int
materialisation per chunk before the 64-bit mask discarded all but
the low bits. Only 64 bits survive the LE64 pack, so the render now
validates the token and parses its last 16 hex digits — value-
identical, cost-bounded.
"""

from __future__ import annotations

import struct

import pytest

from core.sandbox._daemon import _render_compose


def _le64(value: int) -> bytes:
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def test_hex_and_recv_le64_chunks_render():
    recvs = [b"0xdeadbeefcafef00d rest ignored"]
    out = _render_compose(
        [{"kind": "hex", "value": "41 42"},
         {"kind": "recv_le64", "recv_index": 0}],
        recvs,
    )
    assert out == b"AB" + _le64(0xDEADBEEFCAFEF00D)


def test_oversized_hex_token_is_value_identical_to_the_mask():
    # A token far beyond 16 digits: the packed value must equal the
    # unbounded-parse-then-mask semantics (low 64 bits), without
    # materialising the full-width int.
    big = "f" * 100000 + "0123456789abcdef"
    out = _render_compose(
        [{"kind": "recv_le64", "recv_index": 0}],
        [b"0x" + big.encode()],
    )
    assert out == _le64(0x0123456789ABCDEF)


def test_non_hex_token_raises_value_error():
    with pytest.raises(ValueError, match="not a hex integer"):
        _render_compose(
            [{"kind": "recv_le64", "recv_index": 0}],
            [b"zz41 tail"],
        )


def test_non_hex_beyond_the_last_16_digits_still_raises():
    # The budget must not weaken validation: garbage anywhere in the
    # token refuses, exactly as the full-token int() parse did.
    tok = b"xyz" + b"a" * 16
    with pytest.raises(ValueError, match="not a hex integer"):
        _render_compose(
            [{"kind": "recv_le64", "recv_index": 0}],
            [tok],
        )


def test_empty_token_raises():
    with pytest.raises(ValueError, match="empty after tokenization"):
        _render_compose(
            [{"kind": "recv_le64", "recv_index": 0}],
            [b"0x"],
        )


def test_missing_recv_index_raises():
    with pytest.raises(IndexError, match="recv_index=1"):
        _render_compose(
            [{"kind": "recv_le64", "recv_index": 1}],
            [b"0x1"],
        )
