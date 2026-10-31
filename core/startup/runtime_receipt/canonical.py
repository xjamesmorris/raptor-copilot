"""Strict canonical JSON and digest primitives for runtime receipts."""

from __future__ import annotations

import hashlib
import re
from enum import Enum
from typing import Any, TypeAlias

from core.json.utils import dumps_canonical

SCHEMA_NAME = "raptor.runtime_receipt/v1"
SCHEMA_VERSION = 1
RECEIPT_DOMAIN = b"raptor-runtime-receipt-v1\0"
TOKEN_COMMITMENT_DOMAIN = b"raptor-launch-token-v1\0"

MAX_RECEIPT_BYTES = 65_536
MAX_JSON_DEPTH = 12
MAX_OBJECT_MEMBERS = 64
MAX_ARRAY_ITEMS = 64
MAX_STRING_BYTES = 4_096

JsonValue: TypeAlias = dict[str, Any] | list[Any] | str | int | bool | None

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")


class CanonicalValueError(ValueError):
    """A caller supplied a value outside the v1 canonical JSON domain."""


def _validate_string(value: str) -> None:
    if len(value.encode("utf-8")) > MAX_STRING_BYTES:
        raise CanonicalValueError("JSON string exceeds the 4096-byte limit")
    if not value.isprintable():
        raise CanonicalValueError("JSON string contains a control character")


def validate_json_value(value: object, *, depth: int = 0) -> None:
    """Validate the closed JSON value domain before canonicalization."""

    if isinstance(value, Enum):
        raise CanonicalValueError("enum objects must be converted explicitly")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -(2**63) <= value <= 2**64 - 1:
            raise CanonicalValueError("JSON integer is outside the supported range")
        return
    if isinstance(value, str):
        _validate_string(value)
        return
    if isinstance(value, float):
        raise CanonicalValueError("floating-point values are forbidden in receipt v1")
    if isinstance(value, list):
        if depth + 1 > MAX_JSON_DEPTH:
            raise CanonicalValueError("JSON nesting exceeds the depth limit")
        if len(value) > MAX_ARRAY_ITEMS:
            raise CanonicalValueError("JSON array exceeds the item limit")
        for item in value:
            validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if depth + 1 > MAX_JSON_DEPTH:
            raise CanonicalValueError("JSON nesting exceeds the depth limit")
        if len(value) > MAX_OBJECT_MEMBERS:
            raise CanonicalValueError("JSON object exceeds the member limit")
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalValueError("JSON object keys must be strings")
            _validate_string(key)
            validate_json_value(item, depth=depth + 1)
        return
    raise CanonicalValueError(
        f"unsupported canonical JSON value type: {type(value).__name__}"
    )


def canonical_bytes(value: JsonValue) -> bytes:
    """Return the frozen canonical ASCII representation of a strict JSON tree."""

    validate_json_value(value)
    return dumps_canonical(value).encode("ascii")


def sha256_hex(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""

    return hashlib.sha256(data).hexdigest()


def _digest_bytes(value: str) -> bytes:
    if _SHA256_RE.fullmatch(value) is None:
        raise CanonicalValueError("digest must be 64 lowercase hexadecimal characters")
    return bytes.fromhex(value)


def receipt_sha256(
    stable_identity_sha256: str,
    launch_instance_sha256: str,
    launch_binding_sha256: str,
    process_corroboration_sha256: str,
) -> str:
    """Hash the four independently canonicalized receipt sections."""

    preimage = b"".join(
        (
            RECEIPT_DOMAIN,
            _digest_bytes(stable_identity_sha256),
            _digest_bytes(launch_instance_sha256),
            _digest_bytes(launch_binding_sha256),
            _digest_bytes(process_corroboration_sha256),
        )
    )
    return sha256_hex(preimage)


def token_commitment(token_hex: str) -> str:
    """Commit to a 16-byte launch token without persisting the token."""

    if _TOKEN_RE.fullmatch(token_hex) is None:
        raise CanonicalValueError(
            "launch token must be 32 lowercase hexadecimal characters"
        )
    return sha256_hex(TOKEN_COMMITMENT_DOMAIN + bytes.fromhex(token_hex))
