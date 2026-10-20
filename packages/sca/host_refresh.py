"""Validate host-managed public-feed refresh receipts for offline SCA."""

from __future__ import annotations

import stat
import time
from pathlib import Path
from typing import Any

from core.json import load_json

SCHEMA = "raptor.sca-host-refresh/v1"
MAX_AGE_SECONDS = 24 * 3600
REQUIRED_SOURCES = frozenset({
    "api.osv.dev",
    "www.cisa.gov",
    "api.first.org",
    "raw.githubusercontent.com/cisagov/vulnrichment",
})


def fresh_receipt(
    target: Path,
    *,
    cache_root: Path,
    now: float | None = None,
) -> dict[str, Any] | None:
    """Return a fresh, target-bound anonymous refresh receipt."""
    path = cache_root / "host-refresh-receipt.json"
    try:
        mode = path.lstat().st_mode
    except OSError:
        return None
    if not stat.S_ISREG(mode):
        return None
    value = load_json(path, max_bytes=1024 * 1024)
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        return None
    if value.get("anonymous") is not True:
        return None
    try:
        receipt_target = Path(str(value.get("target"))).resolve()
        refreshed_at = float(value.get("refreshed_at"))
    except (TypeError, ValueError, OSError):
        return None
    if receipt_target != target.resolve():
        return None
    age = (time.time() if now is None else now) - refreshed_at
    if age < -300 or age > MAX_AGE_SECONDS:
        return None
    sources = value.get("sources")
    if (
        not isinstance(sources, list)
        or not REQUIRED_SOURCES.issubset({
            str(source) for source in sources
        })
    ):
        return None
    return value


__all__ = [
    "MAX_AGE_SECONDS",
    "REQUIRED_SOURCES",
    "SCHEMA",
    "fresh_receipt",
]
