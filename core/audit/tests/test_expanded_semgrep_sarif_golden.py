"""Byte-level golden test for the expanded-semgrep SARIF emitter.

The golden was captured from ``findings_to_sarif`` BEFORE it moved
onto ``core.sarif.emit``. The document is written with
``save_json(sort_keys=False)``, so member order is the on-disk byte
order — hence serialized comparison, not dict equality.

Input coverage: rule-id dedup, missing rule_id (``(unnamed)``),
empty message (fidelity-3 default text), missing file/line/
expanded_line defaults.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.expanded_semgrep import findings_to_sarif

_GOLDEN = (
    Path(__file__).parent / "data" / "expanded_semgrep_sarif_golden.json"
)


def _inputs() -> list[dict]:
    return [
        {"rule_id": "c.buffer.overflow", "file": "src/a.c", "line": 33,
         "expanded_line": 210, "message": "macro-hidden memcpy overflow"},
        {"rule_id": "c.buffer.overflow", "file": "src/b.c", "line": 4,
         "expanded_line": 90, "message": ""},
        {"file": "src/c.c"},
    ]


def test_sarif_document_is_byte_identical_to_golden():
    doc = findings_to_sarif(_inputs())
    got = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    assert got == _GOLDEN.read_text(encoding="utf-8")
