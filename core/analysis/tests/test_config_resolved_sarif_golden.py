"""Byte-level golden test for the config-resolved SARIF emitter.

The golden was captured from ``to_sarif`` BEFORE it moved onto
``core.sarif.emit``. The document is written with
``save_json(sort_keys=False)``, so member order is the on-disk byte
order — including this emitter's historical ``properties``-before-
``locations`` result order — hence serialized comparison.

Input coverage: rule-id dedup, CWE tags in rule properties, file
under the repo root (relativized), file outside it (left as-is).
"""

from __future__ import annotations

import json
from pathlib import Path

from core.analysis.config_resolved_findings import to_sarif

_GOLDEN = (
    Path(__file__).parent / "fixtures" / "config_resolved_sarif_golden.json"
)


def _inputs() -> list[dict]:
    return [
        {"rule_id": "weak-cipher-config", "cwe": "CWE-327",
         "file": "/raptor-golden-repo/src/conf/A.java", "line": 14,
         "message": "weak algorithm selected via configuration: "
                    "key 'cipher'"},
        {"rule_id": "weak-cipher-config", "cwe": "CWE-327",
         "file": "src/conf/B.java", "line": 3,
         "message": "second hit, relative path"},
        {"rule_id": "weak-hash-config", "cwe": "CWE-328",
         "file": "/elsewhere/C.java", "line": 9,
         "message": "outside the repo root"},
    ]


def test_sarif_document_is_byte_identical_to_golden():
    doc = to_sarif(_inputs(), "/raptor-golden-repo")
    got = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    assert got == _GOLDEN.read_text(encoding="utf-8")


def test_result_member_order_properties_before_locations():
    """This emitter historically wrote ``properties`` ahead of
    ``locations``; the consolidation preserves that byte order."""
    doc = to_sarif(_inputs(), "/raptor-golden-repo")
    res = doc["runs"][0]["results"][0]
    assert list(res) == [
        "ruleId", "level", "message", "properties", "locations",
    ]
