"""Typed read-side view of findings.json rows.

The write side (``findings.py``) builds rows from fully-typed models,
but the read side historically re-parsed the raw dicts — every
consumer repeated the same ``row.get("vuln_type", "")`` /
``row.get("sca") or {}`` digs with slightly different defensive
guards. :class:`FindingRow` mirrors the on-disk row envelope (the
13-key shape ``findings._row_envelope`` owns) so consumers read named,
typed fields instead.

Tolerate-extra-keys discipline: findings.json rows legitimately carry
keys this model doesn't know about — the run lifecycle stamps
``provenance_refs`` onto rows after the scan, operators hand-edit
files, and the schema explicitly allows extras. ``from_row`` therefore
reads only the envelope keys and keeps the ORIGINAL mapping on
``raw``: pass-through consumers (filters, delta buckets) re-emit
``raw`` so unknown keys survive a round trip untouched.

Tolerance also applies to malformed values: a wrong-typed envelope
field degrades to the documented type's default (the same value the
write side would emit for "empty") instead of crashing a report or a
CI gate on a hand-edited row. Rows that aren't dicts at all parse to
``None`` — callers decide whether to skip or pass them through.

Read-side only: nothing here writes or mutates. The on-disk shape is
owned by the writers in ``findings.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .kinds import (
    HYGIENE_PREFIX,
    LICENSE_PREFIX,
    SCA_PREFIX,
    SCAN_HEALTH_PREFIX,
    SUPPLY_CHAIN_PREFIX,
    VULNERABLE_DEPENDENCY,
)


def _str(value: Any) -> str:
    return value if isinstance(value, str) else ""


@dataclass(frozen=True)
class FindingRow:
    """One findings.json row, typed.

    Field defaults are what the write side emits for "empty", so a
    missing key and an explicitly-empty one read the same. ``sca`` is
    kept as a mapping: its layout is per-kind (the vuln block and the
    hygiene block share almost nothing) and consumers dig into exactly
    the per-kind fields they understand.
    """

    raw: dict[str, Any] = field(default_factory=dict)
    id: str = ""
    finding_id: str = ""
    vuln_type: str = ""
    tool: str = ""
    file: str = ""
    function: str = ""
    line: int = 0
    severity: str = "info"
    suppressed: bool = False
    suppression_reason: str | None = None
    title: str = ""
    description: str = ""
    sca: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_row(cls, row: Any) -> FindingRow | None:
        """Parse one row; ``None`` when it isn't a dict.

        Never raises on malformed content — hand-edited findings.json
        may contain stray non-dict elements and wrong-typed fields.
        """
        if not isinstance(row, dict):
            return None
        line = row.get("line")
        reason = row.get("suppression_reason")
        sca = row.get("sca")
        return cls(
            raw=row,
            id=_str(row.get("id")),
            finding_id=_str(row.get("finding_id")),
            vuln_type=_str(row.get("vuln_type")),
            tool=_str(row.get("tool")),
            file=_str(row.get("file")),
            function=_str(row.get("function")),
            line=line if isinstance(line, int) else 0,
            severity=_str(row.get("severity")) or "info",
            suppressed=bool(row.get("suppressed")),
            suppression_reason=(
                reason if isinstance(reason, str) else None
            ),
            title=_str(row.get("title")),
            description=_str(row.get("description")),
            sca=sca if isinstance(sca, dict) else {},
        )

    # -- kind classification (see packages/sca/kinds.py) ----------------

    @property
    def is_sca(self) -> bool:
        """True for any SCA-owned row in a merged multi-tool list."""
        return self.vuln_type.startswith(SCA_PREFIX)

    @property
    def is_vulnerable_dependency(self) -> bool:
        return self.vuln_type == VULNERABLE_DEPENDENCY

    @property
    def is_hygiene(self) -> bool:
        return self.vuln_type.startswith(HYGIENE_PREFIX)

    @property
    def is_supply_chain(self) -> bool:
        return self.vuln_type.startswith(SUPPLY_CHAIN_PREFIX)

    @property
    def is_license(self) -> bool:
        return self.vuln_type.startswith(LICENSE_PREFIX)

    @property
    def is_scan_health(self) -> bool:
        return self.vuln_type.startswith(SCAN_HEALTH_PREFIX)

    # -- common nested reads ---------------------------------------------

    @property
    def advisory(self) -> dict[str, Any]:
        """The representative advisory block (vuln rows); ``{}``
        otherwise."""
        adv = self.sca.get("advisory")
        return adv if isinstance(adv, dict) else {}

    @property
    def reachability_verdict(self) -> str:
        """The ``sca.reachability.verdict`` string; ``not_evaluated``
        when the block is absent or malformed."""
        reach = self.sca.get("reachability")
        if not isinstance(reach, dict):
            return "not_evaluated"
        verdict = reach.get("verdict")
        return str(verdict) if verdict else "not_evaluated"


__all__ = ["FindingRow"]
