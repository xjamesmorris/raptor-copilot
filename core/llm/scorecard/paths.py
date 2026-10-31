"""Shared resolver for the scorecard sidecar's default on-disk path.

Every consumer that needs "the" reliability ledger without an explicit
path must resolve through :func:`default_scorecard_path`. Before this
module existed the resolution was copied inline per consumer, and the
copies drifted: ``tool_evidence`` / ``validate_feedback`` anchored via
``RAPTOR_DIR`` while ``LLMConfig.scorecard_path`` and the CLI/audit
defaults resolved against the process cwd — a bare-shell invocation
from a scanned repo wrote the per-model reliability ledger (which
steers routing, short-circuits, and merge weights) into the target
tree and fragmented the history per-cwd.
"""

from __future__ import annotations

import os
from pathlib import Path

_RELATIVE_DEFAULT = Path("out/llm_scorecard.json")


def default_scorecard_path() -> Path:
    """Default reliability-ledger path, anchored to the RAPTOR install.

    Resolution order:

    1. ``RAPTOR_SCORECARD_PATH`` — explicit operator/test override, so
       sandboxed runs and tests can isolate the on-disk reliability
       data.
    2. ``<RAPTOR_DIR>/out/llm_scorecard.json`` — anchored to the
       install so an invocation from any cwd reads and writes the same
       ledger as launcher runs, instead of dropping a stray
       ``./out/llm_scorecard.json`` next to the analysed repo (same
       rationale as ``core.llm.config._default_cache_dir``).
    3. The relative path, only when ``RAPTOR_DIR`` is unset (hermetic
       test environments) — same convention as the cache dir.
    """
    override = os.environ.get("RAPTOR_SCORECARD_PATH")
    if override:
        return Path(override)
    raptor_dir = os.environ.get("RAPTOR_DIR")
    if raptor_dir:
        return Path(raptor_dir) / _RELATIVE_DEFAULT
    return _RELATIVE_DEFAULT
