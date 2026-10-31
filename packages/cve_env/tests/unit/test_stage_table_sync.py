"""Drift test for the two stage-by-tool tables.

cve_env carries two deliberate copies of the tool → pipeline-stage
mapping, each serving a different consumer with a different value
schema (kept apart on purpose — do NOT unify):

- ``cve_env.config.TOOL_TO_STAGE`` — uppercase stage names for
  budget-engine cost attribution.
- ``cve_env.cli._STAGE_BY_TOOL`` — lowercase names for the
  end-of-run human report.

Both tables' comments promise a sync-enforcing test; this is it. The
invariant compared is the CONCEPTUAL mapping (case-folded, with the
non-pipeline bucket names translated); genuinely intended divergence
is carried in explicit allowlists below, and an allowlist entry that
stops diverging fails too — stale exemptions are drift in the other
direction.
"""

from __future__ import annotations

from cve_env.cli import _STAGE_BY_TOOL
from cve_env.config import STAGES, TOOL_TO_STAGE

# config's non-pipeline buckets and the cli bucket each corresponds
# to. Pipeline stages translate by simple case-folding.
_BUCKET_EQUIV: dict[str, str] = {
    "DIAGNOSTIC": "meta",
    "TERMINAL": "give_up",
}

# Tools whose stage assignment INTENTIONALLY differs between the two
# consumers, as (config stage, cli stage). Recorded, not endorsed:
# removing a divergence must also remove its entry here.
_KNOWN_DIVERGENCE: dict[str, tuple[str, str]] = {
    # Budget engine attributes compose-up cost to LAUNCH (it starts
    # the service); the human report groups it with the other
    # image-materialisation steps under acquire.
    "docker_compose_up": ("LAUNCH", "acquire"),
    # Budget engine bills ToolSearch as research spend; the report
    # hides it with the other harness meta tools.
    "ToolSearch": ("RESEARCH", "meta"),
}

# Keys present in only one table, on purpose.
_KNOWN_ONLY_IN_CONFIG: frozenset[str] = frozenset({
    # Edit costs are attributed (DIAGNOSTIC) but the report's meta
    # bucket never renders, so the cli table omits it.
    "Edit",
})
_KNOWN_ONLY_IN_CLI: frozenset[str] = frozenset({
    # Legacy lowercase alias kept for old transcripts.
    "web_fetch",
    # Glob appears in report transcripts but is not cost-attributed.
    "Glob",
})


def _cli_equivalent(config_stage: str) -> str:
    return _BUCKET_EQUIV.get(config_stage, config_stage.lower())


class TestKeySetSync:
    def test_no_unexplained_config_only_keys(self):
        only = set(TOOL_TO_STAGE) - set(_STAGE_BY_TOOL)
        assert only <= _KNOWN_ONLY_IN_CONFIG, (
            f"tools added to config.TOOL_TO_STAGE but not to "
            f"cli._STAGE_BY_TOOL: {sorted(only - _KNOWN_ONLY_IN_CONFIG)}"
        )

    def test_no_unexplained_cli_only_keys(self):
        only = set(_STAGE_BY_TOOL) - set(TOOL_TO_STAGE)
        assert only <= _KNOWN_ONLY_IN_CLI, (
            f"tools added to cli._STAGE_BY_TOOL but not to "
            f"config.TOOL_TO_STAGE: {sorted(only - _KNOWN_ONLY_IN_CLI)}"
        )

    def test_known_only_lists_stay_current(self):
        # Two-direction: an exemption for a key that now exists in
        # both tables is stale and must be dropped.
        assert _KNOWN_ONLY_IN_CONFIG <= set(TOOL_TO_STAGE)
        assert _KNOWN_ONLY_IN_CONFIG.isdisjoint(_STAGE_BY_TOOL)
        assert _KNOWN_ONLY_IN_CLI <= set(_STAGE_BY_TOOL)
        assert _KNOWN_ONLY_IN_CLI.isdisjoint(TOOL_TO_STAGE)


class TestMappingSync:
    def test_shared_tools_agree_modulo_allowlist(self):
        mismatches = {}
        for tool in set(TOOL_TO_STAGE) & set(_STAGE_BY_TOOL):
            if tool in _KNOWN_DIVERGENCE:
                continue
            want = _cli_equivalent(TOOL_TO_STAGE[tool])
            got = _STAGE_BY_TOOL[tool]
            if want != got:
                mismatches[tool] = (TOOL_TO_STAGE[tool], got)
        assert not mismatches, (
            f"stage tables drifted (config stage, cli stage): "
            f"{mismatches} — sync them or record the divergence in "
            f"_KNOWN_DIVERGENCE with its rationale"
        )

    def test_allowlisted_divergence_still_present(self):
        # Two-direction: once a divergence is fixed, its exemption
        # must go too.
        for tool, (config_stage, cli_stage) in _KNOWN_DIVERGENCE.items():
            assert TOOL_TO_STAGE.get(tool) == config_stage, (
                f"{tool}: config no longer maps to {config_stage!r} — "
                f"update or drop the _KNOWN_DIVERGENCE entry"
            )
            assert _STAGE_BY_TOOL.get(tool) == cli_stage, (
                f"{tool}: cli no longer maps to {cli_stage!r} — "
                f"update or drop the _KNOWN_DIVERGENCE entry"
            )
            assert _cli_equivalent(config_stage) != cli_stage, (
                f"{tool}: recorded divergence no longer diverges — "
                f"drop the _KNOWN_DIVERGENCE entry"
            )


class TestValueVocabulary:
    def test_config_stages_are_declared(self):
        assert set(TOOL_TO_STAGE.values()) <= set(STAGES)

    def test_cli_stages_are_pipeline_or_known_buckets(self):
        allowed = {s.lower() for s in STAGES} | set(_BUCKET_EQUIV.values())
        assert set(_STAGE_BY_TOOL.values()) <= allowed
