"""Analysis-failure records are explicit errors, never minted verdicts.

When the LLM call raises out of ``analyze_vulnerability`` (transport
outage, auth failure), the finding's report record must carry the
canonical ``error`` field + ``status="error"`` — pre-fix the
exception path marked every scanner-severity-``error`` finding
``exploitable=True`` at score 0.5 with ``analysis=None`` and no
marker, indistinguishable from an analysed exploitable verdict.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import packages.llm_analysis.agent as agent_mod
from core.run.finding_status import derive_status
from packages.llm_analysis.agent import VulnerabilityContext


def _make_agent(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "src").mkdir(exist_ok=True)
    (repo / "src" / "auth.c").write_text(
        "".join(f"int line{i};\n" for i in range(1, 60))
    )
    mock_availability = MagicMock()
    mock_availability.external_llm = False
    mock_availability.claude_code = True
    with patch(
        "packages.llm_analysis.agent.detect_llm_availability",
        return_value=mock_availability,
    ):
        agent = agent_mod.AutonomousSecurityAgentV2(
            repo_path=repo,
            out_dir=tmp_path / "out",
            prep_only=True,
            synthesise_checkers=False,
        )
    # Replace the provider with a failing external-LLM stand-in: not a
    # ClaudeCodeProvider, raises on the analysis call.
    llm = MagicMock()
    llm.generate_structured.side_effect = RuntimeError("transport down")
    agent.llm = llm
    return agent


def _vuln(agent, level: str = "error") -> VulnerabilityContext:
    finding = {
        "finding_id": "F1",
        "rule_id": "c.lang.security.strcpy",
        "message": "strcpy into fixed buffer",
        "file": "src/auth.c",
        "startLine": 42,
        "endLine": 42,
        "snippet": "strcpy(buf, input);",
        "level": level,
        "cwe_id": "CWE-120",
        "tool": "semgrep",
        "has_dataflow": False,
        "dataflow_path": None,
        "metadata": {"name": "check_pw"},
    }
    return VulnerabilityContext(finding, agent.repo_path)


class TestAnalysisFailureRecords:
    def test_llm_exception_never_mints_exploitable(self, tmp_path):
        # Scanner severity "error" was the trigger for the old
        # heuristic: a transport failure marked the finding
        # exploitable at 0.5.
        agent = _make_agent(tmp_path)
        vuln = _vuln(agent, level="error")

        assert agent.analyze_vulnerability(vuln) is False
        assert vuln.exploitable is False
        assert vuln.exploitability_score == 0.0

    def test_failure_record_is_explicitly_marked(self, tmp_path):
        agent = _make_agent(tmp_path)
        vuln = _vuln(agent, level="error")
        agent.analyze_vulnerability(vuln)

        record = vuln.to_dict()
        assert "transport down" in record["error"]
        assert record["status"] == "error"
        assert record["exploitable"] is False
        # The status helpers classify it as a crashed analysis, not
        # an analysed (or skipped) finding.
        assert derive_status(record) == "error"

    def test_happy_path_records_carry_no_error_keys(self, tmp_path):
        agent = _make_agent(tmp_path)
        vuln = _vuln(agent)
        record = vuln.to_dict()
        assert "error" not in record
        assert "status" not in record
