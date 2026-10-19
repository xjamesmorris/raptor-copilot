import os
from pathlib import Path
from packages.sca.agent import _find_sca_agent


def test_find_sca_agent_prefers_env_override(tmp_path, monkeypatch):
    # If RAPTOR_SCA_AGENT env points to a non-existent file, it should return None
    monkeypatch.setenv("RAPTOR_SCA_AGENT", str(tmp_path / "nope.py"))
    res = _find_sca_agent()
    assert res is None


def test_find_sca_agent_default_is_file(monkeypatch):
    # Default behaviour should return the resolved path to this file
    # Ensure RAPTOR_SCA_AGENT unset
    monkeypatch.delenv("RAPTOR_SCA_AGENT", raising=False)
    p = _find_sca_agent()
    assert p is not None
    assert p.exists()
    assert p.name == "agent.py"
