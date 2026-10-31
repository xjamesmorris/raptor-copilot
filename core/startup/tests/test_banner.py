"""Tests for core.startup.banner version injection.

The banner asset carries a ``__VERSION__`` placeholder; ``read_logo`` injects
the live version at render time and re-pads the box so the border stays
aligned regardless of the version string's length (a clone's git-describe
string is much longer than a clean release number)."""

import pytest

from core.startup import banner, doctor
from core.startup import init as startup_init


def _version_line(text: str) -> str:
    return next(ln for ln in text.splitlines() if "Based on " in ln)


def test_injects_version_with_leading_v_and_preserves_box_width():
    line = _version_line(banner.read_logo("3.0.0-1786-g7fcf38ea"))
    assert "v3.0.0-1786-g7fcf38ea" in line   # leading 'v' added
    assert "__VERSION__" not in line          # placeholder consumed
    assert line.startswith("║") and line.endswith("║")
    assert len(line) == 77                    # box width unchanged


def test_clean_release_number_keeps_box_width():
    line = _version_line(banner.read_logo("3.0.0"))
    assert "v3.0.0" in line
    assert len(line) == 77


def test_does_not_double_the_v_prefix():
    line = _version_line(banner.read_logo("v3.0.0"))
    assert "vv" not in line
    assert "v3.0.0" in line


def test_overlong_version_still_closes_the_box():
    # Pathologically long string: box can't keep width 77 but must stay closed.
    line = _version_line(banner.read_logo("9" * 60))
    assert line.endswith("║")


def test_empty_version_leaves_placeholder_untouched():
    line = _version_line(banner.read_logo(""))
    assert "__VERSION__" in line


def test_based_on_attribution_remains_claude_code():
    line = _version_line(banner.read_logo("3.1.0"))
    assert "Based on Claude Code - v3.1.0" in line
    assert "GitHub Copilot CLI" not in line
    assert len(line) == 77


@pytest.fixture
def stub_startup_checks(monkeypatch):
    results = {
        "check_tools": ([], [], set()),
        "check_tool_updates": set(),
        "check_llm": (["   llm: no external LLM configured"], []),
        "check_env": (["Python 3.14", "out/ ready"], []),
        "check_lang": ("  lang: tree-sitter", []),
        "check_active_project": None,
    }
    for name, result in results.items():
        monkeypatch.setattr(
            startup_init, name, lambda *_args, _result=result: _result,
        )


@pytest.mark.parametrize("frontend", ("copilot", None))
def test_startup_frontend_line_precedes_llm(
    stub_startup_checks, monkeypatch, tmp_path, capsys, frontend,
):
    output_file = tmp_path / "startup-output"
    monkeypatch.setattr(startup_init, "OUTPUT_FILE", output_file)
    if frontend:
        monkeypatch.setenv("RAPTOR_FRONTEND", frontend)
    else:
        monkeypatch.delenv("RAPTOR_FRONTEND", raising=False)
    monkeypatch.setenv("RAPTOR_FRONTEND_MODEL", "gpt-6-astra")

    startup_init.main()

    output = capsys.readouterr().out
    assert output == output_file.read_text(encoding="utf-8") + "\n"
    lines = output.splitlines()
    env_line = next(line for line in lines if line.startswith("   env:"))
    assert "frontend" not in env_line
    assert "gpt-6-astra" not in env_line
    if frontend:
        frontend_line = "frontend: GitHub Copilot CLI (model: gpt-6-astra)"
        assert lines.count(frontend_line) == 1
        assert lines[lines.index(frontend_line) + 1] == (
            "   llm: no external LLM configured"
        )
    else:
        assert not any(line.startswith("frontend:") for line in lines)


def test_doctor_retains_frontend_fact(stub_startup_checks, monkeypatch):
    monkeypatch.setenv("RAPTOR_FRONTEND", "copilot")
    monkeypatch.setenv("RAPTOR_FRONTEND_MODEL", "gpt-6-astra")
    monkeypatch.setattr(doctor, "_module_dep_warnings", lambda: [])
    monkeypatch.setattr(doctor, "_imported_annotation_advisories", lambda: [])
    monkeypatch.setattr(doctor, "_frontend_readiness", lambda: ([], []))
    monkeypatch.setattr(
        "core.startup.aws_imds.aws_imds_advisories", lambda: [],
    )

    text, failures, warnings = doctor._render(*doctor._gather(), verbose=True)

    assert "frontend GitHub Copilot CLI (model: gpt-6-astra)" in text
    assert failures == warnings == 0


class TestToolUpdateFootnote:
    _TOOL_RESULTS = [
        ("afl++", True),
        ("semgrep 1.79.0", True),
        ("z3", True),
    ]

    def test_asterisk_appended_to_updatable_tool(self):
        out = banner.format_banner(
            "", "quote", self._TOOL_RESULTS, [], [], [], [], [],
            tool_updates={"semgrep"},
        )
        assert "semgrep 1.79.0*" in out

    def test_no_asterisk_when_no_updates(self):
        out = banner.format_banner(
            "", "quote", self._TOOL_RESULTS, [], [], [], [], [],
            tool_updates=set(),
        )
        assert "semgrep 1.79.0 ✓" in out
        assert "*" not in out

    def test_non_updatable_tool_unchanged(self):
        out = banner.format_banner(
            "", "quote", self._TOOL_RESULTS, [], [], [], [], [],
            tool_updates={"semgrep"},
        )
        assert "afl++ ✓" in out
        assert "z3 ✓" in out
