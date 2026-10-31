"""Unit tests for the commands.md exclusion-sentence parse.

The parity lint counts ONLY backticked names in the exclusion
sentence: a bare-word scrape used to count every English word that
collided with a command stem (the word "commands" in the sentence
itself matched commands.md), so renames and rewording flipped the
lint in confusing ways.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "check_command_metadata.py"


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location(
        "check_command_metadata", _SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_backticked_names_extracted(mod) -> None:
    sentence = (
        "internal/duplicate commands (`/commands` itself, "
        "`raptor-scan`, `raptor-fuzz`, `raptor-web`)"
    )
    assert mod._excluded_names(sentence) == {
        "commands", "raptor-scan", "raptor-fuzz", "raptor-web",
    }


def test_bare_prose_words_not_counted(mod) -> None:
    # "commands" appears as prose (and as a bare example name) — with
    # no backticks nothing may be counted, so accidental stem/word
    # collisions can't satisfy or trip the parity check.
    sentence = (
        "internal/duplicate commands (e.g., raptor-scan, raptor-fuzz, "
        "raptor-web)"
    )
    assert mod._excluded_names(sentence) == set()


def test_leading_slash_stripped(mod) -> None:
    assert mod._excluded_names("`/commands`") == {"commands"}


def test_skill_names_use_frontend_slugging(mod) -> None:
    skill = (
        mod.REPO
        / ".claude"
        / "skills"
        / "crash-analysis"
        / "gcov-coverage"
        / "SKILL.md"
    )
    assert mod._canonical_skill_name(skill) == "Code-Coverage-with-gcov"


def test_repo_sentence_matches_frontmatter_set(mod) -> None:
    """The shipped commands.md sentence must parse to exactly the
    frontmatter-excluded set (the lint's end-to-end contract)."""
    text = mod.COMMANDS_INDEX.read_text(encoding="utf-8")
    m = mod._EXCL_SENTENCE_RE.search(text)
    assert m, "exclusion sentence missing from commands.md"
    names = mod._excluded_names(m.group(0))
    flagged = set()
    for md in mod.COMMANDS_DIR.glob("*.md"):
        fm = mod._parse_frontmatter(md.read_text(encoding="utf-8"))
        if fm.get("exclude_from_listing", "").lower() == "true":
            flagged.add(md.stem)
    assert names == flagged


def test_repo_command_and_skill_names_are_disjoint(mod) -> None:
    commands = {path.stem for path in mod.COMMANDS_DIR.glob("*.md")}
    skills = {
        mod._canonical_skill_name(path)
        for path in mod.SKILLS_DIR.rglob("SKILL.md")
    }
    assert commands.isdisjoint(skills)
