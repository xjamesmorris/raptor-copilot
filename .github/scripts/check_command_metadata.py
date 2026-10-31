#!/usr/bin/env python3
"""Lint slash-command metadata: every ``.claude/commands/*.md`` must
carry a parseable ``dispatch:`` frontmatter field, and any
``exclude_from_listing: true`` flag must match the hardcoded exclusion
list in ``commands.md``.

Failing modes:

* missing ``dispatch:`` — Claude would have to infer the dispatch
  from the .md body, defeating the "literal dispatch" rule.
* unknown dispatch shape — only ``skill`` and command-lines beginning
  with ``libexec/``, ``bin/``, ``python3 raptor.py``, or ``bash`` are
  accepted today; new shapes need explicit allowlisting here.
* missing dispatch target — for executable-form dispatches, the
  first-token path must exist on disk (catches typo'd or renamed
  libexec paths at PR time, not at operator-call time).
* exclusion drift — anything with ``exclude_from_listing: true``
  must also appear in commands.md's hardcoded "Exclude internal/
  duplicate commands" list; and vice-versa. Single source of truth.
* discovery collision — command names must be disjoint from canonical
  project-skill names because both supported frontends load the two
  compatibility surfaces into one prompt/skill namespace.

Run::

    python3 .github/scripts/check_command_metadata.py

Exits 0 on clean, non-zero with a per-violation report otherwise.
"""

from __future__ import annotations

import re
import shlex
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
COMMANDS_DIR = REPO / ".claude" / "commands"
COMMANDS_INDEX = COMMANDS_DIR / "commands.md"
SKILLS_DIR = REPO / ".claude" / "skills"

# Dispatch tokens we accept. ``skill`` means "no single libexec — see
# the body of the .md for multi-step workflow." Everything else must
# resolve to a file on disk that the operator's machine can run.
_ACCEPTED_DISPATCH_PREFIXES = (
    "libexec/",
    "bin/",
    "python3 raptor.py",
    "bash ",
)

# The commands.md sentence that owns the documented exclusion list.
_EXCL_SENTENCE_RE = re.compile(
    r"internal/duplicate commands.*?(?=\.\s|\n\n)",
    re.IGNORECASE | re.DOTALL,
)

# A backticked command name inside that sentence: `raptor-scan` or
# `/commands` (leading slash stripped to match .md stems).
_BACKTICKED_NAME_RE = re.compile(r"`/?([\w][\w-]*)`")


def _excluded_names(sentence: str) -> set[str]:
    """Names documented as excluded: backticked tokens only."""
    return set(_BACKTICKED_NAME_RE.findall(sentence))


def _parse_frontmatter(text: str) -> dict[str, str]:
    """Return the YAML-ish frontmatter as a flat dict. The repo uses
    a tiny subset (string scalars only, one key per line) so a real
    YAML parser would be overkill — and would add a CI dependency
    we don't have today."""
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---\n", 4)
    if end == -1:
        return {}
    body = text[4:end]
    out: dict[str, str] = {}
    for line in body.split("\n"):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        out[key.strip()] = val.strip()
    return out


def _canonical_skill_name(path: Path) -> str:
    """Return the frontend-visible skill name for one ``SKILL.md``."""
    metadata = _parse_frontmatter(path.read_text(encoding="utf-8"))
    raw_name = metadata.get("name", path.parent.name).strip()
    if (
        len(raw_name) >= 2
        and raw_name[0] == raw_name[-1]
        and raw_name[0] in {"'", '"'}
    ):
        raw_name = raw_name[1:-1]
    return re.sub(r"\s+", "-", raw_name)


def _check_dispatch(name: str, dispatch: str) -> list[str]:
    errs: list[str] = []
    if dispatch == "skill":
        return errs
    if not any(dispatch.startswith(p) for p in _ACCEPTED_DISPATCH_PREFIXES):
        errs.append(
            f"/{name}: dispatch starts with an unrecognised prefix "
            f"({dispatch!r}); allowlist new shapes in "
            f"check_command_metadata.py if intentional"
        )
        return errs
    # First token of the dispatch is the binary / script — must exist.
    # ``python3 raptor.py <mode>`` is special: raptor.py must exist.
    # ``bash <path>`` similarly.
    tokens = shlex.split(dispatch)
    if not tokens:
        errs.append(f"/{name}: empty dispatch after split")
        return errs
    if tokens[0] in ("python3", "bash"):
        if len(tokens) < 2:
            errs.append(f"/{name}: dispatch {dispatch!r} missing script path")
            return errs
        target = REPO / tokens[1]
    else:
        target = REPO / tokens[0]
    if not target.exists():
        errs.append(
            f"/{name}: dispatch target {target.relative_to(REPO)} "
            f"does not exist (renamed or typo'd?)"
        )
    return errs


def main() -> int:
    if not COMMANDS_DIR.is_dir():
        print(f"FATAL: {COMMANDS_DIR} not a directory", file=sys.stderr)
        return 2
    md_files = sorted(COMMANDS_DIR.glob("*.md"))
    if not md_files:
        print(f"FATAL: no .md files under {COMMANDS_DIR}", file=sys.stderr)
        return 2
    md_names = {path.stem for path in md_files}

    errs: list[str] = []
    excluded_via_frontmatter: set[str] = set()
    for md in md_files:
        name = md.stem
        fm = _parse_frontmatter(md.read_text(encoding="utf-8"))
        dispatch = fm.get("dispatch")
        if not dispatch:
            errs.append(
                f"/{name}: missing ``dispatch:`` frontmatter field. Add either "
                f"a command-line (libexec/... | bin/... | python3 raptor.py "
                f"<mode> | bash ...) or the literal ``skill`` for multi-step "
                f"workflows the body owns."
            )
            continue
        errs.extend(_check_dispatch(name, dispatch))
        if fm.get("exclude_from_listing", "").lower() == "true":
            excluded_via_frontmatter.add(name)

    # Parity: commands.md's hardcoded exclusion list must match the
    # frontmatter-flagged set. Only BACKTICKED names in the exclusion
    # sentence count (`` `raptor-scan` `` / `` `/commands` ``): a bare-
    # word scrape counted every English word that happened to collide
    # with a command stem (the word "commands" in the sentence itself
    # matched commands.md), so renaming a command to a common word or
    # rewording the sentence flipped the lint in confusing ways.
    commands_md = COMMANDS_INDEX.read_text(encoding="utf-8")
    m = _EXCL_SENTENCE_RE.search(commands_md)
    if not m:
        errs.append(
            "commands.md: could not locate the 'Exclude internal/duplicate "
            "commands' sentence — has the wording changed? Update this "
            "lint or restore the sentence."
        )
    else:
        excluded_in_index = _excluded_names(m.group(0))
        if not excluded_in_index:
            errs.append(
                "commands.md: the exclusion sentence names no backticked "
                "commands — list each excluded command as `name` (or "
                "`/name`); bare prose words are not counted."
            )
        # Only names that correspond to .md files can be parity-checked;
        # a mistyped name surfaces as the frontmatter side's
        # "not listed in commands.md's exclude sentence" error.
        excluded_in_index = excluded_in_index & md_names

        missing_in_md = excluded_in_index - excluded_via_frontmatter
        missing_in_index = excluded_via_frontmatter - excluded_in_index
        errs.extend(f"/{n}: listed as excluded in commands.md but missing "
                f"``exclude_from_listing: true`` frontmatter" for n in sorted(missing_in_md))
        errs.extend(f"/{n}: has ``exclude_from_listing: true`` frontmatter but "
                f"not listed in commands.md's exclude sentence" for n in sorted(missing_in_index))

    # Claude and Copilot both load `.claude/commands` alongside project
    # skills. Copilot exposes both through `skill list --json`, and a
    # same-name skill shadows the command rather than preserving two rows.
    # Keep the namespaces disjoint instead of relying on host precedence.
    skill_sources: dict[str, list[Path]] = {}
    if not SKILLS_DIR.is_dir():
        errs.append(f"{SKILLS_DIR.relative_to(REPO)}: skill directory missing")
    else:
        for skill in sorted(SKILLS_DIR.rglob("SKILL.md")):
            name = _canonical_skill_name(skill)
            skill_sources.setdefault(name, []).append(skill)
        for name, paths in sorted(skill_sources.items()):
            if len(paths) > 1:
                members = ", ".join(
                    path.relative_to(REPO).as_posix() for path in paths
                )
                errs.append(f"duplicate skill name {name!r}: {members}")
            if name in md_names:
                members = ", ".join(
                    path.relative_to(REPO).as_posix() for path in paths
                )
                errs.append(
                    f"/{name}: command name collides with project skill(s): "
                    f"{members}"
                )

    if errs:
        print("Command-metadata lint failed:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"OK: {len(md_files)} command .md files lint-clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
