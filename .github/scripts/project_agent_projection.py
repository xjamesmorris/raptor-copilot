#!/usr/bin/env python3
"""Generate and verify the Copilot custom-agent projection.

Claude Code loads RAPTOR's authoritative agents from the ``raptor-agents``
plugin. Those files retain ``model: inherit`` so Claude subagents follow the
session model even when ambient model variables are present. Copilot CLI does
not accept that agent-frontmatter value, so ``.github/agents`` is a mechanical
projection with only that field removed.

Run ``--write`` after editing an authoritative agent. The default and
``--json`` modes are side-effect-free drift checks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import runpy
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
AUTHORITATIVE_DIR = REPO / "plugins" / "agents" / "agents"
COPILOT_DIR = REPO / ".github" / "agents"
PLUGIN_HOOKS = REPO / "plugins" / "agents" / "hooks" / "hooks.json"
HOOK_DISPATCHER = (
    REPO / "plugins" / "agents" / "libexec" / "raptor-agent-hook-dispatch"
)
_MODEL_LINE_RE = re.compile(r"^model:\s*inherit\s*$")
_PROTECTED_AGENT_TYPES = frozenset(
    {
        "raptor-agents:crash-report-fetcher",
        "raptor-agents:oss-investigator-gh-archive-agent",
        "raptor-agents:oss-investigator-github-agent",
        "raptor-agents:oss-investigator-ioc-extractor-agent",
        "raptor-agents:oss-investigator-wayback-agent",
    }
)


@dataclass(frozen=True)
class AgentDocument:
    """Parsed custom-agent markdown."""

    agent_id: str
    path: Path
    metadata: dict[str, Any]
    instructions: str
    text: str


@dataclass(frozen=True)
class ProjectionReport:
    """One deterministic source/projection comparison."""

    agents: tuple[dict[str, object], ...]
    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "authoritative_dir": AUTHORITATIVE_DIR.relative_to(REPO).as_posix(),
            "copilot_dir": COPILOT_DIR.relative_to(REPO).as_posix(),
            "agents": list(self.agents),
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


def _split_frontmatter(path: Path, text: str) -> tuple[str, str]:
    if not text.startswith("---\n"):
        raise ValueError(f"{path}: missing YAML frontmatter")
    end = text.find("\n---\n", 4)
    if end == -1:
        raise ValueError(f"{path}: unterminated YAML frontmatter")
    return text[4:end], text[end + len("\n---\n") :]


def _load_document(path: Path) -> AgentDocument:
    text = path.read_text(encoding="utf-8")
    frontmatter, instructions = _split_frontmatter(path, text)
    try:
        metadata = yaml.safe_load(frontmatter)
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: malformed YAML frontmatter: {exc}") from exc
    if not isinstance(metadata, dict):
        raise ValueError(f"{path}: frontmatter must be a mapping")

    name = metadata.get("name")
    description = metadata.get("description")
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"{path}: name must be a non-empty string")
    if not isinstance(description, str) or not description.strip():
        raise ValueError(f"{path}: description must be a non-empty string")
    skills = metadata.get("skills")
    if skills is not None and (
        not isinstance(skills, list)
        or not all(isinstance(item, str) and item.strip() for item in skills)
    ):
        raise ValueError(
            f"{path}: skills must be a YAML array of non-empty names"
        )
    if not instructions.strip():
        raise ValueError(f"{path}: instructions must not be empty")
    return AgentDocument(
        agent_id=path.stem,
        path=path,
        metadata=metadata,
        instructions=instructions,
        text=text,
    )


def _load_directory(path: Path) -> tuple[dict[str, AgentDocument], list[str]]:
    documents: dict[str, AgentDocument] = {}
    errors: list[str] = []
    if not path.is_dir():
        return {}, [f"{path.relative_to(REPO)}: directory missing"]
    for agent_path in sorted(path.glob("*.md")):
        try:
            document = _load_document(agent_path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        documents[document.agent_id] = document

    by_name: dict[str, list[str]] = {}
    for document in documents.values():
        name = str(document.metadata["name"])
        by_name.setdefault(name, []).append(document.agent_id)
    for name, agent_ids in sorted(by_name.items()):
        if len(agent_ids) > 1:
            errors.append(
                f"{path.relative_to(REPO)}: duplicate agent name {name!r}: "
                + ", ".join(agent_ids)
            )
    return documents, errors


def project_agent_text(document: AgentDocument) -> str:
    """Remove only Claude's explicit model-inheritance field."""
    if document.metadata.get("model") != "inherit":
        raise ValueError(
            f"{document.path}: authoritative agent must declare model: inherit"
        )
    frontmatter, instructions = _split_frontmatter(document.path, document.text)
    lines = frontmatter.splitlines(keepends=True)
    model_indexes = [
        index
        for index, line in enumerate(lines)
        if _MODEL_LINE_RE.fullmatch(line.rstrip("\r\n"))
    ]
    if len(model_indexes) != 1:
        raise ValueError(
            f"{document.path}: expected one literal model: inherit line"
        )
    del lines[model_indexes[0]]
    projected_frontmatter = "".join(lines).rstrip("\r\n")
    return "---\n" + projected_frontmatter + "\n---\n" + instructions


def write_projection() -> None:
    """Regenerate ``.github/agents`` from the authoritative plugin."""
    source, errors = _load_directory(AUTHORITATIVE_DIR)
    if errors:
        raise ValueError("\n".join(errors))
    COPILOT_DIR.mkdir(parents=True, exist_ok=True)
    expected = {f"{agent_id}.md" for agent_id in source}
    for stale in sorted(COPILOT_DIR.glob("*.md")):
        if stale.name not in expected:
            stale.unlink()
    for agent_id, document in sorted(source.items()):
        (COPILOT_DIR / f"{agent_id}.md").write_text(
            project_agent_text(document),
            encoding="utf-8",
        )


def _check_plugin_hook_policy(
    source: dict[str, AgentDocument],
) -> list[str]:
    """Validate the supported plugin-level identity hook boundary."""
    errors: list[str] = []
    for document in source.values():
        if "hooks" in document.metadata:
            errors.append(
                f"{document.path.relative_to(REPO)}: plugin agent "
                "frontmatter must not carry ignored hooks"
            )
        scoped_name = f"raptor-agents:{document.metadata['name']}"
        if scoped_name in _PROTECTED_AGENT_TYPES:
            normalized = " ".join(document.instructions.split())
            if (
                "Copilot custom agents do not execute Claude plugin hooks"
                not in normalized
            ):
                errors.append(
                    f"{document.path.relative_to(REPO)}: protected agent "
                    "must document the Copilot hook limitation"
                )

    try:
        hooks = json.loads(PLUGIN_HOOKS.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{PLUGIN_HOOKS.relative_to(REPO)}: invalid hooks JSON: {exc}"]
    if not isinstance(hooks, dict):
        return [
            f"{PLUGIN_HOOKS.relative_to(REPO)}: hooks JSON must be an object"
        ]
    expected_handler = {
        "type": "command",
        "command": (
            "${CLAUDE_PLUGIN_ROOT}/libexec/raptor-agent-hook-dispatch"
        ),
        "args": [],
        "timeout": 10,
        "onFailure": "block",
    }
    expected_pretool = [
        {
            "matcher": "WebFetch|Bash|Write|Edit",
            "hooks": [expected_handler],
        }
    ]
    hook_map = hooks.get("hooks")
    if (
        not isinstance(hook_map, dict)
        or hook_map.get("PreToolUse") != expected_pretool
    ):
        errors.append(
            f"{PLUGIN_HOOKS.relative_to(REPO)}: PreToolUse dispatcher "
            "configuration drift"
        )

    if not HOOK_DISPATCHER.is_file():
        errors.append(
            f"{HOOK_DISPATCHER.relative_to(REPO)}: dispatcher missing"
        )
        return errors
    if not os.access(HOOK_DISPATCHER, os.X_OK):
        errors.append(
            f"{HOOK_DISPATCHER.relative_to(REPO)}: dispatcher is not executable"
        )
    namespace = runpy.run_path(str(HOOK_DISPATCHER))
    known = set(namespace.get("_KNOWN_RAPTOR_AGENTS", ()))
    policies = set(namespace.get("_POLICIES", {}))
    expected_known = {
        f"raptor-agents:{document.metadata['name']}"
        for document in source.values()
    }
    if known != expected_known:
        errors.append(
            "plugin dispatcher known-agent registry differs from "
            "authoritative frontmatter names"
        )
    if policies != _PROTECTED_AGENT_TYPES:
        errors.append(
            "plugin dispatcher protected-agent policy set differs from "
            "the five reviewed security-sensitive agents"
        )
    return errors


def build_report() -> ProjectionReport:
    """Return semantic and byte-level parity diagnostics."""
    source, source_errors = _load_directory(AUTHORITATIVE_DIR)
    projected, projected_errors = _load_directory(COPILOT_DIR)
    errors = [
        *source_errors,
        *projected_errors,
        *_check_plugin_hook_policy(source),
    ]
    warnings: list[str] = []

    source_ids = set(source)
    projected_ids = set(projected)
    for agent_id in sorted(source_ids - projected_ids):
        errors.append(f"missing Copilot projection: {agent_id}.md")
    for agent_id in sorted(projected_ids - source_ids):
        errors.append(f"unexpected Copilot projection: {agent_id}.md")

    rows: list[dict[str, object]] = []
    for agent_id in sorted(source_ids & projected_ids):
        authoritative = source[agent_id]
        copilot = projected[agent_id]
        try:
            expected_text = project_agent_text(authoritative)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if copilot.text != expected_text:
            errors.append(
                f"{copilot.path.relative_to(REPO)}: generated content drift"
            )

        source_metadata = dict(authoritative.metadata)
        projected_metadata = dict(copilot.metadata)
        source_model = source_metadata.pop("model", None)
        projected_model = projected_metadata.pop("model", None)
        if source_model != "inherit":
            errors.append(
                f"{authoritative.path.relative_to(REPO)}: "
                "Claude agent must declare model: inherit"
            )
        if projected_model is not None:
            warnings.append(
                f"{copilot.path.relative_to(REPO)}: Copilot projection "
                "must omit model"
            )
        if source_metadata != projected_metadata:
            errors.append(
                f"{copilot.path.relative_to(REPO)}: metadata differs beyond model"
            )
        if authoritative.instructions != copilot.instructions:
            errors.append(
                f"{copilot.path.relative_to(REPO)}: instructions differ"
            )

        rows.append(
            {
                "id": agent_id,
                "name": authoritative.metadata["name"],
                "description": authoritative.metadata["description"],
                "tools": authoritative.metadata.get("tools"),
                "skills": authoritative.metadata.get("skills", []),
                "instructions_sha256": hashlib.sha256(
                    authoritative.instructions.encode("utf-8")
                ).hexdigest(),
                "authoritative_path": authoritative.path.relative_to(
                    REPO
                ).as_posix(),
                "copilot_path": copilot.path.relative_to(REPO).as_posix(),
            }
        )
    return ProjectionReport(
        agents=tuple(rows),
        errors=tuple(sorted(set(errors))),
        warnings=tuple(sorted(set(warnings))),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="regenerate the committed Copilot projection before checking",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the side-effect-free inventory report as JSON",
    )
    args = parser.parse_args(argv)

    if args.write:
        try:
            write_projection()
        except ValueError as exc:
            print(f"Agent projection generation failed:\n{exc}", file=sys.stderr)
            return 1
    report = build_report()
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    elif report.errors or report.warnings:
        print("Agent projection check failed:", file=sys.stderr)
        for error in report.errors:
            print(f"  - error: {error}", file=sys.stderr)
        for warning in report.warnings:
            print(f"  - warning: {warning}", file=sys.stderr)
    else:
        print(f"OK: {len(report.agents)} projected agents parity-clean.")
    return 1 if report.errors or report.warnings else 0


if __name__ == "__main__":
    raise SystemExit(main())
