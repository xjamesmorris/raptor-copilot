"""Source-derived feature-ledger fixtures for frontend parity tests.

The ledger records discovery separately from fake-process and live-runtime
validation. It preserves every source asset and reports namespace collisions
instead of silently deduplicating them.
"""

from __future__ import annotations

import importlib.util
import re
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import ModuleType
from typing import cast

import yaml


class FeatureAssetKind(str, Enum):
    """Canonical feature surfaces represented in the ledger."""

    COMMAND = "command"
    SKILL = "skill"
    AGENT = "agent"
    HOST_BUILTIN = "host_builtin"


class FeatureEvidence(str, Enum):
    """Evidence source for one ledger row."""

    SOURCE_METADATA = "source_metadata"
    NON_INFERENCE_DISCOVERY = "non_inference_discovery"
    FAKE_PROCESS = "fake_process"
    LIVE_RUNTIME = "live_runtime"


class FeatureStatus(str, Enum):
    """Validation status kept separate from asset discovery."""

    DISCOVERED = "discovered"
    CANDIDATE_UNVERIFIED = "candidate_unverified"
    FAKE_VERIFIED = "fake_verified"
    LIVE_VERIFIED = "live_verified"
    BLOCKED = "blocked"


class FeatureCollisionClass(str, Enum):
    """Namespace collision classes relevant to host adapters."""

    COMMAND_SKILL = "command_vs_skill"
    COMMAND_BUILTIN = "command_vs_builtin"
    SKILL_BUILTIN = "skill_vs_builtin"
    DUPLICATE_COMMAND = "duplicate_command"
    DUPLICATE_SKILL = "duplicate_skill"
    DUPLICATE_AGENT = "duplicate_agent"
    DUPLICATE_BUILTIN = "duplicate_builtin"


class FrontendAdapter(str, Enum):
    """Decision-layer discovery adapters exercised by parity tests."""

    CLAUDE = "claude"
    COPILOT = "copilot"


_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _validate_name(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not _NAME_RE.fullmatch(value):
        raise ValueError(f"{field_name} is not a canonical asset name")


def _validate_text(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value or not value.isprintable():
        raise ValueError(f"{field_name} must be non-empty printable text")


@dataclass(frozen=True)
class HostBuiltin:
    """One externally discovered host builtin supplied by the caller."""

    name: str
    behavior: str
    evidence_source: str

    def __post_init__(self) -> None:
        _validate_name(self.name, "name")
        _validate_text(self.behavior, "behavior")
        _validate_text(self.evidence_source, "evidence_source")


@dataclass(frozen=True)
class FeatureLedgerEntry:
    """One machine-readable parity row."""

    canonical_name: str
    asset_kind: FeatureAssetKind
    source_asset: str
    behavior: str
    capability_requirement: str
    host_mapping: str
    evidence: FeatureEvidence
    status: FeatureStatus
    operator_exception: str | None = None
    metadata: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _validate_name(self.canonical_name, "canonical_name")
        for field_name in (
            "source_asset",
            "behavior",
            "capability_requirement",
            "host_mapping",
        ):
            _validate_text(getattr(self, field_name), field_name)
        if self.operator_exception is not None:
            _validate_text(self.operator_exception, "operator_exception")
        if self.status is FeatureStatus.LIVE_VERIFIED:
            if self.evidence is not FeatureEvidence.LIVE_RUNTIME:
                raise ValueError("live_verified requires live_runtime evidence")
        if self.evidence is FeatureEvidence.NON_INFERENCE_DISCOVERY:
            if self.status is FeatureStatus.LIVE_VERIFIED:
                raise ValueError("non-inference discovery cannot prove live validation")


@dataclass(frozen=True)
class FeatureCollision:
    """One preserved collision across source or host namespaces."""

    canonical_name: str
    collision_class: FeatureCollisionClass
    members: tuple[str, ...]


@dataclass(frozen=True)
class FeatureLedger:
    """Immutable source-derived ledger and collision inventory."""

    entries: tuple[FeatureLedgerEntry, ...]
    collisions: tuple[FeatureCollision, ...]

    def entries_for(self, canonical_name: str) -> tuple[FeatureLedgerEntry, ...]:
        return tuple(
            entry for entry in self.entries if entry.canonical_name == canonical_name
        )

    def to_dict(self) -> dict[str, object]:
        """Return a fresh JSON-compatible representation."""
        entry_rows: list[dict[str, object]] = []
        for entry in self.entries:
            row: dict[str, object] = {
                "canonical_name": entry.canonical_name,
                "asset_kind": entry.asset_kind.value,
                "source_asset": entry.source_asset,
                "behavior": entry.behavior,
                "capability_requirement": entry.capability_requirement,
                "host_mapping": entry.host_mapping,
                "evidence": entry.evidence.value,
                "status": entry.status.value,
            }
            row["operator_exception"] = entry.operator_exception
            row["metadata"] = dict(entry.metadata)
            entry_rows.append(row)
        return {
            "schema_version": 1,
            "entries": entry_rows,
            "collisions": [
                {
                    "canonical_name": collision.canonical_name,
                    "collision_class": collision.collision_class.value,
                    "members": list(collision.members),
                }
                for collision in self.collisions
            ],
        }


@dataclass(frozen=True)
class FrontendInventoryEntry:
    """One source asset projected through a frontend discovery adapter."""

    canonical_name: str
    asset_kind: FeatureAssetKind
    source_asset: str
    surface: str
    enabled: bool


@dataclass(frozen=True)
class FrontendDuplicate:
    """A duplicate name on one frontend-visible discovery surface."""

    surface: str
    canonical_name: str
    members: tuple[str, ...]


@dataclass(frozen=True)
class FrontendInventory:
    """Deterministic projection of repository assets into one frontend."""

    adapter: FrontendAdapter
    entries: tuple[FrontendInventoryEntry, ...]
    warnings: tuple[str, ...] = ()

    @property
    def duplicates(self) -> tuple[FrontendDuplicate, ...]:
        by_key: dict[tuple[str, str], list[FrontendInventoryEntry]] = defaultdict(
            list
        )
        for entry in self.entries:
            by_key[(entry.surface, entry.canonical_name)].append(entry)
        return tuple(
            FrontendDuplicate(
                surface=surface,
                canonical_name=name,
                members=tuple(sorted(item.source_asset for item in members)),
            )
            for (surface, name), members in sorted(by_key.items())
            if len(members) > 1
        )

    def to_dict(self) -> dict[str, object]:
        """Return a stable JSON-compatible frontend inventory."""
        return {
            "adapter": self.adapter.value,
            "entries": [
                {
                    "canonical_name": entry.canonical_name,
                    "asset_kind": entry.asset_kind.value,
                    "source_asset": entry.source_asset,
                    "surface": entry.surface,
                    "enabled": entry.enabled,
                }
                for entry in self.entries
            ],
            "warnings": list(self.warnings),
        }


def _load_frontmatter_parser(
    repo_root: Path,
) -> Callable[[str], dict[str, str]]:
    checker = repo_root / ".github" / "scripts" / "check_command_metadata.py"
    if not checker.is_file():
        raise FileNotFoundError("canonical command metadata checker is missing")
    spec = importlib.util.spec_from_file_location(
        "_raptor_command_metadata_fixture",
        checker,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load canonical command metadata checker")
    module = importlib.util.module_from_spec(spec)
    assert isinstance(module, ModuleType)
    spec.loader.exec_module(module)
    parser = getattr(module, "_parse_frontmatter", None)
    if not callable(parser):
        raise RuntimeError("canonical command metadata parser is unavailable")
    return cast(Callable[[str], dict[str, str]], parser)


def _load_yaml_frontmatter(path: Path) -> dict[str, object]:
    """Load strict YAML frontmatter for skills and custom agents."""
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError(f"{path}: missing YAML frontmatter")
    end = text.find("\n---\n", 4)
    if end == -1:
        raise ValueError(f"{path}: unterminated YAML frontmatter")
    try:
        loaded = yaml.safe_load(text[4:end])
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: malformed YAML frontmatter: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError(f"{path}: YAML frontmatter must be a mapping")
    return cast(dict[str, object], loaded)


def _canonical_skill_name(path: Path, metadata: Mapping[str, object]) -> str:
    raw_name = metadata.get("name", path.parent.name)
    if not isinstance(raw_name, str) or not raw_name.strip():
        raise ValueError(f"{path}: skill name must be a non-empty string")
    name = re.sub(r"\s+", "-", raw_name.strip())
    _validate_name(name, f"{path}: skill name")
    return name


def _canonical_agent_name(path: Path, metadata: Mapping[str, object]) -> str:
    raw_name = metadata.get("name", path.stem)
    if not isinstance(raw_name, str) or not raw_name.strip():
        raise ValueError(f"{path}: agent name must be a non-empty string")
    name = raw_name.strip()
    _validate_name(name, f"{path}: agent name")
    return name


def _validate_description(path: Path, metadata: Mapping[str, object]) -> None:
    description = metadata.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ValueError(f"{path}: description must be a non-empty string")


def _validate_agent_metadata(path: Path, metadata: Mapping[str, object]) -> None:
    _validate_description(path, metadata)
    skills = metadata.get("skills")
    if skills is not None:
        if not isinstance(skills, list) or not all(
            isinstance(item, str) and item.strip() for item in skills
        ):
            raise ValueError(
                f"{path}: agent skills must be a YAML array of non-empty names"
            )
        if len(skills) != len(set(skills)):
            raise ValueError(f"{path}: agent skills contain duplicate names")
    if metadata.get("model") != "inherit":
        raise ValueError(
            f"{path}: authoritative Claude agent must declare model: inherit"
        )


def _flat_metadata(metadata: Mapping[str, object]) -> dict[str, str]:
    """Keep adapter-relevant metadata in the ledger's scalar form."""
    out: dict[str, str] = {}
    keys = {
        "description",
        "disable-model-invocation",
        "dispatch",
        "enabled",
        "exclude_from_listing",
        "model",
        "name",
        "skills",
        "user-invocable",
    }
    for key in keys:
        if key not in metadata:
            continue
        value = metadata[key]
        if isinstance(value, bool):
            out[key] = "true" if value else "false"
        elif isinstance(value, str):
            out[key] = value
        elif key == "skills" and isinstance(value, list):
            out[key] = ",".join(cast(list[str], value))
    return out


def _source_entry(
    *,
    repo_root: Path,
    path: Path,
    kind: FeatureAssetKind,
    canonical_name: str,
    behavior: str,
    capability_requirement: str,
    host_mapping: str,
    metadata: Mapping[str, str],
) -> FeatureLedgerEntry:
    operator_exception = None
    if metadata.get("exclude_from_listing", "").lower() == "true":
        operator_exception = "excluded_from_listing"
    kept_metadata = tuple(
        sorted(
            (key, value)
            for key, value in metadata.items()
            if key
            in {
                "description",
                "disable-model-invocation",
                "dispatch",
                "enabled",
                "exclude_from_listing",
                "model",
                "name",
                "skills",
                "user-invocable",
            }
        )
    )
    return FeatureLedgerEntry(
        canonical_name=canonical_name,
        asset_kind=kind,
        source_asset=path.relative_to(repo_root).as_posix(),
        behavior=behavior,
        capability_requirement=capability_requirement,
        host_mapping=host_mapping,
        evidence=FeatureEvidence.SOURCE_METADATA,
        status=FeatureStatus.DISCOVERED,
        operator_exception=operator_exception,
        metadata=kept_metadata,
    )


def _collisions(
    entries: tuple[FeatureLedgerEntry, ...],
) -> tuple[FeatureCollision, ...]:
    by_name: dict[str, list[FeatureLedgerEntry]] = defaultdict(list)
    for entry in entries:
        by_name[entry.canonical_name].append(entry)

    found: list[FeatureCollision] = []
    pair_classes = (
        (
            FeatureAssetKind.COMMAND,
            FeatureAssetKind.SKILL,
            FeatureCollisionClass.COMMAND_SKILL,
        ),
        (
            FeatureAssetKind.COMMAND,
            FeatureAssetKind.HOST_BUILTIN,
            FeatureCollisionClass.COMMAND_BUILTIN,
        ),
        (
            FeatureAssetKind.SKILL,
            FeatureAssetKind.HOST_BUILTIN,
            FeatureCollisionClass.SKILL_BUILTIN,
        ),
    )
    duplicate_classes = {
        FeatureAssetKind.COMMAND: FeatureCollisionClass.DUPLICATE_COMMAND,
        FeatureAssetKind.SKILL: FeatureCollisionClass.DUPLICATE_SKILL,
        FeatureAssetKind.AGENT: FeatureCollisionClass.DUPLICATE_AGENT,
        FeatureAssetKind.HOST_BUILTIN: (FeatureCollisionClass.DUPLICATE_BUILTIN),
    }

    for name, group in by_name.items():
        by_kind: dict[FeatureAssetKind, list[FeatureLedgerEntry]] = defaultdict(list)
        for entry in group:
            by_kind[entry.asset_kind].append(entry)
        for left, right, collision_class in pair_classes:
            members = by_kind[left] + by_kind[right]
            if by_kind[left] and by_kind[right]:
                found.append(
                    FeatureCollision(
                        canonical_name=name,
                        collision_class=collision_class,
                        members=tuple(sorted(entry.source_asset for entry in members)),
                    )
                )
        for kind, collision_class in duplicate_classes.items():
            members = by_kind[kind]
            if len(members) > 1:
                found.append(
                    FeatureCollision(
                        canonical_name=name,
                        collision_class=collision_class,
                        members=tuple(sorted(entry.source_asset for entry in members)),
                    )
                )
    return tuple(
        sorted(
            found,
            key=lambda item: (
                item.canonical_name,
                item.collision_class.value,
                item.members,
            ),
        )
    )


def _metadata_enabled(entry: FeatureLedgerEntry) -> bool:
    metadata = dict(entry.metadata)
    if metadata.get("enabled", "").lower() == "false":
        return False
    if (
        entry.asset_kind is FeatureAssetKind.COMMAND
        and metadata.get("user-invocable", "true").lower() == "false"
    ):
        return False
    if (
        entry.asset_kind is FeatureAssetKind.SKILL
        and metadata.get("disable-model-invocation", "false").lower() == "true"
    ):
        return False
    return True


def build_frontend_inventory(
    ledger: FeatureLedger,
    adapter: FrontendAdapter,
) -> FrontendInventory:
    """Project authoritative assets through Claude or Copilot discovery."""
    entries: list[FrontendInventoryEntry] = []
    warnings: list[str] = []
    for entry in ledger.entries:
        if entry.asset_kind is FeatureAssetKind.HOST_BUILTIN:
            continue
        if entry.asset_kind is FeatureAssetKind.AGENT:
            surface = "agent"
        elif adapter is FrontendAdapter.COPILOT:
            # Copilot's JSON skill inventory includes both `.claude/commands`
            # and `.claude/skills`, so they share one name namespace.
            surface = "skill"
        else:
            # Claude's compatibility loader also requires command and skill
            # names to be disjoint: a same-name skill can hide a slash command.
            surface = "prompt"
        entries.append(
            FrontendInventoryEntry(
                canonical_name=entry.canonical_name,
                asset_kind=entry.asset_kind,
                source_asset=entry.source_asset,
                surface=surface,
                enabled=_metadata_enabled(entry),
            )
        )
    return FrontendInventory(
        adapter=adapter,
        entries=tuple(
            sorted(
                entries,
                key=lambda item: (
                    item.surface,
                    item.canonical_name,
                    item.asset_kind.value,
                    item.source_asset,
                ),
            )
        ),
        warnings=tuple(sorted(warnings)),
    )


def frontend_parity_errors(
    ledger: FeatureLedger,
    inventory: FrontendInventory,
) -> tuple[str, ...]:
    """Compare authoritative declarations with one frontend adapter."""
    declared = {
        entry.source_asset
        for entry in ledger.entries
        if entry.asset_kind is not FeatureAssetKind.HOST_BUILTIN
    }
    adapted = {entry.source_asset for entry in inventory.entries}
    errors: list[str] = []
    for source_asset in sorted(declared - adapted):
        errors.append(f"missing: {source_asset}")
    for source_asset in sorted(adapted - declared):
        errors.append(f"unexpected: {source_asset}")
    for duplicate in inventory.duplicates:
        errors.append(
            f"duplicate {duplicate.surface} name {duplicate.canonical_name!r}: "
            + ", ".join(duplicate.members)
        )
    for entry in inventory.entries:
        if not entry.enabled:
            errors.append(f"disabled: {entry.source_asset}")
    errors.extend(f"warning: {warning}" for warning in inventory.warnings)
    return tuple(errors)


def build_feature_ledger(
    repo_root: Path,
    *,
    host_builtins: Iterable[HostBuiltin] = (),
) -> FeatureLedger:
    """Build the current source inventory without hard-coded asset counts."""
    root = repo_root.resolve()
    parser = _load_frontmatter_parser(root)
    entries: list[FeatureLedgerEntry] = []

    commands_dir = root / ".claude" / "commands"
    for path in sorted(commands_dir.glob("*.md")):
        metadata = parser(path.read_text(encoding="utf-8"))
        dispatch = metadata.get("dispatch")
        if not dispatch:
            raise ValueError(
                f"{path.relative_to(root)} lacks canonical dispatch metadata"
            )
        name = path.stem
        entries.append(
            _source_entry(
                repo_root=root,
                path=path,
                kind=FeatureAssetKind.COMMAND,
                canonical_name=name,
                behavior=dispatch,
                capability_requirement="command_dispatch",
                host_mapping=f"/{name}",
                metadata=metadata,
            )
        )

    skills_dir = root / ".claude" / "skills"
    for path in sorted(skills_dir.rglob("SKILL.md")):
        yaml_metadata = _load_yaml_frontmatter(path)
        _validate_description(path, yaml_metadata)
        name = _canonical_skill_name(path, yaml_metadata)
        entries.append(
            _source_entry(
                repo_root=root,
                path=path,
                kind=FeatureAssetKind.SKILL,
                canonical_name=name,
                behavior="load authoritative skill body",
                capability_requirement="skill_loading",
                host_mapping=name,
                metadata=_flat_metadata(yaml_metadata),
            )
        )

    agents_dir = root / "plugins" / "agents" / "agents"
    for path in sorted(agents_dir.glob("*.md")):
        yaml_metadata = _load_yaml_frontmatter(path)
        _validate_agent_metadata(path, yaml_metadata)
        name = _canonical_agent_name(path, yaml_metadata)
        entries.append(
            _source_entry(
                repo_root=root,
                path=path,
                kind=FeatureAssetKind.AGENT,
                canonical_name=name,
                behavior="load authoritative agent definition",
                capability_requirement="agent_dispatch",
                host_mapping=name,
                metadata=_flat_metadata(yaml_metadata),
            )
        )

    for builtin in host_builtins:
        if not isinstance(builtin, HostBuiltin):
            raise TypeError("host_builtins must contain HostBuiltin values")
        entries.append(
            FeatureLedgerEntry(
                canonical_name=builtin.name,
                asset_kind=FeatureAssetKind.HOST_BUILTIN,
                source_asset=f"host-builtin:{builtin.name}",
                behavior=builtin.behavior,
                capability_requirement="host_builtin",
                host_mapping=f"/{builtin.name}",
                evidence=FeatureEvidence.NON_INFERENCE_DISCOVERY,
                status=FeatureStatus.CANDIDATE_UNVERIFIED,
                metadata=(("evidence_source", builtin.evidence_source),),
            )
        )

    frozen_entries = tuple(
        sorted(
            entries,
            key=lambda entry: (
                entry.canonical_name,
                entry.asset_kind.value,
                entry.source_asset,
            ),
        )
    )
    return FeatureLedger(
        entries=frozen_entries,
        collisions=_collisions(frozen_entries),
    )


__all__ = [
    "FeatureAssetKind",
    "FeatureCollision",
    "FeatureCollisionClass",
    "FeatureEvidence",
    "FeatureLedger",
    "FeatureLedgerEntry",
    "FeatureStatus",
    "FrontendAdapter",
    "FrontendDuplicate",
    "FrontendInventory",
    "FrontendInventoryEntry",
    "HostBuiltin",
    "build_feature_ledger",
    "build_frontend_inventory",
    "frontend_parity_errors",
]
