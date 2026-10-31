"""Minimal SARIF 2.1.0 emission — the shared skeleton behind RAPTOR's
per-tool emitters.

Seven emitters (coccinelle, compiler-scan, the scanner's stage and
graduated legs, expanded-semgrep, config-resolved, the import
normalizer) each hand-rolled the same document skeleton: an
insertion-ordered rule catalog deduplicated by id, per-finding result
entries with one physical location, a single-driver run, and the
2.1.0 envelope. The copies had already started to drift (three
different ``$schema`` URIs, one envelope with ``version`` before
``$schema``). This module is the one implementation; each emitter
keeps only its genuinely tool-specific content (messages, regions,
properties, provenance).

Byte-stability contract: these artifacts are written with
``core.json.save_json`` (``sort_keys=False``), so dict INSERTION
ORDER is the on-disk byte order. The key orders produced here are
pinned by the emitters' golden tests — do not reorder members, and
route historical per-site divergences through parameters (see
``result(properties_before_locations=...)``) rather than new dict
shapes.

The ``$schema`` URIs below are historical per-emitter choices, kept
distinct so migrated emitters stay byte-identical. All three resolve
to the same 2.1.0 schema; converging them is a byte-visible change
that belongs to a deliberate follow-up, not this module.
"""

from __future__ import annotations

from typing import Any


SARIF_VERSION = "2.1.0"

# OASIS committee-specification path (semgrep-adjacent emitters).
SCHEMA_URI_COMMITTEE = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master"
    "/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json"
)
# OASIS Schemata path (graduated / config-resolved emitters).
SCHEMA_URI_SCHEMATA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "master/Schemata/sarif-schema-2.1.0.json"
)
# schemastore.org mirror (scanner stage + import normalizer).
SCHEMA_URI_SCHEMASTORE = "https://json.schemastore.org/sarif-2.1.0.json"


class RuleIndex:
    """Insertion-ordered rule catalog deduplicated by rule id.

    First writer wins: :meth:`add` on an id already present is a
    no-op, matching the ``if rule_id not in seen`` idiom every
    emitter used (the first finding of a rule defines the rule).
    """

    def __init__(self) -> None:
        self._rules: list[dict[str, Any]] = []
        self._seen: set[str] = set()

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._seen

    def add(self, rule: dict[str, Any]) -> None:
        """Register *rule* (a dict carrying an ``id``) unless a rule
        with the same id is already present."""
        rule_id = rule["id"]
        if rule_id in self._seen:
            return
        self._rules.append(rule)
        self._seen.add(rule_id)

    def rules(self) -> list[dict[str, Any]]:
        """The accumulated ``tool.driver.rules`` list (live, ordered)."""
        return self._rules


def minimal_rule(
    rule_id: str,
    *,
    full_description: str | None = None,
    level: str = "warning",
    help_uri: str | None = None,
    properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A minimal ``tool.driver.rules[*]`` entry.

    Member order (byte-contractual, see module docstring):
    ``id``, ``name``, ``shortDescription``, [``fullDescription``],
    ``defaultConfiguration``, [``helpUri``], [``properties``].
    Optional members are omitted (not emitted empty) when ``None``.
    """
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": rule_id},
    }
    if full_description is not None:
        rule["fullDescription"] = {"text": full_description}
    rule["defaultConfiguration"] = {"level": level}
    if help_uri is not None:
        rule["helpUri"] = help_uri
    if properties is not None:
        rule["properties"] = properties
    return rule


def location(uri: str, region: dict[str, Any]) -> dict[str, Any]:
    """A ``locations[*]`` entry with one physical location.

    ``region`` is caller-built: emitters differ on which region
    members they emit and on falsy-vs-``None`` omission, and those
    differences are byte-contractual per site.
    """
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": region,
        },
    }


def result(
    rule_id: str,
    message: str,
    locations: list[dict[str, Any]],
    *,
    level: str = "warning",
    properties: dict[str, Any] | None = None,
    properties_before_locations: bool = False,
) -> dict[str, Any]:
    """A ``results[*]`` entry.

    Member order: ``ruleId``, ``level``, ``message``, ``locations``,
    [``properties``]. ``properties_before_locations`` preserves the
    one historical emitter (config-resolved) that wrote ``properties``
    ahead of ``locations`` — byte order, not semantics.

    Members a single emitter appends conditionally (``codeFlows``,
    ``fingerprints``, …) are added by the caller on the returned dict,
    which places them after the members built here.
    """
    entry: dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
    }
    if properties is not None and properties_before_locations:
        entry["properties"] = properties
    entry["locations"] = locations
    if properties is not None and not properties_before_locations:
        entry["properties"] = properties
    return entry


def run(
    tool_name: str,
    rules: list[dict[str, Any]],
    results: list[dict[str, Any]],
    *,
    full_name: str | None = None,
    information_uri: str | None = None,
) -> dict[str, Any]:
    """A single-driver ``runs[*]`` entry.

    Driver member order: ``name``, [``fullName``],
    [``informationUri``], ``rules``. Run-level members an emitter
    adds conditionally (``invocations``) are appended by the caller
    on the returned dict.
    """
    driver: dict[str, Any] = {"name": tool_name}
    if full_name is not None:
        driver["fullName"] = full_name
    if information_uri is not None:
        driver["informationUri"] = information_uri
    driver["rules"] = rules
    return {
        "tool": {"driver": driver},
        "results": results,
    }


def document(
    runs: list[dict[str, Any]],
    *,
    schema_uri: str,
    version_first: bool = False,
) -> dict[str, Any]:
    """The SARIF 2.1.0 envelope.

    ``version_first`` preserves the import normalizer's historical
    ``version``-before-``$schema`` member order; every other emitter
    writes ``$schema`` first.
    """
    if version_first:
        return {
            "version": SARIF_VERSION,
            "$schema": schema_uri,
            "runs": runs,
        }
    return {
        "$schema": schema_uri,
        "version": SARIF_VERSION,
        "runs": runs,
    }
