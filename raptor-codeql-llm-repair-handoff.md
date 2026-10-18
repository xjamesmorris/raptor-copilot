# RAPTOR CodeQL and Claude Structured-Output Repair Closeout

Original diagnosis: 2026-10-14
Closeout reconciled: 2026-10-16
Landed commit: `9d4acdcfce00bc47679be3a2b85cda00eae4fd85`

## Status

Closed.

This closeout verifies the identified framework repairs and local CodeQL pack
resolution. It is not a claim that the historical test target, or any other
target, is vulnerability-free.

The original run exposed two independent failures:

1. Claude Code rejected a structured-output schema whose root had
   `properties` and `required` but no `"type": "object"`.
2. The standalone CodeQL 2.26.2 installation could create the Rust database
   but could not resolve `codeql/rust-queries`; its local cache contained an
   empty partial `0.1.44` directory.

The RAPTOR source repairs landed in `9d4acdcf`. The CodeQL host issue was
resolved by using the CodeQL 2.27.2 bundle, which carries a compatible Rust
extractor and query packs. Current read-only resolution confirms that the
Rust pack and both configured suites are usable. No repository-owned repair
or cache mutation remains for this incident.

This closeout supersedes the original handoff's pending repair and
force-download instructions. Do not reapply the landed patch or modify the
CodeQL cache merely because the historical diagnosis described those actions.

## Original scope

The diagnosis came from:

- Diagnostic checkout:
  `<framework-checkout>`
- Test target:
  `<rust-test-target>`
- Original incomplete run:
  `out/<historical-agentic-run>/`

The old run remains useful evidence of the pre-fix failures, but it is not the
post-fix verification run. The placeholders intentionally omit
machine-specific checkout names; artifact paths are relative to the framework
checkout.

## Repair reconciliation

| Original proposal | Current disposition |
| --- | --- |
| Add a root object type to descriptive schemas. | Landed in `core/llm/providers.py`; `_normalize_schema()` returns `"type": "object"` for converted descriptive schemas. |
| Add a root object type to property-based schemas that omit one. | Landed in `core/llm/providers.py`; the property-schema path uses `setdefault("type", "object")`. |
| Preserve an explicit root type, including a non-object type. | Landed; `setdefault` does not rewrite an explicit type. The downstream consumer remains responsible for rejecting an incompatible schema. |
| Add focused schema regressions. | Landed in `packages/llm_analysis/tests/test_cc_dispatch_schema.py` for descriptive, property-based, explicit non-object, and real analysis schemas. |
| Keep the short operator-facing CodeQL download summary but retain the complete failure privately. | Landed in `packages/codeql/query_runner.py`; the complete redacted and control-safe stderr is written to a mode-`0600` artifact while the result summary remains bounded to 200 characters. |
| Add a diagnostic regression. | Landed in `packages/codeql/tests/test_pack_download.py`; it checks completeness beyond 200 characters, secret redaction, control-byte escaping, private permissions, and the bounded summary. |
| Force-download or manually move the empty cached Rust pack. | Historical host-recovery guidance only. It is unnecessary on the current host because the bundled pack resolves successfully. No cache was changed during this closeout. |
| Add a proxy-host or sandbox-readable-path exception. | Not supported by the evidence and not implemented. The original Claude request reached the API, and the schema error—not Landlock optional-path warnings—caused the failure. |
| Verify Rust CodeQL and the full workflow after repair. | Completed in the implementation session and recorded below. |

## Landed files and retained regressions

Commit `9d4acdcf` changed:

- `core/llm/providers.py`
  - normalizes descriptive schemas as root objects;
  - adds the missing type to property-based schemas;
  - preserves explicit types.
- `packages/llm_analysis/tests/test_cc_dispatch_schema.py`
  - `test_descriptive_schema_converted_to_json_schema`;
  - `test_property_schema_gains_root_object_type`;
  - `test_explicit_non_object_root_type_is_preserved`;
  - `test_analysis_schema_normalises`.
- `packages/codeql/query_runner.py`
  - persists complete sanitized pack-download stderr privately;
  - retains a bounded operator summary and records the artifact path.
- `packages/codeql/tests/test_pack_download.py`
  - `test_failed_download_persists_complete_sanitized_stderr`.

The current shared tree contains later uncommitted MVP work in
`packages/codeql/query_runner.py`. That work refactors common diagnostic
sanitization through `_sanitise_diagnostic_stream()` but retains the landed
pack-download behavior and regression. The other three landed repair files
remain unchanged from `9d4acdcf`.

## Recorded post-fix verification

The retained implementation-session evidence records:

- 129 focused tests passed;
- the broader relevant run passed with 5,781 passed and 35 skipped;
- Ruff and `git diff --check` passed;
- a live Claude structured-output call returned `{"answer":"ok"}` without the
  former `input_schema.type` HTTP 400;
- Rust CodeQL executed 30 query groups and produced SARIF successfully;
- the full agentic workflow exited successfully with a zero-findings terminal
  disposition.

Those results establish the original end-to-end acceptance criteria. This
closeout does not repeat networked Claude or full agentic execution.

## Current closeout validation

Focused current-tree regression run:

```text
python3 -m pytest -q \
  packages/llm_analysis/tests/test_cc_dispatch_schema.py \
  core/llm/tests/test_response_validation.py \
  packages/codeql/tests/test_pack_download.py

123 passed
```

Targeted lint and in-memory compilation passed for:

- `core/llm/providers.py`
- `packages/codeql/query_runner.py`
- `packages/codeql/tests/test_pack_download.py`
- `packages/llm_analysis/tests/test_cc_dispatch_schema.py`

Tracked-worktree and closeout-document diff checks also passed.

Read-only CodeQL compatibility checks on 2026-10-16 found:

- CLI: `2.27.2`
- Rust extractor:
  `<codeql-install>/rust`
- `codeql/rust-all@0.2.23`
- `codeql/rust-queries@0.1.44`
- `rust-security-and-quality.qls`: resolves to 41 query files
- `rust-security-extended.qls`: resolves to 39 query files

The configured RAPTOR suite names therefore match the packs visible to the
current CLI. These commands performed resolution only: no pack download,
cache removal, or cache rewrite occurred.

## Remaining host prerequisites

There is no current blocker on this host.

On a different host, Rust CodeQL still requires a CodeQL distribution with:

1. the Rust extractor;
2. a compatible `codeql/rust-queries` pack;
3. readable `rust-security-and-quality.qls` and, when requested,
   `rust-security-extended.qls`.

If read-only resolution does not find those components, that is a host
installation prerequisite, not evidence that the RAPTOR repairs are missing.
Repair the CodeQL installation deliberately before running a networked pack
download or changing an operator cache.

A live Claude verification additionally requires the operator's normal
provider credentials and permitted egress. Those are runtime prerequisites,
not repository defects.

## Incident boundaries

The newer frontend-acceptance target's strict-schema/dispatch failure is
tracked separately as MVP-05. Its reported `unknown keyword: "reasoning"`
symptom does not establish a recurrence of this incident: `reasoning` was an
ordinary output property in the Rust schema, while the repaired defect was
the missing root object type. That target must be diagnosed from its own
complete sanitized artifact and must not be folded into this closeout.

The original Rust corpus's
`sca:supply_chain:binary_in_package` result was independently shown to be a
packaging false positive because Cargo excluded `target/`. That corpus result
is also separate from the framework repair.
