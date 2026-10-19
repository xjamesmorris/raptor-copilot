# Copilot workstream TODO

Updated: October 16, 2026.

This is the shared workstream backlog. `local-issues.txt` remains the operator's
personal observation file; it is not this tracker and is not modified here.

Priority order is P0 (trustworthy execution/results), P1 (required functionality
and parity acceptance), then P2 (installation/documentation closeout).
Unchecked items are work to do, not claims that a root cause is already known.
Dependencies are noted explicitly; otherwise tasks can proceed independently.

## Phase 1: Parity MVP

MVP means reliable native-Linux Copilot operation as RAPTOR's interactive
frontend, with the existing Claude frontend's applicable command, project,
session, lifecycle, coverage, and reporting behavior. Analysis-provider
configuration remains separate. A new headless Copilot provider or production
admission of the synthetic runtime-receipt path is not implicitly required.

**Current baseline:** `ff6e4eba8` enables the interactive Copilot frontend.
`9d4acdcf` already contains the earlier Rust CodeQL/Claude schema repair.
`README-Copilot.md` and `docs/copilot-patch-map.md` describe the current launch
path; `HANDOFF.md` and `HUMAN-REVIEW.md` are older September 13 snapshots.

### P0

- [x] **MVP-01 - Make capped/partial runs and per-tool failures truthful.**

  **Completed October 16, 2026:** reports now record assessment completeness,
  cap reasons, typed verdict distributions, and explicit per-tool execution
  states. A requested scan with no usable scanner output exits 1 while
  preserving diagnostics; usable complete or partial output exits 0. Focused
  report, lifecycle, compatibility, cap, timeout, and all-failed regressions
  pass.

  Review the historical completed frontend-acceptance scan recorded as
  `out/<historical-frontend-acceptance-run>/`: 407 raw findings, 370 unique,
  10 reviewed, and 360 explicitly skipped by the provider-default cap.
  This is an intentional selection limit, not evidence that 370 findings
  were reviewed. Separately, SCA timed out but the aggregate JSON presents
  it as disabled. The Markdown summary also groups all 10 results as False
  Positive despite the recorded six False Positive, one Mitigated, and three
  Test Code verdicts.

  **Done when:** terminal, generated Markdown, JSON, and lifecycle metadata
  distinguish execution completion from assessment completeness; preserve
  actual verdicts; expose attempted/succeeded/failed/skipped phases, selected
  cap, unreviewed count, reasons, and artifact references. Make the cap and
  existing explicit higher/all-review options clear, retain the unreviewed
  queue, and do not silently make paid analysis unbounded. Define and test
  the aggregate exit-status contract. Share this reporting repair with
  fedithread RP-1 in MVP-03 rather than implementing it twice.

- [x] **MVP-02 - Root-cause and fix the frontend-acceptance execution-subagent timeout/wait.**

  **Completed October 16, 2026:** repository instructions now treat an
  `initial_wait` expiry as an observation boundary rather than proof that a
  RAPTOR command failed, retain the stable command handle through completion,
  and require exact-handle cancellation and child cleanup. The historical
  `command_timeout` label and later exit-0 completion are recorded as observed
  facts; external Copilot runtime causality is not claimed. Execution-subagent
  policy precedence and the no-banner-diversion rule have regression coverage.

  Investigate the operator-observed internal timeout against the historical
  frontend-acceptance session record. Its history proves a Bash
  `command_timeout` while the scan subsequently completed. A post-run
  execution-subagent validation call then lasted from October 15 at 23:22 UTC
  to October 16 at 03:26 UTC before reporting success. The inspected events
  do not establish an explicit internal-subagent timeout or its root cause.
  Do not equate a tool wait boundary, a pipeline deadline, and the separate
  600-second SCA timeout.

  **Done when:** reproduce or isolate the failing layer, preserve the exact
  command/error/timing evidence, and fix the responsible integration or
  invocation. Long-running commands must remain observable without duplicate
  scans, lost completion, or unexplained multi-hour validation waits.
  Exercise completion, real timeout, cancellation, and child cleanup; if
  upstream-owned, record the minimal reproduction and a verified mitigation.

- [x] **MVP-03 - Complete the fedithread Semgrep/CodeQL repair handoff.**

  **Completed October 16, 2026:** JavaScript/TypeScript CodeQL now uses
  no-build extraction unless the operator explicitly supplies a build
  command; RAPTOR-owned Semgrep scope excludes exact `.git` metadata without
  excluding `.github`, hidden, ignored, test, or git-named application paths;
  and IRIS local-pack diagnostics now have sanitized private artifacts and
  explicit install/query health. MVP-01 supplies the shared partial/failure
  reporting contract. The combined validation passed 359 tests with two
  repository-marked integration/corpus deselections, including a real
  uncached JavaScript extraction and positive-query fixture.

  Source: [Semgrep/CodeQL handoff](raptor-semgrep-codeql-fedithread-repair-handoff.md).
  The handoff preserves the historical diagnosis and now records the landed
  CQ-1, RP-1, SG-1, and CQ-2 resolutions. The repairs avoid target package
  installation, retain target immutability and anti-suppression behavior, and
  report standard and IRIS CodeQL health independently.

  **Acceptance evidence:** fresh, distinct-path JS/TS fixtures exercise the uncached
  selection path; actual extraction and positive-query detection succeed
  without target writes or lifecycle scripts; explicit builds and compiled
  languages retain their behavior. Git internals are excluded by owned
  policy while hidden, ignored, untracked, and test application files remain
  eligible. Preserve full sanitized IRIS diagnostics and distinguish install
  warnings, usable cached dependencies, and actual query failure.

### P1

- [x] **MVP-04 - Diagnose and fix the frontend-acceptance target's independent SCA timeout.**

  **Completed October 16, 2026:** the mechanical SCA subprocess had
  incorrectly enabled deep LLM review and triage, reaching a Claude Code call
  whose timeout matched the parent 600-second limit after mechanical analysis
  had completed. Mechanical mode now disables deep gates centrally, propagates
  precise deadlines and bounded request timeouts, rejects contradictory or
  unknown options, records private phase diagnostics, and provides
  cancellation/descendant cleanup across normal and degraded backends.

  The run's `sca/stderr.log` records `sca-agent timed out after 600s`.
  Determine which dependency-analysis step consumed that budget and whether
  the cause is subprocess execution, dependency resolution, sandbox/egress,
  or deadline propagation; none is established by that one-line diagnostic.

  **Done when:** the cause is reproduced and repaired, with bounded progress
  and cancellation, useful private diagnostics, and an explicit failure
  status through MVP-01. Demonstrate successful dependency analysis or an
  evidence-backed, visible unsupported/skipped disposition. Do not merely
  raise the timeout, weaken containment, or claim zero dependency findings.

- [x] **MVP-05 - Resolve the frontend-acceptance Claude dispatch errors separately.**

  **Completed October 16, 2026:** Claude Code received an unnormalized
  descriptive schema whose top-level `reasoning` field was interpreted as an
  unsupported JSON Schema keyword. Four prefilter and ten analysis dispatches
  failed, while circuit-breaking exposed only three failures in the aggregate.
  Schema classification/normalization, typed errors, private diagnostics,
  circuit-breaker settlement, mixed-task reporting, cancellation, and partial
  usage/accounting are now covered. Property-based object schemas still gain
  the required root type; valid advanced JSON Schema forms pass through
  without caller mutation.

  The run recorded three failed dispatches despite ten successful per-finding
  analyses. Its captured output also reported a strict-schema
  `unknown keyword: "reasoning"` error. Recover the complete sanitized
  diagnostic and identify the exact task/schema/transport before choosing
  a repair; this does not establish a recurrence of the earlier missing
  root-object-type bug.

  **Done when:** reproduce and fix any remaining schema, transport, or
  per-call-budget defect; add the focused failing case; preserve successful
  findings and honest failed-attempt/accounting details. A final successful
  subset must not conceal failed enrichment or review tasks.

- [x] **MVP-06 - Close out the already-implemented Rust CodeQL/Claude handoff.**

  **Completed October 16, 2026:** the handoff now records that `9d4acdcf`
  already landed root-object normalization, explicit-type preservation,
  private sanitized pack-download diagnostics, and their regressions. Local
  CodeQL 2.27.2 resolves the Rust extractor, `rust-queries@0.1.44`, and both
  configured suites without cache mutation or network access. No duplicate
  implementation was added.

  Source: [CodeQL/Claude handoff](raptor-codeql-llm-repair-handoff.md).
  The missing root `"type": "object"` normalization and complete private
  CodeQL pack-download diagnostics landed in `9d4acdcf`; session history
  also records successful Rust CodeQL and full-workflow verification.
  The handoff now records those repairs as closed and keeps the original
  incomplete run only as historical evidence.

  **Acceptance evidence:** the handoff is reconciled with the landed source, retained
  regression cases, and verification artifacts; record any genuinely
  remaining environment/pack recovery separately. Confirm descriptive and
  property-based schemas gain the missing type without rewriting an
  explicit type. Keep this closeout separate from MVP-05's newer failure.

- [x] **MVP-07 - Support and document launcher-to-Copilot `--yolo`.**

  **Completed October 16, 2026:** the launcher already forwarded `--yolo`;
  explicit contracts, native argv tests, and documentation now cover target,
  project, continuation, and argument-order permutations. It remains opt-in,
  Copilot-specific, and independent of RAPTOR project trust and sandbox
  policy. Native exit status and rejection stderr propagate unchanged.

  `bin/raptor` already has generic flag passthrough, so first verify the
  actual argv and installed Copilot behavior instead of assuming the flag
  is dropped. Repair any real parsing/dispatch gap and document the explicit
  opt-in in `README-Copilot.md`.

  **Done when:** `--yolo` reaches Copilot unchanged with a target, project
  selection, and session continuation; it is not mistaken for a target or
  enabled by default. Add focused launcher coverage, preserve existing
  Claude flag behavior, and do not turn this frontend permission choice
  into RAPTOR project trust or a sandbox bypass.

- [x] **MVP-08 - Allow explicitly selected, catalog-unlisted Copilot models.**

  **Completed October 16, 2026:** explicit listed or catalog-unlisted Copilot
  model values are preserved exactly through both `--model VALUE` and
  `--model=VALUE`; RAPTOR does not substitute from its offline catalog.
  Empty/missing values and ambiguous separated forms are rejected before
  target reinterpretation. Native Copilot/service admission remains
  authoritative and upstream rejection remains visible.

  Follow the operator's working Rhyolite-style explicit/configured selection,
  without requiring every usable model to appear in the offline catalog.
  The launcher already forwards an explicit model string: trace where any
  rejection actually occurs, distinguishing RAPTOR resolution from the
  native CLI and service. Keep frontend, child-agent, and analysis-provider
  model selection separate.

  **Done when:** a valid explicit model absent from the offline catalog is
  retained through supported configuration and dispatch, without a catalog
  edit or silent substitution. Test both an unlisted valid selection and a
  genuinely invalid one; surface upstream rejection honestly. Preserve
  exact provider/model routing, credentials, and unknown capability/cost
  semantics rather than inventing limits or zero prices. Document any
  upstream constraint instead of claiming passthrough can bypass it.

- [x] **MVP-09 - Check Claude unlisted-model parity; patch separately if needed.**

  **Completed October 16, 2026:** Claude frontend forwarding was already
  exact, while headless resolution rejected or altered unusual configured and
  provider-qualified model IDs. The standalone patch preserves opaque IDs,
  credentials, API routes, case and separators; retains unknown
  capability/cost semantics; prevents fallback or fast-tier substitution; and
  keeps unqualified typo and upstream errors loud.

  Inspect the Claude frontend and applicable Claude Code analysis path.
  Shared configuration already supports exact configured unusual model
  names; establish which remaining catalog gate, if any, blocks explicit
  operator selection.

  **Done when:** either demonstrate that existing supported behavior
  satisfies the same explicit-selection contract, or deliver the necessary
  fix as a standalone patch independent of Copilot activation. Preserve
  aliases, explicit provider routing, and loud errors for invalid models;
  do not introduce silent fallback or broadly relax validation. It may reuse
  MVP-08's contract/tests but must not depend on a new Copilot provider.

- [x] **MVP-10 - Run and record live frontend parity acceptance.**

  **Completed October 17, 2026 (October 18 UTC):** bounded live Claude Code
  2.1.301 and Copilot CLI 1.0.100-1 sessions verified all 39 commands, all 18
  custom agents, Copilot's 52 command/skill entries, exact project/session
  binding, continuation and explicit resume, read coverage, lifecycle
  completion/failure/cancellation, direct SessionEnd orphan cleanup, and
  report/artifact discovery. Coverage manifests and JSON use exact realpaths
  and mode `0600`; fixtures and source remained unchanged.

  Claude custom agents inherit the parent model even when conflicting
  subagent environment variables are present. Copilot's built-in managed
  `execution_subagent` ignored a repository model request and used its
  upstream-selected model; usage output is therefore authoritative and this
  is documented as an upstream limitation, not a repository parity failure.
  The five security-sensitive custom-agent hook policies are enforced by the
  Claude launcher plugin and are explicitly **not** Copilot guarantees.
  Live `--yolo` was not exercised, and synthetic runtime receipts remain
  test-only and non-authorizing.

  Suggested acceptance work: compare the supported Claude and native-Linux
  Copilot paths using deterministic fixtures and bounded live smoke runs.
  Existing fake/process tests and one completed scan do not alone prove
  every interactive workflow.

  **Acceptance evidence:** recorded command/skill/agent discovery, initial
  target dispatch, model/flag forwarding, project binding and isolation,
  continuation/resume, read-coverage plugin events, lifecycle completion,
  failure/cancellation, and report/artifact discovery. Distinguish the parent
  frontend, execution subagents, and finding-analysis provider. Keep native
  executable identity checks and the synthetic-receipt authority boundary.
  Depends on the applicable fixes in MVP-01 through MVP-09.

### P2

- [x] **MVP-11 - Verify dependency readiness on a fresh Fedora environment.**

  **Completed October 18, 2026 (October 19 UTC):** a fresh
  `fedora-cascade44` Fedora 44 Cloud Edition VM installed the documented core
  toolchain, completed `uv sync --locked` in approximately 1.8 seconds,
  installed Semgrep separately with pipx, and installed native Claude and
  Copilot frontends with their official scripts. Native host claims,
  discovery, launcher-backed doctor, source integrity, and a 642-test
  cross-frontend runtime parity matrix passed.

  The run exposed and repaired two clean-install gaps: doctor did not
  distinguish Copilot's incompatible npm loader from its required native ELF,
  and release archives omitted Copilot's `.github/agents` projection and
  repository settings. Doctor now prints the official native-install
  remediation, and release tests preserve runtime Copilot/plugin surfaces
  while continuing to exclude CI/development paths.

  CodeQL, Coccinelle, AFL++, GDB, Joern, radare2, rr, Frida, tree-sitter
  grammars, and BigQuery configuration were deliberately left absent and are
  reported as optional capability reductions. Cloud-init completed with a
  recoverable hostname warning, but the resulting hostname, SSH, networking,
  and passwordless sudo were correct. No frontend authentication, model
  request, vulnerability scan, or host credential copy occurred.

  Suggested acceptance work: use a fresh Fedora VM template with
  `fedora-cascade44` and the documented setup path, rather than relying on
  this developer machine's preinstalled tools.

  **Acceptance evidence:** native Copilot, Python dependencies, and required scanners
  install and pass a representative bounded parity smoke run. Required
  missing dependencies fail actionably; optional tools and reduced coverage
  are clearly distinguished. Repair installer/checker gaps actually found,
  document recovery steps, and avoid making optional enrichers universal
  prerequisites. Depends on MVP-10's acceptance checklist.

- [ ] **MVP-12 - Reconcile workstream documentation before MVP signoff.**

  `HANDOFF.md` and `HUMAN-REVIEW.md` still describe the September 13 gated,
  uncommitted state, superseded by October's publication and frontend
  activation. Both repair handoffs are currently untracked local files.

  **Done when:** clearly label historical snapshots, publish a consistent
  current status/limitations entry point, and link this tracker from the
  Copilot documentation. Preserve both handoffs with the workstream's
  eventual version-controlled changes so task references remain usable.
  Update tasks with completion evidence, remaining limits, and the final
  parity decision; do not present old approvals as current authorization.
  Depends on the relevant implementation and acceptance outcomes above.

## Phase 2: Post-MVP

No tasks assigned.
