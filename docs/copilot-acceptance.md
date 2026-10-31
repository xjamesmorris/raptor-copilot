# Copilot frontend acceptance record

This is the version-controlled acceptance and review record for the GitHub
Copilot CLI workstream. Scope and limitations are in
[README-Copilot.md](../README-Copilot.md#current-status). Task state is in
[copilot-todo.md](../copilot-todo.md).

Earlier September handoff and checklist notes are operator-local archives.
They are not tracked status, current checkout state, or authorization.

## Current position - October 30, 2026

| Area | Status | Evidence |
|---|---|---|
| Interactive native-Linux frontend | Accepted within its bounded scope | Live parity, October 17 (MVP-10) |
| Fresh-install readiness | Accepted within its bounded scope | Fresh Fedora 44, October 18 (MVP-11) |
| Copilot-native `/agentic` analysis | Implemented; offline contract checks pass | [October 27 offline refresh](#october-27-offline-refresh) |
| Current-tip live acceptance | Accepted within its bounded, recovery-aware scope | [October 28 live acceptance](#october-28-current-tip-live-acceptance) |
| Native stage adapters | Accepted within bounded combined live scope | [October 30 POST-04 acceptance](#october-30-post-04-combined-live-acceptance) |
| Public-release hygiene | Local checks pass; history-privacy choice remains | [October 30 release preflight](#october-30-public-release-preflight) |

**Parity decision:** retain the recorded October 17 frontend acceptance and
October 18 fresh-install acceptance within their stated scopes. The October 27
refresh remains offline regression evidence; the October 28 live run closes
POST-02 only within the exceptions recorded below. None of these results
establish unrestricted workflow parity, production authority for the synthetic
runtime-receipt path, or authorization for additional services.
POST-03 subsequently implemented validation, context/threat-model, gap-audit,
model-role and sequential adapters. POST-04 exercised those additions together
in fresh bounded parallel and sequential runs; it does not retroactively widen
the October 28 live scope.

## October 30 POST-04 combined live acceptance

The accepted post-fix baseline is RAPTOR commit `69a46c1d8` and fixture commit
`62515b751`. The launcher used `--yolo` with
`gpt-5.6-sol-daybreak-blue`; managed roles used
`gpt-5.6-sol-daybreak-blue` and `gpt-5.6-sol`. No standalone provider,
replacement frontend, saved credential or external-service fallback was used.

| Check | Result |
|---|---|
| Parallel path | Context/threat-model attachment, two concurrent analysis tasks, consensus, judge, aggregate, canonical synthesis, residual audit and strict validation completed |
| Sequential path | The same task graph completed with maximum observed concurrency exactly one and no task overlap |
| Scheduling | Parallel maximum concurrency exactly two; independent tasks overlapped for about 117.5 seconds |
| Audit | Two residual functions reviewed; one Finding, one Clean, four tool-grounded sweeps; three gaps remain |
| Validation | Exact `0 -> A -> B -> C -> D -> E -> F -> 1` order; two Confirmed (Unverified) injections and one False Positive display result |
| Integrity | Target commit/hashes and clean status preserved; `apply_target_patches: false`; no target patches |
| Re-finalization | Two additional finalizations per parent created no duplicate requests, receipts, assignments, artifacts or journal rows |
| Independent verification | 178/178 checks passed before re-finalization and 178/178 passed afterward |

The first completed pair exposed two real acceptance defects: audit reports
retained `run_status=running` and parent reports lost audit coverage counts;
re-finalization also appended duplicate journal assertions. Commit
`69a46c1d8` terminalizes the attached audit metadata, propagates the bound
coverage counts and makes identical journal emission idempotent. Fresh runs
then recorded completed/non-resumable audits, matching parent totals
(`2 reviewed`, `3 gaps`) and stable journals (`3 -> 3` rows).

The accepted scope remains bounded. Each parent selected two of ten eligible
scanner findings, SCA used cache-only data, validation lacked mechanically
bound witness receipts, and repository accounting correctly leaves Copilot
AI-credit/USD totals unknown. Exact ignored run paths, hashes, commands,
host-usage records and the retained failed-attempt history are in
`out/copilot-post03-acceptance-20261030/acceptance-evidence.md`.

## October 30 public-release preflight

Local publication hygiene was run without network access:

- A redacting reachable-history scanner examined 43,134 blobs
  (about 2.2 GB). High-signal matches reduced to seven unique values, all
  confirmed as fake self-test credentials, examples, corpus content or secret
  rule data. No private repository/check-out markers were found.
- The bundled hard-coded-key Semgrep rule produced seven findings, all in
  tests or the self-test fixture.
- A clean local clone at `69a46c1d8` completed `uv sync --locked --offline`,
  reported version `3.1.0-4310-g69a46c1d8`, passed all 39 command metadata
  checks and all 96 release-workflow checks, and remained clean.
- The SCA calibration attribution checker and its ten tests passed. The root
  MIT license, `CITATION.cff`, subsystem MIT license and calibration
  attribution remain present.
- The branch is 91 commits ahead and zero behind local `upstream/main`; no new
  binary, archive or key-like files were identified.

One privacy choice remains before publication: all 91 branch-only commits use
one non-noreply personal-domain identity. Full-history publication would expose
that address. The recommended default is a sanitized snapshot, or a separately
reviewed email rewrite if preserving detailed history is more important.
Repository visibility changes, public pushes and public PR creation remain
external actions requiring fresh explicit approval.

## October 27 offline refresh

Scope: base `c3044dedc` plus the POST-01, documentation and repository-gate
worktree changes. Checks used existing local dependencies and hermetic
fixtures. No installed frontend was launched and no external service was
used. Native frontend executables in these tests are repository-owned
fixtures, not the installed Copilot or Claude.

| Check | Result |
|---|---|
| Cargo/mixed-language description, build probes, readiness and CodeQL no-build routing | 154 passed; 1 default slow-test deselection |
| Native handoff/finalization, service isolation, partial reporting, CodeQL database handling and owned-fake frontend contracts | 275 passed; no skips or deselections |
| Scoped mypy on the four changed runtime modules | No issues |

The deselection is
`test_validate_probe_cwd.py::test_real_maven_probe_ignores_repo_jvm_config`,
excluded by the repository's default slow-test policy and not counted as a
pass.

Reproduce without installing dependencies or contacting services:

```bash
.venv/bin/python -m pytest core/build/tests/test_validate_detected_types.py core/build/tests/test_detector_subdir_autotools.py core/build/tests/test_validate_probe_cwd.py packages/describe/tests/test_target_shape.py packages/describe/tests/test_tool_readiness.py packages/codeql/tests/test_buildless_mode.py -q
.venv/bin/python -m pytest packages/llm_analysis/tests/test_copilot_native.py core/security/tests/test_session_services.py packages/autonomous/tests/test_agentic_partial_reporting.py packages/codeql/tests/test_database_manager.py core/startup/tests/test_host.py -q
.venv/bin/mypy --follow-imports=silent --no-incremental core/build/build_detector.py packages/codeql/agent.py packages/describe/target_shape.py packages/describe/tool_readiness.py
```

These results do not prove live model dispatch, full frontend parity, fresh
SCA feeds, host-credit enforcement, or production runtime-receipt authority.

### Repository gates

The CI-lint tier (`.github/tests` and `.github/scripts/tests`) and both
repository-invariant scanners exposed failures already present at `c3044dedc`.
Each was triaged rather than suppressed wholesale:

| Gate | Finding | Disposition |
|---|---|---|
| Execution-wait doctrine test | Expected the retired `gpt-6-astra` repository default | Aligned with the committed native `auto` default (`721c2f0eb`) |
| CodeQL pack-resolution pins | IRIS `--additional-packs` roots site was unpinned | Pinned after confirming provenance: the vendored `~/.codeql` cache, else the installed CLI distribution's `qlpacks` directory; never the scanned tree |
| ReDoS idiom census | Banner version-line pattern crossed newlines | Pattern restricted to a single line, removing the census member |
| Miswiring scanner | Four artifact findings | One classification-window false positive and three operator/audit outputs, each baselined with a specific note |
| Vocabulary scanner | Thirteen new literal lists | JSON Schema keywords, a closed provider-route map, and persistence field manifests, each baselined with a specific note |
| Vocabulary scanner | Cargo added a build-probe entry | `_VALIDATION_COMMANDS` count updated from 18 to 19 |

Remaining non-failing warnings predate POST-03: five report-schema list
growths and fourteen stale miswiring baseline entries. The report-writer
closure also retains thirteen pre-existing Bash manual-audit entries.

## October 28 current-tip live acceptance

The operator completed the automated POST-02 procedure on October 28, 2026
local time (October 29 UTC), using RAPTOR commit `a2e7e3825`, Copilot CLI
1.0.105 and fixture commit `28476b576`. The accepted scope was deliberately
bounded to two selected findings per run.

| Check | Result |
|---|---|
| Successful native run | Both sentinels emitted; one part owned two findings; independent lint passed; finalization completed the same run and produced the report, orchestrated JSON and receipt |
| Cancellation/resume | Managed same-service analysis was stopped before writing `part-001`; the run remained Interrupted; premature finalization refused the missing part; only that part was re-dispatched; independent lint and same-run finalization passed |
| Assignment integrity | One active owner per part per attempt; no duplicate concurrent assignment; exact selected-finding coverage |
| Host usage | Cancellation session recorded the explicit operator-selected model, complete status and `39793780000` totalNanoAiu; repository USD limits remained separate |
| Reductions | SCA remained offline/cache-only; then-unsupported native stages remained visible (they were subsequently implemented in POST-03); the explicit two-finding cap left two eligible findings unselected |
| Focused verification | POST-02/native-contract tests passed; scoped mypy and Ruff passed; miswiring/vocabulary gates reported no new findings |

The acceptance is not exception-free:

- An administrator-managed setting replaced an earlier requested model with
  `gpt-6.1-sol`, whose initial `/agentic` prompt returned a cybersecurity 422.
  The successful run recovered within that same launcher-bound session by
  executing only local scan/prep and dispatching the assigned part through the
  active session's operator-selected managed agent. No second frontend or
  provider was started. The helper now requires `--frontend-model` so every
  acceptance session records an explicit same-service model rather than
  inheriting a replaceable default.
- Recovery-path local scan/prep omitted `session_host` from run metadata. The
  verifier did not rewrite it: it required the exact recorded launcher argv,
  fresh Copilot session-only startup banner, target and timestamps,
  Copilot-only finalized model manifest, usage artifact and native receipt.
- The successful session's usage artifact did not attribute managed-agent
  credits. Its zero values are recorded as incomplete/unknown accounting, not
  zero spend. The cancellation session provided complete selected-model
  attribution.

The durable operator workspace was
`out/copilot-post02-acceptance-20261029T011725Z/`; its generated
`acceptance-evidence.md` records the run directories, hashes, usage and four
completed transcript/operator attestations. The workspace remains ignored
runtime evidence rather than a version-controlled source file.

## POST-02 live acceptance procedure

Run this only as an operator from a properly launcher-started session. The
launcher exports RAPTOR's internal-dispatch marker and establishes project and
session binding, the service policy, and the coverage plugin. Do not export
`_RAPTOR_TRUSTED=1` for a plain `copilot` session as a substitute; it bypasses
only the dispatch guard. Do not start a second frontend, provider, or account
to complete any step.

The deterministic setup and verification are automated by:

```bash
.venv/bin/python .github/scripts/copilot_post02_acceptance.py prepare \
  --frontend-model <approved-model-id>
```

The command creates and commits an operator-owned fixture under an ignored
`out/copilot-post02-acceptance-*` workspace, records the checkout and Copilot
version, and prints the exact next command. Its launcher subcommands refuse to
run from inside an existing Copilot process. It starts explicit projectless
bounded sessions pinned to the operator's required `--frontend-model`, records
host usage through `--usage-output-file`, discovers the exact run from the
fixture and launch time rather than choosing the newest output, independently
lints every result, checks lifecycle/artifact integrity, proves incomplete
finalization is refused, and writes `acceptance-evidence.md`. Explicit model
selection avoids administrator replacement of a repository/session default
with a model that refuses the authorized security-analysis prompt; the model
remains within the active Copilot account and is recorded in state/evidence.

The operator still performs four live actions: exit the development session
before launch, let the successful run finish, press Ctrl+C once after managed
analysis starts in the cancellation run, and paste the helper-generated prompt
that resumes only the incomplete parts of that same run. The evidence draft
leaves transcript-only checks as explicit attestations: both sentinels were
visibly emitted, one active managed agent owned each part per attempt, no
duplicate concurrent dispatch occurred, only the cancelled part was
re-dispatched on resume, and no second service/account path was used.

If the frontend rejects its initial `/agentic` prompt before local scan/prep
and the operator recovers within that same launcher-bound session, the tool
child may omit `session_host` from run metadata. The checker never rewrites or
invents that field. It accepts only a missing value—not a conflicting host—
when the exact recorded launcher argv, fresh Copilot session-only startup
banner, target and timestamps, Copilot-only model manifest, usage artifact and
native finalization artifacts all corroborate the run. The evidence draft
records this as an acceptance exception. Likewise, a usage file that reports
zero or omits managed-agent attribution is recorded as incomplete host-credit
accounting, never as proof of zero spend.

1. Prepare a small operator-owned fixture repository with one or two
   deliberately unsafe files. Record its commit, the RAPTOR commit and worktree
   state, `copilot --version`, and the startup `frontend:` and `llm:` lines.
2. Launch a bounded run, for example
   `./bin/raptor --frontend copilot --max-findings 2 <fixture-repo>`.
3. Confirm scan/prep prints both `OUTPUT_DIR=` and `COPILOT_NATIVE_MANIFEST=`
   and leaves the lifecycle Interrupted.
4. Confirm one managed agent per part, no duplicate part or finding
   assignment, and a passing independent
   `libexec/raptor-copilot-agentic lint-part` for every part.
5. Confirm finalization exits 0, the lifecycle becomes Completed, and
   `agentic-report.md`, `orchestrated_report.json` and
   `copilot-native/finalization-receipt.json` are present with a complete
   assessment of the selected findings.
6. In a second bounded run, cancel during managed analysis and confirm the run
   stays Interrupted. Finalization must refuse missing parts. After the
   remaining parts are linted, it must complete the same run.
7. Record host usage from `/usage` separately from repository USD limits.
   `--max-cost-usd` does not meter Copilot-managed agent credits.
8. Confirm no other harness, provider, or account was used. Report
   offline/cache-only SCA and any unsupported native stages as visible
   reductions.

Any missing sentinel, duplicate assignment, unlinted part, unexpected
external service, or second frontend fails the acceptance.
