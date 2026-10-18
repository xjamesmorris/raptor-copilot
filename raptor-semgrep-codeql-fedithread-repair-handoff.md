# RAPTOR Semgrep and CodeQL Repair Handoff: fedithread

Prepared: 2026-10-15.

**Status:** Framework repairs completed and validated on October 16, 2026.
This remains a repair record, not a claim that the target is
vulnerability-free.

## Implementation update

- **CQ-1:** JavaScript/TypeScript uses CodeQL no-build extraction when the
  operator has not supplied an explicit build command. Fresh-path live
  validation performed real extraction and a positive query without invoking
  package-manager canaries or modifying the target.
- **RP-1:** MVP-01 now records truthful per-tool execution state, assessment
  completeness, caps, partial results, failure reasons, and artifact
  references in machine-readable and human-readable reports.
- **SG-1:** RAPTOR's owned Semgrep scope excludes exact `.git` metadata,
  including nested directories and worktree/submodule pointer files, while
  preserving anti-suppression behavior and scanning `.github`, hidden,
  ignored, untracked, test, malformed, and git-named application paths.
- **CQ-2:** IRIS local-pack installation and query health are reported
  separately. Complete sanitized diagnostics are persisted privately with
  bounded references; a successful query after an install warning is
  degraded rather than failed, while query failures remain explicit.

Combined focused validation passed **359 tests** with two repository-marked
integration/corpus deselections. Ruff, Python compilation, command metadata,
and diff checks passed.

## Scope and baseline

Framework checkout:

```text
<framework-checkout>
```

The scan manifest recorded framework commit
`9d4acdcfce00bc47679be3a2b85cda00eae4fd85`, with a dirty worktree, and version
`3.1.0-4270-g9d4acdcfc-local`. Preserve unrelated existing changes. Source line
numbers below are navigation hints for the inspected checkout; use the named
symbols if they move.

| Item | Observed value |
|------|----------------|
| Requested target | `<target-checkout>` |
| Canonical target | `<canonical-target-checkout>` |
| Target commit | `d3e22807835e84c1fb2970acb0a4a3cadcceecc7` |
| Target worktree after both scans | Clean, at the same commit |
| Platform | Linux, Python 3.14.7 |
| Semgrep | 1.172.0 |
| CodeQL | 2.27.2 |
| Target shape | Nine application JS files, six JS test files, HTML, npm manifest |
| Manifest | No declared dependencies or build script; only test/serve scripts |

The checkout placeholders omit machine- and user-specific path prefixes. Both
target placeholders refer to the same fedithread checkout before and after
canonical path resolution.

The runs occurred on **October 14, 2026, approximately 21:39-21:48 PDT**,
equivalent to **October 15, 2026, approximately 04:39-04:48 UTC**. The UTC date
in the reports and local date in directory names refer to the same runs.

The existing root file `raptor-codeql-llm-repair-handoff.md` describes a
different Rust target and Claude structured-output failure. Leave it intact;
do not conflate its diagnosis with this JavaScript case.

## Historical repair priorities and initial impact

| ID | Issue | Initial observed impact |
|----|-------|-------------------------|
| CQ-1 | Automatic npm install selected for JavaScript extraction | Initial CodeQL database creation failed against the read-only target |
| RP-1 | Aggregate report conflates enabled scanners with successful scanners | Initial report showed CodeQL zero findings without an explicit per-tool failure status |
| SG-1 | Semgrep scanned Git sample hooks | Four irrelevant parse failures polluted coverage diagnostics |
| CQ-2 | IRIS LocalFlowSource pack-install warning | Recovery-run install returned status 2; at the time, its exact cause and final enrichment impact were unresolved |

This was the original priority order before implementation. CQ-1, RP-1, SG-1,
and CQ-2 are now implemented and validated as described below. The historical
CQ-2 warning remains independent of the initial npm failure; completing its
diagnostic/reporting repair did not retroactively establish the warning's
external cause.

## Commands and durable evidence

The original command, run from the framework checkout, was:

```bash
python3 raptor.py agentic --repo <target-checkout>
```

It exited 0 after about 198.5 seconds, despite the failed CodeQL subprocess.

Original run directory:

```text
out/<original-agentic-run>/
```

Successful CodeQL recovery directory:

```text
out/<codeql-recovery-run>/
```

| Base directory | Relative artifact | What it establishes |
|----------------|-------------------|---------------------|
| Original run | `.raptor-run.json` | Target commit, versions, lifecycle marked completed |
| Original run | `scan/coverage-semgrep.json` | 15 examined JS files and four Git-hook parse failures |
| Original run | `scan/scan_metrics.json` | Zero findings; no failed or dropped Semgrep packs |
| Original run | `scan/scan-manifest.json` | `policy_groups: ["all"]`, parallel scanning |
| Original run | `raptor_agentic_report.json` | Aggregate status/reporting discrepancies |
| Original run | `autonomous/autonomous_analysis_report.json` | `mode: "prep_only"`, zero results and LLM requests |
| Original run | `sca/findings.json` | Separate missing-lockfile hygiene finding |
| Original run | `agentic-report.md` | Human-readable summary, manually supplemented after recovery |
| Recovery run | `codeql_report.json` | Successful database creation and 201 standard queries |
| Recovery run | `coverage-codeql.json` | 17 actual target files examined |
| Recovery run | `codeql_javascript.sarif` | Zero standard CodeQL findings |
| Recovery run | `codeql_javascript_iris.sarif` | IRIS SARIF exists; do not infer install health solely from its existence |

Failed database-creation log:

```text
codeql_dbs/<target-db-key>/.staging-failed-javascript/log/database-create-<timestamp>.log
```

Successful database and extraction log:

```text
codeql_dbs/<target-db-key>/javascript-db
codeql_dbs/<target-db-key>/javascript-db/log/database-create-<timestamp>.log
```

Run directories and failed staging directories may eventually be cleaned.
The essential diagnostics are copied below so this handoff remains useful.
Raw JSON reports were not rewritten to merge the recovery run; only the
original run's Markdown report was supplemented.

## SG-1: Semgrep parses Git sample hooks

### Historical observed facts

Semgrep examined all 15 application/test JavaScript files and emitted zero
findings. It recorded these four failures, all under the canonical target:

| Relative path | Line | Diagnostic |
|---------------|------|------------|
| `.git/hooks/commit-msg.sample` | 69 | Syntax error: `2` was unexpected |
| `.git/hooks/pre-push.sample` | 47 | Syntax error: `2` was unexpected |
| `.git/hooks/pre-rebase.sample` | 41 | Syntax error: `2` was unexpected |
| `.git/hooks/push-to-checkout.sample` | 26 | Syntax error: `2` was unexpected |

These are not application-JavaScript parse failures. Do not describe this as
four production files missed, a failed Semgrep engine, or four vulnerabilities.

### Historical failure and diagnosis

`packages/static-analysis/scanner.py:1000` (`run_single_semgrep`) builds argv
through `packages.semgrep.runner.build_cmd`.

`packages/semgrep/runner.py:149-247` deliberately uses:

```text
--disable-nosem
--no-git-ignore
--x-ignore-semgrepignore-files
```

These prevent a target from hiding findings with inline suppression,
`.gitignore`, or `.semgrepignore`. The scope-isolation flag also removes
Semgrep's built-in ignore baseline. RAPTOR restores selected exclusions with
`SCOPE_EXCLUDE_BASELINE` in `packages/semgrep/runner.py:57-114`.

At the time of the original run and first handoff draft, that baseline did
**not** include `.git`. This explained a plausible path for Git metadata to
enter the scan, consistent with the observed failures. The first draft
correctly labeled the final flag/exclusion interaction as an unverified
diagnosis rather than a completed fix. Subsequent focused live regressions
isolated the behavior and the repair is now implemented.

### Implemented resolution and current contract

The proposed narrow repair direction was adopted. The
`packages.semgrep.runner.SCOPE_EXCLUDE_BASELINE` tuple now contains the exact
basename `.git`, emitted by `build_cmd` as a RAPTOR-owned `--exclude` pattern.
On the validated Semgrep version, it excludes root and nested `.git`
directories plus worktree/submodule `.git` pointer files. The exclusion is
visible as `cli_exclude_flags_match` scope evidence.

The anti-suppression controls remain in force:
`--disable-nosem`, `--no-git-ignore`, and
`--x-ignore-semgrepignore-files` are still used. The policy does not
blanket-exclude hidden paths or first-party-plausible names. `.github`,
`.env` files, ignored/untracked source, `test/`, `tests/`, malformed
application files, and application paths whose names merely contain `git`
remain in scope.

### Implemented regression coverage

- `packages/semgrep/tests/test_runner.py` pins the exact owned baseline and
  command construction, retains the planted-ignore and first-party scope
  checks, and adds
  `test_exact_git_exclusion_keeps_near_misses_and_first_party_scope` plus
  `test_root_and_nested_git_pointer_files_are_excluded`.
- The live fixture contains Git sample hooks, nested metadata, pointer files,
  `.github`, git-named near misses, matching first-party files, and a genuine
  malformed application file. Git metadata is excluded while the malformed
  application file remains in `files_failed`.
- `packages/static-analysis/tests/test_scanner_semgrep_parallel.py` adds
  `TestSemgrepScopeLiveParity`, proving the package runner and the
  static-analysis sequential and parallel paths observe the same exact scope.

## CQ-1: CodeQL selects npm installation for a no-build JS target

### Historical exact failure

The failed database log, lines 592-603, shows:

```text
npm error code EROFS
npm error syscall open
npm error path <canonical-target-checkout>/package-lock.json
npm error errno -30
npm error rofs EROFS: read-only file system, open '<canonical-target-checkout>/package-lock.json'
Spawned process exited abnormally (code 226; tried to run: [.../.raptor_codeql_build_c6q68tpb.sh])
```

The enclosing CodeQL step returned 1, while the full agentic command continued
and returned 0. The target has no dependencies and no build script.
Read-only containment blocked an unnecessary write; this is not evidence
that the target needs writable permissions or additional dependencies.

### Historical pre-repair call chain

| Historical location | Pre-repair behavior |
|---------------------|---------------------|
| `packages/codeql/agent.py:448-550`, `CodeQLAgent.run_autonomous_analysis` | JavaScript reached build-system detection unless explicitly overridden |
| `core/build/build_detector.py:177-205`, build-system patterns | The JavaScript npm command was `npm install && npm run build`; fallback was `npm install` |
| `core/build/build_detector.py:537-544` | A manifest without a build script selected the install-only fallback |
| `packages/codeql/database_manager.py:1565-1640`, `DatabaseManager.create_database` | A nonempty build command became CodeQL `--command`, with a wrapper when necessary |
| `core/build/build_detector.py:2094-2112`, `generate_no_build_config` | The existing no-build representation used `command=""` |

At the baseline, the compiled-language buildless policy covered `cpp`, `java`,
and `csharp`, not JavaScript. The implemented repair did not mechanically add
JavaScript to that compiled-language set; it introduced the separate
interpreted-language route described below, preserving compiled-language
version gates and cache rules.

### Historical successful workaround

The following command was executed successfully, with the normal RAPTOR
lifecycle and sandbox settings:

```bash
python3 raptor.py codeql --repo <target-checkout> --languages javascript \
  --build-command <codeql-install>/javascript/tools/autobuild.sh
```

The supplied file was inspected first: it invokes the installed CodeQL
JavaScript extractor, not the target's npm scripts. `--build-command` generally
opts a language into traced execution, so this was not permission to
substitute arbitrary repository scripts. The path was machine-specific and
was not hardcoded as the permanent framework fix.

Observed recovery:

- Exit status 0; `codeql_report.json.success` is true.
- Actual extraction covered all nine application JS files, six JS test files,
  `index.html`, and `package.json`.
- The standard `javascript-security-and-quality.qls` suite ran 201 queries
  and emitted zero findings.
- Both run manifests reached `completed`; the target remained clean at its
  original commit.

The explicit-language report contains
`languages_detected.javascript.file_count: 0`; that is not the extraction
count. Database metadata reports 127 files, which is also not the target-only
count. Use the 17 entries in `coverage-codeql.json` and individual
`Done extracting .../fedithread/...` log records as target-coverage evidence.

### Implemented permanent resolution and current contract

The proposed CodeQL-specific route is now implemented in
`packages.codeql.agent.CodeQLAgent.run_autonomous_analysis`.
`_INTERPRETED_NO_BUILD_LANGUAGES` covers `javascript` and `typescript`.
Unless the operator supplies a nonempty per-language build command, those
languages bypass package-manager build detection and use the existing
empty-command `no-build` representation. CodeQL's bundled JavaScript
extractor then performs normal extraction without a database-create
`--command`; this is intentionally distinct from compiled-language
`--build-mode=none`.

Language aliases are normalized at the same boundary as build-command keys,
so `js`/`ts` follow the no-build route and an explicit command supplied under
an alias still opts into traced execution. A generic traced-build trust
setting without an explicit JavaScript/TypeScript command does not re-enable
package-manager execution.

`BuildDetector` still reports npm/yarn/pnpm evidence for its other consumers.
The repair did not install dependencies into the target, add a lockfile,
grant target write access, weaken the sandbox, or hardcode the machine-local
extractor workaround. It also did not use `--build-command true` as a
zero-work success surrogate.

### Implemented regression and live validation

The historical cache trap was avoided with a fresh disposable fixture at a
distinct canonical path. The slow local regression
`packages/codeql/tests/test_javascript_nobuild_live.py::
test_javascript_fixture_extracts_and_queries_without_package_manager`:

- creates package-manager and lifecycle-script canaries;
- performs a fresh JavaScript database extraction with network blocked;
- runs a deterministic positive query for an extracted fixture function;
- records nonempty source coverage; and
- verifies the target tree is byte-for-byte unchanged, with no lockfiles,
  dependency tree, or lifecycle canary output.

`packages/codeql/tests/test_buildless_mode.py` covers JavaScript/TypeScript
canonical names and aliases, preservation of an explicit alias-keyed build
command, the no-build result under a trust marker without a command, and
continued npm detection for non-CodeQL consumers. Existing compiled-language,
cache, language-normalization, and build-command refusal coverage remained
part of the focused validation.

## RP-1: Reports must distinguish failure, no findings, and no review

### Historical reporting failure

The original `raptor_agentic_report.json` recorded:

```text
tools_used.codeql = true
phases.scanning.completed = true
phases.scanning.codeql.enabled = true
phases.scanning.codeql.findings = 0
phases.scanning.codeql.languages = []
```

Those fields did not expose the failed database step. The top-level process
and lifecycle still reported completion.

In the pre-repair final-report construction inspected at
`raptor_agentic.py:4945-5036`, `scanning.completed` derived from
`not skip_scan`, while missing `codeql_metrics` became zero findings and an
empty language list.

The same run also illustrates two nearby reporting distinctions:

- `autonomous/autonomous_analysis_report.json` is `prep_only`, with zero
  results and zero LLM requests. Do not call that a completed LLM review.
- SCA wrote one missing-lockfile hygiene finding to `sca/findings.json`, but
  the aggregate report has `tools_used.sca: true` while `phases.sca.enabled`
  and `completed` are false and `hygiene_findings` is zero. This is separate
  from scanner vulnerabilities; the dependency-free manifest makes the
  warning low-value here. Historically, it established that enablement,
  completion, scanner findings, and hygiene output could not be inferred from
  one another.

The manually supplemented historical `agentic-report.md` remains a handoff
aid. It was not, by itself, evidence of an automated repair at the time.

### Implemented resolution and current contract

The automated report path now carries additive, explicit state instead of
inferring success from enablement:

- `raptor_agentic._tool_state` records `requested`, `attempted`, `completed`,
  `failed`, and `skipped`, plus bounded failure/skip reasons, findings, and
  sanitized bounded artifact references for Semgrep, CodeQL, and SCA.
- `_assessment_from_reports` and the orchestrator's assessment summary record
  `requested`, `eligible`, `selected`, `analyzed`, `unreviewed`, cap value,
  cap source, cap reason, and completeness. Mechanically ineligible prep
  records do not create a false analysis backlog.
- `_build_run_result` distinguishes `complete`, usable `partial`, and
  `failed`. A run with successful Semgrep output and failed CodeQL output is
  visibly partial and returns 0 because usable aggregate evidence exists.
  If requested scanners produce no usable output, the result is failed and
  returns 1. CLI/configuration failures before aggregate output retain exit 2.
- `_result_contract_fields` persists the additive machine-readable
  `result` and `assessment` objects without deleting legacy report fields.
  `_completion_partial_metadata` carries the same truth into lifecycle
  metadata, including per-tool failure receipts.
- `_build_tool_execution_report_section` renders per-tool state, whether it
  was attempted, findings or `unknown`, reason, and artifact in Markdown.
  `_finalize_run_lifecycle` completes usable partial runs with explicit
  partial metadata and fails all-unusable requested-scanner runs.

Standard CodeQL success and IRIS enrichment health are also kept separate:
an install warning followed by successful enrichment queries is reported as
degraded enrichment, not as a failed standard CodeQL scanner.

### Implemented regression coverage

`packages/autonomous/tests/test_agentic_partial_reporting.py` covers the
original Semgrep-success/CodeQL-failure case, all-requested-scanners-failed
behavior, requested-but-skipped scanners, SCA timeout state, bounded private
failure artifacts, assessment caps and unreviewed counts, additive JSON
persistence, Markdown state rendering, and lifecycle completion/failure
metadata. `packages/autonomous/tests/test_agentic_cli_exit_code.py` pins the
CLI's explicit return of the persisted aggregate exit contract, and
`core/run/tests/test_orchestrated_report_schema.py` pins the assessment
schema.

## CQ-2: IRIS install warning and enrichment-health reporting

### Historical warning and unresolved external cause

The recovery command reported that the IRIS LocalFlowSource pack installation
returned status 2. Standard CodeQL analysis succeeded and an IRIS SARIF was
emitted. The install warning alone does not establish that all IRIS queries
failed. Its exact external cause and effect were not isolated during the
historical recovery session, and the completed framework repair does not
retroactively identify them.

At that time, the relevant behavior was:

- `packages.codeql.query_runner.QueryRunner._run_local_pack` performed the
  lazy `codeql pack install` and then proceeded to analysis.
- Its lazy `codeql pack install` call uses the configured egress proxy.
- On nonzero return, only a 300-character warning summary was retained in the
  visible diagnostic path even though execution could proceed to analysis.

That 300-character-only limitation is historical. Authentication, network
denial, missing dependencies, and other possible causes must still not be
asserted for the original status-2 event without its underlying diagnostic
stream.

The recovery also emitted mountless-sandbox/degraded-egress warnings. No
sandbox override flags were supplied. Keep those warnings separate from
CQ-1; they are not justification to weaken containment or grant new network
access.

### Implemented resolution and current contract

`QueryRunner._run_local_pack` now models installation and query execution as
independent completed/failed/skipped states:

- Complete pack-install stdout and stderr are redacted, control-escaped, and
  persisted in a private mode-`0600` JSON artifact by
  `_persist_local_pack_install_diagnostics`. The 300-character value remains
  only a bounded operator/report summary, not the sole retained diagnostic.
- Failed query stdout and stderr receive the same treatment through
  `_persist_local_pack_query_diagnostics`.
- `_local_pack_enrichment_health` treats successful query execution after an
  install warning as completed but degraded enrichment. A query failure stays
  failed even if installation also warned, and both states remain visible.
- `summarize_iris_enrichment_health` exposes aggregate and per-language
  machine-readable health with bounded, sanitized artifact references.
  `CodeQLWorkflowResult.to_dict` and the agentic per-tool projection preserve
  that state without rewriting successful standard CodeQL analysis as failed.
- When pinned dependencies are already available in the local CodeQL cache,
  installation is explicitly skipped rather than reported as an attempted
  success. Diagnostic-artifact write failures are surfaced separately and do
  not falsify the underlying install/query execution state.

The sandbox and egress policy were not weakened.

### Implemented regression coverage

`packages/codeql/tests/test_iris_install_diagnostics.py` covers complete
private sanitized streams, bounded visible summaries, successful and skipped
installation, install-warning/query-success degradation, genuine query
failure, diagnostic-artifact write failure, workflow serialization, and
bounded hostile artifact references.
`packages/codeql/tests/test_terminal_output_scrub.py` continues to pin safe
terminal rendering for install and query diagnostics.
`packages/autonomous/tests/test_agentic_partial_reporting.py` verifies that
degraded or failed enrichment remains distinct from standard CodeQL scanner
success.

## Completion record and validation boundaries

When this handoff was first written, no fixes or regression tests had yet been
implemented. That statement is historical and superseded: CQ-1, RP-1, SG-1,
and CQ-2 are now implemented, with the focused validation summarized in the
implementation update.

The validation used fresh local fixtures, the locally installed CodeQL
bundle, mocked IRIS subprocess outcomes where appropriate, and the focused
repository test suites. It did **not** perform a new full fedithread agentic
or CodeQL rescan, did **not** validate a real external registry/network
failure path, and did **not** establish zero vulnerabilities. The historical
zero-finding Semgrep and standard CodeQL outputs remain evidence about those
specific runs only. Repair completion is not a vulnerability-free assessment
of the target.
