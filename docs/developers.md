# Developer Guide

**This page is developer-facing by design.** It is the one sanctioned
home for developer documentation under `docs/` — everything else in
this directory documents the operator surface (flags, outputs,
behaviour). It carries the durable orientation a new contributor
needs and nothing deeper: the tree, docstrings, and `--help` output
are the reference for anything this page does not cover, and if a
section here grows past orientation size it is restoring cut material,
not curating. Contribution *process* — setup, tests, style, review,
security conventions — lives in [CONTRIBUTING.md](../CONTRIBUTING.md).

## The two-layer split

RAPTOR is a Python **execution layer** (scanning, subprocess
management, SARIF parsing, LLM dispatch, cost tracking — no judgement
calls) driven by an interactive **decision-layer frontend**. Claude
Code remains the default; GitHub Copilot CLI is supported when selected
explicitly on Linux and resolved to a directly identifiable native
executable. The backend-neutral host/session contract in
`core/startup/host.py` keeps frontend selection, installed executable
presence, verified session ownership, and headless provider usability as
separate facts. Native decision assets live in `.claude/`, `tiers/`,
`plugins/agents/`, and `CLAUDE.md`. The split is deliberate: the Python
layer runs standalone in CI, the decision layer drives it interactively.
When you add a capability, the mechanical part goes in Python and the
judgement part goes in a skill or command file — never the other way
round.

## Decision-asset discovery contract

`.claude/commands` and `.claude/skills` are authoritative for both
frontends. Keep command stems disjoint from frontend-normalized skill names
(skill frontmatter names have whitespace replaced with `-`). Claude can hide
a same-name slash command, and Copilot projects commands and skills into the
same `skill list --json` namespace, where one row shadows the other.

Custom agents have a split presentation with one source of truth:

- `plugins/agents/agents/*.md` is authoritative and is loaded only into
  Claude by `bin/raptor` as the `raptor-agents` plugin. Every definition
  explicitly declares `model: inherit`; do not remove it. Claude Code
  2.1.301 otherwise permits ambient `CLAUDE_CODE_SUBAGENT_MODEL` or
  `ANTHROPIC_MODEL` selection to change a subagent away from the session
  model. Plain `claude` does not auto-load this plugin; the launcher also
  establishes the trusted `RAPTOR_DIR`/project identity required by its
  security-hook dispatcher.
- `.github/agents/*.md` is the generated Copilot projection. It is identical
  in name, description, tools, skills, hooks, and instruction body, with only
  `model: inherit` removed because Copilot rejects that custom-agent value.
  Never edit projected files directly.

After an authoritative edit, run
`python3 .github/scripts/project_agent_projection.py --write`. The default
check and `--json` inventory are side-effect-free. Projection and
feature-ledger tests reject missing, duplicate, disabled, warning-producing,
or semantically divergent entries.

Sensitive Claude-agent tool restrictions live in
`plugins/agents/hooks/hooks.json`, not agent frontmatter. Its fail-closed
dispatcher keys policy on Claude's plugin-scoped `agent_type`, invokes the
existing focused validators without a shell, and leaves the main session,
built-ins, other plugins, and known unrestricted RAPTOR agents unchanged.
Copilot does not execute this Claude plugin hook; `.github/agents` parity is
prompt/tool metadata parity only, never a claim that the five restricted
agents have the same mechanical URL/Bash/write boundary there.

There are two upstream observation limits in Copilot CLI 1.0.100-1. Skills,
plugins, and instructions have native JSON list commands, but custom agents
do not; the repository's projection `--json` report is deterministic local
evidence, while a fresh `/agent` or `/env` UI capture is still required for
live host acceptance. Remote-agent-index lookup failures and the bundled
`computer-use` plugin-directory warning originate outside this repository,
so RAPTOR records them but does not suppress or reinterpret them. Claude's
complete slash-command inventory is likewise exposed by the live init event,
so deterministic layout parity does not replace a bounded live rerun.

Reviewers and automated agents evaluating the staged Copilot work should use
the [Copilot integration patch map](copilot-patch-map.md) to distinguish
direct integration changes, required security foundations, fake-only
validation layers, and independent LLM improvements.

## Layering rules

- **`core/`** is shared infrastructure. Dependencies point one way:
  everything may import `core/`, `core/` does not import `packages/`
  at module level (the few exceptions are lazy, function-level imports
  for feature probes such as `doctor`).
- **`packages/`** holds independent security capabilities. Each
  package owns its CLI, tests, and domain logic. Cross-package imports
  stay minimal; where capabilities genuinely compose, one package may
  drive a sibling (e.g. `static-analysis` runs the `semgrep` and
  `coccinelle` stages).
- **`libexec/`** scripts are thin dispatch shims for the decision
  layer; they delegate to `core/` or `packages/` and hold no logic
  worth testing on its own.
- **`engine/`** separates detection rules from the packages that run
  them, so rule updates never touch package code.
- Structural facts vs reasoning: `core/inventory/` captures what the
  code *is* (file enumeration, function extraction, call graph);
  `core/analysis/` reasons about it (reachability, taint summaries,
  the binary oracle). Keep new code on the right side of that line.
- `core/llm/` is the only place provider APIs are touched. It gives
  every caller cost tracking, retries, caching, and the per-model
  reliability scorecard for free.

## Package map

One line of purpose per real capability (run `ls packages/` for the
authoritative list; each package's README or module docstring is the
detail):

- **`static-analysis`** — Semgrep policy-group scanning plus the
  Coccinelle stage; normalises everything to SARIF (`scanner.py`).
- **`semgrep`** / **`coccinelle`** — rule-pack management and the
  `.cocci` runner behind the scan stage, consumed by
  `static-analysis` and the audit tool chain.
- **`codeql`** — CodeQL database creation, suite execution, and
  dataflow validation (SMT path feasibility plus LLM review).
- **`llm_analysis`** — LLM exploitability analysis of findings; the
  orchestrator dispatches `claude -p` sub-agents and correlates
  multi-model verdicts.
- **`exploitability_validation`** — the staged `/validate` pipeline
  proving findings real, reachable, and exploitable.
- **`fuzzing`** — AFL++ campaign orchestration, corpus management,
  crash collection and ranking.
- **`binary_analysis`** — GDB-driven crash triage and context
  extraction for externally- or fuzzer-discovered crashes.
- **`exploit_feasibility`** — binary mitigation analysis; produces the
  `exploitation_paths` verdicts the exploit workflow is gated on.
- **`sca`** — dependency scanning against OSV/KEV/EPSS advisory data,
  SBOM generation, CI gating.
- **`web`** — crawler, fuzzer, and OWASP-style scanner for web
  applications (alpha).
- **`code_understanding`** — the `/understand` modes (map, trace,
  hunt, teach, study).
- **`checker_synthesis`** — turns one confirmed bug into a Semgrep or
  Coccinelle rule and sweeps the codebase for variants.
- **`frida`** — dynamic instrumentation runs (attach/spawn, JS hooks,
  event capture).
- **`joern`** — Joern CPG server lifecycle and queries for the audit
  tool chain.

The hypothesis-driven audit itself lives in `core/audit/`
(orchestrator, strategies, gates) because several packages and the
decision layer share it.

## engine/: authoring detection rules

Where rules live:

- `engine/semgrep/rules/<category>/*.yaml` — in-repo Semgrep rules.
- `engine/coccinelle/rules/*.cocci` — Coccinelle semantic patches;
  `prereqs/` holds inventory patches, `source_intel/` the
  source-intel rules.
- `engine/codeql/queries/` and `engine/codeql/suites/` — custom CodeQL
  queries and suite configs. Defaults are the official per-language
  `security-and-quality` suites; see `engine/codeql/suites/README.md`.

Conventions a new rule must follow:

- **Fixture gate.** Every in-repo Semgrep rule ships a positive
  fixture (must fire) and a negative fixture (must stay silent) under
  `engine/semgrep/tests/fixtures/`; the real semgrep binary
  adjudicates in `engine/semgrep/tests/test_rule_fixtures.py`.
- **Negative controls.** `engine/negative_controls/` holds known-safe
  code that superficially resembles each bug family (e.g. a
  parameterised query whose SQL text still contains `SELECT` and a
  `LIKE '%'`). Synthesized per-hypothesis rules are run against the
  matching control at sweep time (`core/audit/sweep.py`); a rule that
  fires on it is a presence detector and its verdict is capped at
  inconclusive. A new bug-family keyword needs a control fixture.
- **Data packs over hardcoding.** Identifier vocabularies live in
  JSON packs, not in rule or Python logic:
  `engine/coccinelle/source_intel/crypto/packs/` (schema and growth
  rules in its README — a new library is a new pack file, no `.cocci`
  edit; invalid entries are dropped with a warning, a structurally
  broken pack is skipped, never fatal),
  `core/audit/data/vocab_packs/`, and
  `core/function_taxonomy/data/packs/`. The vocab-lists CI gate
  (below) enforces this.

## CLI help-text standard

Every CLI entry point (package agents, `libexec/` scripts) ships a
`--help` with:

1. a one-paragraph description of what it does;
2. required arguments;
3. optional arguments with their defaults;
4. at least two usage examples.

`--help` is authoritative. End-user docs describe the operator
surface and defer to it — do not add flag inventories to `docs/`
pages when you add a flag; update the help text.

## Sandbox: what code may assume

[sandbox.md](sandbox.md) is the operator surface; the `sandbox()` /
`run()` docstrings in `core/sandbox/` are the kwarg reference. The
model in ten lines:

- Isolation composes up to six layers — user, network, PID, IPC, and
  mount namespaces plus Landlock/seccomp/rlimits. Each layer falls
  back gracefully with a one-time warning; nothing silently downgrades
  to "no isolation", and the untrusted entry points fail closed
  rather than degrade silently.
- Egress-proxy enforcement is tiered, strongest available first:
  empty network namespace bridged to the proxy; Landlock pin to the
  proxy port plus a UDP block; environment variables alone as the
  last resort.
- New code picks a **trust level**, not kwargs: `run_untrusted()` /
  `run_untrusted_networked()` for anything attacker-derived,
  `run_trusted()` only when the full command line is RAPTOR-owned.

What code must **never** assume: that a specific layer engaged on a
given host — the run's `sandbox_info` stamps (`proxy_enforcement`,
`mount_ns_degraded`, `degraded_net_deny`, `audit_engaged`) are the
truth, so read them instead of assuming; that `$HOME`, `/tmp`, or the
network inside a sandbox are the host's; or that it may bypass
`core.sandbox` for subprocess work touching untrusted input.

## Mechanical gates you will hit

The full control inventory, triggers, and reproduce-locally commands
are in [ci-controls.md](ci-controls.md). The ones that bite
contributors, one line each:

- **ruff** (PR-blocking) — `F401`/`F811`/`F821`/`F841` over changed
  Python files; config in `pyproject.toml`.
- **command-metadata** (PR-blocking,
  `.github/scripts/check_command_metadata.py` and
  `.github/scripts/project_agent_projection.py`) — command dispatch
  metadata must resolve, the generated Copilot agents must match the
  authoritative Claude plugin definitions, and the plugin-level
  identity-hook registry/configuration must stay closed.
- **env-docs** (PR gate + daily sweep, `.github/scripts/check_env_docs.py`) — extracts
  every environment variable the tree reads or writes; an undocumented
  operator-facing variable fails, and so does a stale entry in
  [environment.md](environment.md).
- **vocab-lists** (PR gate + daily sweep, `.github/scripts/check_vocab_lists.py`) —
  literal function-name lists longer than nine names outside the
  data-pack seams fail; route the names through a pack.
- **miswiring** (PR gate + daily sweep, `.github/scripts/check_miswiring.py`) — dead
  definitions, kwarg/signature mismatches, swallowed exceptions,
  parsed-but-never-read flags. Note it counts textual mentions in
  `docs/`, `.claude/`, `bin/`, `tiers/`, and `.github/` as
  references — a doc line can keep a symbol "alive".
- **optional-dep-imports** (PR gate + daily sweep) — test files importing optional
  packages need an import guard, or they pass on developer hosts and
  fail on bare CI.
- **canonical-json** (PR gate + daily sweep, `.github/scripts/check_canonical_json.py`)
  — canonical JSON byte forms are frozen: inside the MAC/hash module
  list every raw `json.dumps` must be `core.json.dumps_canonical` or
  baselined with a note, and a `json.dumps` result flowing into
  `hashlib`/`hmac` anywhere is a new canonical site that must be
  routed through `dumps_canonical` or baselined.
- **ci-controls doc guard** (PR,
  `.github/tests/test_ci_controls_docs.py`) — every path named in
  [ci-controls.md](ci-controls.md) must exist on disk.
- **preflight hazards** (PR, `.github/workflows/preflight.yml`) —
  re-runs the PR's changed tests under CI-reality hazards (hidden
  optional deps, shuffle legs, duration guard).

Each baseline file under `.github/scripts/*_baseline.json` is an
exception list whose target size is zero: fix the finding, or baseline
it deliberately with a note.
