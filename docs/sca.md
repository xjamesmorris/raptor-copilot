# Software Composition Analysis

RAPTOR's SCA subsystem is a mechanical-tier dependency scanner. It
extracts every dependency from a project, matches against OSV, CISA KEV
and EPSS advisories, surfaces hygiene and supply-chain heuristics, and
proposes hardening patches. No LLM is required for the core pipeline --
the scanner, advisory matcher, reachability analysis and fix planner are
all deterministic.

See also: [commands](python-cli.md), [dependencies](dependencies.md).

---

## Usage

**Slash command:**

```bash
/sca /path/to/project
/sca fix /path/to/project --apply
```

**CLI entry point:**

```bash
bin/raptor-sca /path/to/project
```

**Python dispatch:**

```bash
python3 raptor.py sca --repo /path/to/project
```

`bin/raptor-sca` strips dangerous environment variables (`LD_PRELOAD`,
`PYTHON*`, etc.) before dispatching to the Python implementation.

---

## Subcommands

The default (no subcommand) is `scan` -- the full analyse pipeline.

| Subcommand | Purpose |
|------------|---------|
| `scan` (default) | Walk the target, match every dep against OSV/KEV/EPSS, write findings + report + SBOM + SARIF. |
| `fix` | Pin loose deps and fix CVEs. Safe plan by default; `--apply` to modify files. |
| `check <eco> <name> <ver>` | Single-dep pre-install safety verdict (Clean / Review / Block). |
| `upgrade <eco> <name> <from> <to>` | Forward-looking upgrade impact: advisories resolved vs introduced. Exit codes: 0 = no new advisories introduced, 1 = non-trivial trade-off, 2 = invalid arguments **or verdict unavailable** (OSV lookup degraded; the report carries a "verdict unavailable" section instead of a wrong 0/1). |
| `diff <a.json> <b.json>` | Compare two `findings.json` files. |
| `verify <path> --proposed <dir>` | Round-trip check: re-scan with proposed overlay applied. |
| `health` | Probe every registry client; report reachability. |
| `purl <eco> <name> <ver>` | Build a canonical Package URL. |
| `render <findings.json>` | Re-render `report.md` / SARIF from an existing findings file. |
| `clean-cache` | Reclaim disk space from stale cache entries. Removes entries older than `--max-age` days from `~/.raptor/cache/sca/`. |
| `dt-push` | Upload a CycloneDX SBOM to a Dependency-Track instance. Requires `--url` and `$DT_API_KEY` (or the deprecated `--api-key` flag — argv is world-readable via `/proc/*/cmdline`; the env var wins when both are set). |
| `suppress` | Manage the suppression overlay (`.raptor-sca-suppress.yml`). Sub-actions: `list` (view current suppressions), `check` (validate against fresh findings and surface stale entries). |
| `bump` | Dependency version bump operations. |
| `fingerprint` | Compute, save or check-drift on a binary or OCI image fingerprint. Modes: compute+print (default), `--save` (store baseline), `--check` (detect drift from saved baseline). Accepts local file paths or OCI image refs. |
| `triage` | LLM-assisted triage of supply-chain candidates (typosquat auditing). Runs automatically during scan unless `--skip-triage` is passed; this subcommand invokes it standalone. |
| `fix-diff` | Fetch the upstream fix diffs for findings in a `findings.json` (cap with `--max-cves`). |

---

## Scanning

### Ecosystems

The main ecosystems supported with manifest and lockfile parsing:

| Ecosystem | Manifests and lockfiles |
|-----------|------------------------|
| Python | `requirements*.txt`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `setup.py`, `setup.cfg` |
| Node.js | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `shrinkwrap.json` |
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`, `gradle.lockfile` |
| Rust | `Cargo.toml`, `Cargo.lock` |
| Go | `go.mod`, `go.sum` |
| Ruby | `Gemfile`, `Gemfile.lock` |
| .NET | `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.config`, `packages.lock.json` |
| PHP | `composer.json`, `composer.lock` |
| C/C++ | `vcpkg.json`, `conanfile.txt`, `conanfile.py`, `conan.lock`, `CMakeLists.txt` (FetchContent) |

Discovery also covers `.gitmodules`, Helm charts (`Chart.yaml` /
`Chart.lock`), Docker Compose, GitLab CI, and
`.pre-commit-config.yaml`.

### Inline-Install Sources

In addition to manifests, RAPTOR parses inline package installs from:

- **Dockerfiles**: `Dockerfile`, `Containerfile`, `Dockerfile.<x>`, `*.dockerfile`
- **devcontainers**: `devcontainer.json` / `.devcontainer.json` (`postCreateCommand`, `onCreateCommand`, etc.)
- **Shell scripts**: `*.sh`, `*.bash`
- **GitHub Actions workflows**: `.github/workflows/*.yml` (`run:` block bodies)

Recognised commands across all four shapes: `pip`, `pipx`, `uv pip`,
`apt`, `apt-get`, `yum`, `dnf`, `apk`, `npm`, `npx`, `bunx`, `yarn`,
`pnpm`, `cargo install`, `gem install`, `brew install`, `go install`.

### Advisory Matching

| Source | Use | Cache |
|--------|-----|-------|
| OSV.dev (`/v1/querybatch`, `/v1/vulns/<id>`) | Advisory and affected ranges | 24h disk |
| CISA KEV catalogue | Known-exploited filter | 24h disk |
| FIRST.org EPSS | Exploitation probability | 24h disk |
| CISA Vulnrichment | SSVC exploitation decision (`active`/`poc`/`none`) | 7d disk (1d for upstream misses) |
| Per-ecosystem registries | Version listing for fix | 24h disk |

EPSS and Vulnrichment are fetched once per scan over the unique CVE
set: EPSS in 100-id batches, Vulnrichment SSVC in parallel under a
per-scan budget of 1000 uncached fetches (container-image scans can
carry tens of thousands of distro CVE findings). The budget is spent
on the highest-value CVEs first — non-KEV before KEV-listed, then by
severity and EPSS; findings past the budget simply show no SSVC
signal for that run, and later runs pick them up as the cache warms.

Registries supported: PyPI, npm, crates.io, RubyGems,
Go (proxy.golang.org), Maven Central, Packagist, NuGet, Debian Sources,
Homebrew. Run `raptor-sca health` to probe all ten in one shot.

Bundled data (the popular-package lists behind the typosquat
heuristics, the KEV/EPSS calibration corpus, and the calibration
project samples) is kept fresh by scheduled repository workflows —
see [CI controls](ci-controls.md) for the refresh cadence and the
matching manual scripts under `packages/sca/scripts/`. The typosquat
list refresh refuses an upstream feed that would replace more than
half of the existing reference set (supply-chain guard against a
poisoned feed); `--allow-churn` overrides after review.

Maven coordinates parsed from Gradle DSL files use the canonical
`group:artifact` (colon) shape. Findings from historical runs that
recorded the old slash shape will not correlate with new runs — those
rows never matched an advisory, so re-scan rather than merge.

### Scan Flags

```
--include-commented       parse `# pkg==X` lines as deps (info severity)
--no-inline-installs      skip Dockerfile/sh/GHA inline install extraction
--no-supply-chain         skip mechanical supply-chain heuristics
--no-reachability         skip module-level reachability scan
--no-kev / --no-epss      skip the named enrichment
--offline                 skip network; cache-only
--use-offline-db          route OSV lookups through a local sqlite copy of
                          the OSV daily dumps (air-gapped environments;
                          --offline-db-path overrides its location)
--baseline <findings.json> additionally write baseline-delta.json/.md with
                          only NEW / CLEARED findings since a previous run
--pr-comment              with --baseline, also write pr-comment.md for
                          `gh pr comment --body-file` (--pr-comment-label
                          sets the header label)
--html                    write a self-contained report.html alongside
                          report.md
--skip-triage             skip LLM triage pass
--trust-repo              honour repo-shipped policy files this run
--no-trust-repo           keep strict checks, overriding --trust-repo
                          and the project's `config` trust marker
```

In a Copilot session, the `/agentic` mechanical SCA worker uses this
offline mode in a network-blocked sandbox rather than creating an
unauthorised egress proxy. Its results are marked partial because
uncached or stale vulnerability feeds cannot be refreshed. A standalone
`/sca` scan also supports explicit `--offline`; live feed requests remain
blocked by the session service policy. Workflow-history signing checks
use an empty, private GPG home in that sandbox: presence of a signature
is distinguishable from an unsigned commit, but keys unavailable to the
worker cannot verify the signature's validity.

The Copilot host may refresh public OSV/KEV/EPSS/Vulnrichment cache entries
after an explicit operation-scoped approval. A fresh anonymous receipt at
`~/.raptor/cache/sca/host-refresh-receipt.json`, bound to the exact target,
lets `/agentic` distinguish approved fresh feed data from an arbitrary stale
offline cache; repository networking remains disabled either way.

Repo trust is gated: on untrusted runs a repo-shipped suppression
overlay (`.raptor-sca-suppress.yml`) and license-policy file are
reported but ignored. Precedence: `--no-trust-repo` > `--trust-repo`
> the governing project's `config` trust marker (the run pin's project in-run, this session's project otherwise; one-target gated) > off.

---

## SBOM Generation

Every scan produces a **CycloneDX 1.5** SBOM with VEX block by default
(`sbom.cdx.json`).

An **SPDX 2.3** SBOM can be generated alongside the CycloneDX output by
passing `--spdx`:

```bash
bin/raptor-sca /path/to/project --spdx
```

This writes `sbom.spdx.json` in addition to the default `sbom.cdx.json`.
The SPDX emitter consumes the same resolved dependency data as the
CycloneDX emitter, rendered to the SPDX 2.3 JSON schema. SPDX 2.3 does
not have a native VEX block (SPDX 3.0 will); operators wanting
VEX-in-SPDX should use an external VEX overlay.

### Importing Existing SBOMs

The `--sbom` flag imports a CycloneDX SBOM as the dependency list,
bypassing manifest discovery and parser dispatch:

```bash
bin/raptor-sca /path/to/project --sbom /path/to/sbom.cdx.json
```

This is useful when the build system already emits an SBOM (cargo
auditable, Maven cyclonedx-plugin, Trivy, Snyk export) and you want to
scan the exact resolved deps the build produced rather than re-parsing
manifests. When combined with `--repo`, RAPTOR uses the source tree for
reachability analysis while taking the dep list from the SBOM.

---

## Reachability Analysis

SCA reachability is mechanical. RAPTOR does not ask an LLM whether a
dependency is reachable; it derives the verdict from source evidence and
advisory metadata. LLM review can still run later in the pipeline
unless `--no-llm` is set, but it is not the source of truth for the
reachability verdict.

Best results come from scanning the full source tree. SBOM-only scans
can still identify vulnerable components, but they usually do not
contain enough source context to prove whether a vulnerable package or
function is used.

### Two-Tier Analysis

| Tier | What RAPTOR checks |
|------|--------------------|
| Module/package reachability | Whether project source imports or requires the vulnerable dependency. Python uses AST import parsing; npm uses lightweight import/require scanning; other ecosystems use their own import scanners. |
| Function-level reachability | When advisory data names affected functions or symbols, RAPTOR builds a source inventory/call graph and checks whether those affected functions appear to be called from project code. |

### Reachability Verdicts

| Verdict | Meaning |
|---------|---------|
| `likely_called` | Evidence that an advisory-listed affected function or symbol is called from project source. |
| `imported` | The vulnerable package is imported or required from non-test source, but no specific affected function call proven. |
| `not_function_reachable` | The package is present or imported, but advisory-listed affected functions were not found in the project call evidence. |
| `not_reachable` | No production import/use evidence for the dependency. |
| `called_in_dead_code` | A call was found, but the call site appears to live in dead or unreachable code. |
| `not_evaluated` | RAPTOR could not make a reliable reachability claim for this dependency/ecosystem/run shape. |

Treat `not_reachable` and `not_function_reachable` as triage signals,
not as mathematical proof that the vulnerability is impossible to
trigger. Dynamic dispatch, plugin loading, reflection, generated code,
incomplete source trees, and SBOM-only input can all reduce confidence.

Reports group the detailed vulnerability section into *Reachable /
likely used*, *Present, needs review*, and *Probably not reachable*.

---

## Fix Planning

The `fix` subcommand pins loose dependencies and fixes CVEs:

```bash
# Show fix plan (no files modified)
bin/raptor-sca fix /path/to/project

# Apply fixes in place
bin/raptor-sca fix /path/to/project --apply

# Write rewritten manifests to a separate directory
bin/raptor-sca fix /path/to/project --out proposed/

# CVEs only, skip loose-pin tightening
bin/raptor-sca fix /path/to/project --cve-only

# Upgrade all deps to latest safe version
bin/raptor-sca fix /path/to/project --apply --harden

# Allow fixes that cross a major version boundary
bin/raptor-sca fix /path/to/project --allow-major

# Mechanical-only mode (no LLM, CI-safe)
bin/raptor-sca fix /path/to/project --no-llm

# Never edit test-fixture manifests (pins there are test assertions)
bin/raptor-sca fix /path/to/project --apply \
    --exclude '**/tests/**' --exclude '**/fixtures/**' \
    --exclude '**/testdata/**'
```

### Fix Flags

| Flag | Purpose |
|------|---------|
| `--apply` | Apply changes directly to manifest files |
| `--out <dir>` | Write rewritten manifests to a separate directory |
| `--cve-only` | Only fix CVEs -- do not tighten loose pins |
| `--harden` | Upgrade all deps to the latest safe version. Candidates the promotion-safety check demotes carry the distinct `demoted_safety` status in the candidates JSON and report (inert under every flag combination). |
| `--allow-major` | Include fixes that cross a major version boundary |
| `--no-llm` | Skip LLM analysis (mechanical-only, fast, CI-safe) |
| `--findings <path>` | Reuse findings from a previous scan |
| `--exclude <glob>` | Exclude matching paths from the write set (repeatable). Also accepted by `bump`. |

`--exclude` filters only what gets *edited* -- scanning still reports
findings in excluded trees. Globs match the target-relative path;
`*` spans `/`, and a leading `**/` also matches at the target root.
Typical use: protecting test-fixture manifests whose deliberately-old
pins are test assertions. When patterns drop candidates, the report
prints one summary line with the count; without `--exclude`, writes
that land under test/fixture paths get an informational note.

### LLM-Assisted Major Bumps

When an LLM provider is configured, `fix --allow-major` automatically
analyses major-version-bump CVEs against your project's actual call
sites. If the LLM judges the bump safe, it is included in the plan. If
breaking changes are found, the output shows what breaks and where.

In CI (no LLM), `fix` falls back to mechanical mode -- warns about
major bumps and exits non-zero so the pipeline can flag them. Use
`--no-llm` to force mechanical-only mode regardless.

### Fix Output

| File | Format | Audience |
|------|--------|----------|
| `changes.json` | Structured change record | Tooling, CI |
| `changes.md` | Human-readable change log | Operators |
| `proposed/` | Rewritten manifest copies | Review, then `cp` or `git apply` |

---

## CI Integration

### Hard Gate: Severity Threshold

```yaml
- run: bin/raptor-sca $PROJECT --skip-review --skip-triage \
       --fail-on-severity high --fail-on-kev
  # exits 1 if any finding above threshold or KEV-listed
```

### Soft Gate: Track Over Time

```yaml
- run: |
    bin/raptor-sca $PROJECT --out before-${{github.sha}}
    bin/raptor-sca fix $PROJECT --apply
    bin/raptor-sca $PROJECT --out after-${{github.sha}}
    bin/raptor-sca diff before-*/findings.json after-*/findings.json
```

### PR Gate: Only Fail on Regressions

A turn-key workflow lives at `.github/workflows/sca-pr-gate.yml`.
Triggered on PRs touching any manifest, lockfile,
Dockerfile/Containerfile, docker-compose file, CI workflow, or
pre-commit config, it:

1. Scans the PR merge result (the PR as merged into `main`).
2. Scans `main` as baseline.
3. Diffs the two findings sets.
4. Posts the markdown delta as a PR comment (idempotent -- updates the
   existing bot comment instead of creating new ones on every push).
5. Mirrors the same content to the workflow run's step summary.
6. Fails the build only when new high+ findings appear; resolved ones
   do not penalise the PR.

Operator-tunable: change `--fail-on-severity high` in the workflow to
`medium` for stricter gating, or to `critical` for noisier projects.
The diff command's exit code is 0 = no regression at threshold,
1 = regression found, 2 = inputs invalid.

### Pre-Flight: Registries Reachable

```yaml
- run: bin/raptor-sca health
  # exits 1 if any registry is unreachable; useful behind a corporate proxy
```

### Gate Flags

| Flag | Purpose |
|------|---------|
| `--fail-on-severity <level>` | Exit non-zero if any vulnerable-dependency finding meets or exceeds this severity (info / low / medium / high / critical) |
| `--fail-on-kev` | Exit non-zero if any finding is in the CISA Known Exploited Vulnerabilities catalogue, even below `--fail-on-severity` |
| `--fail-on-supply-chain <level>` | Exit non-zero if any supply-chain finding meets or exceeds this severity |
| `--fail-on-hygiene <level>` | Exit non-zero if any hygiene finding meets or exceeds this severity |
| `--fail-on-license <level>` | Exit non-zero if any license finding meets or exceeds this severity |
| `--fail-on-capability-drift` | Exit non-zero on any image capability-drift finding, regardless of severity |
| `--max-added-capability-buckets <N>` | Exit non-zero when a capability-drift finding adds more than N capability buckets (0 = any new bucket fails) |
| `--include-suppressed` | Evaluate findings marked suppressed in `.raptor-sca-suppress.yml` (default: skip them) |
| `--skip-review` | Skip LLM review pass (faster, CI-appropriate) |
| `--skip-triage` | Skip LLM triage pass |

The same `--fail-on-*` flags work on `render findings.json`, so a CI
job can scan once and gate on the persisted findings.

---

## Output

Every scan run produces:

| File | Format | Audience |
|------|--------|----------|
| `findings.json` | RAPTOR findings schema | Other RAPTOR commands (`/validate`, `/patch`) |
| `report.md` | Human-readable | Operators |
| `sbom.cdx.json` | CycloneDX 1.5 + VEX | SBOM consumers, Dependency-Track, etc. |
| `sbom.spdx.json` | SPDX 2.3 | Compliance pipelines (only when `--spdx` passed) |
| `findings.sarif` | SARIF 2.1.0 | GitHub / GitLab / IDE integrations |
| `diagnostics.json` | Private JSON (mode `0600`) | Current/completed phase, deadline, cancellation/timeout reason, and final success/failed/skipped/unsupported disposition |

When `/agentic` launches its always-on SCA subprocess, that child is
mechanical: LLM review and triage remain gated behind the distinct deep
`--sca` phase. The parent propagates a slightly shorter child deadline and
the child caps each HTTP retry loop, leaving time to write
`diagnostics.json` and exit before the parent timeout. A timeout or
cancellation is therefore a visible failed disposition with an active phase,
never an empty successful scan.
For targets outside the RAPTOR checkout, the sandbox mounts only the canonical
RAPTOR `core/` and `packages/` trees and the Python runtime read-only, not the
whole checkout. An external `RAPTOR_SCA_AGENT` override grants its agent file
only; logs and the SCA cache retain their existing writable paths. The logger
does not require unrelated `out/jobs` or CodeQL directories inside the worker.

The mode contract is enforced centrally: the public API normalizes
`analysis_mode="mechanical"` to review/triage disabled, while direct
`RunOptions` construction rejects contradictory mechanical-plus-LLM gates.
Sub-second remaining deadlines are passed as sub-second transport bounds (or
refused before dispatch when too little time remains); they are never rounded
up beyond the declared deadline. The direct agent accepts the documented SCA
and shared sandbox flags only, including wrapper-forwarded `--sandbox-floor`;
unknown options fail at argparse instead of being silently dropped.

Under `/agentic`, SCA retains its historical 600-second bounded subprocess
default when `--phase-timeout` is omitted; the repository-wide default used by
the other phases does not silently lengthen it. An explicitly supplied
positive `--phase-timeout` overrides SCA too. Explicit
`--phase-timeout 0` means unbounded for both the parent wait and the child:
no internal SCA deadline is installed.

When `/agentic` is already running under an accepted `--no-sandbox` or
`--sandbox none` consent, the SCA worker receives that same backed nonce
through a dedicated RAPTOR-worker dispatch channel. The SCA launcher cannot
mint consent from an arbitrary environment value, and ordinary sandboxed
children still have the nonce stripped.

The direct internal `python -m packages.sca.agent` compatibility surface is
narrower: it runs RAPTOR's data parsers and does not execute target
build/install code, so its historical `--sandbox none` / `--no-sandbox`
library path remains available without minting a global disable consent.
`--no-sandbox` overrides a simultaneously supplied profile before strict
argument parsing. Agentic workers carry a hidden provenance bit and always
re-enter the shared consent gate; external target-execution entry points are
unchanged.

In imported-SARIF-only and `--openant-only` workflows, always-on SCA is
additive rather than a primary scanner requirement. Its failure remains
visible as a partial-run reason and private diagnostic, but cannot by itself
turn otherwise usable imported/OpenAnt output into exit status 1. Explicit
`--sca` and normal Semgrep/CodeQL runs keep SCA in the required scanner set.

### Render Flags

The `render` subcommand re-renders `report.md` / SARIF from an existing
`findings.json` and supports reachability filters:

```
--only-reachable          render only likely_called/imported vuln findings
--hide-not-reachable      hide not_reachable/not_function_reachable vuln findings
--reachability <list>     comma-separated vuln reachability allowlist
```

Reachability filters apply only to `sca:vulnerable_dependency` rows;
hygiene, supply-chain, and licence rows are preserved when re-rendering.

---

## Limitations

- **Dependency resolution is metadata-only by design** -- resolving
  versions never executes a package's build backend. Sdist-only
  manifests fail the dry-run loudly; `--allow-sdist-builds` is the
  explicit per-run risk acceptance.
- **Library-mode floor-raise unsupported on some ecosystems** --
  `harden` refuses to corridor-pin a library's deps and emits
  `library_floor_raise_unsupported` for inline-install (Dockerfile
  `RUN pip install foo`), Debian, Cargo, Go modules, RubyGems. The
  application path still pins these.
- **OSV `affected_functions` coverage is patchy** -- function-level
  reachability only fires when an advisory ships symbol-level metadata.
  Python and Go are the best-covered ecosystems; npm, Maven and others
  mostly stay at the module-level `imported` verdict.
- **CHA-precision for dynamic dispatch in Java / C#** -- virtual and
  interface dispatch currently lands in `not_function_reachable` when the
  static graph cannot narrow the receiver type.
