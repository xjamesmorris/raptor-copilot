# RAPTOR with GitHub Copilot CLI

Copilot can host RAPTOR's interactive decision layer on Linux, loading its
instructions, commands, skills, agents, and coverage plugin. Repository-owned
execution is **session-only and offline**: it cannot silently switch to a
separate harness, provider, account, or ancillary service.

## Service/account boundary

Only the already-running Copilot session owns its authenticated account.
RAPTOR does not treat another `copilot` process, a Claude CLI installation,
an API key, a configured provider endpoint, or a local inference server as
that session. A different model within the active Copilot service is not,
by itself, a different account.

Under both direct Copilot launches and `--frontend copilot`, RAPTOR:

- disables provider autodetection, credential probes, Claude fallback,
  provider dispatchers, update checks, and automatic SAGE/Ollama calls;
- refuses explicit standalone providers too: `--model`, saved credentials,
  `--yolo`, sandbox overrides, and project trust are not service consent;
- installs a Linux seccomp network ceiling at RAPTOR's `core` bootstrap.
  Native descendants remain offline even if they clear their environment.
  Named Unix services and loopback inference are blocked as well as remote
  services; anonymous stream/seqpacket socketpairs remain usable for IPC;
- refuses execution if the ceiling cannot be installed, if socket/io_uring
  descriptors were inherited, or if bootstrap occurs after threads started.
  Linux and `libseccomp.so.2` are required.

External work requires fresh authorization for the exact operation, service,
account/credential identity, and data being sent. RAPTOR has neither a
verified bridge to Copilot's current credentials nor a verified scoped-grant
channel, so repository-managed external transports stay blocked; there is
no environment/config opt-out. Network-dependent commands may therefore
refuse rather than complete. Native session reasoning and local file work
remain available. Approval to patch this repository does not grant service
access, and deleting markers or launching another harness is not a remedy.

**Boundary:** this protects repository Python entry points and their process
trees, plus the repository's SAGE shell entry points. It is not an OS-wide
firewall: arbitrary tools launched directly by Copilot, host-managed MCP or
extensions, Copilot's own account routing, already-running processes, and
hostile same-UID modification of the framework are outside that enforcement.
The project instructions require explicit approval on those host surfaces;
host/OS controls are necessary for a universal egress guarantee.

## Quickstart

Install the native Linux Copilot CLI and sign in with `copilot login`:

```bash
curl -fsSL https://gh.io/copilot-install | bash
```

Do **not** use `npm install -g @github/copilot` for RAPTOR's Copilot frontend.
That upstream-supported package installs a JavaScript loader; RAPTOR's live
host contract intentionally requires a directly identifiable native Linux ELF
and will refuse the loader. Install Python dependencies with
`uv sync --locked`; source scanning also needs Semgrep. From this checkout's
root:

```bash
source .venv/bin/activate
./bin/raptor doctor --verbose

# Start with this repository's Copilot defaults
./bin/raptor --frontend copilot

# Or explicitly select Astra, max reasoning, and long context
./bin/raptor --frontend copilot --model gpt-6-astra \
  --reasoning-effort=max --context=long_context

# Start against a target, resume an exact session, or use Copilot's global
# latest-session selection
./bin/raptor --frontend copilot /path/to/code
./bin/raptor --frontend copilot --max-findings 500 --max-cost-usd 500 /path/to/code
./bin/raptor --frontend copilot --resume <session-id-or-name>
./bin/raptor --frontend copilot --continue

# Explicitly grant Copilot all permissions for this launch only
./bin/raptor --frontend copilot --yolo /path/to/code
./bin/raptor --frontend copilot --project my-project --yolo --continue
```

Use `./bin/raptor` to avoid accidentally selecting another checkout on PATH.
Keep `=value` for the reasoning/context flags; separate values would be
interpreted as target arguments by RAPTOR's passthrough parser.

Prefer `--resume <session-id-or-name>` (or `--resume=<...>`) for bounded
automation. RAPTOR maps it to Copilot's exact `--session-id` surface, preserves
the value, and starts no `/raptor` turn. It cannot be combined with
`--continue` or a target. Bare `--continue` intentionally retains Copilot's
native global-recent-session behavior; `RAPTOR_REGISTRY_HOME` isolates
RAPTOR's project/run ownership but does not redefine Copilot's global history.

`--yolo` is an explicit Copilot frontend permission choice. RAPTOR passes it
through unchanged only when the operator supplies it; RAPTOR never enables it
by default. It is not `--trust-repo`, does not set a RAPTOR project trust
marker, and does not weaken RAPTOR analysis sandbox policy. With a target,
project selection remains launcher-owned while Copilot receives `--yolo` and
the `/raptor <target>` prompt (unless `--max-findings` or `--max-cost-usd`
selects `/agentic`). With `--continue`, Copilot receives both `--yolo` and
`--continue` without a new initial prompt. These recognized launcher options
keep the same roles when ordered before or after one another or the target;
none is reinterpreted as the target or as project trust.

The launcher submits `/raptor` by default, which dispatches the agentic
pipeline. `--max-findings N` (or `--max-findings=N`) instead submits
`/agentic --max-findings N --repo <target>`; use `0` to remove the
finding-count cap. `--max-cost-usd USD` (or `--max-cost-usd=USD`) submits
`/agentic --max-cost-usd USD --repo <target>` to set a positive per-run
LLM cost cap. You can combine the two flags; `inf` requests no per-run cap,
but a `tuning.json` default ceiling can still apply. Both are launcher
options, not Copilot CLI options. An explicit target must be an existing
repository directory; without one, `/agentic` resolves the active project
target or caller directory as usual. Neither option can be combined with
`--continue` or `--resume`. The launcher `--model` still selects only the
Copilot session model, not RAPTOR's finding-analysis model. Other analysis
time and call limits still apply.

Startup reports the frontend on its own line immediately above `llm:`, for
example with an explicit `--model gpt-6-astra`:

```text
frontend: GitHub Copilot CLI (model: gpt-6-astra)
   llm: Copilot session only (standalone providers blocked)
```

Without an explicit model, the label is `session/config default`. The static
"Based on Claude Code" attribution is not the active frontend indicator.
Claude CLI installation is not authentication or authorization, so its
availability is not advertised as a fallback here. Startup does not
validate other accounts or warm ancillary services.

## Development defaults

For ordinary development without starting RAPTOR's `/raptor` workflow, run
`copilot` from this checkout. Direct launch skips RAPTOR's preflight checks,
session/project binding, and automatic coverage-plugin loading.

Copilot loads RAPTOR's agents from the generated `.github/agents/`
projection. The authoritative definitions live in
`plugins/agents/agents/` for Claude Code and retain explicit
`model: inherit`; the projection is instruction-identical but omits that one
Copilot-incompatible field. Regenerate and verify it with:

```bash
python3 .github/scripts/project_agent_projection.py --write
python3 .github/scripts/project_agent_projection.py --json
```

The JSON command is side-effect-free and must report 18 agents with empty
`errors` and `warnings`. Copilot CLI 1.0.100-1 has no native JSON custom-agent
list, so `/agent` or `/env` remains the live UI acceptance surface.

The projection does **not** provide Claude plugin-hook parity. Copilot custom
agents do not execute `plugins/agents/hooks/hooks.json`; the five
identity-gated URL/Bash/write restrictions documented in
`docs/agent-security.md` are Claude-launcher guarantees only. Copilot retains
the same agent prompts and tool grants, but do not describe those hook
restrictions as mechanically enforced on this frontend.

New Copilot sessions here default to **GPT-6 Astra, max reasoning, long
context**, stored only in `.github/copilot/settings.json`. The repository does
not set a model for Copilot's built-in managed `execution_subagent`. To
reapply the parent defaults:

```bash
copilot config --repo model gpt-6-astra
copilot config --repo reasoningEffort max
copilot config --repo contextTier long_context
```

Use `copilot --continue` or `copilot --resume` to resume development sessions;
resumed sessions can retain their previous model selection.

### Explicit and catalog-unlisted parent models

The launcher treats a non-empty Copilot `--model` value as an opaque native
frontend model id. It does not require the id to appear in Copilot's offline
help catalog, rewrite it, add a catalog row, or silently substitute another
model:

```bash
# One RAPTOR session
./bin/raptor --frontend copilot --model gpt-6-astra
./bin/raptor --frontend copilot \
  --model=gpt-6-astra

# Repository default used by direct Copilot and by RAPTOR launches without
# an explicit --model
copilot config --repo model auto
```

Both `--model VALUE` and `--model=VALUE` preserve the model text exactly.
Missing and empty Copilot values are rejected, and a following option is not
consumed as the model. If an unusual model id itself starts with `-`, use the
equals form so the value remains unambiguous.

Repository configuration is stored in `.github/copilot/settings.json`.
When no launcher `--model` is present, the startup line deliberately says
`session/config default`: RAPTOR leaves native configuration and resumed
session state to Copilot rather than parsing or restating an effective model.

Catalog absence does not prove service availability. The native Copilot CLI,
organization policy, configured provider, and service remain the acceptance
boundary. If they reject an unavailable or invalid model, RAPTOR preserves
that failure; it does not retry with the repository default or another model.

This passthrough does not create a RAPTOR analysis provider, alter Copilot
provider credentials or wire-model routing, or invent capability, token-limit,
or cost metadata for an unknown model. Parent frontend, child-agent, and
RAPTOR analysis model controls remain separate as described below.

### Copilot session credit floor

The installed Copilot CLI used for MVP-10 acceptance, 1.0.100-1, documents and
enforces a minimum `--max-ai-credits` value of **30**. The launcher recognizes
both `--max-ai-credits 30` and `--max-ai-credits=30`, rejects unambiguously
decimal values below 30 before frontend execution, and otherwise preserves the
native argument for Copilot to validate. RAPTOR does not invent a smaller
credit budget or reinterpret this parent-conversation limit as a child-model or
finding-analysis limit.

The limit is conversation-wide, and Copilot learns a model call's usage only
after that call returns. One call may therefore cross the configured limit
before Copilot blocks a later call. Use the supported floor for bounded smoke
runs and measure actual usage from `--usage-output-file`; do not describe 30 as
a guarantee that the session will consume 30 credits.

## MVP-10 live parity acceptance

Bounded live acceptance completed on October 17, 2026 (October 18 UTC) with
Claude Code 2.1.301 and Copilot CLI 1.0.100-1. The composite runs verified:

- all 39 commands and all 18 custom agents under both frontends, plus all 52
  Copilot project command/skill entries;
- exact project and session binding, same-session continuation, and explicit
  Copilot resume without injected name or initial prompt;
- one canonical read-coverage record per source read, exact realpaths, and
  owner-only `0600` manifest and JSON artifacts;
- Completed, Failed, Cancelled, and direct SessionEnd orphan-cleanup states;
- project status, coverage, provenance, findings, and report artifacts;
- separate parent, managed-child, and RAPTOR finding-analysis model controls;
  and
- unchanged fixtures, source files, and tracked worktree content.

Raw transcripts, usage, machine identity, and session evidence remain local
under ignored `out/mvp10-parity-*` and `.mvp10-state/` paths; they are not
commit artifacts.

The acceptance has three explicit boundaries:

1. Live `--yolo` was not exercised; deterministic native-argv tests cover its
   explicit Copilot-only passthrough.
2. Copilot's built-in managed `execution_subagent` ignored a repository model
   request and selected GPT-5.6 Luna. Usage output is authoritative; this is
   an upstream limitation rather than a repository parity failure.
3. The five security-sensitive custom-agent WebFetch/Bash/Write policies are
   enforced by the Claude launcher plugin. Copilot custom agents do not run
   Claude plugin hooks, so those restrictions are not Copilot guarantees.

## The three model controls

| Layer | Configuration |
|---|---|
| Parent Copilot session | Repository defaults above, `--model`, or `/model` |
| Copilot managed execution child | Upstream-managed; observe the effective model in usage output |
| RAPTOR finding analysis | `/agentic --model MODEL` and `~/.config/raptor/models.json` |

An execution subagent using Luna does not mean the parent or RAPTOR's analysis
model changed. In the 1.0.100-1 live acceptance, a repository
`subagents.agents.execution-subagent.model` request for GPT-5.4 Mini did not
pin this built-in managed agent: usage output showed GPT-5.6 Luna instead.
The observed `execution_subagent` tool-call arguments also contain `query`,
`description`, and `mode`, not a per-call model field. Prompt prose and that
repository key therefore are not exact model controls for this managed agent.

Usage output is authoritative for the model Copilot actually selected. Record
that observed model, but do not require it to match a requested child model or
present a difference as an acceptance failure. An explicit parent `--model`
remains parent-only, and neither parent nor managed-child selection configures
RAPTOR finding analysis.

Outside Copilot, RAPTOR analysis can use configured providers or its Claude
Code fallback. Inside Copilot, those transports are blocked: selecting this
frontend does not enable a headless Copilot provider, and repeating
`/agentic --model` does not authorize other services/accounts.

## Long-running commands and child permissions

RAPTOR analysis commands intentionally stream progress, cost, and the
`OUTPUT_DIR` sentinel without filtering. Copilot's higher-priority tool policy
still governs execution: use `execution_subagent` for ordinary execution and
multi-command terminal work. When the active policy permits direct shell for
exactly one command whose complete, unfiltered stdout is required, a literal
RAPTOR analysis dispatch fits that narrow exception; otherwise use
`execution_subagent`. The repository does not create a broader exception.

For a permitted direct-shell dispatch, use one attached synchronous shell
with a stable shell ID. Treat `initial_wait` as an observation window, not a
process deadline:

| Event | Meaning and action |
|---|---|
| Bash explicitly reports that the command is still running and returns a shell ID, while telemetry carries `shell_error_category=command_timeout` | Preserve that shell ID. The label alone does not establish a process or RAPTOR timeout; do not fail or restart the run. |
| `shell_completed` notification | Read the same shell once with `read_bash`; use its final exit code and `.raptor-run.json` lifecycle state. |
| Operator cancellation | Stop that shell ID; Copilot terminates its process tree. Do not detach it or kill by name. |
| RAPTOR/SCA timeout | A final process or lifecycle outcome. SCA's own 600-second operation timeout is unrelated to the frontend wait, as is max-findings capping. |

Post-run artifact reads should stay in the parent and use non-shell file tools
where possible. Terminal validation remains on `execution_subagent` unless one
exact command independently satisfies the same direct-shell exception.
Dispatched children skip RAPTOR's operator-facing startup banner, so they
never shell out merely to read `.startup-output`.

### Bounded one-child acceptance

For an acceptance turn that authorizes exactly one logical child operation,
keep the parent tool surface narrow:

```text
--allow-tool=view
--allow-tool=shell(libexec/raptor-run-lifecycle:*)
--allow-tool=execution_subagent
--deny-tool=write
--deny-tool=edit
```

Do not add `--allow-all-tools` or `--yolo`. In the acceptance prompt, state
that each enumerated lifecycle command is a separate exact direct-shell call
under the complete-unfiltered-stdout exception, and that
`execution_subagent` is reserved for the one logical child operation. Also
state: **if higher-priority routing cannot satisfy that one-call cap, stop
before a second child call and report the acceptance blocked**.

This prompt plus allowlist narrows repository-owned routing but is not a
mechanical call counter and does not control Copilot's upstream scheduler.
Acceptance must inspect persisted tool events and require exactly one unique
`execution_subagent` call. It must also inspect usage output and record the
effective managed-child model because prompt prose and repository configuration
cannot pin it on 1.0.100-1. Any extra child call fails the live acceptance;
an observed child-model difference does not.

### Observed incident evidence and limits

The following are persisted-event observations from the historical Copilot
incident record. Its session-start event identifies Copilot CLI 1.0.99-1, but
that context does not prove that the version or an internal Copilot mechanism
caused the observed labels or delays.

- Repository inspection found no RAPTOR-added command or execution-subagent
  deadline in the launcher path. The persisted run artifacts recorded normal
  completion. SCA's timeout and findings capping are separate pipeline
  controls; the event stream does not identify either as the cause of the
  shell or child wait.
- The shell tool started at 23:02:45Z, command permission finished at
  23:07:33Z, and at 23:10:33Z its event carried `command_timeout` telemetry
  plus text that the shell was still running. The same shell later notified
  completion at 23:21:18Z, and one `read_bash` returned exit 0. These facts
  prove that the RAPTOR command continued and completed after the observation
  boundary; they do not prove why the external runtime applied that label.
- A validation execution subagent started at 23:22:39Z. Two child shell
  permissions were requested at 23:22:46Z and completed by
  `human_response` at 03:24:52Z and 03:24:58Z. The remaining validation work
  finished at 03:26:39Z. The four-hour span is directly correlated with
  pending human approvals in the event stream. It does not, by itself, prove
  the execution subagent's internal scheduler state or establish an internal
  deadline.

## Useful checks

```bash
copilot config --repo --list --json
python -m core.startup.host copilot
./bin/raptor --help
```

The host check must succeed with a native Linux executable; unsupported
wrappers/platforms still refuse before session effects. Use `/help`, `/model`,
and `/subagents` inside Copilot. See `CONTRIBUTING.md` for development
conventions and `README.md` for broader RAPTOR usage.
