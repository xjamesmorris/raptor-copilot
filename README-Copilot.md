# RAPTOR with GitHub Copilot CLI

Copilot can host RAPTOR's interactive decision layer on Linux, loading its
instructions, commands, skills, agents, and coverage plugin. The Python
execution layer and separate analysis-provider configuration remain unchanged.

## Quickstart

Install a native Linux Copilot CLI and sign in with `copilot login`. Install
Python dependencies with `uv sync --locked`; source scanning also needs
Semgrep. From this checkout's root:

```bash
source .venv/bin/activate

# Start with this repository's Copilot defaults
./bin/raptor --frontend copilot

# Or explicitly select Astra, max reasoning, and long context
./bin/raptor --frontend copilot --model gpt-6-astra \
  --reasoning-effort=max --context=long_context

# Start against a target, or resume the latest session
./bin/raptor --frontend copilot /path/to/code
./bin/raptor --frontend copilot --continue

# Explicitly grant Copilot all permissions for this launch only
./bin/raptor --frontend copilot --yolo /path/to/code
./bin/raptor --frontend copilot --project my-project --yolo --continue
```

Use `./bin/raptor` to avoid accidentally selecting another checkout on PATH.
Keep `=value` for the reasoning/context flags; separate values would be
interpreted as target arguments by RAPTOR's passthrough parser.

`--yolo` is an explicit Copilot frontend permission choice. RAPTOR passes it
through unchanged only when the operator supplies it; RAPTOR never enables it
by default. It is not `--trust-repo`, does not set a RAPTOR project trust
marker, and does not weaken RAPTOR analysis sandbox policy. With a target,
project selection remains launcher-owned while Copilot receives `--yolo` and
the `/raptor <target>` prompt. With `--continue`, Copilot receives both
`--yolo` and `--continue` without a new initial prompt. These recognized
launcher options keep the same roles when ordered before or after one another
or the target; none is reinterpreted as the target or as project trust.

Startup reports the frontend on its own line immediately above `llm:`, for
example with an explicit `--model gpt-6-astra`:

```text
frontend: GitHub Copilot CLI (model: gpt-6-astra)
   llm: no external LLM configured
```

Without an explicit model, the label is `session/config default`. The static
"Based on Claude Code" attribution is not the active frontend indicator.
The Claude Code line under `llm:` only reports that its analysis CLI is
installed on PATH; it does not verify authentication or select the frontend.
RAPTOR can use Claude Code for analysis independently of the Copilot frontend.

## Development defaults

For ordinary development without starting RAPTOR's `/raptor` workflow, run
`copilot` from this checkout. Direct launch skips RAPTOR's preflight checks,
session/project binding, and automatic coverage-plugin loading.

New Copilot sessions here default to **GPT-6 Astra, max reasoning, long
context**, stored only in `.github/copilot/settings.json`. To reapply:

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
copilot config --repo model gpt-6-astra
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

## The three model controls

| Layer | Configuration |
|---|---|
| Parent Copilot session | Repository defaults above, `--model`, or `/model` |
| Copilot child agents | `/subagents`; separate model, effort, and context settings |
| RAPTOR finding analysis | `/agentic --model MODEL` and `~/.config/raptor/models.json` |

An execution subagent using Luna does not mean the parent or RAPTOR's analysis
model changed. Subagent overrides and global settings are intentionally
unchanged. To opt the execution subagent into parent inheritance for this
repository:

```bash
copilot config --repo subagents.agents.execution-subagent.model inherit
copilot config --repo subagents.agents.execution-subagent.effortLevel inherit
copilot config --repo subagents.agents.execution-subagent.contextTier inherit
```

RAPTOR analysis requires a configured provider or its Claude Code fallback.
Selecting the Copilot frontend does not enable a headless Copilot provider.
Repeat `/agentic --model` for independent configured analysis models.

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
