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
```

Use `./bin/raptor` to avoid accidentally selecting another checkout on PATH.
Keep `=value` for the reasoning/context flags; separate values would be
interpreted as target arguments by RAPTOR's passthrough parser.

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
