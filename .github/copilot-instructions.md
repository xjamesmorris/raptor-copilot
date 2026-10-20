# Copilot service/account isolation

Use this repository only through the account/service that authenticated the
current Copilot session. Read `CLAUDE.md` for the repository workflow; its
Copilot session service boundary takes precedence over automatic provider,
recovery, installation, cross-model, and SAGE instructions.

Do not invoke another harness, standalone LLM SDK, new Copilot process, or
different account as a fallback. Installed CLIs, saved keys/configuration,
model selections, project trust, `--yolo`, and earlier approvals do not
authorize a service call.

Before any additional service is used, obtain fresh approval identifying the
operation, destination, account/credential identity, and data being sent.
This includes local sidecars/inference, MCP servers, cloud APIs, web lookups,
downloads, package installation, telemetry, and target network requests.
Do not probe credentials or contact a service to discover whether access is
authorized. If approval or identity cannot be established, stop.

Approval to modify code grants no external-service access. Never remove
Copilot identity markers, disable the service guard, switch credentials,
start another session, or bypass a failed transport to finish a task.

Use native tools and managed children of the already-running Copilot
session, not repository-spawned harnesses. Native model selection is distinct
from an account/service switch.

RAPTOR currently cannot attest a standalone transport to the active Copilot
account or verify a scoped external grant, so those transports refuse.
The runtime network ceiling applies to repository Python processes and
their descendants, not to Copilot internals or arbitrary host tool calls.
Do not claim stronger enforcement.
