"""Workflow-consistency tests over agent grants and plugin hook policy.

The authoritative agent frontmatter owns tool grants. Claude's supported
plugin-level PreToolUse dispatcher owns per-agent URL/command/write
restrictions. These tests pin the Rule-of-Two decisions documented in
docs/security.md so metadata or policy edits cannot silently re-grow a
severed leg:

  * crash-analysis pipeline: only the fetcher touches the network;
    orchestrator, analyzer, checker, and generators carry no
    WebFetch/WebSearch.
  * the fetcher is fetch-only (Read, Write, WebFetch) with dispatcher
    policies for both URL and write-path validation.
  * every WebFetch grant in the agent set is paired with the
    plugin policy or is an explicitly listed exception.
"""

import runpy
import unittest
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[3]
_AGENTS_DIR = _REPO / "plugins" / "agents" / "agents"
_DISPATCHER = (
    _REPO / "plugins" / "agents" / "libexec" / "raptor-agent-hook-dispatch"
)
_DISPATCH = runpy.run_path(str(_DISPATCHER))
_POLICIES = _DISPATCH["_POLICIES"]

# Agents whose WebFetch is deliberately NOT plugin-policy-gated. offsec-specialist
# is the inherent all-tools / needs-HITL exception (docs/security.md).
_WEBFETCH_HOOK_EXEMPT = {"offsec-specialist"}

_NETWORK_TOOLS = {"WebFetch", "WebSearch"}


def _frontmatter(path):
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise AssertionError(f"{path.name}: missing frontmatter")
    block = text[4:].split("\n---", 1)[0]
    try:
        data = yaml.safe_load(block)
    except yaml.YAMLError as exc:
        raise AssertionError(
            f"{path.name}: malformed agent frontmatter: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise TypeError(f"{path.name}: frontmatter is not a mapping")
    return data


def _tools(front):
    raw = front.get("tools")
    if raw is None:
        return None  # all-tools default
    return {t.strip() for t in str(raw).split(",") if t.strip()}


def _load_all():
    agents = {}
    for path in sorted(_AGENTS_DIR.glob("*.md")):
        front = _frontmatter(path)
        agents[front.get("name", path.stem)] = front
    return agents


class TestCrashPipelinePins(unittest.TestCase):

    def setUp(self):
        self.agents = _load_all()

    def test_orchestrator_has_no_network_tools(self):
        tools = _tools(self.agents["crash-analysis-agent"])
        self.assertIsNotNone(tools, "orchestrator must pin an explicit "
                                    "tool list, not the all-tools default")
        self.assertEqual(
            tools,
            {"Read", "Write", "Edit", "Bash", "Grep", "Glob", "Task"},
        )

    def test_analyzer_and_checker_have_no_network_tools(self):
        for name in ("crash-analyzer", "crash-analysis-checker",
                     "function-trace-generator", "coverage-analyzer"):
            tools = _tools(self.agents[name])
            self.assertIsNotNone(
                tools, f"{name} must pin an explicit tool list")
            self.assertFalse(
                tools & _NETWORK_TOOLS,
                f"{name} must not carry network tools; has {tools}")

    def test_fetcher_is_fetch_only(self):
        front = self.agents["crash-report-fetcher"]
        self.assertEqual(_tools(front), {"Read", "Write", "WebFetch"})

    def test_fetcher_webfetch_is_anchor_gated(self):
        policy = _POLICIES["raptor-agents:crash-report-fetcher"]
        script, args = policy["WebFetch"]
        self.assertEqual(script, "webfetch-domain-allowlist.py")
        self.assertEqual(args[0], "--anchor-file")
        self.assertIn("crash-report-fetcher-{session}.anchor", args[1])
        self.assertEqual(
            policy["Write"],
            ("write-path-allowlist.py", ("bug-report.json",)),
        )
        self.assertEqual(policy["Edit"], policy["Write"])

    def test_hook_script_exists_and_is_executable_python(self):
        hook = _REPO / ".claude" / "hooks" / "webfetch-domain-allowlist.py"
        self.assertTrue(hook.is_file())
        first = hook.read_text(encoding="utf-8").splitlines()[0]
        self.assertTrue(first.startswith("#!"))


class TestGHArchiveAgentPins(unittest.TestCase):
    """Pin the gh-archive Rule-of-Two decision (docs/security.md):
    Bash is narrowed to the typed BigQuery wrapper + the evidence-kit
    ingest script via a per-agent PreToolUse allowlist hook."""

    def setUp(self):
        self.front = _load_all()["oss-investigator-gh-archive-agent"]

    def test_tool_list_is_pinned(self):
        self.assertEqual(_tools(self.front), {"Bash", "Read", "Write"})

    def test_bash_allowlist_hook_is_wired(self):
        script, prefixes = _POLICIES[
            "raptor-agents:oss-investigator-gh-archive-agent"
        ]["Bash"]
        self.assertEqual(script, "bash-command-allowlist.py")
        self.assertIn("libexec/raptor-bq-query", prefixes)
        self.assertTrue(
            any("ingest_bq_events.py" in prefix for prefix in prefixes)
        )

    def test_hook_allows_only_the_two_typed_commands(self):
        # The allowlist must not quietly grow a broad interpreter grant
        # (a bare "python3"/"bash" prefix would be arbitrary exec).
        _, prefixes = _POLICIES[
            "raptor-agents:oss-investigator-gh-archive-agent"
        ]["Bash"]
        self.assertEqual(prefixes, (
            "libexec/raptor-bq-query",
            ("python3 .claude/skills/oss-forensics/github-evidence-kit/"
             "scripts/ingest_bq_events.py"),
        ))

    def test_hook_script_exists_and_is_executable_python(self):
        hook = _REPO / ".claude" / "hooks" / "bash-command-allowlist.py"
        self.assertTrue(hook.is_file())
        first = hook.read_text(encoding="utf-8").splitlines()[0]
        self.assertTrue(first.startswith("#!"))

    def test_wrapper_and_ingest_script_exist(self):
        self.assertTrue((_REPO / "libexec" / "raptor-bq-query").is_file())
        self.assertTrue(
            (_REPO / ".claude" / "skills" / "oss-forensics" /
             "github-evidence-kit" / "scripts" /
             "ingest_bq_events.py").is_file())


class TestWebFetchGrantsAreGated(unittest.TestCase):

    def test_every_webfetch_grant_carries_the_domain_hook(self):
        for name, front in _load_all().items():
            if name in _WEBFETCH_HOOK_EXEMPT:
                continue
            tools = _tools(front)
            grants_webfetch = tools is None or "WebFetch" in tools
            if not grants_webfetch:
                continue
            self.assertIsNotNone(
                tools,
                f"{name}: all-tools default silently grants WebFetch — "
                "pin an explicit tool list or add to the exempt set")
            policy = _POLICIES.get(f"raptor-agents:{name}", {})
            self.assertIn(
                "WebFetch",
                policy,
                f"{name}: WebFetch granted without plugin URL policy",
            )
            self.assertEqual(
                policy["WebFetch"][0],
                "webfetch-domain-allowlist.py",
            )

    def test_agent_frontmatter_contains_no_ignored_hooks(self):
        for name, front in _load_all().items():
            self.assertNotIn(
                "hooks",
                front,
                f"{name}: plugin agent frontmatter hooks are ignored",
            )


if __name__ == "__main__":
    unittest.main()
