"""Shared test scaffolding — the canonical fakes and fixtures that
test suites across the tree had copy-pasted (and drifted).

NOT collected as tests (no ``test_*.py`` modules except under
``tests/``); import from suites as ``from core.testing import ...``.

Patterns provided (each replaces a family of per-suite copies):

* :class:`FakeStructuredProvider` — provider-level stub for
  ``generate_structured`` with canned ``(result, raw)``, call
  counting, last-kwargs capture, and the full usage-counter block
  ``LLMClient`` diffs. Carries ``**kwargs`` — the drifted copies that
  dropped it TypeError'd on per-call ``temperature``.
* :func:`make_test_client` / :func:`install_provider` — the minimal
  no-API-key ``LLMClient`` builder (the ``LLMClient.__new__`` private-
  attribute litany that four suites re-spelled) plus the provider-key
  wiring.
* :func:`reset_llm_egress_state` — the egress/proxy-env/OLLAMA_HOST
  hermeticity fixture body shared by per-directory conftests (wrap
  with ``yield from`` in an autouse fixture).
* :func:`make_hermetic_cli` — protocol-neutral real-process fakes with
  isolated HOME/XDG/RAPTOR state, no inherited ambient credentials,
  guarded caller overrides, pinned PATH guards, and invocation/process
  capture.
* :func:`init_scratch_repo` / :func:`git_run` — hermetic git fixture
  repos: scrubbed global/system config, pinned identity, signing off,
  deterministic default branch.

Dead-scaffolding cleanups elsewhere should converge suites onto these
rather than deleting-and-reinventing.
"""

from core.testing.fake_llm import (
    FakeModel,
    FakeStructuredProvider,
    ensure_anthropic_error_types,
    install_provider,
    make_anthropic_provider,
    make_test_client,
)
from core.testing.fake_cli import (
    FAKE_CLI_CONFIG_ERROR,
    FAKE_CLI_GUARD_EXIT,
    FAKE_CLI_SPAWN_ERROR,
    FakeCLIBehavior,
    FakeCLIInvocation,
    FakeCLIProcess,
    FakeCLISecretObservation,
    HermeticCLIWorkspace,
    OwnedFakeExecutable,
    make_hermetic_cli,
)
from core.testing.gitrepo import git_run, init_scratch_repo
from core.testing.llm_env import (
    DEFAULT_OLLAMA_HOST,
    PROXY_ENV_VARS,
    reset_llm_egress_state,
)
from core.testing.treesitter import (
    force_census_regex_fallback,
    requires_ts,
    ts_parser_available,
)

__all__ = [
    "DEFAULT_OLLAMA_HOST",
    "FAKE_CLI_CONFIG_ERROR",
    "FAKE_CLI_GUARD_EXIT",
    "FAKE_CLI_SPAWN_ERROR",
    "PROXY_ENV_VARS",
    "FakeCLIBehavior",
    "FakeCLIInvocation",
    "FakeCLIProcess",
    "FakeCLISecretObservation",
    "FakeModel",
    "FakeStructuredProvider",
    "HermeticCLIWorkspace",
    "OwnedFakeExecutable",
    "ensure_anthropic_error_types",
    "force_census_regex_fallback",
    "git_run",
    "init_scratch_repo",
    "install_provider",
    "make_anthropic_provider",
    "make_hermetic_cli",
    "make_test_client",
    "requires_ts",
    "reset_llm_egress_state",
    "ts_parser_available",
]
