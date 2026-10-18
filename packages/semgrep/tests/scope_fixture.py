"""Shared live fixture for Semgrep scan-scope regressions."""

from __future__ import annotations

import subprocess
from pathlib import Path

SCOPE_MARKER = "RAPTOR_SCOPE_MARKER"

GIT_NEAR_MISS_FINDINGS = (
    ".github/workflows/security.py",
    "git_config.py",
    "legitimate-git-module.py",
    "services/git-tools/adapter.py",
    "src/git/client.py",
)

_BASE_SCOPE_FINDINGS = (
    ".env",
    ".hidden/hidden.py",
    "app.py",
    "ignored.py",
    "nosem.py",
    "tests/test_scope.py",
)

EXPECTED_SCOPE_FINDINGS = tuple(sorted(
    _BASE_SCOPE_FINDINGS + GIT_NEAR_MISS_FINDINGS,
))


def write_scope_rule(root: Path) -> Path:
    """Write local-only rules that exercise Python, shell, and generic scope."""
    rule = root / "scope-rules.yaml"
    rule.write_text(
        "rules:\n"
        "  - id: scope.python-eval\n"
        "    pattern: eval(...)\n"
        "    message: eval use\n"
        "    languages: [python]\n"
        "    severity: ERROR\n"
        "  - id: scope.shell-eval\n"
        "    pattern: eval $X\n"
        "    message: shell eval use\n"
        "    languages: [bash]\n"
        "    severity: ERROR\n"
        "  - id: scope.marker\n"
        f"    pattern: {SCOPE_MARKER}\n"
        "    message: scope marker\n"
        "    languages: [generic]\n"
        "    severity: ERROR\n",
        encoding="utf-8",
    )
    return rule


def create_git_scope_fixture(root: Path) -> Path:
    """Create an uncommitted Git tree with metadata and first-party edge cases."""
    target = root / "target"
    subprocess.run(
        ["git", "init", "-q", str(target)],
        check=True,
        capture_output=True,
        timeout=60,
    )
    nested_repo = target / "nested-repo"
    subprocess.run(
        ["git", "init", "-q", str(nested_repo)],
        check=True,
        capture_output=True,
        timeout=60,
    )

    for repo in (target, nested_repo):
        (repo / ".git" / "hooks" / "raptor-scope.sample").write_text(
            f"{SCOPE_MARKER}\n",
            encoding="utf-8",
        )

    for pointer_dir in (target / "submodule", target / "worktree"):
        pointer_dir.mkdir()
        (pointer_dir / ".git").write_text(
            f"gitdir: ../metadata/{SCOPE_MARKER}\n",
            encoding="utf-8",
        )

    (target / ".github" / "workflows").mkdir(parents=True)
    (target / ".hidden").mkdir()
    (target / "services" / "git-tools").mkdir(parents=True)
    (target / "src" / "git").mkdir(parents=True)
    (target / "tests").mkdir()
    (target / "app.py").write_text('eval("app")\n', encoding="utf-8")
    (target / "git_config.py").write_text(
        'eval("git config module")\n',
        encoding="utf-8",
    )
    (target / "ignored.py").write_text('eval("ignored")\n', encoding="utf-8")
    (target / "legitimate-git-module.py").write_text(
        'eval("legitimate git module")\n',
        encoding="utf-8",
    )
    (target / "nosem.py").write_text(
        'eval("inline")  # nosem\n',
        encoding="utf-8",
    )
    (target / ".github" / "workflows" / "security.py").write_text(
        'eval("github workflow")\n',
        encoding="utf-8",
    )
    (target / ".hidden" / "hidden.py").write_text(
        'eval("hidden")\n',
        encoding="utf-8",
    )
    (target / "services" / "git-tools" / "adapter.py").write_text(
        'eval("git tools adapter")\n',
        encoding="utf-8",
    )
    (target / "src" / "git" / "client.py").write_text(
        'eval("git client")\n',
        encoding="utf-8",
    )
    (target / "tests" / "test_scope.py").write_text(
        'eval("test")\n',
        encoding="utf-8",
    )
    (target / ".env").write_text(f"{SCOPE_MARKER}\n", encoding="utf-8")
    (target / "broken.sh").write_text(
        "#!/bin/sh\nif then fi\n",
        encoding="utf-8",
    )

    (target / ".gitignore").write_text(
        "*.py\n.env\n.hidden/\ntests/\n",
        encoding="utf-8",
    )
    (target / ".semgrepignore").write_text("*\n", encoding="utf-8")
    return target


def relative_scope_path(raw_path: str, target: Path) -> str:
    """Render an absolute Semgrep path relative to the fixture target."""
    return Path(raw_path).resolve().relative_to(target.resolve()).as_posix()
