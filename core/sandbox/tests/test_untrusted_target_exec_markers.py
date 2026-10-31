"""Untrusted children carry no RAPTOR-identifying env names at all.

TARGET_ENV_STRIP_SET removes the trust markers and the session
credential, but several RAPTOR_* names legitimately ride the safe-env
allowlist for RAPTOR's own tool children (RAPTOR_EF_* budget knobs,
the RAPTOR_CI stamp the interactivity gate reads, transport kill
switches). To a hostile binary every one of them is a one-getenv
"you are inside RAPTOR" tell and an anti-analysis trigger. The
untrusted-workload arm of run()'s target-env staging therefore
applies ``RaptorConfig.strip_target_exec_markers`` — the whole
RAPTOR_*/_RAPTOR prefix family goes, the same contract as the frida
spawn path. Trusted tool spawns keep the allowlisted knobs: their
children consume them by contract.

Run integration tests: pytest -m integration \
    core/sandbox/tests/test_untrusted_target_exec_markers.py
"""

from __future__ import annotations

import shutil
import sys

import pytest

from core.sandbox import context as _ctx


def _require_sandbox():
    if sys.platform != "linux":
        pytest.skip("Linux-only sandbox internals")
    from core.sandbox import check_net_available
    if not check_net_available():
        pytest.skip("User namespaces not available")


def _env_keys(env_output: str) -> list[str]:
    return [line.split("=", 1)[0]
            for line in env_output.splitlines() if "=" in line]


@pytest.mark.integration
def test_untrusted_child_sees_no_raptor_name_family(monkeypatch, tmp_path):
    """/usr/bin/env inside run_untrusted() must show NO name from the
    RAPTOR_*/_RAPTOR family — including allowlist survivors that the
    plain strip set never covered."""
    _require_sandbox()
    env_bin = shutil.which("env") or "/usr/bin/env"
    # Guarantee marker-family names exist in the parent env so their
    # absence in the child is the strip working, not an unset parent.
    monkeypatch.setenv("RAPTOR_EF_TIMEOUT_FAST", "5")
    monkeypatch.setenv("RAPTOR_CI", "1")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    result = _ctx.run_untrusted(
        [env_bin],
        output=str(out_dir),
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, (
        f"env exited {result.returncode}: {result.stderr!r}"
    )
    assert "PATH=" in result.stdout, "child env output looks empty"
    leaked = [k for k in _env_keys(result.stdout)
              if k.startswith(("RAPTOR_", "_RAPTOR"))]
    assert leaked == [], (
        f"RAPTOR-identifying names leaked into the untrusted child "
        f"env: {leaked}"
    )


@pytest.mark.integration
def test_trusted_tool_child_keeps_allowlisted_knobs(tmp_path):
    """Both directions: the marker strip is untrusted-workload only —
    a trusted tool spawn still delivers the documented RAPTOR_EF_*
    budget knobs its children consume by contract."""
    _require_sandbox()
    from core.config import RaptorConfig
    env_bin = shutil.which("env") or "/usr/bin/env"
    tgt = tmp_path / "t"
    out = tmp_path / "o"
    tgt.mkdir()
    out.mkdir()
    env = dict(RaptorConfig.get_safe_env())
    env["RAPTOR_EF_TIMEOUT_FAST"] = "5"
    result = _ctx.run(
        [env_bin], target=str(tgt), output=str(out),
        env=env, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, (
        f"env exited {result.returncode}: {result.stderr!r}"
    )
    assert "RAPTOR_EF_TIMEOUT_FAST=5" in result.stdout, (
        "trusted tool child lost its allowlisted RAPTOR_EF_* knob — "
        "the target-exec marker strip must not apply to the trusted "
        "arm"
    )
