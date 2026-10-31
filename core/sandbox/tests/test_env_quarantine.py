"""Loader-variable quarantine for launcher-carrying sandbox paths.

The seatbelt watcher shim (the one remaining launcher-carrying path —
the Linux unshare/pid1-shim chain is deleted; every Linux lane execs
the target directly) must never exec with live loader variables
(``LD_*`` / ``DYLD_*`` / ``GCONV_PATH`` / ``GLIBC_TUNABLES``) from a
caller-supplied env dict — those are quarantined into
``_RAPTOR_ENV_RESTORE`` and re-applied by the shim at target exec, so
the TARGET's effective env is unchanged while the trusted bootstrap
runs clean.

The shim-side restore contract (every quarantined name restorable,
non-loader keys rejected, the key never visible to the target) is
pinned by test_seatbelt_shim.py::test_env_restore_reapplied_at_target_
exec; this module pins the pure quarantine helper and the Linux
round-trip (loader vars reach the target verbatim on the direct-exec
lanes).
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from core.sandbox import context as _ctx
from core.sandbox._env_quarantine import (
    ENV_RESTORE_KEY,
    quarantine_loader_env,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _require_sandbox():
    if sys.platform != "linux":
        pytest.skip("Linux-only sandbox internals")
    from core.sandbox import check_net_available
    if not check_net_available():
        pytest.skip("User namespaces not available")


# ─── quarantine helper (pure unit) ──────────────────────────────────


class TestQuarantineLoaderEnv:
    def test_loader_vars_moved_to_payload(self):
        env = {
            "PATH": "/usr/bin",
            "LD_PRELOAD": "/x/evil.so",
            "LD_LIBRARY_PATH": "/x/lib",
            "DYLD_INSERT_LIBRARIES": "/x/evil.dylib",
            "GCONV_PATH": "/x/gconv",
            "GLIBC_TUNABLES": "glibc.malloc.check=1",
        }
        out = quarantine_loader_env(env)
        assert out["PATH"] == "/usr/bin"
        for k in ("LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
                  "GCONV_PATH", "GLIBC_TUNABLES"):
            assert k not in out, f"{k} still live in launcher env"
        restored = json.loads(out[ENV_RESTORE_KEY])
        assert restored["LD_PRELOAD"] == "/x/evil.so"
        assert restored["GLIBC_TUNABLES"] == "glibc.malloc.check=1"
        assert len(restored) == 5

    def test_no_loader_vars_no_payload_key(self):
        out = quarantine_loader_env({"PATH": "/usr/bin", "HOME": "/h"})
        assert ENV_RESTORE_KEY not in out
        assert out == {"PATH": "/usr/bin", "HOME": "/h"}

    def test_caller_supplied_restore_key_dropped_never_merged(self):
        env = {
            ENV_RESTORE_KEY: json.dumps({"LD_PRELOAD": "/attacker.so"}),
            "PATH": "/usr/bin",
        }
        out = quarantine_loader_env(env)
        assert ENV_RESTORE_KEY not in out

    def test_caller_restore_key_dropped_even_with_loader_vars(self):
        env = {
            ENV_RESTORE_KEY: json.dumps({"LD_PRELOAD": "/attacker.so"}),
            "LD_LIBRARY_PATH": "/legit",
        }
        out = quarantine_loader_env(env)
        restored = json.loads(out[ENV_RESTORE_KEY])
        assert restored == {"LD_LIBRARY_PATH": "/legit"}

    def test_input_dict_not_mutated(self):
        env = {"LD_PRELOAD": "/x.so", "PATH": "/usr/bin"}
        snapshot = dict(env)
        quarantine_loader_env(env)
        assert env == snapshot


# ─── pid1 shim restore semantics (direct, no namespaces needed) ─────


@pytest.mark.integration
def test_caller_loader_var_reaches_target_not_lost(tmp_path):
    """Loader-variable handling must be transparent to the TARGET: a
    caller-supplied loader variable reaches it on every Linux backend
    (verbatim — every Linux lane execs the target directly), and the
    quarantine key never appears.

    Uses plain run() — run_untrusted's strict_env contract strips
    loader vars outright (by design, covered elsewhere); intentional
    loader vars are a plain-run capability."""
    _require_sandbox()
    from core.config import RaptorConfig
    env_bin = shutil.which("env") or "/usr/bin/env"
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    caller_env = dict(RaptorConfig.get_safe_env())
    caller_env["LD_LIBRARY_PATH"] = "/quarantine-marker"
    result = _ctx.run(
        [env_bin],
        block_network=True,
        output=str(out_dir),
        env=caller_env, env_caller_filtered=True,
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, (
        f"env exited {result.returncode}: {result.stderr!r}"
    )
    assert "LD_LIBRARY_PATH=/quarantine-marker" in result.stdout, (
        "caller loader var lost in the quarantine round trip"
    )
    assert f"{ENV_RESTORE_KEY}=" not in result.stdout, (
        "restore payload key leaked into the target env"
    )

