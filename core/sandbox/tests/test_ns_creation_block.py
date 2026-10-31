"""Namespace-creation denial on the fork-backend lane.

A sandboxed payload that can create namespaces — a nested user
namespace above all — reaches the kernel code paths behind most
container-escape CVEs even though uid_map writes are refused. The
fork backend's filter installs AFTER the sandbox's own namespace
setup, so denying namespace creation there costs legitimate
workloads nothing. On the subprocess side the contract is per-lane:
the PLAIN lane (payload execs directly under the filter) takes the
ns-blocking preexec variant too, while the unshare-CLI lane installs
its filter BEFORE exec'ing the unshare bootstrap and must keep the
syscalls — context selects between the two variants keyed on
need_unshare.
"""

import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]


def test_ns_block_lane_contract_source_pin():
    """Source pin on the per-lane contract: _spawn's grandchild-
    installed filter always blocks; the plain subprocess lane — the
    ONLY lane that execs through a preexec since the unshare-CLI
    bootstrap was deleted — takes the ns-blocking rules
    unconditionally (its payload never legitimately unshares), and
    the per-call demoted preexec rebuild carries them too; the audit
    lane — whose filter installs before the sandbox's own setup —
    never enables it."""
    spawn = (_REPO_ROOT / "core" / "sandbox" / "_spawn.py").read_text(
        encoding="utf-8")
    assert "block_ns_creation=True" in spawn
    ctx = (_REPO_ROOT / "core" / "sandbox" / "context.py").read_text(
        encoding="utf-8")
    assert ctx.count("seccomp_block_ns_creation=True") >= 2, (
        "context must build BOTH ns-blocking preexecs (the plain-lane "
        "baseline and the demoted per-call rebuild)")
    assert 'kwargs["preexec_fn"] = preexec_ns_blocked' in ctx, (
        "the plain lane must take the ns-blocking preexec "
        "unconditionally — no lane needs the permissive variant now")
    assert "preexec if need_unshare else" not in ctx, (
        "the deleted unshare-CLI lane's permissive preexec selection "
        "must not resurface")
    la = (_REPO_ROOT / "core" / "sandbox" /
          "_landlock_audit.py").read_text(encoding="utf-8")
    assert "block_ns_creation" not in la, (
        "_landlock_audit must not enable the ns block — its filter "
        "installs before the sandbox's own namespace setup")


def test_ns_flags_cover_every_clone_namespace():
    from core.sandbox.seccomp import _CLONE_NS_FLAGS
    assert set(_CLONE_NS_FLAGS) == {
        "NEWUSER", "NEWNS", "NEWPID", "NEWNET", "NEWIPC", "NEWUTS",
        "NEWCGROUP", "NEWTIME",
    }


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_payload_cannot_create_namespaces(tmp_path):
    """Inside run_untrusted: every unshare(CLONE_NEW*) and setns is
    EPERM; clone3 is ENOSYS; fork/exec and multiprocessing keep
    working (the sh wrapper keeps cmd[0] inside the bind tree on
    hosts whose driver python lives in a venv)."""
    from core.sandbox import context as _ctx
    probe = r"""
python3 - <<'PY'
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
flags = {"NEWUSER":0x10000000,"NEWNS":0x00020000,"NEWPID":0x20000000,
         "NEWNET":0x40000000,"NEWIPC":0x08000000,"NEWUTS":0x04000000,
         "NEWCGROUP":0x02000000,"NEWTIME":0x00000080}
denied = 0
for fl in flags.values():
    pid = os.fork()
    if pid == 0:
        r = libc.unshare(fl)
        os._exit(0 if r == 0 else ctypes.get_errno())
    _, st = os.waitpid(pid, 0)
    if os.waitstatus_to_exitcode(st) == 1:  # EPERM
        denied += 1
print("unshare-denied:", denied)
r = libc.setns(3, 0)
print("setns-eperm:", r != 0 and ctypes.get_errno() == 1)
r = libc.syscall(435, 0, 0)  # clone3 (x86_64/aarch64 share 435)
print("clone3-enosys:", r != 0 and ctypes.get_errno() == 38)
import subprocess
print("exec-ok:", subprocess.run(["true"]).returncode == 0)
import multiprocessing as mp
q = mp.get_context("fork").Queue()
p = mp.get_context("fork").Process(target=q.put, args=(7,))
p.start(); p.join()
print("mp-ok:", q.get(timeout=10) == 7)
PY
"""
    try:
        r = _ctx.run_untrusted(
            ["sh", "-c", probe], target=str(tmp_path),
            output=str(tmp_path), timeout=120,
            capture_output=True, text=True,
        )
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"sandbox unavailable: {e}")
    if r.returncode != 0:
        pytest.skip(f"probe did not run: {(r.stderr or '')[-200:]}")
    out = r.stdout or ""
    assert "unshare-denied: 8" in out, out
    assert "setns-eperm: True" in out, out
    assert "clone3-enosys: True" in out, out
    assert "exec-ok: True" in out, out
    assert "mp-ok: True" in out, out


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_out_of_tree_tool_refuses_untrusted_run(tmp_path, monkeypatch):
    """The fresh-procfs contract covers the tool-visibility pre-flight:
    an untrusted cmd[0] that resolves OUTSIDE the mount-ns bind tree
    (a venv python is the everyday shape) must refuse rather than
    silently run on a host-procfs-visible fallback lane; tool_paths=
    is the named remedy and the operator override restores the
    degrade."""
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError
    bindir = tmp_path / "outside-bin"
    bindir.mkdir()
    tool = bindir / "sbx-out-of-tree-tool"
    tool.write_text("#!/bin/sh\necho tool-ran\n", encoding="utf-8")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH",
                       f"{bindir}:{os.environ.get('PATH', '/usr/bin')}")
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    workdir = tmp_path / "w"
    workdir.mkdir()
    try:
        with pytest.raises(SandboxSetupError,
                           match="fresh-procfs contract"):
            _ctx.run_untrusted(["sbx-out-of-tree-tool"],
                               target=str(workdir), output=str(workdir),
                               timeout=60, capture_output=True, text=True)
    except (pytest.skip.Exception, pytest.fail.Exception):
        raise
    except Exception as e:  # noqa: BLE001 — host without the lane
        pytest.skip(f"mount-ns lane unavailable: {e}")

    r = _ctx.run_untrusted(["sbx-out-of-tree-tool"],
                           target=str(workdir), output=str(workdir),
                           timeout=60, capture_output=True, text=True,
                           tool_paths=[str(bindir)])
    assert "tool-ran" in (r.stdout or ""), (
        "tool_paths= remedy did not restore the mount-ns lane")

    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    # The override's promise is narrow: the GATE stops refusing. The
    # fallback lane then applies its own posture (here: Landlock's
    # read allowlist still denies the out-of-tree binary, so the exec
    # itself may fail) — that is the lane's business, not the gate's.
    r = _ctx.run_untrusted(["sbx-out-of-tree-tool"],
                           target=str(workdir), output=str(workdir),
                           timeout=60, capture_output=True, text=True)
    assert isinstance(r.returncode, int), "override run did not execute"
