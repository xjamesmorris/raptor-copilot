"""RLIMIT_NPROC on the macOS seatbelt lane: relative ceiling, not an
absolute cap.

macOS counts RLIMIT_NPROC against the user's TOTAL simultaneous
processes, so an absolute cap equal to the configured budget sits
BELOW current usage on any busy host and makes every fork inside the
sandbox fail EAGAIN (and admits budget-minus-count forks on a quiet
one). The spawn layer now mirrors the Linux no-namespace lane:
ceiling = current same-UID process count + budget, clamped to the
hard limit; when ps cannot produce a count the cap is skipped with a
warning (Linux /proc-unreadable parity).

One more darwin quirk, confirmed on a real macOS runner: setrlimit
silently stores at most kern.maxprocperuid for RLIMIT_NPROC whatever
value is requested (even under an infinite hard limit), so the spawn
layer requests min(count + budget, kernel clamp) and these tests
compute their expectations with the same clamp — via the real sysctl
helper on macOS, and via a monkeypatched clamp for the emulated
darwin-shape cases on Linux (where the helper is platform-gated to
None).

Emulation stacks on reality: monkeypatching the production sysctl
helper fakes what production REQUESTS, but the actual setrlimit
syscall still hits the actual kernel — on a real darwin host the real
kern.maxprocperuid clamp applies underneath any emulated value (a
fake clamp above the ceiling cannot stop the real kernel storing
less). Every expectation therefore carries the REAL clamp (captured
at import, before any monkeypatch) as an unconditional floor, and the
anti-mask test picks its fake values relative to the real clamp on
darwin so the observed number is the true count+budget.

Cross-platform: SANDBOX_EXEC is swapped for a pass-through script so
the REAL shim + trampoline apply the preexec on Linux too; the count
is monkeypatched to a deterministic value well above any plausible
live usage so lowering the soft limit never breaks the test's own
process tree.
"""

from __future__ import annotations

import logging
import resource
import sys

import pytest

from core.sandbox import _macos_spawn

# Every test here does a real setrlimit through the shim, with the
# REAL kernel clamp (captured below) folded into its expectations —
# a real-kernel binding on BOTH platforms. Carrying both native
# markers keeps the file running natively on Linux and Darwin while
# the darwin-emulation gate deselects it: a monkeypatched darwin
# clamp with the real kernel's clamp applying underneath measures
# neither platform.
pytestmark = [pytest.mark.linux_native, pytest.mark.darwin_native]

_SOFT_DUMP = [sys.executable, "-c",
              "import resource; "
              "print(resource.getrlimit(resource.RLIMIT_NPROC)[0])"]

# The REAL kernel clamp (None on Linux), captured at import time —
# i.e. before any test monkeypatches the production helper. The
# actual kernel applies this underneath every emulated value.
_REAL_KERNEL_CLAMP = _macos_spawn._darwin_nproc_kernel_clamp()


def _fake_sandbox_exec(tmp_path):
    fake = tmp_path / "fake-sandbox-exec"
    fake.write_text('#!/bin/sh\nshift 3\nexec "$@"\n')  # drop -p <profile> --
    fake.chmod(0o755)
    return str(fake)


def test_same_uid_process_count_works_here():
    """ps -xo pid= -U <uid> is portable across the BSD and procps ps
    families — the helper must produce a plausible count on this
    host (at minimum, this very process)."""
    count = _macos_spawn._same_uid_process_count()
    assert isinstance(count, int) and count >= 1


def _expected_soft(requested: int, kernel_clamp: "int | None") -> int:
    """The soft limit the child must observe: count+budget, bounded by
    the inherited hard limit, by the clamp PRODUCTION saw (real or
    monkeypatched — it bounds what production requests), and by the
    REAL kernel clamp, which the actual setrlimit hits regardless of
    any emulation (emulation stacks on reality; see module docstring)."""
    _, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    expected = (requested if hard == resource.RLIM_INFINITY
                else min(requested, hard))
    if kernel_clamp is not None:
        expected = min(expected, kernel_clamp)
    if _REAL_KERNEL_CLAMP is not None:
        expected = min(expected, _REAL_KERNEL_CLAMP)
    return expected


def test_ceiling_is_count_plus_budget_clamped(tmp_path, monkeypatch):
    fake_count = 100000  # far above live usage: the ceiling can only RAISE
    budget = 64
    monkeypatch.setattr(_macos_spawn, "_same_uid_process_count",
                        lambda: fake_count)
    monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                        _fake_sandbox_exec(tmp_path))
    out = tmp_path / "out"
    out.mkdir()
    r = _macos_spawn.run_sandboxed(
        list(_SOFT_DUMP), output=str(out),
        nproc_limit=budget,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, timeout=20,
    )
    assert r.returncode == 0, r.stderr
    soft = int(r.stdout.strip())
    # The REAL kernel-clamp helper: None on Linux (platform-gated),
    # the live kern.maxprocperuid on a macOS runner — the same value
    # the production path folds into its request.
    expected = _expected_soft(fake_count + budget,
                              _macos_spawn._darwin_nproc_kernel_clamp())
    assert soft == expected, (
        f"child soft NPROC {soft} != count+budget ceiling {expected} "
        f"(absolute-cap regression?)")


def _live_same_uid_tasks() -> "int | None":
    """Live same-UID kernel TASK count — RLIMIT_NPROC's actual
    accounting unit on Linux is tasks (every thread), not processes,
    so the ps-based process count underestimates what a lowered soft
    limit is compared against at fork time. /proc scan on Linux; the
    ps process count elsewhere (darwin's limit counts processes)."""
    if sys.platform == "linux":
        import os
        uid = os.getuid()
        total = 0
        for p in os.listdir("/proc"):
            if not p.isdigit():
                continue
            try:
                if os.stat(f"/proc/{p}").st_uid != uid:
                    continue
                total += len(os.listdir(f"/proc/{p}/task"))
            except OSError:
                continue  # raced exit — best-effort census
        return total or None
    return _macos_spawn._same_uid_process_count()


def test_kernel_clamp_bounds_the_request(tmp_path, monkeypatch):
    """Darwin shape emulated on any host: a kernel clamp BELOW
    count+budget wins — the spawn layer must request the honoured
    value, so the child reads exactly the clamp.

    The fake clamp is sized relative to LIVE same-UID usage rather
    than fixed: the kernel checks a lowered RLIMIT_NPROC against the
    UID's live task count at fork time, so a fixed sub-usage value
    made the shim's own fork die EAGAIN whenever a parallel test tier
    held more live tasks than the constant — while any value far
    below count+budget still makes the clamp win the min() this test
    pins."""
    fake_count = 100000
    budget = 64
    live = _live_same_uid_tasks()
    if live is None:
        pytest.skip("live same-UID task count unavailable — cannot "
                    "size a fork-safe sub-ceiling clamp")
    fake_clamp = max(1333, live * 2 + 1024)
    if fake_clamp >= fake_count + budget - 128:
        pytest.skip("live same-UID usage leaves no window for a "
                    "clamp below count+budget")
    if _REAL_KERNEL_CLAMP is not None and fake_clamp >= _REAL_KERNEL_CLAMP:
        # The emulated clamp must stay the BINDING one: at or above
        # the real kern.maxprocperuid the kernel bound takes over and
        # the child would observe the real clamp, not the emulation.
        pytest.skip("no window between live usage and "
                    "kern.maxprocperuid for a binding emulated clamp")
    _, _hard = resource.getrlimit(resource.RLIMIT_NPROC)
    if _hard != resource.RLIM_INFINITY and fake_clamp > _hard:
        # A soft request above the hard limit cannot be granted (a
        # tight container --ulimit nproc), so the clamp under test
        # would never reach the child.
        pytest.skip("NPROC hard limit below the sized clamp — no "
                    "window to observe the emulated clamp")
    monkeypatch.setattr(_macos_spawn, "_same_uid_process_count",
                        lambda: fake_count)
    monkeypatch.setattr(_macos_spawn, "_darwin_nproc_kernel_clamp",
                        lambda: fake_clamp)
    monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                        _fake_sandbox_exec(tmp_path))
    out = tmp_path / "out"
    out.mkdir()
    r = _macos_spawn.run_sandboxed(
        list(_SOFT_DUMP), output=str(out),
        nproc_limit=budget,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, timeout=20,
    )
    if (r.returncode != 0
            and "Resource temporarily unavailable" in (r.stderr or "")):
        # The census-sized clamp is a SNAPSHOT: same-UID task load
        # can spike past it inside the spawn window, and then the
        # kernel refuses the shim's own fork before production
        # semantics are observable — the same pure load flake, just
        # later. Skipping here cannot mask an absolute-cap
        # regression: test_ceiling_is_count_plus_budget_clamped
        # EAGAINs deterministically under a budget-sized limit and
        # carries no such guard.
        pytest.skip("same-UID task load crossed the emulated clamp "
                    "during spawn")
    assert r.returncode == 0, r.stderr
    assert int(r.stdout.strip()) == _expected_soft(fake_count + budget,
                                                   fake_clamp)


def test_clamp_above_ceiling_keeps_relative_arithmetic(tmp_path,
                                                       monkeypatch):
    """Anti-degeneration guard: with the kernel clamp ABOVE
    count+budget, the child must still observe the RELATIVE ceiling —
    the clamp must never swallow the count+budget assertion (an
    absolute-cap regression stays red under a sub-clamp count).

    On a real darwin host a fake clamp cannot lift the REAL one (the
    actual setrlimit still hits the actual kernel), so the fake
    values are picked relative to the real kern.maxprocperuid: the
    whole request sits strictly below it — the kernel never
    interferes and the child observes the true count+budget — with
    headroom above live usage so the shim's own fork survives the
    lowered limit (no window: skip; the absolute-cap mutation stays
    red on darwin via the other two ceiling tests). On Linux there is
    no kernel clamp underneath and the emulation is exact."""
    budget = 64
    if _REAL_KERNEL_CLAMP is None:
        fake_count = 100000  # far above live usage: ceiling only RAISES
        fake_clamp = 200000  # above the ceiling: must not matter
    else:
        real_usage = _macos_spawn._same_uid_process_count()
        if real_usage is None:
            # Broken ps already fails its own test in this file; do
            # not let a None usage open the window guard blindly (an
            # unguarded lowered limit could EAGAIN the shim's fork).
            pytest.skip("same-UID process count unavailable — cannot "
                        "size the sub-clamp window safely")
        fake_count = _REAL_KERNEL_CLAMP - budget - 128
        if fake_count <= real_usage + 128:
            pytest.skip(
                "no window between live same-UID usage and "
                "kern.maxprocperuid to observe the relative ceiling "
                "below the real kernel clamp")
        fake_clamp = _REAL_KERNEL_CLAMP  # above the request by construction
    monkeypatch.setattr(_macos_spawn, "_same_uid_process_count",
                        lambda: fake_count)
    monkeypatch.setattr(_macos_spawn, "_darwin_nproc_kernel_clamp",
                        lambda: fake_clamp)
    monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                        _fake_sandbox_exec(tmp_path))
    out = tmp_path / "out"
    out.mkdir()
    r = _macos_spawn.run_sandboxed(
        list(_SOFT_DUMP), output=str(out),
        nproc_limit=budget,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, timeout=20,
    )
    assert r.returncode == 0, r.stderr
    soft = int(r.stdout.strip())
    expected = _expected_soft(fake_count + budget, fake_clamp)
    assert soft == expected, (
        f"child soft NPROC {soft} != relative ceiling {expected} "
        f"(clamp-masking or absolute-cap regression?)")


def test_kernel_clamp_helper_platform_gated():
    """On non-darwin hosts the helper must return None without
    touching sysctl (Linux sysctl exists with different semantics)."""
    if sys.platform == "darwin":
        clamp = _macos_spawn._darwin_nproc_kernel_clamp()
        assert clamp is None or clamp > 0
    else:
        assert _macos_spawn._darwin_nproc_kernel_clamp() is None


def test_count_unavailable_skips_cap_with_warning(tmp_path, monkeypatch,
                                                  caplog):
    """No count → no cap (never a blind absolute one), and the skip is
    named to the operator."""
    monkeypatch.setattr(_macos_spawn, "_same_uid_process_count",
                        lambda: None)
    monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                        _fake_sandbox_exec(tmp_path))
    out = tmp_path / "out"
    out.mkdir()
    inherited_soft, _ = resource.getrlimit(resource.RLIMIT_NPROC)
    with caplog.at_level(logging.WARNING, logger="core.sandbox._macos_spawn"):
        r = _macos_spawn.run_sandboxed(
            list(_SOFT_DUMP), output=str(out),
            nproc_limit=64,
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, timeout=20,
        )
    assert r.returncode == 0, r.stderr
    assert int(r.stdout.strip()) == inherited_soft
    assert any("skipping the RLIMIT_NPROC" in rec.message
               for rec in caplog.records)


def test_no_budget_means_no_count_and_no_cap(tmp_path, monkeypatch):
    """nproc_limit unset/zero: the counting helper must not even run
    (no ps cost on the default path) and the limit stays inherited."""
    def boom():
        raise AssertionError("counted with no nproc budget")

    monkeypatch.setattr(_macos_spawn, "_same_uid_process_count", boom)
    monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                        _fake_sandbox_exec(tmp_path))
    out = tmp_path / "out"
    out.mkdir()
    inherited_soft, _ = resource.getrlimit(resource.RLIMIT_NPROC)
    r = _macos_spawn.run_sandboxed(
        list(_SOFT_DUMP), output=str(out),
        nproc_limit=0,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, timeout=20,
    )
    assert r.returncode == 0, r.stderr
    assert int(r.stdout.strip()) == inherited_soft
