"""LIVE denied-class floor coverage — real probes, real refusal.

Every other test of the floor contract's userns-denied behaviour
simulates the denial (monkeypatched ``check_net_available`` /
``check_unshare_engages`` seams) so it can exercise the refusal SHAPE
on capable hosts. That left the REAL refusal path — the one a
genuinely userns-denied kernel takes through the live probes — bound
by no test at all: the same class of gap that let the staged-pidns
creation denial (restricted userns) live unseen until run artifacts
surfaced it.

This module closes it with INVERSE gating: the live tests run ONLY
where the kernel genuinely denies the namespace backend
(``check_net_available()`` is False — outright userns denial, or the
staged pid-ns refusal folded into the same probe) and SKIP on capable
hosts, where the refusal cannot fire without simulation. The
feature-matrix denied lanes (core/sandbox/scripts/feature-matrix/:
``default``, ``no-userns``, ``restricted-userns``, ``no-mount-nonet``,
``no-both``) run the whole suite in genuinely-denied containers and
are where these tests bind; ``test_denied_matrix_lanes_bind_this_module``
turns a silently-skipped denied lane into a red failure so the
denied-class coverage can never go probe-vacuous again.

Doctrine: NO probe, seam, or backend monkeypatching anywhere in this
file — the live path is the entire point. The environment variable
(``RAPTOR_ALLOW_DEGRADED_UNTRUSTED``) and the CLI consent slot
(``state._cli_sandbox_floor``) are the call's INPUT configuration —
the consent surfaces an operator would set — not probe simulation.
"""

from __future__ import annotations

import os
import shutil
import sys

import pytest

from core.sandbox.errors import SandboxFloorError

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux namespace lanes")


def _ns_backend_available() -> bool:
    # The namespace-backend foundation probe backend selection keys on
    # (single-call userns creation AND the staged pid-ns self-test) —
    # the same verdict that routes production onto the refusal /
    # degradation lanes this module exercises.
    from core.sandbox.probes import check_net_available
    return check_net_available()


_NS_BACKEND_AVAILABLE = _ns_backend_available()

# Inverse capability gate: capability.py's markers skip where features
# are ABSENT; this one skips where the feature is PRESENT, because the
# subject under test is the refusal a denied kernel produces.
denied_kernel_only = pytest.mark.skipif(
    _NS_BACKEND_AVAILABLE,
    reason="requires a userns-DENIED kernel: exercises the LIVE "
           "untrusted-entry refusal and degradation paths with real "
           "probes; on this host the namespace backend engages, so "
           "the refusal cannot fire (the feature-matrix denied lanes "
           "bind these tests)",
)


def _skip_unless_seccomp() -> None:
    from core.sandbox.seccomp import check_seccomp_available
    if not check_seccomp_available():
        pytest.skip("libseccomp required to reach the userns arm live "
                    "(without it the seccomp axis arm refuses first)")


def _expected_achievable():
    """The achievable tier the LIVE landlock probe implies (the
    refusal's honesty contract: policy layers still engage when the
    kernel has them, else nothing does)."""
    from core.sandbox import tiers
    from core.sandbox.landlock import check_landlock_available
    return (tiers.ContainmentTier.LANDLOCK_ONLY
            if check_landlock_available()
            else tiers.ContainmentTier.BARE)


@denied_kernel_only
class TestLiveDeniedFloor:
    """End-to-end floor behaviour on a genuinely denied kernel."""

    def test_unwaived_untrusted_refuses_live(self, tmp_path, monkeypatch):
        """(a) An unwaived untrusted-shaped call hits the LIVE userns
        arm: typed SandboxFloorError with honest floor/achievable/
        source, a floor_refusal evidence record, and zero spawn
        side-effects — the target command never ran, no sandbox
        setup began."""
        from core.sandbox import context as ctx
        from core.sandbox import summary, tiers
        _skip_unless_seccomp()
        monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED",
                           raising=False)
        target = tmp_path / "target"
        target.mkdir()
        out = tmp_path / "run"
        out.mkdir()
        marker = out / "spawned"
        with pytest.raises(SandboxFloorError) as excinfo:
            ctx.run_untrusted(["touch", str(marker)], target=str(target),
                              output=str(out), timeout=60)
        err = excinfo.value
        # Typed fields: floor is the class default; achievable follows
        # the LIVE landlock probe (nothing simulated in this module).
        assert err.floor is tiers.ContainmentTier.MOUNT_NS
        assert err.achievable is _expected_achievable()
        # Floor-source honesty: nothing consented, so the chain
        # resolves to the fail-closed class default...
        assert ctx.resolve_untrusted_floor() == (
            tiers.ContainmentTier.MOUNT_NS, tiers.FLOOR_SOURCE_DEFAULT)
        # ...and the refusal names the host condition plus every
        # consent surface (the default-source remedy set).
        msg = str(err)
        assert ("run_untrusted: this host cannot create unprivileged "
                "user namespaces") in msg
        for surface in ("--sandbox-floor landlock",
                        "/project set sandbox-floor landlock",
                        "RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1"):
            assert surface in msg
        # Zero spawn side-effects: the command never executed and
        # sandbox construction never began (no fake home).
        assert not marker.exists()
        assert not (out / ".home").exists()
        # The refusal left durable evidence: a floor_refusal record in
        # the run-dir stream, surfaced by summary generation — and it
        # never masquerades as a denial.
        assert (out / ".audit" / summary.DENIALS_FILE).exists()
        result = summary.summarize_and_write(out)
        assert result is not None
        assert result["total_floor_refusals"] >= 1
        rec = result["floor_refusals"][0]
        assert rec["status"] == "unverifiable_environment"
        assert rec["floor"] == "mount-ns"
        assert rec["achievable"] == tiers.tier_label(
            _expected_achievable())
        assert "mount-ns required" in result["floor_refusal_line"]
        assert result["total_denials"] == 0

    def test_waived_untrusted_runs_degraded_with_honest_stamps(
            self, tmp_path, monkeypatch):
        """(b) With the operator waiver the SAME host runs the call on
        the live degradation path — the command genuinely executes at
        the landlock tier and the posture stamps tell the truth about
        what contained it and who consented."""
        from core.sandbox import context as ctx
        from core.sandbox import summary
        from core.sandbox.landlock import (
            _get_landlock_abi,
            check_landlock_available,
        )
        if not check_landlock_available():
            pytest.skip("requires Landlock: the waived degradation "
                        "path delivers the landlock tier — without it "
                        "there is nothing to degrade TO here")
        if _get_landlock_abi() < 4:
            pytest.skip("requires Landlock ABI v4+: run_untrusted's "
                        "network block needs the degraded TCP-connect "
                        "deny on a namespace-less host")
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        target = tmp_path / "target"
        target.mkdir()
        out = tmp_path / "run"
        out.mkdir()
        marker = out / "ran-live"
        touch = shutil.which("touch")
        assert touch, "touch not found on PATH"
        result = ctx.run_untrusted([touch, str(marker)],
                                   target=str(target), output=str(out),
                                   timeout=60)
        assert result.returncode == 0
        assert marker.exists(), (
            "waived degraded run returned without executing the command")
        info = result.sandbox_info  # type: ignore[attr-defined]
        assert info["containment_tier"] == "landlock"
        assert info["containment_floor"] == "landlock"
        assert info["floor_source"] == "env"
        # The requested network block engaged on the degraded lane
        # (Landlock TCP deny), stamped for forensic readers.
        assert info.get("degraded_net_deny") is True
        # A consented degrade is not a refusal: no floor_refusal
        # evidence for this run.
        summarized = summary.summarize_and_write(out)
        assert (summarized is None
                or summarized.get("total_floor_refusals", 0) == 0)

    def test_explicit_pin_refuses_naming_the_pin(self, tmp_path,
                                                 monkeypatch):
        """(c) An explicit --sandbox-floor pin above the landlock tier
        refuses on the live denied kernel even with the env waiver set
        (explicit surfaces win in both directions), and the refusal
        names the pinning surface."""
        from core.sandbox import cli, context as ctx
        from core.sandbox import state, summary, tiers
        _skip_unless_seccomp()
        # The pin must beat the env waiver — set both. Register the
        # slot with monkeypatch first (guaranteed restore), then set it
        # through the PRODUCTION flag setter (validated argparse path).
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        monkeypatch.setattr(state, "_cli_sandbox_floor",
                            state._cli_sandbox_floor)
        cli.set_cli_sandbox_floor("mount-ns")
        target = tmp_path / "target"
        target.mkdir()
        out = tmp_path / "run"
        out.mkdir()
        marker = out / "spawned"
        assert ctx.resolve_untrusted_floor() == (
            tiers.ContainmentTier.MOUNT_NS, tiers.FLOOR_SOURCE_FLAG)
        with pytest.raises(SandboxFloorError) as excinfo:
            ctx.run_untrusted(["touch", str(marker)], target=str(target),
                              output=str(out), timeout=60)
        err = excinfo.value
        assert err.floor is tiers.ContainmentTier.MOUNT_NS
        assert err.achievable is _expected_achievable()
        # The refusal names the pin and its authority over the env var.
        assert ("--sandbox-floor currently pins the floor at "
                "'mount-ns', which the env var does not override"
                ) in str(err)
        assert not marker.exists()
        result = summary.summarize_and_write(out)
        assert result is not None
        assert result["total_floor_refusals"] >= 1
        rec = result["floor_refusals"][0]
        assert rec["status"] == "unverifiable_environment"
        assert rec["floor"] == "mount-ns"


# Feature-matrix lanes whose seccomp profile FORCES the namespace
# backend away (profiles/lanes.py). The `default` lane also denies in
# practice (stock docker confinement) but is record-only by design
# ("probe, don't assume"), so its binding shows up in the lane junit
# rather than being asserted here.
_DENIED_FORCED_LANES = frozenset({
    "no-userns", "restricted-userns", "no-mount-nonet", "no-both"})

# The subset whose profile also keeps Landlock PRESENT (lanes.py
# `expect`): there the waived-degradation live test has a landlock
# tier to degrade to and must bind. `no-both` fakes Landlock to
# ENOSYS, so that test's skip is the honest production truth there
# (nothing to degrade to) and is not asserted.
_LANDLOCK_PRESENT_LANES = frozenset({
    "no-userns", "restricted-userns", "no-mount-nonet"})


def test_denied_matrix_lanes_bind_this_module() -> None:
    """Binding guard: the inverse gate must never leave the live
    denied-class tests silently skipped in the exact lanes built to
    bind them.

    Inside a feature-matrix lane that forces the namespace backend
    away (SXV_LANE is stamped by the harness container), assert BOTH
    halves of bindability: the class gate is OFF (the live probe
    really reports the backend denied — an inverted or wrong-probe
    gate fails here, loudly, in every matrix run), and libseccomp is
    present so the userns-arm tests run rather than skip. Everywhere
    else — capable hosts, plain CI — this guard skips: it polices the
    matrix lanes, not general hosts.
    """
    lane = os.environ.get("SXV_LANE", "")
    if lane not in _DENIED_FORCED_LANES:
        pytest.skip("binding guard applies only inside a "
                    "namespace-denying feature-matrix lane (SXV_LANE)")
    # Introspect the marks actually APPLIED to the class (not the
    # module-level boolean the gate was built from) so an inverted or
    # rewired gate expression is caught too. EVERY class-level skipif
    # must be falsy here — a future truthy mark stacked next to the
    # inverse gate would vacate all three tests just as silently.
    # getattr: pytest attaches ``pytestmark`` to marked classes at
    # runtime.
    marks = getattr(TestLiveDeniedFloor, "pytestmark", [])
    gates = [m for m in marks if getattr(m, "name", "") == "skipif"]
    assert gates, "the live class lost its inverse skipif gate"
    for gate in gates:
        assert not gate.args[0], (
            f"lane {lane} forces the namespace backend away, but a "
            f"class-level skipif holds the denied-class tests OUT of "
            f"the lane built to bind them "
            f"(reason: {gate.kwargs.get('reason', '?')!r})")
    from core.sandbox.seccomp import check_seccomp_available
    assert check_seccomp_available(), (
        f"lane {lane}: libseccomp unavailable, so the userns-arm live "
        f"tests skipped — denied-class refusal coverage is vacuous in "
        f"this lane; fix the lane image")
    if lane in _LANDLOCK_PRESENT_LANES:
        # The waived-degradation live test additionally needs the
        # degraded TCP-connect deny (Landlock ABI v4+) — on an older
        # kernel it would skip in EVERY denied lane at once, silently
        # vacating a third of the module. Landlock itself is forced
        # present by these lanes' profiles; the ABI is the host
        # kernel's, so name it when it is the vacating condition.
        from core.sandbox.landlock import (
            _get_landlock_abi,
            check_landlock_available,
        )
        assert (check_landlock_available()
                and _get_landlock_abi() >= 4), (
            f"lane {lane} keeps Landlock present, but the live "
            f"probe/ABI (available={check_landlock_available()}, "
            f"abi={_get_landlock_abi()}) cannot carry the "
            f"waived-degradation live test — it skipped, so the "
            f"degradation-path denied-class coverage is vacuous in "
            f"this lane; run the matrix on a Landlock ABI v4+ kernel")
