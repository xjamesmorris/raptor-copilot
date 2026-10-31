#!/usr/bin/env python3
"""Lane definitions: docker security options + intended feature shape.

Single source of truth, consumed two ways:
  * run-matrix.sh:   python3 profiles/lanes.py args <lane> --profiles DIR
                     -> newline-separated docker run arguments
  * bin/report.py:   imports LANES and compares each lane's probed
                     shape against the two expectation tiers:
                       expect      — features the lane's own
                                     configuration FORCES (seccomp
                                     fakes, denials) plus the harness's
                                     host floor. A mismatch means the
                                     lane didn't apply -> the cell is
                                     SHAPE-DIVERGED and the run fails.
                       expect_env  — environment-conditioned features
                                     with their NOMINAL values. A
                                     mismatch is a real host shape, not
                                     a harness bug: the cell
                                     self-classifies as
                                     degraded(<features>) and the run
                                     does NOT fail on shape (test
                                     failures still gate). GitHub
                                     runners land here: Ubuntu's
                                     apparmor_restrict_unprivileged_userns
                                     leaves userns creation working but
                                     denies mount capability inside, so
                                     the full lane probes
                                     UNS=ok MNT=fail — previously
                                     stamped "as-intended" by a
                                     host-conditioned expectation,
                                     burying the divergence the table
                                     itself printed.
                     expect=None with no expect_env = record-only lane
                     ("probe, don't assume").

Design notes
------------
All custom-profile lanes share apparmor=unconfined + CAP_SYS_ADMIN +
root-entry /proc unmasking so that exactly ONE variable — the seccomp
profile — differs between them. Rationale:

  * apparmor=unconfined: Ubuntu's docker-default AppArmor profile denies
    mount(2) even inside a fully-owned user namespace, which would fuse
    the mount/procfs probe results across lanes and mask the seccomp
    variable under test.
  * --user root + SXV_UNMASK=1 (see bin/entry.sh): docker's masked
    /proc paths make procfs "not fully visible", so the kernel refuses
    fresh `mount -t proc` inside a user namespace regardless of
    permissions. The local engine rejects `systempaths=unmasked`
    (verified empirically), so the entry shim unmounts the masks as
    container-root and drops to the runner user. Restores the
    bare-metal runner shape the lanes are modelling.
  * CAP_SYS_ADMIN: the moby default profile only installs its
    unshare/clone/clone3 allow group when the container has
    CAP_SYS_ADMIN in its bounding set (the cap gates which *rules* are
    compiled in, not per-process privilege); it also legalises the
    unmask step. Tests still run as the unprivileged uid-1001 runner
    user, which holds no capabilities.

`default` is stock docker confinement — no overrides, no expectations;
the probe records what it actually blocks.
"""

import argparse
import sys

LANE_ORDER = ["full", "default", "no-landlock", "no-mount",
              "restricted-userns", "no-mount-nonet", "no-userns",
              "no-both"]

_COMMON = [
    "--security-opt", "apparmor=unconfined",
    "--cap-add", "SYS_ADMIN",
    "--user", "root",
    "-e", "SXV_UNMASK=1",
]

# Mount-capability features are environment-conditioned on lanes that
# don't force them: the host's apparmor_restrict_unprivileged_userns
# sysctl is kernel-wide (docker --privileged cannot override it), so a
# feature-complete lane on a restricted host probes MNT=fail without
# any harness bug. Nominal (feature-complete) values:
_ENV_MOUNT_NOMINAL = {"mount_in_userns": "ok",
                      "proc_mount_in_userns": "ok",
                      "pivot_root_in_userns": "ok"}

# Tests that must appear PASSED — not skipped, not absent — in a
# lane's junit (report.py gates on it like a divergence). These are
# the binding guards of inverse-gated live coverage: a test module
# that runs ONLY where a kernel feature is genuinely denied cannot
# defend itself against being skipped wholesale (a module-level gate
# skips its own in-file guard too), so the lane that exists to bind
# it asserts the guard ran and passed. Applied to every lane whose
# seccomp profile forces the namespace backend away; the `default`
# lane stays record-only by design ("probe, don't assume").
_EXPECT_BOUND_DENIED_NS = [
    "test_denied_matrix_lanes_bind_this_module",
]

LANES: dict[str, dict[str, object]] = {
    "full": {
        "docker_args": ["--privileged"],
        "expect": {"landlock": "present", "userns": "ok", "seccomp": "ok"},
        "expect_env": dict(_ENV_MOUNT_NOMINAL),
        "intent": "namespaces AND Landlock available",
    },
    "default": {
        "docker_args": [],
        "expect": None,  # probe, don't assume
        "intent": "stock docker confinement (empirical)",
    },
    # no-landlock mirrors `full` in every respect except the faked-away
    # Landlock syscalls (allow-all seccomp base + cap-add ALL), so its
    # failure delta against `full` isolates pure Landlock absence.
    "no-landlock": {
        "docker_args": ["--security-opt", "seccomp=@PROFILES@/no-landlock.json",
                        "--security-opt", "apparmor=unconfined",
                        "--cap-add", "ALL",
                        "--user", "root", "-e", "SXV_UNMASK=1"],
        "expect": {"landlock": "enosys", "userns": "ok", "seccomp": "ok"},
        "expect_env": dict(_ENV_MOUNT_NOMINAL),
        "intent": "pre-5.13-kernel fake: namespaces yes, Landlock ENOSYS",
    },
    # Mount-capability-denied lanes, made permanent the day a GitHub
    # runner proved the population exists (userns creation worked, every
    # mount inside was denied — Ubuntu's restricted-userns AppArmor
    # transition). Three variants because the real populations diverge
    # in what the capability guards see:
    #   no-mount           mount OPERATIONS denied, all namespace
    #                      creation works — outer-container-seccomp
    #                      shape; userns probe True, engagement probe
    #                      True; tests gate on the MOUNT probe.
    #   restricted-userns  no-mount plus the STAGED pid-ns creation
    #                      denial — the shape live-confirmed on the
    #                      GitHub runner (see make_profiles.py):
    #                      userns/net probes True but the spawn
    #                      backend's engagement probe goes False, so
    #                      namespace-backed runs refuse loudly and
    #                      backend-premised tests skip via
    #                      requires_ns_backend.
    #   no-mount-nonet     additionally denies netns creation — kept
    #                      for lattice coverage of the
    #                      userns-probe-False path (first modelled as
    #                      the runner shape; superseded by
    #                      restricted-userns when live artifacts
    #                      arrived).
    # All features forced by the seccomp profile — static expectations,
    # no env tier.
    "no-mount": {
        "docker_args": ["--security-opt", "seccomp=@PROFILES@/no-mount.json",
                        *_COMMON],
        "expect": {"landlock": "present", "userns": "ok",
                   "mount_in_userns": "fail", "proc_mount_in_userns": "fail",
                   "pivot_root_in_userns": "fail", "seccomp": "ok"},
        "intent": "namespaces ok, mount operations denied (outer seccomp)",
    },
    "restricted-userns": {
        "docker_args": ["--security-opt",
                        "seccomp=@PROFILES@/restricted-userns.json",
                        *_COMMON],
        "expect": {"landlock": "present", "userns": "ok",
                   "mount_in_userns": "fail", "proc_mount_in_userns": "fail",
                   "pivot_root_in_userns": "fail", "seccomp": "ok"},
        "expect_bound": _EXPECT_BOUND_DENIED_NS,
        "intent": ("mount ops + staged pid-ns creation denied "
                   "(GitHub-runner shape, live-confirmed)"),
    },
    "no-mount-nonet": {
        "docker_args": ["--security-opt",
                        "seccomp=@PROFILES@/no-mount-nonet.json",
                        *_COMMON],
        "expect": {"landlock": "present", "userns": "ok",
                   "mount_in_userns": "fail", "proc_mount_in_userns": "fail",
                   "pivot_root_in_userns": "fail", "seccomp": "ok"},
        "expect_bound": _EXPECT_BOUND_DENIED_NS,
        "intent": "mount ops + netns creation denied (userns-probe-False)",
    },
    "no-userns": {
        "docker_args": ["--security-opt", "seccomp=@PROFILES@/no-userns.json",
                        *_COMMON],
        "expect": {"landlock": "present", "userns": "denied",
                   "mount_in_userns": "fail", "proc_mount_in_userns": "fail",
                   "pivot_root_in_userns": "fail", "seccomp": "ok"},
        "expect_bound": _EXPECT_BOUND_DENIED_NS,
        "intent": "userns denied (EPERM), Landlock present",
    },
    "no-both": {
        "docker_args": ["--security-opt", "seccomp=@PROFILES@/no-both.json",
                        *_COMMON],
        "expect": {"landlock": "enosys", "userns": "denied",
                   "mount_in_userns": "fail", "proc_mount_in_userns": "fail",
                   "pivot_root_in_userns": "fail", "seccomp": "ok"},
        "expect_bound": _EXPECT_BOUND_DENIED_NS,
        "intent": "no namespaces, no Landlock",
    },
}


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_args = sub.add_parser("args")
    p_args.add_argument("lane", choices=LANE_ORDER)
    p_args.add_argument("--profiles", required=True,
                        help="directory holding the generated seccomp JSONs")
    sub.add_parser("list")
    ns = ap.parse_args()

    if ns.cmd == "list":
        print("\n".join(LANE_ORDER))
        return
    lane = LANES[ns.lane]
    args = lane["docker_args"]
    assert isinstance(args, list)
    for a in args:
        sys.stdout.write(a.replace("@PROFILES@", ns.profiles) + "\n")


if __name__ == "__main__":
    main()
