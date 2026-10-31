#!/usr/bin/env python3
"""Derive lane seccomp profiles from docker's default profile JSON.

Input: profiles/moby-default-seccomp-v28.3.0.json (pinned copy of
moby/moby profiles/seccomp/default.json at tag v28.3.0 — the closest
published tag to the local docker engine; later tags 404 on raw
githubusercontent at fetch time).

Outputs (into --out DIR):
  no-landlock.json  allow-all base (defaultAction SCMP_ACT_ALLOW, arch
                    map copied from the default profile) with
                    landlock_create_ruleset / landlock_add_rule /
                    landlock_restrict_self as an explicit
                    SCMP_ACT_ERRNO(ENOSYS=38) group — a faithful fake of
                    a pre-5.13 bare-metal kernel (probe sees ENOSYS, not
                    EPERM; pivot_root/mount/unshare all work, unlike the
                    docker default profile which omits pivot_root and so
                    EPERMs it via defaultErrnoRet even with
                    CAP_SYS_ADMIN — verified empirically). This keeps
                    the lane a SINGLE-variable diff against `full`.
  no-userns.json    default profile with unshare/clone/clone3 removed
                    from every group, then:
                      * unshare/clone with CLONE_NEWUSER (0x10000000) in
                        the flags arg -> EPERM (SCMP_CMP_MASKED_EQ)
                      * unshare/clone without CLONE_NEWUSER -> allow
                      * clone3 -> ENOSYS(38) unconditionally, forcing
                        libc fallback to clone (clone3's flags live in
                        user memory and cannot be seccomp-filtered)
                    s390/s390x carry clone's flags in arg1; mirrored for
                    completeness even though this harness is x86_64.
  no-both.json      composition of the two transforms.
  no-mount.json     default profile with mount-OPERATION denial while
                    every namespace creation stays available: the
                    mount-syscall family (classic mount(2) and the new
                    fsopen/fsconfig/fsmount/move_mount/open_tree/
                    mount_setattr API, plus pivot_root) -> EPERM
                    unconditionally, covering util-linux builds that
                    use either API. This is the outer-container-seccomp
                    shape: the spawn ladder reaches its mid-flight
                    mount failure instead of dying at namespace
                    creation (denying CLONE_NEWNS itself was tried
                    first and produced a DIFFERENT, harsher shape).
                    umount2 stays allowed: the entry shim's root-stage
                    unmasking must keep working (in the modelled shape
                    nothing can create a mount to unmount anyway).
  restricted-userns.json  no-mount plus STAGED pid-namespace-creation
                    denial — the GitHub-runner shape, confirmed from
                    live runner artifacts (probe.json + spawn
                    tracebacks): single-call multi-namespace creation
                    works, but a second unshare(CLONE_NEWPID) issued
                    from inside the already-created user namespace
                    EPERMs (Ubuntu's apparmor_restrict_unprivileged_userns
                    transition). Adds a masked partition on unshare's
                    flags: NEWPID without concurrent NEWUSER -> EPERM;
                    complementary allows for everything else.
  no-mount-nonet.json  no-mount plus network-namespace-creation denial
                    — a hypothesised variant kept for lattice coverage
                    of the userns-probe-False degradation path (it was
                    first modelled as the runner shape; live artifacts
                    later showed the runner actually denies the staged
                    pid-ns creation and the self-map write instead —
                    see restricted-userns.json). Adds:
                      * unshare/clone with CLONE_NEWNET (0x40000000)
                        in the flags arg -> EPERM; without -> allow
                        (CLONE_NEWUSER/NEWNS/NEWPID keep working)
                      * clone3 -> ENOSYS (same rationale as no-userns)
"""

import argparse
import copy
import json
from pathlib import Path

LANDLOCK_SYSCALLS = [
    "landlock_add_rule",
    "landlock_create_ruleset",
    "landlock_restrict_self",
]
USERNS_SYSCALLS = ["clone", "clone3", "unshare"]
CLONE_NEWNET = 0x40000000
CLONE_NEWPID = 0x20000000
MOUNT_SYSCALLS = [
    "mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "move_mount",
    "open_tree",
    "mount_setattr",
    "pivot_root",
]
CLONE_NEWUSER = 0x10000000
CLONE_NEWNS = 0x00020000
ENOSYS = 38
EPERM = 1


def _strip_names(profile: dict, names: list[str]) -> None:
    """Remove the given syscall names from every group; drop empty groups."""
    kept = []
    for group in profile["syscalls"]:
        group["names"] = [n for n in group["names"] if n not in names]
        if group["names"]:
            kept.append(group)
    profile["syscalls"] = kept


def no_landlock_allow_all(profile: dict) -> dict:
    """Pre-5.13-kernel fake: everything allowed except landlock_* -> ENOSYS."""
    return {
        "defaultAction": "SCMP_ACT_ALLOW",
        "archMap": copy.deepcopy(profile.get("archMap", [])),
        "syscalls": [{
            "names": list(LANDLOCK_SYSCALLS),
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": ENOSYS,
        }],
    }


def strip_landlock(profile: dict) -> dict:
    """Default-profile variant of the landlock transform (used for the
    no-both composition, where docker-profile realism is kept because
    the userns denial dominates anyway)."""
    p = copy.deepcopy(profile)
    _strip_names(p, LANDLOCK_SYSCALLS)
    p["syscalls"].append({
        "names": list(LANDLOCK_SYSCALLS),
        "action": "SCMP_ACT_ERRNO",
        "errnoRet": ENOSYS,
    })
    return p


def no_userns(profile: dict) -> dict:
    p = copy.deepcopy(profile)
    _strip_names(p, USERNS_SYSCALLS)
    masked = lambda index, datum: [{  # noqa: E731
        "index": index,
        "value": CLONE_NEWUSER,      # mask
        "valueTwo": datum,           # expected (arg & mask)
        "op": "SCMP_CMP_MASKED_EQ",
    }]
    p["syscalls"] += [
        # x86_64 (and everything but s390*): flags in arg0 for both.
        {"names": ["clone", "unshare"], "action": "SCMP_ACT_ERRNO",
         "errnoRet": EPERM, "args": masked(0, CLONE_NEWUSER),
         "excludes": {"arches": ["s390", "s390x"]}},
        {"names": ["clone", "unshare"], "action": "SCMP_ACT_ALLOW",
         "args": masked(0, 0),
         "excludes": {"arches": ["s390", "s390x"]}},
        # s390*: clone flags in arg1; unshare stays arg0.
        {"names": ["clone"], "action": "SCMP_ACT_ERRNO",
         "errnoRet": EPERM, "args": masked(1, CLONE_NEWUSER),
         "includes": {"arches": ["s390", "s390x"]}},
        {"names": ["clone"], "action": "SCMP_ACT_ALLOW",
         "args": masked(1, 0),
         "includes": {"arches": ["s390", "s390x"]}},
        {"names": ["unshare"], "action": "SCMP_ACT_ERRNO",
         "errnoRet": EPERM, "args": masked(0, CLONE_NEWUSER),
         "includes": {"arches": ["s390", "s390x"]}},
        {"names": ["unshare"], "action": "SCMP_ACT_ALLOW",
         "args": masked(0, 0),
         "includes": {"arches": ["s390", "s390x"]}},
        # clone3 cannot be arg-filtered; ENOSYS forces libc's clone path.
        {"names": ["clone3"], "action": "SCMP_ACT_ERRNO",
         "errnoRet": ENOSYS},
    ]
    return p


def no_mount(profile: dict) -> dict:
    """Outer-seccomp shape: every namespace CREATION allowed, mount
    OPERATIONS denied (see module docstring). Single-variable diff
    against `full`: only the mount-syscall family EPERMs — the shape
    an outer container seccomp filter that blocks the mount family
    produces, where the spawn ladder reaches its mid-flight mount
    failure instead of dying at namespace creation."""
    p = copy.deepcopy(profile)
    _strip_names(p, MOUNT_SYSCALLS)
    p["syscalls"].append({
        "names": list(MOUNT_SYSCALLS),
        "action": "SCMP_ACT_ERRNO",
        "errnoRet": EPERM,
    })
    return p


def restricted_userns(profile: dict) -> dict:
    """The GitHub-runner shape, confirmed from live artifacts: every
    single-call multi-namespace creation works (the flat engagement
    probe passes), the mount family EPERMs, and the spawn backend's
    STAGED second unshare(CLONE_NEWPID) — issued from inside the
    already-created user namespace — EPERMs (the runner's spawn child
    died exactly there). Faked as no_mount plus a masked partition on
    unshare's flags: NEWPID without concurrent NEWUSER -> EPERM; no
    NEWPID, or NEWPID together with NEWUSER, -> allow. clone/clone3
    stay unfiltered on purpose: every surface RAPTOR exercises reaches
    pid-ns creation via unshare(2) (os.unshare in the spawn backend,
    unshare(2) inside util-linux `unshare`), so filtering the clone
    family would model a denial nothing observes. The runner also
    denies the --map-root-user self-map write (a procfs write seccomp
    cannot express); every surface RAPTOR exercises converges anyway:
    the util-linux probes still report mount/proc/pivot fail (at the
    mount instead of the map write), and the spawn — whose newuidmap
    mapping works on the real runner — dies at the same staged call."""
    p = no_mount(profile)
    _strip_names(p, ["unshare"])
    masked = lambda datum: [{  # noqa: E731
        "index": 0,
        "value": CLONE_NEWUSER | CLONE_NEWPID,   # mask
        "valueTwo": datum,                       # expected (arg & mask)
        "op": "SCMP_CMP_MASKED_EQ",
    }]
    p["syscalls"] += [
        # staged pid-ns creation (NEWPID set, NEWUSER not in the same
        # call) -> EPERM
        {"names": ["unshare"], "action": "SCMP_ACT_ERRNO",
         "errnoRet": EPERM, "args": masked(CLONE_NEWPID)},
        # complements — MUST be arg-filtered partitions, not an
        # unconditional allow: docker/libseccomp gives an
        # unconditional rule precedence over the arg-filtered ERRNO
        # (verified empirically), which would void the denial.
        {"names": ["unshare"], "action": "SCMP_ACT_ALLOW",
         "args": [{"index": 0, "value": CLONE_NEWPID, "valueTwo": 0,
                   "op": "SCMP_CMP_MASKED_EQ"}]},
        {"names": ["unshare"], "action": "SCMP_ACT_ALLOW",
         "args": masked(CLONE_NEWUSER | CLONE_NEWPID)},
    ]
    return p


def no_mount_nonet(profile: dict) -> dict:
    """GitHub-runner shape: user/pid/ipc/mount namespace CREATION
    allowed, mount OPERATIONS and network-namespace creation denied
    (see module docstring; both denials were observed together on the
    real runner — `unshare --user --pid --fork --ipc` engages while
    `unshare --user --net` and every mount(2) inside an owned
    namespace refuse). Landlock and everything else keep working, so
    the delta against `no-mount` isolates the netns denial and the
    delta against `full` is the restricted-userns capability-denial
    shape."""
    p = copy.deepcopy(profile)
    _strip_names(p, USERNS_SYSCALLS + MOUNT_SYSCALLS)
    masked = lambda index, datum: [{  # noqa: E731
        "index": index,
        "value": CLONE_NEWNET,       # mask
        "valueTwo": datum,           # expected (arg & mask)
        "op": "SCMP_CMP_MASKED_EQ",
    }]
    p["syscalls"] += [
        # x86_64 (and everything but s390*): flags in arg0 for both.
        {"names": ["clone", "unshare"], "action": "SCMP_ACT_ERRNO",
         "errnoRet": EPERM, "args": masked(0, CLONE_NEWNET),
         "excludes": {"arches": ["s390", "s390x"]}},
        {"names": ["clone", "unshare"], "action": "SCMP_ACT_ALLOW",
         "args": masked(0, 0),
         "excludes": {"arches": ["s390", "s390x"]}},
        # s390*: clone flags in arg1; unshare stays arg0.
        {"names": ["clone"], "action": "SCMP_ACT_ERRNO",
         "errnoRet": EPERM, "args": masked(1, CLONE_NEWNET),
         "includes": {"arches": ["s390", "s390x"]}},
        {"names": ["clone"], "action": "SCMP_ACT_ALLOW",
         "args": masked(1, 0),
         "includes": {"arches": ["s390", "s390x"]}},
        {"names": ["unshare"], "action": "SCMP_ACT_ERRNO",
         "errnoRet": EPERM, "args": masked(0, CLONE_NEWNET),
         "includes": {"arches": ["s390", "s390x"]}},
        {"names": ["unshare"], "action": "SCMP_ACT_ALLOW",
         "args": masked(0, 0),
         "includes": {"arches": ["s390", "s390x"]}},
        # clone3 cannot be arg-filtered; ENOSYS forces libc's clone
        # path so the NEWNET filter above cannot be bypassed.
        {"names": ["clone3"], "action": "SCMP_ACT_ERRNO",
         "errnoRet": ENOSYS},
        # Mount capability denied outright, both mount APIs.
        {"names": list(MOUNT_SYSCALLS), "action": "SCMP_ACT_ERRNO",
         "errnoRet": EPERM},
    ]
    return p


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=str(
        Path(__file__).parent / "moby-default-seccomp-v28.3.0.json"))
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    base = json.loads(Path(args.base).read_text())
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, prof in (
        ("no-landlock", no_landlock_allow_all(base)),
        ("no-mount", no_mount(base)),
        ("restricted-userns", restricted_userns(base)),
        ("no-mount-nonet", no_mount_nonet(base)),
        ("no-userns", no_userns(base)),
        ("no-both", no_userns(strip_landlock(base))),
    ):
        (out / f"{name}.json").write_text(json.dumps(prof, indent=1) + "\n")
        print(f"wrote {out / f'{name}.json'}")


if __name__ == "__main__":
    main()
