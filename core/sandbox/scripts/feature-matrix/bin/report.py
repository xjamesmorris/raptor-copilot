#!/usr/bin/env python3
"""Aggregate a results/<timestamp>/ run dir into the lane matrix.

Reads per-lane probe.json + junit-*.xml + pytest-*.rc + meta.json,
compares each probed shape against the lane's intended shape
(lanes/lanes.py), prints the matrix, and writes matrix.md + matrix.json
+ failures.txt into the run dir.

Exit status: 0 only if every lane ran, no test failures/errors, and no
lane's probe diverged from its intended feature shape. The matrix keys
on PROBED capabilities — a lane whose probe diverged is flagged
SHAPE-DIVERGED loudly, because its test results then describe a
different feature combination than the lane name claims.
"""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "profiles"))
from lanes import LANE_ORDER, LANES  # noqa: E402


def parse_junits(lane_dir: Path, expect_bound=()) -> dict:
    from typing import Any
    agg: dict[str, Any] = {"tests": 0, "failures": 0, "errors": 0,
                           "skipped": 0, "failed_tests": [],
                           "junit_found": False,
                           # Binding guards (lanes.py `expect_bound`):
                           # tests that must be PASSED in this lane —
                           # "absent" until seen, then their observed
                           # status. Gated like a divergence in main().
                           "bound": {name: "absent"
                                     for name in expect_bound}}
    for junit in sorted(lane_dir.glob("junit-*.xml")):
        agg["junit_found"] = True
        try:
            root = ET.parse(junit).getroot()
        except ET.ParseError:
            agg["failed_tests"].append(f"<unparseable {junit.name}>")
            agg["errors"] += 1
            continue
        suites = root.iter("testsuite")
        for s in suites:
            agg["tests"] += int(s.get("tests", 0))
            agg["failures"] += int(s.get("failures", 0))
            agg["errors"] += int(s.get("errors", 0))
            agg["skipped"] += int(s.get("skipped", 0))
        for case in root.iter("testcase"):
            if case.find("failure") is not None or case.find("error") is not None:
                agg["failed_tests"].append(
                    f"{case.get('classname', '?')}::{case.get('name', '?')}")
            name = case.get("name", "")
            if name in agg["bound"]:
                if (case.find("failure") is not None
                        or case.find("error") is not None):
                    agg["bound"][name] = "failed"
                elif case.find("skipped") is not None:
                    agg["bound"][name] = "skipped"
                else:
                    agg["bound"][name] = "passed"
    return agg


_FEATURE_SHORT = {
    "landlock": "ll",
    "userns": "uns",
    "mount_in_userns": "mnt",
    "proc_mount_in_userns": "proc",
    "pivot_root_in_userns": "pivot",
    "seccomp": "sec",
}


def shape_check(lane: str, probed: dict | None) -> tuple[str, list, list]:
    """-> (verdict, divergences, degradations).

    divergences are FATAL: the probe is missing, or a probed feature
    contradicts a value the lane's own configuration forces (`expect`)
    — the lane did not apply, so its test results describe a different
    feature combination than the lane name claims.

    degradations are NON-FATAL but named: an environment-conditioned
    feature (`expect_env`) probed below its nominal value. That is a
    real host shape (e.g. GitHub runners deny mount capability inside
    unprivileged user namespaces), not a harness bug — the cell
    self-classifies as degraded(<features>) so a novel runner shape is
    labelled honestly instead of stamped as-intended while its test
    column bleeds. Test failures still gate the run either way.
    """
    spec = LANES[lane]
    expect = spec["expect"]
    env_expect = spec.get("expect_env") or {}
    if probed is None:
        return "NO-PROBE", ["probe.json missing/unreadable"], []
    if expect is None and not env_expect:
        return "recorded", [], []
    # A lane may carry either tier alone (expect=None + env tier is a
    # legal future shape); treat a missing hard tier as an empty one.
    if expect is None:
        expect = {}
    assert isinstance(expect, dict)
    diverged = [f"{k}: intended {v!r}, probed {probed.get(k)!r}"
                for k, v in expect.items() if probed.get(k) != v]
    if diverged:
        return "SHAPE-DIVERGED", diverged, []
    assert isinstance(env_expect, dict)
    degraded_keys = [k for k, v in env_expect.items() if probed.get(k) != v]
    if degraded_keys:
        degradations = [f"{k}: nominal {env_expect[k]!r}, "
                        f"probed {probed.get(k)!r}" for k in degraded_keys]
        label = ",".join(_FEATURE_SHORT.get(k, k) for k in degraded_keys)
        return f"degraded({label})", [], degradations
    return "as-intended", [], []


def fmt_shape(probed: dict | None, abi=None) -> str:
    if probed is None:
        return "?"
    ll = probed.get("landlock", "?")
    if ll == "present":
        ll = f"abi{abi}"
    return (f"LL={ll} UNS={probed.get('userns', '?')} "
            f"MNT={probed.get('mount_in_userns', '?')} "
            f"PROC={probed.get('proc_mount_in_userns', '?')} "
            f"PIVOT={probed.get('pivot_root_in_userns', '?')} "
            f"SEC={probed.get('seccomp', '?')}")


def main() -> None:
    run_dir = Path(sys.argv[1]).resolve()
    rows = []
    exit_bad = False
    stray = []

    for image_dir in sorted(p for p in run_dir.iterdir() if p.is_dir()):
        image = image_dir.name
        if image in ("profiles",):
            continue
        # A lane dir the report does not know is itself a harness
        # error: results exist that the matrix would silently drop.
        stray += [f"{image}/{d.name}" for d in image_dir.iterdir()
                  if d.is_dir() and d.name not in LANE_ORDER]
        for lane in LANE_ORDER:
            lane_dir = image_dir / lane
            if not lane_dir.is_dir():
                continue
            probe = None
            probe_full = None
            try:
                probe_full = json.loads((lane_dir / "probe.json").read_text())
                probe = probe_full.get("shape")
            except (OSError, json.JSONDecodeError):
                pass
            meta = {}
            try:
                meta = json.loads((lane_dir / "meta.json").read_text())
            except (OSError, json.JSONDecodeError):
                pass
            tests = parse_junits(
                lane_dir, LANES[lane].get("expect_bound") or ())
            verdict, divergences, degradations = shape_check(lane, probe)

            harness_err = None
            if meta.get("rc") not in (0, None):
                harness_err = f"container rc={meta.get('rc')}"
            elif not tests["junit_found"]:
                harness_err = "no junit produced"
            elif tests["tests"] == 0:
                # An empty collection reports "0 failures" for a tier
                # that never ran — gate it like any other harness error.
                harness_err = "junit contains zero tests"

            # Binding guards: an expect_bound test that is skipped or
            # absent means the lane silently did NOT exercise coverage
            # that exists only here (inverse-gated live tests) — fatal
            # like a shape divergence. Failed guards already gate via
            # the ordinary failure count; list them here too so the
            # BIND line names them.
            bound_bad = [f"{name}: {status}"
                         for name, status in tests["bound"].items()
                         if status != "passed"]

            bad = bool(divergences or verdict == "NO-PROBE"
                       or tests["failures"] or tests["errors"]
                       or harness_err or bound_bad)
            exit_bad |= bad

            rows.append({
                "image": image, "lane": lane,
                "landlock_abi": (probe_full or {}).get("landlock", {}).get("abi"),
                "probed_shape": probe, "shape_verdict": verdict,
                "divergences": divergences, "degradations": degradations,
                "harness_error": harness_err,
                "bound": tests["bound"], "bound_bad": bound_bad,
                "duration_s": meta.get("duration_s"),
                **{k: tests[k] for k in
                   ("tests", "failures", "errors", "skipped", "failed_tests")},
            })

    # ---- render ---------------------------------------------------------
    # shape column width fits the widest verdict:
    # degraded(mnt,proc,pivot) = 24.
    hdr = (f"{'image':<6} {'lane':<12} {'probed features':<56} "
           f"{'shape':<24} {'pass':>5} {'fail':>5} {'err':>4} {'skip':>5}")
    lines = [hdr, "-" * len(hdr)]
    for r in rows:
        passed = r["tests"] - r["failures"] - r["errors"] - r["skipped"]
        lines.append(
            f"{r['image']:<6} {r['lane']:<12} "
            f"{fmt_shape(r['probed_shape'], r['landlock_abi']):<56} "
            f"{r['shape_verdict']:<24} "
            f"{passed:>5} {r['failures']:>5} {r['errors']:>4} {r['skipped']:>5}"
            + (f"  !! {r['harness_error']}" if r["harness_error"] else ""))
    table = "\n".join(lines)
    print(table)

    # Environment degradations: named, non-fatal (see shape_check).
    degr_lines = [f"[{r['image']}/{r['lane']}] DEGRADED {d}"
                  for r in rows for d in r["degradations"]]
    if degr_lines:
        print("\nEnvironment degradations (non-fatal, cells self-classified):")
        print("\n".join(degr_lines))

    fail_lines = []
    for r in rows:
        for d in r["divergences"]:
            fail_lines.append(f"[{r['image']}/{r['lane']}] DIVERGENCE {d}")
        for t in r["failed_tests"]:
            fail_lines.append(f"[{r['image']}/{r['lane']}] FAIL {t}")
        for b in r["bound_bad"]:
            fail_lines.append(
                f"[{r['image']}/{r['lane']}] BIND required-passing "
                f"test not bound: {b}")
        if r["harness_error"]:
            fail_lines.append(
                f"[{r['image']}/{r['lane']}] HARNESS {r['harness_error']}")
    if fail_lines:
        print("\nFailures / divergences:")
        print("\n".join(fail_lines))

    if not rows:
        print("HARNESS ERROR: no lane results found under "
              f"{run_dir} — nothing was tested")
        sys.exit(1)
    if stray:
        print("HARNESS ERROR: unknown lane result dirs (results the "
              "matrix would silently drop): " + ", ".join(stray))
        exit_bad = True

    (run_dir / "matrix.json").write_text(json.dumps(rows, indent=1) + "\n")
    (run_dir / "failures.txt").write_text("\n".join(fail_lines) + "\n")
    md = ["# sandbox-matrix run " + run_dir.name, "", "```", table, "```", ""]
    if degr_lines:
        md += ["## Environment degradations (non-fatal)", "", "```"]
        md += degr_lines + ["```", ""]
    if fail_lines:
        md += ["## Failures / divergences", "", "```"] + fail_lines + ["```", ""]
    (run_dir / "matrix.md").write_text("\n".join(md))
    print(f"\nwrote {run_dir}/matrix.json matrix.md failures.txt")
    sys.exit(1 if exit_bad else 0)


if __name__ == "__main__":
    main()
