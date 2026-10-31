"""Per-call symlink-TOCTOU guard on the macOS backend's scratch dirs.

``_macos_spawn.run_sandboxed`` (re)creates ``{output}/.home`` (plus
its XDG subdirs) and ``{output}/.tmp`` on EVERY call with
symlink-following ``os.makedirs``. A sandboxed child has write access
to ``output``, so with one sandbox() context issuing multiple run()
calls, a child from run N can replace one of those (empty) dirs with
a symlink to a user-writable location outside ``output`` — run N+1's
parent-side makedirs then materialises directories at the
attacker-chosen destination, the bounded write-outside-sandbox escape
the Linux fake-home guard closes at sandbox() construction. The same
lstat refusal must run per call on this backend.

Mock-level: the guard is plain lstat/refuse logic with nothing
Apple-specific, so it is exercised cross-platform (the clean-run
control swaps SANDBOX_EXEC for a pass-through, the
test_macos_grant_pinning pattern).
"""

from __future__ import annotations

import os
import sys

import pytest

from core.sandbox import _macos_spawn

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX-only",
)


def _fake_sandbox_exec(tmp_path):
    fake = tmp_path / "fake-sandbox-exec"
    fake.write_text('#!/bin/sh\nshift 3\nexec "$@"\n')  # drop -p <profile> --
    fake.chmod(0o755)
    return str(fake)


def _run(out_dir: str, **kw):
    return _macos_spawn.run_sandboxed(
        ["/bin/echo", "ok"],
        output=out_dir,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, timeout=30,
        **kw,
    )


def test_symlinked_fake_home_refuses_and_writes_nothing(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    os.symlink(str(victim), str(out / ".home"))

    with pytest.raises(ValueError, match="refuses to materialise"):
        _run(str(out), fake_home=True)
    # The escape this guard closes: nothing may have been
    # materialised through the link.
    assert os.listdir(victim) == []


def test_symlinked_xdg_subdir_refuses(tmp_path):
    # The swap can target a subpath instead of .home itself: .home is
    # a real dir, .home/.local is the link.
    out = tmp_path / "out"
    out.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    home = out / ".home"
    home.mkdir()
    os.symlink(str(victim), str(home / ".local"))

    with pytest.raises(ValueError, match="refuses to materialise"):
        _run(str(out), fake_home=True)
    assert os.listdir(victim) == []


def test_symlinked_scratch_tmp_refuses(tmp_path):
    # {output}/.tmp is created whenever write isolation engages
    # (output= alone suffices) — no fake_home needed to reach it.
    out = tmp_path / "out"
    out.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    os.symlink(str(victim), str(out / ".tmp"))

    with pytest.raises(ValueError, match="refuses to materialise"):
        _run(str(out))
    assert os.listdir(victim) == []


def test_non_dir_scratch_tmp_refuses(tmp_path):
    # Non-symlink replacement (regular file) must refuse too: the
    # guard is "regular directory or absent", not "not a symlink".
    out = tmp_path / "out"
    out.mkdir()
    (out / ".tmp").write_text("plug")

    with pytest.raises(ValueError, match="refuses to materialise"):
        _run(str(out))


def test_clean_reuse_still_runs(tmp_path, monkeypatch):
    # Both-directions control: legitimate reuse of an output dir whose
    # scratch dirs are real directories must keep working.
    monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                        _fake_sandbox_exec(tmp_path))
    out = tmp_path / "out"
    out.mkdir()
    r1 = _run(str(out), fake_home=True)
    assert r1.returncode == 0, (r1.stderr, r1.stdout)
    r2 = _run(str(out), fake_home=True)
    assert r2.returncode == 0, (r2.stderr, r2.stdout)
    assert (out / ".home" / ".config").is_dir()
    assert (out / ".tmp").is_dir()
