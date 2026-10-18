"""Tests for core.run.safe_io.safe_run_mkdir."""

from __future__ import annotations

import os
import json

import pytest

from core.run.safe_io import (
    ARTIFACT_REFERENCE_MAX_BYTES,
    ARTIFACT_REFERENCE_MAX_COUNT,
    ARTIFACT_REFERENCES_MAX_BYTES,
    PRIVATE_TEXT_MAX_BYTES,
    UnsafeRunDirError,
    bound_artifact_references_in_record,
    bounded_artifact_reference_fields,
    safe_run_mkdir,
    write_private_json,
    write_private_text,
)


# ── Fresh-create behaviour ───────────────────────────────────────────────


def test_fresh_create_sets_mode_0700(tmp_path):
    p = tmp_path / "fresh"
    safe_run_mkdir(p)
    assert p.is_dir()
    assert (p.stat().st_mode & 0o777) == 0o700


def test_fresh_create_default_mode_unaffected_by_loose_umask(tmp_path):
    """Default mode 0o700 has no group/world bits, so no umask value can
    relax it to something more permissive. Verifies the security invariant
    that fresh-created dirs are always owner-only."""
    old = os.umask(0o000)
    try:
        p = tmp_path / "fresh"
        safe_run_mkdir(p)
        assert (p.stat().st_mode & 0o777) == 0o700
    finally:
        os.umask(old)


def test_str_path_accepted(tmp_path):
    p = tmp_path / "fresh"
    safe_run_mkdir(str(p))
    assert p.is_dir()


def test_symlinked_parent_allowed(tmp_path):
    """Symlinks higher in the path are not refused — by design.

    Defending against parent-chain manipulation is out of scope: an
    attacker who can manipulate parent directories has capabilities
    well beyond what this helper is intended to defend against, and
    parent-chain refusal would break legitimate FHS / mount-symlink
    layouts (e.g. ``/home`` → ``/data/home``)."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    p = link / "child"
    safe_run_mkdir(p)
    assert p.is_dir()


# ── Pre-existing safe dirs accepted ──────────────────────────────────────


def test_existing_owner_only_dir_accepted(tmp_path):
    p = tmp_path / "a"
    p.mkdir(mode=0o700)
    safe_run_mkdir(p)


def test_idempotent(tmp_path):
    p = tmp_path / "a"
    safe_run_mkdir(p)
    safe_run_mkdir(p)


def test_world_readable_dir_allowed(tmp_path):
    """0o755 (default umask 0o022) is read-only by other users, so not
    an injection vector — accept without warning. Chmod after mkdir to
    pin the mode regardless of the test runner's umask."""
    p = tmp_path / "a"
    p.mkdir()
    p.chmod(0o755)
    safe_run_mkdir(p)


def test_group_writable_warns_but_allowed(tmp_path, monkeypatch):
    """0o775 (default umask 0o002 + private user group) is the most common
    real-world existing run-dir mode. Warn but accept.

    The warning's content is asserted by patching the module logger:
    :class:`RaptorLogger` is a singleton with ``propagate=False`` and a
    StreamHandler bound to a pre-pytest stderr, so caplog/capfd cannot
    observe its output."""
    p = tmp_path / "a"
    p.mkdir()
    p.chmod(0o775)

    captured: list[str] = []
    from core.run import safe_io as mod
    monkeypatch.setattr(mod.logger, "warning", lambda msg, **_: captured.append(msg))

    safe_run_mkdir(p)

    assert captured, "expected a warning to be logged"
    assert "group-writable" in captured[0].lower()


# ── Refusals ─────────────────────────────────────────────────────────────


def test_world_writable_refused(tmp_path):
    p = tmp_path / "a"
    p.mkdir()
    p.chmod(0o777)
    with pytest.raises(UnsafeRunDirError, match="world-writable"):
        safe_run_mkdir(p)


def test_symlink_to_dir_refused(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(UnsafeRunDirError, match="non-directory"):
        safe_run_mkdir(link)


def test_symlink_to_file_refused(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(UnsafeRunDirError, match="non-directory"):
        safe_run_mkdir(link)


def test_dangling_symlink_refused(tmp_path):
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "nonexistent")
    with pytest.raises(UnsafeRunDirError, match="non-directory"):
        safe_run_mkdir(link)


def test_regular_file_refused(tmp_path):
    p = tmp_path / "file"
    p.write_text("x")
    with pytest.raises(UnsafeRunDirError, match="non-directory"):
        safe_run_mkdir(p)


def test_foreign_uid_refused(tmp_path, monkeypatch):
    """Existing dir owned by a different UID must be refused.

    Simulated via geteuid monkeypatch — actually chowning would require
    CAP_CHOWN which test environments don't have."""
    p = tmp_path / "a"
    p.mkdir(mode=0o700)
    real_uid = os.lstat(p).st_uid
    monkeypatch.setattr(os, "geteuid", lambda: real_uid + 1)
    with pytest.raises(UnsafeRunDirError, match="not owned by current user"):
        safe_run_mkdir(p)


def test_hostile_umask_still_yields_0o700():
    """The docstring promised 0o700 "regardless of the caller's
    umask" while the mkdir mode was in fact masked (umask 0o277 gave
    0o500) — the claim now holds via fchmod on the created handle."""
    import stat as _stat
    from pathlib import Path
    from tempfile import TemporaryDirectory

    from core.run.safe_io import safe_run_mkdir
    with TemporaryDirectory() as td:  # parent minted pre-umask
        old_umask = os.umask(0o277)
        try:
            d = Path(td) / "run"
            safe_run_mkdir(d)
            assert _stat.S_IMODE(os.lstat(d).st_mode) == 0o700
        finally:
            os.umask(old_umask)


def test_private_json_is_mode_0600_and_refuses_symlink(tmp_path):
    artifact = tmp_path / "receipt.json"
    write_private_json(artifact, {"status": "failed"})
    assert artifact.stat().st_mode & 0o777 == 0o600
    assert json.loads(artifact.read_text(encoding="utf-8")) == {
        "status": "failed",
    }

    target = tmp_path / "target.json"
    target.write_text('{"untouched": true}\n', encoding="utf-8")
    artifact.unlink()
    artifact.symlink_to(target)
    with pytest.raises(OSError):
        write_private_json(artifact, {"status": "overwritten"})
    assert target.read_text(encoding="utf-8") == '{"untouched": true}\n'


def test_private_text_is_bounded_mode_0600_and_refuses_symlink(tmp_path):
    artifact = tmp_path / "stderr.log"
    write_private_text(artifact, "bounded diagnostic\n")
    assert artifact.stat().st_mode & 0o777 == 0o600
    assert artifact.read_text(encoding="utf-8") == "bounded diagnostic\n"

    with pytest.raises(ValueError, match="byte budget"):
        write_private_text(
            artifact,
            "x" * (PRIVATE_TEXT_MAX_BYTES + 1),
        )
    assert artifact.read_text(encoding="utf-8") == "bounded diagnostic\n"

    target = tmp_path / "target.log"
    target.write_text("untouched\n", encoding="utf-8")
    artifact.unlink()
    artifact.symlink_to(target)
    with pytest.raises(OSError):
        write_private_text(artifact, "overwritten\n")
    assert target.read_text(encoding="utf-8") == "untouched\n"


def test_artifact_references_are_sanitized_and_bounded():
    secret = "glpat-AbCdEfGhIjKlMnOpQrStUvWx"
    hostile = (
        "out/\x1b]0;title\x07/\u202e/"
        + secret
        + "/"
        + "x" * (ARTIFACT_REFERENCE_MAX_BYTES * 2)
    )
    fields = bounded_artifact_reference_fields(
        [f"{hostile}-{index}" for index in range(
            ARTIFACT_REFERENCE_MAX_COUNT + 10
        )]
    )
    refs = fields["artifacts"]

    assert len(refs) <= ARTIFACT_REFERENCE_MAX_COUNT
    assert sum(
        len(ref.encode("utf-8")) + (1 if index else 0)
        for index, ref in enumerate(refs)
    ) <= ARTIFACT_REFERENCES_MAX_BYTES
    assert all(
        len(ref.encode("utf-8")) <= ARTIFACT_REFERENCE_MAX_BYTES
        for ref in refs
    )
    assert all("\x1b" not in ref and "\x07" not in ref for ref in refs)
    assert all("\u202e" not in ref for ref in refs)
    assert all(secret not in ref for ref in refs)
    assert all("[REDACTED]" in ref for ref in refs)
    assert fields["artifact"] == refs[0]
    assert fields["artifact_references_truncated"] is True
    assert fields["artifact_references_omitted"] > 0


def test_nested_artifact_arrays_rebounded_and_prior_omissions_preserved():
    record = {
        "status": "completed",
        "artifacts": ["top\x1b.sarif"],
        "languages": {
            "python": {
                "artifacts": [
                    f"nested-{index}-\u202e"
                    for index in range(ARTIFACT_REFERENCE_MAX_COUNT + 4)
                ],
                "artifact_references_omitted": 3,
            },
        },
    }

    bounded = bound_artifact_references_in_record(record)

    assert bounded["artifacts"] == ["top\\x1b.sarif"]
    python = bounded["languages"]["python"]
    assert len(python["artifacts"]) <= ARTIFACT_REFERENCE_MAX_COUNT
    assert all("\u202e" not in ref for ref in python["artifacts"])
    assert python["artifact_references_truncated"] is True
    assert python["artifact_references_omitted"] >= 7
