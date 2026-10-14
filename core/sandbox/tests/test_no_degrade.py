"""Opt-in no-degrade sandbox policy."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from core.sandbox import _spawn
from core.sandbox import context as ctx
from core.sandbox.errors import SandboxSetupError


@pytest.mark.skipif(sys.platform != "linux", reason="Linux no-degrade policy")
def test_no_degrade_ignores_waiver_and_refuses_before_child_exec(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "child-ran"
    target = tmp_path / "target"
    output = tmp_path / "output"
    target.mkdir()
    output.mkdir()
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    monkeypatch.setattr(ctx._seccomp, "check_seccomp_available", lambda: True)
    monkeypatch.setattr(ctx, "spawn_backend_available", lambda: False)

    with pytest.raises(SandboxSetupError, match="no_degrade"):
        ctx.run_untrusted_networked(
            [
                "/usr/bin/python3",
                "-c",
                f"from pathlib import Path; Path({str(marker)!r}).touch()",
            ],
            target=str(target),
            output=str(output),
            proxy_hosts=["synthetic.invalid"],
            no_degrade=True,
            capture_output=True,
            text=False,
        )

    assert not marker.exists()
    assert os.environ["RAPTOR_ALLOW_DEGRADED_UNTRUSTED"] == "1"


def test_default_networked_call_keeps_existing_degrade_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}
    target = tmp_path / "target"
    output = tmp_path / "output"
    target.mkdir()
    output.mkdir()
    monkeypatch.setattr(
        ctx,
        "_require_userns_or_optin",
        lambda *args, **kwargs: False,
    )

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(ctx, "run", fake_run)
    ctx.run_untrusted_networked(
        ["/bin/true"],
        target=str(target),
        output=str(output),
        proxy_hosts=["synthetic.invalid"],
    )

    assert captured["kwargs"]["no_degrade"] is False
    assert captured["kwargs"]["require_fresh_procfs"] is (
        ctx.untrusted_fresh_procfs_required()
    )


@pytest.mark.skipif(sys.platform != "linux", reason="Linux bind-source identity pin")
def test_bind_source_identities_refuse_stale_pin_before_child_exec(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "bind-identity-child-ran"
    target = tmp_path / "target"
    output = tmp_path / "output"
    target.mkdir()
    output.mkdir()
    identity = target.stat()

    with pytest.raises(SandboxSetupError, match="bind-source validation pin failed"):
        _spawn.run_sandboxed(
            [
                "/usr/bin/python3",
                "-c",
                f"from pathlib import Path; Path({str(marker)!r}).touch()",
            ],
            target=str(target),
            output=str(output),
            block_network=False,
            nproc_limit=0,
            limits={},
            writable_paths=[str(output)],
            readable_paths=None,
            allowed_tcp_ports=None,
            seccomp_profile=None,
            seccomp_block_udp=False,
            env=None,
            cwd=None,
            timeout=5,
            capture_output=True,
            text=True,
            bind_source_identities={
                str(target): (identity.st_dev, identity.st_ino + 1),
            },
        )

    assert not marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux backend policy")
def test_cancel_fd_is_refused_when_only_fallback_backend_is_available(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "cancel-fallback-child-ran"
    target = tmp_path / "target"
    output = tmp_path / "output"
    target.mkdir()
    output.mkdir()
    cancel_r, cancel_w = os.pipe()
    try:
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        monkeypatch.setattr(ctx, "check_mount_available", lambda: False)
        with pytest.raises(SandboxSetupError, match="cancel_fd"):
            ctx.run_untrusted_networked(
                [
                    "/usr/bin/python3",
                    "-c",
                    f"from pathlib import Path; Path({str(marker)!r}).touch()",
                ],
                target=str(target),
                output=str(output),
                proxy_hosts=["synthetic.invalid"],
                cancel_fd=cancel_r,
                capture_output=True,
                text=False,
            )
        assert not marker.exists()
    finally:
        os.close(cancel_r)
        os.close(cancel_w)
