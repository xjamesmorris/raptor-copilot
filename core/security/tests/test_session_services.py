"""Copilot service isolation must refuse before credentials or I/O are used."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from core.security import session_services as policy

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("RAPTOR_FRONTEND", "copilot"),
        ("COPILOT_CLI", "1"),
        ("COPILOT_AGENT_SESSION_ID", "fixture-session"),
        (policy.POLICY_ENV, policy.POLICY_VALUE),
        (policy.POLICY_ENV, "0"),
        (policy.POLICY_ENV, "unknown"),
    ),
)
def test_copilot_identity_is_deny_only_and_latched(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(policy.ServiceAuthorizationError, match="exact service"):
        policy.require_service_authorization("a test service")
    monkeypatch.delenv(name)
    monkeypatch.setenv("RAPTOR_FRONTEND", "claude")
    with pytest.raises(policy.ServiceAuthorizationError):
        policy.require_service_authorization("a test service")


def test_non_copilot_behavior_is_unchanged(monkeypatch):
    monkeypatch.setenv("RAPTOR_FRONTEND", "claude")
    policy.require_service_authorization("a test service")
    assert not policy.session_services_restricted()


def test_safe_child_environment_retains_policy_without_provider_credentials(
    monkeypatch,
):
    from core.config import RaptorConfig

    monkeypatch.setenv("COPILOT_CLI", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fixture-other-account")
    monkeypatch.setenv("OPENAI_API_KEY", "fixture-other-account")
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "fixture-other-account")
    monkeypatch.setenv("RAPTOR_CC_TRANSPORT_DISABLED", "0")
    monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/fixture/other-account.sock")
    for env in (RaptorConfig.get_safe_env(), RaptorConfig.get_llm_env()):
        assert env[policy.POLICY_ENV] == policy.POLICY_VALUE
        assert env["RAPTOR_CC_TRANSPORT_DISABLED"] == "1"
        assert env["RAPTOR_COPILOT_TRANSPORT_DISABLED"] == "1"
        assert env["RAPTOR_NO_SESSION_FALLBACK"] == "1"
        assert not any(name in env for name in (
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
            "AWS_BEARER_TOKEN_BEDROCK", "RAPTOR_LLM_SOCKET",
        ))


def test_autodetection_never_reads_config_probes_or_reuses_cached_availability(
    monkeypatch,
):
    from core.llm import config, detection

    monkeypatch.setenv("COPILOT_CLI", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fixture-other-account")
    monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/fixture/other-account.sock")
    monkeypatch.setattr(
        detection, "_cached_llm_availability",
        detection.LLMAvailability(True, True, True),
    )
    read_config = Mock(side_effect=AssertionError("must not read saved accounts"))
    probe = Mock(side_effect=AssertionError("must not probe services"))
    monkeypatch.setattr(detection, "_models_config_path", read_config)
    monkeypatch.setattr(config, "_get_best_thinking_model", probe)
    monkeypatch.setattr(
        config, "_operator_primary_override",
        config.ModelConfig(provider="anthropic", model_name="fixture"),
    )
    assert detection.detect_llm_availability() == detection.LLMAvailability(
        False, False, False,
    )
    assert detection._get_available_ollama_models() == []
    assert detection._read_config_models() == []
    assert config._get_default_primary_model(prefer=["anthropic"]) is None
    assert config._get_default_fallback_models() == []
    assert config._build_claudecode_config() is None
    read_config.assert_not_called()
    probe.assert_not_called()


@pytest.mark.parametrize(
    "provider", ("anthropic", "openai", "gemini", "bedrock", "ollama",
                 "claudecode", "claudecode-resumable", "copilot"),
)
def test_explicit_provider_is_not_service_or_account_authorization(
    monkeypatch, provider,
):
    from core.llm.config import ModelConfig
    from core.llm.providers import create_provider

    monkeypatch.setenv("COPILOT_CLI", "1")
    config = ModelConfig(
        provider=provider, model_name="fixture-model",
        api_key="fixture-other-account",
        api_base="https://same-brand.example.test",
    )
    with pytest.raises(policy.ServiceAuthorizationError) as error:
        create_provider(config)
    assert "fixture-other-account" not in str(error.value)
    assert "same-brand.example.test" not in str(error.value)


def test_direct_provider_and_harness_entrypoints_refuse(monkeypatch):
    from core.llm.cc_adapter import cc_subprocess_env, cc_transport_disabled
    from core.llm.config import ModelConfig
    from core.llm.providers import ClaudeCodeLLMProvider, OpenAICompatibleProvider

    monkeypatch.setenv("COPILOT_CLI", "1")
    monkeypatch.setenv("RAPTOR_CC_TRANSPORT_DISABLED", "0")
    config = ModelConfig(provider="openai", model_name="fixture")
    for action in (
        cc_subprocess_env, cc_transport_disabled,
        lambda: OpenAICompatibleProvider(config),
        lambda: ClaudeCodeLLMProvider(config),
    ):
        with pytest.raises(policy.ServiceAuthorizationError):
            action()


def test_dispatcher_and_session_fallback_refuse_before_bootstrap(monkeypatch):
    from core.llm.dispatcher import lifecycle
    from core.llm.dispatcher.auth import CredentialStore
    from core.llm.dispatcher.server import LLMDispatcher
    from core.llm.session_fallback import client_with_session_fallback

    monkeypatch.setenv("COPILOT_CLI", "1")
    monkeypatch.setenv("RAPTOR_NO_SESSION_FALLBACK", "0")
    seed = Mock(side_effect=AssertionError("must not load alternate credentials"))
    monkeypatch.setattr(lifecycle, "seed_from_config", seed)
    for action in (
        CredentialStore,
        lifecycle.ensure_inprocess_dispatcher_env,
        lambda: LLMDispatcher("fixture"),
        lambda: client_with_session_fallback(Mock(), "fixture"),
    ):
        with pytest.raises(policy.ServiceAuthorizationError):
            action()
    seed.assert_not_called()


@pytest.mark.parametrize("structured", (False, True))
def test_service_policy_refusal_is_terminal_not_retryable(
    tmp_path, monkeypatch, structured,
):
    from core.llm.config import ModelConfig
    from core.testing import make_test_client

    client = make_test_client(tmp_path, enable_caching=False, max_retries=3)
    client.config.enable_fallback = True
    client.config.fallback_models = [
        ModelConfig(provider="openai", model_name="fixture-fallback"),
    ]
    dispatch = Mock(side_effect=policy.ServiceAuthorizationError("not authorized"))
    monkeypatch.setattr(client, "_get_provider", dispatch)
    with pytest.raises(policy.ServiceAuthorizationError, match="not authorized"):
        if structured:
            client.generate_structured("fixture", {"type": "object"})
        else:
            client.generate("fixture")
    assert dispatch.call_count == 1


def test_cached_provider_cannot_cross_into_restricted_session(tmp_path, monkeypatch):
    from core.testing import install_provider, make_test_client

    client = make_test_client(tmp_path, enable_caching=False)
    provider = Mock()
    install_provider(client, provider)
    assert client.primary_provider is provider
    monkeypatch.setenv("COPILOT_CLI", "1")
    with pytest.raises(policy.ServiceAuthorizationError):
        _ = client.primary_provider
    provider.generate.assert_not_called()


@pytest.mark.parametrize("url", (
    "https://example.test/data", "http://127.0.0.1:12345/data",
))
def test_http_requests_including_loopback_refuse_before_pool_use(
    monkeypatch, url,
):
    from core.http.urllib_backend import UrllibClient

    pool = Mock()
    client = UrllibClient(_http=pool)
    monkeypatch.setenv("COPILOT_CLI", "1")
    with pytest.raises(policy.ServiceAuthorizationError):
        client.get_bytes(url)
    pool.request.assert_not_called()


def test_python_audit_blocks_direct_sdk_dns_and_socket_paths(monkeypatch):
    monkeypatch.setenv("COPILOT_CLI", "1")
    for action in (
        lambda: socket.getaddrinfo("example.test", 443),
        lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM),
        lambda: policy._network_audit("socket.connect", (None, "/fixture.sock")),
    ):
        with pytest.raises(policy.ServiceAuthorizationError):
            action()


@pytest.mark.parametrize("kwargs", (
    {"block_network": False},
    {"profile": "none"},
    {"disabled": True},
    {"use_egress_proxy": True, "proxy_hosts": ["example.test"]},
))
def test_networked_subprocess_options_are_not_consent(monkeypatch, kwargs):
    from core.sandbox import sandbox

    monkeypatch.setenv("COPILOT_CLI", "1")
    with pytest.raises(policy.ServiceAuthorizationError):
        with sandbox(**kwargs):
            pytest.fail("network-enabled sandbox was entered")


def test_startup_and_sage_skip_services_without_probing(monkeypatch):
    from core.sage import hooks
    from core.sage.client import SageClient
    from core.sage.config import SageConfig
    from core.startup import init

    monkeypatch.setenv("COPILOT_CLI", "1")
    probe = Mock(side_effect=AssertionError("must not validate credentials"))
    monkeypatch.setattr(init, "_test_key", probe)
    lines, warnings = init.check_llm()
    assert "standalone providers blocked" in lines[0]
    assert warnings
    assert not init._check_pypi_update("fixture", "1")
    assert hooks._get_client() is None
    assert not hooks._ollama_gpu_available()
    with pytest.raises(policy.ServiceAuthorizationError):
        SageClient(SageConfig(enabled=True))
    probe.assert_not_called()


@pytest.mark.parametrize("script", ("raptor-sage-mcp", "raptor-sage-setup"))
def test_sage_shell_wrappers_refuse_before_docker(tmp_path, script):
    marker = tmp_path / "docker-called"
    fake = tmp_path / "docker"
    fake.write_text(
        "#!/bin/sh\nprintf called > \"$DOCKER_CALL_MARKER\"\nexit 1\n",
        encoding="utf-8",
    )
    fake.chmod(0o700)
    env = dict(
        os.environ, COPILOT_CLI="1", _RAPTOR_TRUSTED="1",
        PATH=f"{tmp_path}:{os.defpath}", DOCKER_CALL_MARKER=str(marker),
    )
    result = subprocess.run(
        ["/bin/bash", str(ROOT / "libexec" / script)],
        env=env, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 3, result.stderr
    assert "Copilot session service policy blocks" in result.stderr
    assert not marker.exists()


def _copilot_program(source: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, COPILOT_CLI="1")
    return subprocess.run(
        [sys.executable, "-c", source],
        cwd=ROOT, env=env, capture_output=True, text=True,
        close_fds=True, timeout=15,
    )

@pytest.mark.linux_native
@pytest.mark.skipif(sys.platform != "linux", reason="Linux namespace backend")
def test_offline_sandbox_keeps_mount_namespace_without_loopback_socket():
    from core.sandbox.probes import check_mount_available

    if not check_mount_available():
        pytest.skip("mount namespace unavailable on this host")
    result = _copilot_program(r'''
import tempfile
from core.sandbox import run
with tempfile.TemporaryDirectory() as out:
    scan = run(
        ["/usr/bin/true"], block_network=True,
        target=out, output=out, capture_output=True,
        text=True, timeout=10,
    )
    print("MOUNT", scan.sandbox_info.get("mount_ns_active"), scan.returncode)
''')
    assert result.returncode == 0, result.stderr
    assert "MOUNT True 0" in result.stdout
    assert "falling back to Landlock-only" not in result.stderr


@pytest.mark.linux_native
@pytest.mark.skipif(sys.platform != "linux", reason="Linux seccomp ceiling")
def test_native_child_remains_offline_with_empty_environment():
    result = _copilot_program(r'''
import subprocess
import sys
import core
child = """
import ctypes
import errno
import socket
import threading
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
seccomp = ctypes.CDLL("libseccomp.so.2")
seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
for name in (b"io_uring_setup", b"io_uring_enter", b"io_uring_register", b"pidfd_getfd"):
    number = seccomp.seccomp_syscall_resolve_name(name)
    assert number >= 0
    assert libc.syscall(number, 0, 0, 0, 0, 0, 0) == -1
    assert ctypes.get_errno() == errno.EPERM
failures = []
def check():
    try:
        for family, kind in (
            (socket.AF_INET, socket.SOCK_STREAM),
            (socket.AF_INET6, socket.SOCK_DGRAM),
            (socket.AF_UNIX, socket.SOCK_STREAM),
        ):
            try:
                socket.socket(family, kind)
            except OSError as error:
                assert error.errno == errno.EPERM
            else:
                raise AssertionError("network socket allowed")
        try:
            socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        except OSError as error:
            assert error.errno == errno.EPERM
        else:
            raise AssertionError("addressable datagram pair allowed")
        a, b = socket.socketpair()
        a.sendall(b"ok")
        assert b.recv(2) == b"ok"
        a.close()
        b.close()
    except BaseException as error:
        failures.append(error)
thread = threading.Thread(target=check)
thread.start()
thread.join()
assert not failures, failures
print("isolated")
"""
result = subprocess.run(
    [sys.executable, "-I", "-c", child], env={}, close_fds=True,
    capture_output=True, text=True, timeout=10,
)
assert result.returncode == 0, result.stderr
print(result.stdout, end="")
''')
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "isolated"


@pytest.mark.linux_native
@pytest.mark.skipif(sys.platform != "linux", reason="Linux seccomp ceiling")
@pytest.mark.parametrize("setup", (
    "import socket; pair = socket.socketpair()",
    "import ctypes; ctypes.CDLL = lambda *a, **k: (_ for _ in ()).throw(OSError('unavailable'))",
    "import threading; threading.Thread(target=threading.Event().wait, daemon=True).start()",
))
def test_bootstrap_refuses_inherited_sockets_or_unavailable_containment(setup):
    result = _copilot_program(setup + "\nimport core\nprint('must not execute')")
    assert result.returncode != 0
    assert "service isolation could not be installed" in result.stderr
    assert "must not execute" not in result.stdout
