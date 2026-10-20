"""Fail-closed service boundary for repository code hosted by Copilot.

Copilot owns its authenticated session. A standalone SDK, another CLI
process (even ``copilot``), a dispatcher socket, or a localhost sidecar
does not prove use of that session's service/account. None is implicitly
authorized by installed software, saved credentials, or model selection.

There is deliberately no environment/config opt-out or persistent grant.
Until a transport can verify fresh authorization for an exact operation
and account, it refuses. Native tools in the already-running Copilot
session are outside this module; their approvals remain host-owned.

The Python audit hook gives explicit request-level errors; a Linux seccomp
ceiling also covers native descendants of repository Python entry points.
Neither controls arbitrary tools run directly by the host, or hostile
same-UID code outside that process tree.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
from collections.abc import Mapping, MutableMapping

POLICY_ENV = "RAPTOR_SESSION_SERVICE_POLICY"
POLICY_VALUE = "copilot-only"
COPILOT_MARKERS = ("COPILOT_CLI", "COPILOT_AGENT_SESSION_ID")

NOTICE = (
    "Copilot session-only service policy: standalone LLM providers, other "
    "harnesses/accounts, and ancillary services are not authorized. "
    "Use the already-running Copilot session; saved credentials, model "
    "flags, and prior approvals do not authorize another service."
)


class ServiceAuthorizationError(RuntimeError):
    """An operation would leave the authenticated session's service boundary."""


def _restricted_environment(environ: Mapping[str, str]) -> bool:
    # This marker can only tighten policy. Even an unknown/non-empty value
    # must not act as an opt-out or turn a typo into permission.
    return (
        bool(environ.get(POLICY_ENV))
        or environ.get("RAPTOR_FRONTEND", "").strip().lower() == "copilot"
        or any(environ.get(name) for name in COPILOT_MARKERS)
    )


_restricted = _restricted_environment(os.environ)
_notice_shown = False
_audit_installed = False
_kernel_filter_installed = False


def session_services_restricted() -> bool:
    """Latch Copilot identity: later environment edits cannot relax it."""
    global _restricted
    if not _restricted and _restricted_environment(os.environ):
        _restricted = True
    return _restricted


def require_service_authorization(operation: str) -> None:
    """Refuse an external operation without guessing its account identity.

    ``operation`` is a fixed, caller-owned label, never an endpoint, key,
    account name, or other potentially sensitive configuration value.
    """
    if session_services_restricted():
        raise ServiceAuthorizationError(
            f"Copilot session service policy blocked {operation}. "
            "Fresh authorization for the exact service, account, and "
            "operation cannot be verified by this transport. No fallback "
            "or alternate credentials will be used."
        )


def report_session_service_policy() -> None:
    """Explain optional-service suppression once per process."""
    global _notice_shown
    if session_services_restricted() and not _notice_shown:
        _notice_shown = True
        logging.getLogger(__name__).warning(NOTICE)


def pin_child_service_policy(environ: MutableMapping[str, str]) -> None:
    """Carry the restrictive policy through sanitized worker environments."""
    if session_services_restricted():
        environ[POLICY_ENV] = POLICY_VALUE
        environ["RAPTOR_CC_TRANSPORT_DISABLED"] = "1"
        environ["RAPTOR_COPILOT_TRANSPORT_DISABLED"] = "1"
        environ["RAPTOR_NO_SESSION_FALLBACK"] = "1"


_NETWORK_EVENTS = frozenset({
    "socket.connect",
    "socket.getaddrinfo",
    "socket.gethostbyaddr",
    "socket.gethostbyname",
    "socket.sendto",
})


def _network_audit(event: str, args: tuple[object, ...]) -> None:
    if event in _NETWORK_EVENTS:
        require_service_authorization("a network/service connection")
    elif event == "socket.__new__":
        # Anonymous Unix socketpairs remain usable for local IPC. Internet
        # sockets and named Unix service connections are not implicit grants.
        if len(args) > 1 and args[1] != socket.AF_UNIX:
            require_service_authorization("a network socket")
    elif event == "socket.sendmsg" and len(args) > 1 and args[1] is not None:
        require_service_authorization("a network/service datagram")


def install_python_network_guard() -> None:
    """Cover direct Python HTTP/SDK calls, including loopback and redirects."""
    global _audit_installed
    if not _audit_installed:
        sys.addaudithook(_network_audit)
        _audit_installed = True


def install_session_service_guards() -> None:
    """Constrain repository Python entry points before they load consumers."""
    global _kernel_filter_installed
    install_python_network_guard()
    if session_services_restricted() and not _kernel_filter_installed:
        from core.security.offline_network import install_offline_network_filter
        try:
            install_offline_network_filter()
        except (OSError, AttributeError) as exc:
            raise ServiceAuthorizationError(
                "Copilot service isolation could not be installed; refusing "
                "repository execution rather than allowing unverified egress."
            ) from exc
        _kernel_filter_installed = True
        pin_child_service_policy(os.environ)
