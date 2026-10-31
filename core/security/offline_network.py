"""Irreversible, process-local network denial for Copilot-owned RAPTOR work.

Kept independent of core.sandbox: its eager imports are unsafe during the
core package bootstrap. This is a network-only ceiling, not a filesystem
or same-UID isolation boundary.
"""

from __future__ import annotations

import ctypes
import errno
import os
import sys


class _ArgCmp(ctypes.Structure):
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]


def install_offline_network_filter() -> None:
    """Deny new sockets/connections in all threads and their descendants.

    Anonymous Unix stream/seqpacket socketpairs remain available for IPC.
    Named Unix sockets, Internet sockets, legacy socketcall, and io_uring
    cannot create an alternate service path. Refuse inherited sockets:
    otherwise write(2) could still send through an already-connected fd.
    Any unsupported host/library/kernel condition is a hard error.
    """
    if sys.platform != "linux":
        raise OSError("Copilot service isolation requires Linux seccomp")

    with os.scandir("/proc/self/task") as tasks:
        if sum(1 for _ in tasks) != 1:
            raise OSError(
                "Copilot service isolation must be installed before threads start"
            )
    with os.scandir("/proc/self/fd") as entries:
        for entry in entries:
            try:
                target = os.readlink(entry.path)
            except FileNotFoundError:
                continue
            if target.startswith("socket:") or (
                target.startswith("anon_inode:") and "io_uring" in target
            ):
                raise OSError(
                    "Copilot service isolation refuses inherited network descriptors"
                )

    lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.restype = None
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
        ctypes.c_uint, ctypes.POINTER(_ArgCmp),
    ]
    lib.seccomp_rule_add_array.restype = ctypes.c_int
    lib.seccomp_attr_set.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32,
    ]
    lib.seccomp_attr_set.restype = ctypes.c_int
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_load.restype = ctypes.c_int

    def check(rc: int, operation: str) -> None:
        if rc != 0:
            raise OSError(f"Copilot service isolation: {operation} failed ({rc})")

    allow = 0x7FFF0000
    deny = 0x00050000 | errno.EPERM
    ctx = lib.seccomp_init(allow)
    if not ctx:
        raise OSError("Copilot service isolation: seccomp_init failed")
    try:
        # NNP cannot be unset; TSYNC covers already-existing threads.
        check(lib.seccomp_attr_set(ctx, 3, 1), "no-new-privileges")
        check(lib.seccomp_attr_set(ctx, 4, 1), "thread synchronization")
        check(lib.seccomp_attr_set(ctx, 2, 0x80000000), "bad-architecture denial")

        for name in (
            b"socket", b"connect", b"pidfd_getfd",
            b"io_uring_setup", b"io_uring_enter", b"io_uring_register",
        ):
            number = lib.seccomp_syscall_resolve_name(name)
            if number < 0:
                raise OSError(
                    "Copilot service isolation: required syscall unavailable"
                )
            check(
                lib.seccomp_rule_add_array(ctx, deny, number, 0, None),
                "network syscall denial",
            )
        legacy = lib.seccomp_syscall_resolve_name(b"socketcall")
        if legacy >= 0:
            check(
                lib.seccomp_rule_add_array(ctx, deny, legacy, 0, None),
                "legacy socket denial",
            )

        pair = lib.seccomp_syscall_resolve_name(b"socketpair")
        if pair < 0:
            raise OSError("Copilot service isolation: socketpair unavailable")
        family = _ArgCmp(0, 1, 1, 0)  # SCMP_CMP_NE, AF_UNIX
        check(
            lib.seccomp_rule_add_array(ctx, deny, pair, 1, ctypes.byref(family)),
            "socketpair family denial",
        )
        # Datagram pairs accept explicit destinations via sendto/sendmsg.
        for kind in range(16):
            if kind in (1, 5):  # SOCK_STREAM, SOCK_SEQPACKET
                continue
            comparison = _ArgCmp(1, 7, 0xF, kind)  # SCMP_CMP_MASKED_EQ
            check(
                lib.seccomp_rule_add_array(
                    ctx, deny, pair, 1, ctypes.byref(comparison),
                ),
                "socketpair type denial",
            )
        check(lib.seccomp_load(ctx), "network filter installation")
    finally:
        lib.seccomp_release(ctx)
