"""Loader-variable quarantine for launcher-carrying sandbox paths.

The seatbelt watcher shim on macOS is a trusted bootstrap process
that execs BEFORE the sandboxed target: it runs with the trust marker
present. Handing it the caller's ``env=`` dict verbatim means
dynamic-loader variables in that dict (``LD_PRELOAD``,
``LD_LIBRARY_PATH``, ``LD_AUDIT``, ``DYLD_INSERT_LIBRARIES``, ...)
inject code into the bootstrap chain itself, not just the target.
(The Linux unshare/pid1-shim chain was this module's other consumer
until that lane was deleted — every Linux lane now execs the target
directly.)

``quarantine_loader_env`` moves every ``LD_*`` / ``DYLD_*`` variable
out of the live environment into a JSON payload under
``ENV_RESTORE_KEY``. The payload is inert data for the loader; the
shim pops the key and re-applies the pairs immediately before the
target exec, so the TARGET's effective environment is unchanged — the
caller's loader variables apply inside containment (their documented
semantics), never to the bootstrap.

The key is RAPTOR-internal: a caller-supplied dict carrying it
directly is dropped, never merged (same posture as the retired
``_RAPTOR_KEEP_TRUST_MARKERS`` in-band key). A caller that wants
loader variables in the target env sets them as normal env keys.
"""

from __future__ import annotations

import json

ENV_RESTORE_KEY = "_RAPTOR_ENV_RESTORE"

_LOADER_PREFIXES = ("LD_", "DYLD_")

# Exact-name loader-adjacent vectors that the prefixes miss: GCONV_PATH
# loads attacker iconv modules into any glibc process; GLIBC_TUNABLES is
# parsed by ld.so itself at startup.
_LOADER_EXACT = frozenset({"GCONV_PATH", "GLIBC_TUNABLES"})


def quarantine_loader_env(env: dict[str, str]) -> dict[str, str]:
    """Return a copy of ``env`` safe to hand to a launcher chain.

    ``LD_*`` / ``DYLD_*`` pairs are removed and packed as JSON under
    ``ENV_RESTORE_KEY`` for the shim to re-apply at target exec. Any
    pre-existing ``ENV_RESTORE_KEY`` is dropped unconditionally — the
    key is RAPTOR-minted, never caller-supplied.
    """
    quarantined: dict[str, str] = {}
    kept: dict[str, str] = {}
    for k, v in env.items():
        if k == ENV_RESTORE_KEY:
            continue
        if k.startswith(_LOADER_PREFIXES) or k in _LOADER_EXACT:
            quarantined[k] = v
        else:
            kept[k] = v
    if quarantined:
        kept[ENV_RESTORE_KEY] = json.dumps(quarantined)
    return kept
