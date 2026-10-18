#!/usr/bin/env python3
"""PreToolUse policy helper: enforce a WebFetch domain allowlist.

The ``raptor-agents`` plugin registers one supported plugin-level
``PreToolUse`` hook. Its trusted identity dispatcher selects this helper for
the relevant scoped agent type and passes policy as argv data. Keeping the
URL decision here preserves the focused unit-tested implementation; agent
frontmatter hooks are not an enforcement boundary for plugin agents.

Direct usage:

    webfetch-domain-allowlist.py github.com api.github.com

Arguments are the allowed hostnames (case-insensitive exact match).
With ``--https-any`` instead of a hostname list, any host is allowed
but the scheme must be https (used by agents that fetch
operator-supplied URLs on arbitrary vendor domains).

With ``--anchor-file <path>`` the allowlist is derived at run time
from an operator-provenance anchor file the dispatching orchestrator
writes BEFORE the agent sees any fetched content. A literal
``{session}`` in the path is replaced with this launcher session's
``RAPTOR_SESSION_PID`` (``default`` outside the launcher), so
concurrent sessions in the same repo get separate anchors — writer
(libexec/raptor-fetch-anchor) and enforcer resolve the same
placeholder from the same inherited environment. The file's shape:

  - line 1 (first non-empty, non-``#`` line): the operator-supplied
    URL (or bare hostname) — the anchor;
  - later lines: extra allowed hostnames (exact match), one per line
    — operator-visible additions for attachment hosts outside the
    anchor's domain.

A fetch is allowed when its host shares the anchor's registrable
domain (eTLD+1, conservative built-in heuristic — not a full public
suffix list) or exactly matches an extra-host line. Every decision is
appended to ``<path>.log`` (timestamp, verdict, host, URL) so hosts
the fetched page pulled in — attachment CDNs and the like — are
operator-auditable. Scheme must be https in every mode.

Contract (Claude Code PreToolUse payload forwarded by the dispatcher):
  stdin  — JSON with ``tool_name`` and ``tool_input`` (``url`` key).
  exit 0 — allow the call.
  exit 2 — block the call; stderr is fed back to the agent.

Fail-closed: unparseable input, a missing/relative URL, an unknown
flag, or a missing/empty/non-https anchor file is blocked.
"""

import datetime
import json
import os
import re
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit

# Common multi-label public suffixes for the registrable-domain
# heuristic. Deliberately small: a miss here makes the check STRICTER
# (two sibling hosts under an unlisted suffix compare as different
# registrable domains and the fetch is denied), never looser.
_MULTI_LABEL_SUFFIXES = frozenset({
    "ac.jp", "ac.uk", "co.in", "co.jp", "co.kr", "co.nz", "co.uk",
    "co.za", "com.ar", "com.au", "com.br", "com.cn", "com.mx",
    "com.tr", "go.jp", "gov.uk", "ne.jp", "net.au", "net.uk",
    "or.jp", "org.au", "org.uk",
})
_MAX_ANCHOR_BYTES = 64 * 1024
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _registrable_domain(host: str) -> str:
    """eTLD+1 approximation for a lowercased hostname."""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _printable(value: str) -> str:
    """Escape control bytes so a hostile URL cannot forge audit lines
    (an interior newline in the fetched-page-derived URL would write
    a fake decision row)."""
    return "".join(
        ch if 0x20 <= ord(ch) < 0x7F or ord(ch) >= 0xA0 else
        f"\\x{ord(ch):02x}"
        for ch in value
    )


def _valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    return all(_HOST_LABEL_RE.fullmatch(label) for label in host.split("."))


def _has_symlink_component(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            return False
        except OSError:
            return True
        if stat.S_ISLNK(mode):
            return True
    return False


def _read_anchor_entries(anchor_file: str) -> tuple[list[str] | None, str | None]:
    path = Path(anchor_file)
    if not path.is_absolute() or ".." in path.parts:
        return None, "anchor path must be absolute and traversal-free"
    if _has_symlink_component(path):
        return None, "anchor path contains a symlink"
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        return None, "platform cannot enforce no-follow anchor reads"
    flags = os.O_RDONLY | nofollow
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None, "anchor file is missing, unreadable, or unsafe"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            return None, "anchor must be a single-link regular file"
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            return None, "anchor owner does not match the current user"
        if info.st_size > _MAX_ANCHOR_BYTES:
            return None, "anchor exceeds the 64 KiB size limit"
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(8192, _MAX_ANCHOR_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_ANCHOR_BYTES:
                return None, "anchor exceeds the 64 KiB size limit"
    except OSError:
        return None, "anchor read failed"
    finally:
        os.close(fd)
    try:
        text = b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError:
        return None, "anchor is not valid UTF-8"
    entries = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if any(not entry.isprintable() for entry in entries):
        return None, "anchor contains control characters"
    return entries, None


def _log_decision(anchor_file: str, verdict: str, host: str, url: str) -> None:
    """Best-effort audit trail next to the anchor file."""
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        return
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | nofollow
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    line = (
        f"{stamp}\t{verdict}\t{_printable(host)}\t"
        f"{_printable(url)}\n"
    ).encode("utf-8")
    try:
        fd = os.open(f"{anchor_file}.log", flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                return
            view = memoryview(line)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    return
                view = view[written:]
        finally:
            os.close(fd)
    except OSError:
        # Logging never changes the verdict; an unwritable log
        # directory must not turn a deny into a crash or an allow
        # into a deny.
        pass


def _check_anchor(anchor_file: str, host: str, url: str) -> int:
    """Anchor-file mode decision for an https URL's ``host``."""
    entries, error = _read_anchor_entries(anchor_file)
    if error is not None or entries is None:
        sys.stderr.write(
            "webfetch-domain-allowlist: anchor file "
            f"{_printable(anchor_file)!r} is invalid ({error}); "
            "blocking the WebFetch call "
            "(fail-closed). The orchestrator must write the "
            "operator-supplied URL there before dispatching this agent.\n"
        )
        return 2

    if not entries:
        sys.stderr.write(
            f"webfetch-domain-allowlist: anchor file {anchor_file!r} has "
            "no anchor URL; blocking the WebFetch call (fail-closed).\n"
        )
        return 2

    anchor = entries[0]
    if "://" not in anchor:
        anchor = f"https://{anchor}"
    try:
        anchor_parts = urlsplit(anchor)
    except ValueError:
        anchor_parts = None
    anchor_host = ""
    if anchor_parts is not None and anchor_parts.scheme.lower() == "https":
        anchor_host = (anchor_parts.hostname or "").lower().rstrip(".")
    if (
        not anchor_host
        or not _valid_hostname(anchor_host)
        or anchor_parts is None
        or anchor_parts.username is not None
        or anchor_parts.password is not None
    ):
        sys.stderr.write(
            f"webfetch-domain-allowlist: anchor file {anchor_file!r} does "
            "not start with a valid https URL; blocking the WebFetch "
            "call (fail-closed).\n"
        )
        return 2

    extra_hosts = {entry.lower().rstrip(".") for entry in entries[1:]}
    if any(not _valid_hostname(extra) for extra in extra_hosts):
        sys.stderr.write(
            "webfetch-domain-allowlist: anchor contains an invalid extra "
            "hostname; blocking the WebFetch call (fail-closed).\n"
        )
        return 2
    allowed = (
        host == anchor_host
        or host in extra_hosts
        or _registrable_domain(host) == _registrable_domain(anchor_host)
    )
    _log_decision(anchor_file, "allow" if allowed else "deny", host, url)
    if allowed:
        return 0

    sys.stderr.write(
        f"webfetch-domain-allowlist: host {host!r} is outside the "
        f"registrable domain of the operator-supplied URL "
        f"({_registrable_domain(anchor_host)!r}) and not an "
        "operator-listed extra host. The fetch was blocked and logged. "
        "If the bug report genuinely links an attachment on this host, "
        "report that to the orchestrator/operator instead of retrying.\n"
    )
    return 2


def main(argv: list[str]) -> int:
    https_any = False
    anchor_file = None
    allowed = set()
    it = iter(argv)
    for arg in it:
        if arg == "--https-any":
            https_any = True
        elif arg == "--anchor-file":
            anchor_file = next(it, None)
            if anchor_file is None:
                sys.stderr.write(
                    "webfetch-domain-allowlist: --anchor-file requires a "
                    "path; blocking the WebFetch call (fail-closed).\n"
                )
                return 2
            if "{session}" in anchor_file:
                import os
                session = (os.environ.get("RAPTOR_SESSION_PID", "").strip()
                           or "default")
                anchor_file = anchor_file.replace("{session}", session)
        elif arg.startswith("--"):
            sys.stderr.write(
                f"webfetch-domain-allowlist: unknown flag {arg!r}; "
                "blocking the WebFetch call (fail-closed).\n"
            )
            return 2
        else:
            allowed.add(arg.lower())

    try:
        payload = json.load(sys.stdin)
    except ValueError:
        sys.stderr.write(
            "webfetch-domain-allowlist: unparseable hook input; "
            "blocking the WebFetch call (fail-closed).\n"
        )
        return 2

    tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
    url = tool_input.get("url") if isinstance(tool_input, dict) else None
    if not isinstance(url, str) or not url.strip():
        sys.stderr.write(
            "webfetch-domain-allowlist: no url in tool input; "
            "blocking the WebFetch call (fail-closed).\n"
        )
        return 2
    if url != url.strip() or not url.isprintable():
        sys.stderr.write(
            "webfetch-domain-allowlist: url contains whitespace or control "
            "characters; blocking the WebFetch call (fail-closed).\n"
        )
        return 2

    try:
        parts = urlsplit(url.strip())
    except ValueError:
        sys.stderr.write(
            f"webfetch-domain-allowlist: unparseable url {url!r}; "
            "blocking the WebFetch call (fail-closed).\n"
        )
        return 2

    if parts.scheme.lower() != "https":
        sys.stderr.write(
            f"webfetch-domain-allowlist: scheme {parts.scheme!r} denied — "
            "this agent may only fetch https:// URLs.\n"
        )
        return 2

    if https_any:
        return 0

    host = (parts.hostname or "").lower().rstrip(".")
    if not _valid_hostname(host):
        sys.stderr.write(
            "webfetch-domain-allowlist: url hostname is invalid; "
            "blocking the WebFetch call (fail-closed).\n"
        )
        return 2
    if host in allowed:
        return 0

    if anchor_file is not None:
        return _check_anchor(anchor_file, host, url.strip())

    sys.stderr.write(
        f"webfetch-domain-allowlist: host {host!r} is not in this agent's "
        f"allowlist ({', '.join(sorted(allowed))}). The fetch was blocked. "
        "If the investigation genuinely requires this host, report that to "
        "the orchestrator/operator instead of retrying.\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
