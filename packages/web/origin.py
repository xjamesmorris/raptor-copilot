"""The package's one URL-origin normalization primitive.

Origin comparison is the core scope-containment check for /web — the
client, browser gate, execution policy, ffuf runner, and discovery
modules all decide "is this URL still the target?" by comparing these
tuples. One implementation keeps the semantics from drifting apart
(pre-consolidation, four of six hand-rolled copies treated an explicit
``:0`` port as the default port).
"""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlparse


def origin_of(
    url: str, *, scheme_map: Mapping[str, str] | None = None,
) -> tuple[str, str, int]:
    """Normalized ``(scheme, hostname, port)`` for scope comparison.

    * scheme and hostname are lowercased; a missing hostname yields
      ``""`` (which never matches a real origin).
    * ``scheme_map`` optionally folds equivalent schemes together
      before the default port is derived (the browser gate maps
      ws/wss onto http/https).
    * the default port (80/443) fills in only when the URL carries NO
      port. An explicit ``:0`` is preserved: port 0 is falsy but is
      NOT the default port, so ``https://host:0/`` must not compare
      equal to ``https://host/``.
    * an out-of-range or non-numeric port (a hostile crawled anchor
      like ``http://h:99999/x``) normalizes to ``-1`` — an impossible
      port that never matches a real origin — instead of letting
      urlparse's deferred ValueError abort the calling phase.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme_map:
        scheme = scheme_map.get(scheme, scheme)
    default_port = 443 if scheme == "https" else 80
    try:
        port = parsed.port
    except ValueError:
        return (scheme, (parsed.hostname or "").lower(), -1)
    return (
        scheme,
        (parsed.hostname or "").lower(),
        default_port if port is None else port,
    )
