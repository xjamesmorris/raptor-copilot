"""Shared npm-alias spec handling.

npm (and Yarn / pnpm via the same protocol) lets a manifest install a
package under a different local name::

    "my-lodash": "npm:lodash@^4.17.21"

The alias governs the ``node_modules/`` folder name only — what ships
is the TARGET. Every npm-family parser therefore records the target as
``Dependency.name`` (advisory lookups, purls, and cross-run identity
key on what actually ships) and preserves the alias spelling in
``Dependency.alias_name`` for display and fix-materialisation.

This module is the one place that splits an ``npm:`` spec and decides
whether it is an alias (``npm:<pkg>[@<range>]``) or the bare protocol
form (``npm:<range>``, Yarn Berry) — a range operator must never be
mistaken for a package name.
"""

from __future__ import annotations

import re

# A plausible npm package name (plain or scoped). Range operators and
# comparators (``^1.2``, ``>=2``) fail this — that's half of the
# alias/protocol discriminator for ``npm:`` specs; digit-leading names
# are legal on npm (``7zip-bin``, ``0x``, ``3d-view``), so bare
# versions pass and are excluded by ``_VERSIONISH_RE`` below.
NPM_NAMEISH_RE = re.compile(
    r"^(?:@[A-Za-z0-9][\w.\-]*/)?[A-Za-z0-9_][\w.\-]*$"
)

# A bare version / x-range token (``4.17.21``, ``1.x``, ``2``,
# ``1.2.3-beta.1``). Used to disambiguate ``npm:<token>`` WITHOUT an
# inner ``@`` separator: the protocol form pins a version, an alias
# names a package.
_VERSIONISH_RE = re.compile(
    r"^v?\d+(?:\.(?:\d+|[xX*]))*(?:[-+].*)?$"
)


def looks_like_package_name(token: str, *, has_spec: bool) -> bool:
    """True when ``token`` (the part after ``npm:``) names a package.

    ``has_spec`` — an explicit ``@<spec>`` separator followed the
    token. With a separator the form is unambiguous
    (``npm:<name>@<spec>``), so any name-shaped token qualifies —
    including fully-numeric names like ``2048``. Without one,
    version-shaped tokens (``npm:4.17.21``, ``npm:1.x``) are the bare
    protocol form, not a name.
    """
    if not token or not NPM_NAMEISH_RE.match(token):
        return False
    if has_spec:
        return True
    return not _VERSIONISH_RE.match(token)


def split_npm_alias(spec: str) -> tuple[str, str] | None:
    """Split ``npm:<target>[@<spec>]`` into ``(target, inner_spec)``.

    ``inner_spec`` is whatever follows the target's ``@`` separator —
    a range in manifests (``^4.17.21``), a concrete version in
    lockfiles (``4.17.21``) — or ``""`` when absent. Returns ``None``
    when ``spec`` isn't an alias: either no ``npm:`` prefix, or the
    token after the prefix doesn't look like a package name
    (``npm:^4.17.21`` and ``npm:1.x`` are the bare protocol-range
    form; treating a range as a package name would poison the
    canonical name and every downstream advisory lookup).
    """
    if not spec.startswith("npm:"):
        return None
    rest = spec[len("npm:"):]
    # The rightmost ``@`` past position 0 separates target from spec;
    # a scoped target's leading ``@`` is not a separator.
    if "@" in rest[1:]:
        sep = rest.rindex("@")
        target = rest[:sep] if sep > 0 else rest
        inner_spec = rest[sep + 1:] if sep > 0 else ""
        has_spec = sep > 0
    else:
        target = rest
        inner_spec = ""
        has_spec = False
    if not looks_like_package_name(target, has_spec=has_spec):
        return None
    return target, inner_spec
