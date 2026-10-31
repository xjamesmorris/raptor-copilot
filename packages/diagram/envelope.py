"""Shared list-envelope unwrapping for diagram JSON inputs.

The /understand and /validate JSON artifacts carry their payload
either as a bare list or wrapped in a dict envelope. Unwrapping by
"whichever list value comes first" silently returned a metadata array
(e.g. a provenance list) instead of the payload whenever the envelope
carried more than one list — so the positional fallback is accepted
only when the dict holds exactly ONE list. Every loader must route
through here; a hand-rolled ``next(iter(data.values()))`` fallback is
exactly the bug this module exists to prevent.
"""

from __future__ import annotations


def unwrap_list(data: object, keys: tuple[str, ...]) -> list | None:
    """Return the list payload of *data*, or None when there isn't one.

    Bare lists pass through. Dict envelopes are unwrapped by the
    KNOWN payload *keys* first (in order); the positional first-list
    fallback applies only when the dict carries exactly one list.
    Anything else — no list, several unrecognised lists, non-dict
    scalars — returns None so callers degrade explicitly instead of
    rendering a metadata array as the payload.
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in keys:
            v = data.get(key)
            if isinstance(v, list):
                return v
        lists = [v for v in data.values() if isinstance(v, list)]
        if len(lists) == 1:
            return lists[0]
    return None
