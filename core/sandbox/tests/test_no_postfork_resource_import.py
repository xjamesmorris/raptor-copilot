"""No post-fork ``import resource`` in the spawn/audit fork children.

The fork-site comments promise children built from pre-imported
modules only: a post-fork import can block on another thread's
import-lock state frozen at fork (the tracer child then never writes
its ready byte and the parent's deadline aborts the audited run).
``resource`` was still imported INSIDE the tracer/target/grandchild
branches of both spawn backends; it now lives at module level.
Source pin so the banned pattern cannot creep back in.
"""

from __future__ import annotations

import inspect
import re

from core.sandbox import _landlock_audit, _spawn


def test_resource_is_module_level_and_never_lazy():
    for mod in (_spawn, _landlock_audit):
        src = inspect.getsource(mod)
        # Present at module level (column 0) exactly once...
        assert len(re.findall(r"^import resource$", src, re.M)) == 1, (
            f"{mod.__name__}: expected one module-level "
            f"'import resource'"
        )
        # ...and nowhere inside a function/branch (any indented
        # spelling, including aliased) — fork-child code must use
        # pre-imported modules only.
        lazy = re.findall(r"^\s+import resource\b.*$", src, re.M)
        assert lazy == [], (
            f"{mod.__name__}: lazy 'import resource' reintroduced "
            f"(post-fork import hazard): {lazy}"
        )
