"""Bounded, thread-safe memo for repeated mechanical tool sweeps.

Several /audit backends produce output that is a pure function of
inputs far coarser than one hypothesis: a CodeQL ``database analyze``
evaluates a query over the WHOLE database regardless of which
function the hypothesis names, and a compiler-analyzer pass emits
every diagnostic for the WHOLE translation unit. Running those
backends once per hypothesis re-pays the full cost for byte-identical
results. This memo collapses the repeats: the first caller with a
given key executes, everyone else reuses the parsed result.

Scope and safety:

* Values are parsed RESULTS held in-process. Execution on a miss
  still goes through the caller's compute callable — including its
  sandbox — unchanged; the memo never provides an unsandboxed path.
* Keys must embed content stamps (file hashes, tool identity) so a
  process outliving one run cannot serve stale results; a caller that
  cannot build a trustworthy key passes ``key=None`` and always
  executes.
* Exceptions from ``compute`` propagate and cache nothing — a failed
  execution is never replayed as a result.
* Concurrent callers of the SAME key are collapsed onto one
  execution via a per-key lock; distinct keys never block each other.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable, Hashable

T = TypeVar("T")


class BoundedMemo(Generic[T]):
    """LRU-bounded memo with per-key in-flight collapse."""

    def __init__(self, max_entries: int) -> None:
        if max_entries < 1:
            msg = f"max_entries must be >= 1, got {max_entries}"
            raise ValueError(msg)
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._values: OrderedDict[Hashable, T] = OrderedDict()
        self._key_locks: dict[Hashable, threading.Lock] = {}
        self.hit_count = 0
        self.miss_count = 0

    def get_or_compute(
        self,
        key: Hashable | None,
        compute: Callable[[], T],
    ) -> tuple[T, bool]:
        """Return ``(value, was_cached)`` for *key*.

        ``key=None`` bypasses the memo entirely (compute every time)
        for callers that cannot build a content-stamped key.
        """
        if key is None:
            return compute(), False

        with self._lock:
            if key in self._values:
                self._values.move_to_end(key)
                self.hit_count += 1
                return self._values[key], True
            key_lock = self._key_locks.setdefault(key, threading.Lock())

        with key_lock:
            # Re-check: a concurrent same-key caller may have computed
            # and stored while this thread waited on the key lock.
            with self._lock:
                if key in self._values:
                    self._values.move_to_end(key)
                    self.hit_count += 1
                    return self._values[key], True
            try:
                value = compute()
            except BaseException:
                # Nothing was stored, so eviction would never reclaim
                # this key's lock — drop it here or an always-failing
                # key retries into unbounded _key_locks growth. A
                # waiter already holding a reference keeps its lock
                # object; the worst case is one duplicate compute.
                with self._lock:
                    if key not in self._values:
                        self._key_locks.pop(key, None)
                raise
            with self._lock:
                self.miss_count += 1
                self._values[key] = value
                self._values.move_to_end(key)
                while len(self._values) > self._max_entries:
                    evicted, _ = self._values.popitem(last=False)
                    # A thread still holding the evicted key's lock
                    # keeps its own reference; dropping the dict entry
                    # only means a later same-key caller re-executes.
                    self._key_locks.pop(evicted, None)
            return value, False

    def peek(
        self,
        key: Hashable | None,
        *,
        touch: bool = True,
    ) -> tuple[T | None, bool]:
        """Non-computing lookup: ``(value, found)``.

        Never blocks on a key lock and never executes — for callers
        deciding whether a computation is still needed after waiting
        on an external mutual-exclusion resource, or whether bulk work
        can be skipped because every key is already present.
        ``touch=True`` counts a found value as a hit and refreshes its
        LRU position (a real serve); ``touch=False`` is a speculative
        probe that must not perturb eviction order or the hit stats.
        """
        if key is None:
            return None, False
        with self._lock:
            if key in self._values:
                if touch:
                    self._values.move_to_end(key)
                    self.hit_count += 1
                return self._values[key], True
            return None, False

    def clear(self) -> None:
        with self._lock:
            self._values.clear()
            self._key_locks.clear()
            self.hit_count = 0
            self.miss_count = 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._values)
