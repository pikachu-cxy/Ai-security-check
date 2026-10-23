"""One bounded, disposable source representation per connection; never authority.

Callers authenticate the task and re-read/hash current source before every hit.
The key binds the source representation; records, coverage and authority stay out.
"""
from __future__ import annotations

import sys
from threading import Lock
from time import monotonic


MAX_BYTES = 2_000_000
TTL_SECONDS = 60


class TaskSourceCache:
    def __init__(self, *, maximum_bytes=MAX_BYTES, ttl_seconds=TTL_SECONDS, now=monotonic):
        self.maximum_bytes = maximum_bytes
        self.ttl_seconds = ttl_seconds
        self.now = now
        self._entry = None
        self._lock = Lock()

    def get(self, key):
        with self._lock:
            entry = self._entry
            if entry is None:
                return None
            if self.now() >= entry[1]:
                self._entry = None
                return None
            if entry[0] != key:
                return None
            # Callers may add related obligations or build responses from the
            # returned lists. They cannot mutate the retained source body.
            return list(entry[2]), list(entry[3])

    def put(self, key, lines, truncated_lines):
        body, truncated = tuple(lines), tuple(truncated_lines)
        entry = (tuple(key), self.now() + self.ttl_seconds, body, truncated)
        # Include container, key and per-line object overhead, not only UTF-8
        # payload bytes. Counting shared strings twice is conservative.
        size = (sys.getsizeof(entry) + sum(sys.getsizeof(value) for value in entry)
                + sum(sys.getsizeof(value) for value in entry[0])
                + sum(sys.getsizeof(line) for line in body)
                + sum(sys.getsizeof(number) for number in truncated))
        with self._lock:
            self._entry = entry if size <= self.maximum_bytes else None

    def discard_task(self, workspace, task_ref):
        with self._lock:
            if self._entry is not None and self._entry[0][:2] == (workspace, task_ref):
                self._entry = None
