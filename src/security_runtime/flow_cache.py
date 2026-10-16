"""Bounded process-local caches. No disk deserialization or stat-only freshness."""
from collections import OrderedDict
import copy
import os
from threading import RLock


class FlowCache:
    def __init__(self, *, ast_bytes=32_000_000, result_bytes=8_000_000, entries=32):
        self.ast_bytes, self.result_bytes, self.entries = ast_bytes, result_bytes, entries
        self.asts, self.results = OrderedDict(), OrderedDict()
        self.lock = RLock()
        self.pid = os.getpid()

    def _owned(self):
        # Child processes must not inherit a possibly locked parent cache.
        if self.pid != os.getpid():
            self.asts, self.results = OrderedDict(), OrderedDict()
            self.lock, self.pid = RLock(), os.getpid()

    def _put(self, collection, key, value, size, budget, count):
        if size > budget: return
        with self.lock:
            collection.pop(key, None)
            collection[key] = (copy.deepcopy(value), size)
            while len(collection) > count or sum(v[1] for v in collection.values()) > budget:
                collection.popitem(last=False)

    def _get(self, collection, key):
        with self.lock:
            item = collection.get(key)
            if item is None: return None
            collection.move_to_end(key)
            return copy.deepcopy(item[0])

    def parse(self, key, text, parser):
        self._owned()
        tree = self._get(self.asts, key)
        if tree is not None: return tree, True
        tree = parser(text)
        # An estimate bounds retained source-equivalent AST storage, not RSS.
        self._put(self.asts, key, tree, len(text.encode('utf-8')) * 16 + 4096, self.ast_bytes, 1024)
        return tree, False

    def get(self, key):
        self._owned()
        return self._get(self.results, key)

    def discard(self, prefix):
        self._owned()
        with self.lock:
            for key in list(self.results):
                if key[:len(prefix)] == prefix: del self.results[key]

    def put(self, key, payload):
        self._owned()
        self._put(self.results, key, payload, len(repr(payload).encode('utf-8')) * 2,
                  self.result_bytes, self.entries)

    def affected(self, prefix, changed):
        """Conservative batch-level reverse dependencies from retained analyses."""
        self._owned()
        with self.lock:
            return tuple(dict.fromkeys(name for key, (value, _) in self.results.items()
                if key[:len(prefix)] == prefix and
                changed.intersection(set(value['hashes']) | set(value['probes']))
                for name in value['targets']))
