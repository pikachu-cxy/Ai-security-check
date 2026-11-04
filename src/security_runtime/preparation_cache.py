"""Disposable, content-keyed preparation shared by scanner processes.

Only rule metadata/configuration and successful version probes belong here.
Source, selected targets, findings and scan authority never enter this cache.
"""
import hashlib
import json
import sqlite3

from .hook_state import HookStateStore
from .tasks.durable import SignedRecords


class PreparationCache:
    def __init__(self, root=None):
        from .toolchain import default_data_root
        root = root or default_data_root()
        self.hooks = HookStateStore(root / 'preparation-cache')
        self.store = SignedRecords(self.hooks, root, 'preparations-v1.db')
        self.store.max_rows = 32
        self.store.max_record_bytes = 16_000_000
        self.store.max_total_bytes = 64_000_000

    @staticmethod
    def key(kind, identity):
        return kind + ':' + hashlib.sha256(repr(identity).encode()).hexdigest()

    def get(self, kind, identity):
        try:
            row = self.store.read(self.key(kind, identity))
            return row['value'] if row else None
        except (OSError, ValueError, sqlite3.Error, KeyError):
            return None

    def put(self, kind, identity, value):
        key = self.key(kind, identity)
        # Leave space for the signed-record envelope.
        size = len(json.dumps(value, ensure_ascii=True).encode()) + 4096
        if size > self.store.max_record_bytes:
            return
        try:
            self.hooks.key(self.store.root)
            with self.store.transaction() as db:
                db.execute('DELETE FROM records WHERE key=?', (key,))
                while True:
                    count, used = db.execute(
                        'SELECT count(*), coalesce(sum(length(CAST(data AS BLOB))),0) FROM records').fetchone()
                    if count < self.store.max_rows and used + size <= self.store.max_total_bytes:
                        break
                    db.execute('DELETE FROM records WHERE rowid=(SELECT min(rowid) FROM records)')
                self.store._put(db, key, dict(value=value))
        except (OSError, ValueError, sqlite3.Error):
            # Cache failure falls back to normal preparation, not scan failure.
            pass
