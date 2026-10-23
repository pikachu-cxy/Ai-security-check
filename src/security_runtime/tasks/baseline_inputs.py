"""Private original scanner bytes, captured once alongside the task baseline.

These are not agent evidence. Missing/expired bytes are never reconstructed from
the current checkout. A failed capture does not prevent sanitized task review.
"""
from contextlib import contextmanager
import hashlib
import os
import sqlite3
import uuid

from ..hook_state import no_links
from ..scan_input import check_private_input_parent, _windows_private_directory, _write, _read_file
from .durable import SignedRecords
from .queued_inputs import QueuedInputs, MAX_TOTAL

CONTRACT = 'task-risk-attribution-v1'
TTL = 30 * 86400
MAX_BYTES = 20_000_000


class BaselineInputs(QueuedInputs):
    def __init__(self, hooks, root, **kwargs):
        SignedRecords.__init__(self, hooks, root, 'task-before-inputs.db', **kwargs)
        from ..scan_attempt import _input_parent
        self.parent = _input_parent(hooks).parent / 'b'

    @contextmanager
    def writer(self, task_ref):
        sink = _Writer(self, task_ref)
        try:
            self.collect_expired()
            sink.start()
        except (OSError, ValueError, sqlite3.DatabaseError):
            sink.fail()
        try:
            yield sink
        except BaseException:
            sink.fail()
            raise
        finally:
            if not sink.sealed:
                sink.fail()

    def collect_expired(self):
        for row in self.rows():
            if row['expires_at'] <= self.now():
                self.discard(row['key'])


class _Writer:
    def __init__(self, store, task_ref):
        self.store, self.task_ref = store, task_ref
        self.ref = 'qi1-' + uuid.uuid4().hex
        self.row = None
        self.hashes, self.size = {}, 0
        self.failed, self.sealed = False, False

    def start(self):
        store = self.store
        no_links(store.parent)
        if store.parent.resolve().is_relative_to(store.root):
            raise ValueError('Before inputs require private storage')
        check_private_input_parent(store.parent)
        store.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = store.parent/self.ref
        with store.transaction() as db:
            if sum(r['reserved_bytes'] for r in store._all(db))+MAX_BYTES > MAX_TOTAL:
                raise ValueError('Before input capacity exceeded')
            self.row = store._put(db, self.ref, dict(state='PREPARING', task_ref=self.task_ref,
                hashes={}, created_at=store.now(), expires_at=store.now()+TTL,
                reserved_bytes=MAX_BYTES, directory_identity=None))
            if os.name == 'nt':
                _windows_private_directory(target)
            else:
                target.mkdir(mode=0o700)
            info = target.stat()
            self.row = store._put(db, self.ref, dict(self.row,
                directory_identity=[info.st_dev, info.st_ino]))

    def put(self, name, raw):
        if self.failed:
            return
        try:
            if self.size+len(raw) > MAX_BYTES or len(raw) > 1_000_000:
                raise ValueError('Before input byte limit')
            sha = hashlib.sha256(raw).hexdigest()
            if name in self.hashes:
                if self.hashes[name] != sha:
                    raise ValueError('Before input changed during capture')
                return
            _write(self.store.parent/self.ref, name, raw)
            self.hashes[name] = sha
            self.size += len(raw)
        except (OSError, ValueError, sqlite3.DatabaseError):
            self.fail()

    def seal(self, baseline, auxiliary):
        try:
            from .security import _environment, digest_value
            for name, sha in auxiliary.items():
                if sha is None or _environment(name):
                    continue
                if name not in self.hashes:
                    self.put(name, _read_file(self.store.root/name, 1_000_000))
                if self.hashes.get(name) != sha:
                    raise ValueError('Before configuration changed')
            expected = {p:s for p,s in {**baseline['hashes'], **auxiliary}.items()
                        if s is not None and not _environment(p)}
            if self.failed or expected != self.hashes:
                raise ValueError('Before source capture incomplete')
            with self.store.transaction() as db:
                self.row = self.store._put(db, self.ref, dict(self.row, state='READY',
                    hashes=self.hashes, auxiliary=auxiliary, reserved_bytes=self.size,
                    baseline_digest=digest_value(baseline['hashes'])))
            self.store.open(self.ref)
            self.sealed = True
            return dict(status='AVAILABLE', ref=self.ref, auxiliary=auxiliary,
                        expires_at=self.row['expires_at'])
        except (OSError, ValueError, sqlite3.DatabaseError):
            self.fail()
            return dict(status='UNAVAILABLE', reason='ORIGINAL_SCANNER_INPUT_UNAVAILABLE')

    def fail(self):
        self.failed = True
        if self.row is not None:
            try:
                self.store.discard(self.ref)
            except (OSError, ValueError, sqlite3.DatabaseError):
                pass  # Signed retention obligation remains; never delete an unverified directory.
