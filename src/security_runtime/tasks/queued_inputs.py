"""Private bounded raw inputs retained only until queued static execution ends."""
import hashlib
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import stat
import re
import uuid
import sqlite3

from ..hook_state import no_links, native_io_path
from ..scan_input import check_private_input_parent, _write, _read_file, _windows_private_directory
from .durable import SignedRecords

MAX_TOTAL = 96_000_000


class QueuedInputs(SignedRecords):
    def __init__(self, hooks, root, **kwargs):
        super().__init__(hooks, root, 'task-queued-inputs.db', **kwargs)
        from ..scan_attempt import _input_parent
        self.parent = _input_parent(hooks).parent/'q'

    @contextmanager
    def writer(self):
        """Retain raw bytes during end capture, before the workspace lock.

        Preparation binds capture receipts; publication binds its sealed
        snapshot reference. Workers verify every private byte before scanning.
        The existing capture API and already queued records keep their contract.
        """
        sink = _CaptureWriter(self)
        try:
            sink.start()
            yield sink
        finally:
            if not sink.sealed:
                sink.discard()

    def capture(self, end, auxiliary, *, snapshot=None, record=None):
        from .security import _environment
        no_links(self.parent)
        if self.parent.resolve().is_relative_to(self.root):
            raise ValueError('Queued inputs require private storage outside the source workspace')
        check_private_input_parent(self.parent)
        self.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        ref = 'qi1-'+uuid.uuid4().hex
        target = self.parent/ref
        expected = {**end['hashes'], **auxiliary}
        expected = {p:sha for p, sha in expected.items() if sha is not None and not _environment(p)}
        with self.transaction() as db:
            rows = self._all(db)
            # Reserve a complete bounded task before writing any raw bytes.
            if sum(r['reserved_bytes'] for r in rows)+20_000_000 > MAX_TOTAL:
                raise ValueError('Queued input storage capacity exceeded')
            binding = dict(hashes=expected)
            if snapshot is not None:
                from .closeout_pages import scope
                binding = dict(snapshot_scope=scope(record, snapshot), auxiliary=auxiliary)
            row = self._put(db, ref, dict(state='PREPARING', **binding,
                created_at=self.now(), expires_at=self.now()+86400,
                reserved_bytes=20_000_000, directory_identity=None))
            if os.name == 'nt':
                _windows_private_directory(target)
            else:
                target.mkdir(mode=0o700)
            info = target.stat()
            row = self._put(db, ref, dict(row, directory_identity=[info.st_dev, info.st_ino]))
        try:
            size = 0
            for name, sha in expected.items():
                raw = _read_file(self.root/name, 1_000_000)
                if hashlib.sha256(raw).hexdigest() != sha:
                    raise ValueError('Source changed during queued input capture')
                size += len(raw)
                if size > 20_000_000:
                    raise ValueError('Queued input size limit exceeded')
                _write(target, name, raw)
            with self.transaction() as db:
                self._put(db, ref, dict(row, state='READY', reserved_bytes=size))
            self.open(ref)
            return ref
        except Exception:
            self.discard(ref)
            raise

    def open(self, ref):
        row = self.read(ref)
        if (not row or row['state'] != 'READY' or row['expires_at'] <= self.now()
                or re.fullmatch(r'qi1-[a-f0-9]{32}', ref) is None):
            raise ValueError('Queued input unavailable')
        if 'snapshot_scope' in row:
            from .closeout_pages import restore
            from .security_state import TaskSecurityStore
            from .security import _environment
            scope = row['snapshot_scope']
            state = TaskSecurityStore(self.hooks, self.root, now=self.now)
            end = restore(state, scope, scope['end'])
            expected = {**end['hashes'], **row['auxiliary']}
            row = dict(row, hashes={p:sha for p,sha in expected.items()
                                   if sha is not None and not _environment(p)})
        return self._open_tree(ref, row, row['hashes'])

    def _directory(self, ref, row):
        path = self.parent/ref
        no_links(path)
        info = path.stat()
        from ..persisted_file_identity import historical_identity_matches
        if not historical_identity_matches(row['directory_identity'], info,
                                           captured_at=row['created_at']):
            raise ValueError('Queued input directory replaced')
        return path

    def _open_tree(self, ref, row, hashes):
        path = self._directory(ref, row)
        found = set()
        entries = 0
        for directory, children, files in os.walk(path, followlinks=False):
            entries += len(children)+len(files)
            if entries > 30000:
                raise ValueError('Queued input inventory limit exceeded')
            no_links(Path(directory))
            for name in children:
                no_links(Path(directory)/name)
            for name in files:
                item = Path(directory)/name
                relative = item.relative_to(path).as_posix()
                if relative not in hashes:
                    raise ValueError('Unexpected queued input')
                raw = _read_file(item, 1_000_000)
                if hashlib.sha256(raw).hexdigest() != hashes[relative]:
                    raise ValueError('Queued input modified')
                found.add(relative)
        if found != set(hashes):
            raise ValueError('Queued input incomplete')
        return path

    def discard(self, ref):
        # Only signed, identity-matched owned directories may be removed.
        with self.transaction() as db:
            row = self._get(db, ref)
            if row is None:
                return
            if re.fullmatch(r'qi1-[a-f0-9]{32}', ref) is None:
                raise ValueError('Invalid queued input reference')
            path = self.parent/ref
            no_links(path)
            if path.exists():
                info = path.stat()
                from ..persisted_file_identity import historical_identity_matches
                if not historical_identity_matches(row['directory_identity'], info,
                                                   captured_at=row['created_at']):
                    raise ValueError('Queued input directory replaced')
                count = 0
                for directory, children, files in os.walk(path, followlinks=False):
                    no_links(Path(directory))
                    count += len(children)+len(files)
                    if count > 30000:
                        raise ValueError('Queued input cleanup limit exceeded')
                    for name in (*children, *files):
                        no_links(Path(directory)/name)
                def writable(function, name, error):
                    os.chmod(name, stat.S_IREAD | stat.S_IWRITE)
                    function(name)
                shutil.rmtree(native_io_path(path), onexc=writable)
            db.execute('DELETE FROM records WHERE key=?', (ref,))

    def collect(self, active_refs):
        for row in self.rows():
            if row['expires_at'] <= self.now() or (row['state'] == 'READY'
                    and row['key'] not in active_refs and row['created_at']+300 <= self.now()):
                self.discard(row['key'])


class _CaptureWriter:
    """Unpublished raw inputs use the original quota, identity and lifetime."""

    def __init__(self, store):
        self.store = store
        self.ref = 'qi1-' + uuid.uuid4().hex
        self.row = None
        self.hashes, self.size = {}, 0
        self.prepared = self.sealed = False
        self.auxiliary = None

    def start(self):
        store = self.store
        no_links(store.parent)
        if store.parent.resolve().is_relative_to(store.root):
            raise ValueError('Queued inputs require private storage outside the source workspace')
        check_private_input_parent(store.parent)
        store.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = store.parent/self.ref
        with store.transaction() as db:
            if sum(row['reserved_bytes'] for row in store._all(db)) + 20_000_000 > MAX_TOTAL:
                raise ValueError('Queued input storage capacity exceeded')
            self.row = store._put(db, self.ref, dict(state='PREPARING', hashes={},
                created_at=store.now(), expires_at=store.now()+86400,
                reserved_bytes=20_000_000, directory_identity=None))
            if os.name == 'nt':
                _windows_private_directory(target)
            else:
                target.mkdir(mode=0o700)
            info = target.stat()
            self.row = store._put(db, self.ref, dict(self.row,
                directory_identity=[info.st_dev, info.st_ino]))

    def put(self, name, raw):
        if self.prepared or self.sealed or self.row is None:
            raise ValueError('Queued input capture is not writable')
        sha = hashlib.sha256(raw).hexdigest()
        if name in self.hashes:
            if self.hashes[name] != sha:
                raise ValueError('Source changed during queued input capture')
            return
        if len(raw) > 1_000_000 or self.size+len(raw) > 20_000_000:
            raise ValueError('Queued input size limit exceeded')
        _write(self.store.parent/self.ref, name, raw)
        self.hashes[name] = sha
        self.size += len(raw)

    @staticmethod
    def expected(end, auxiliary):
        from .security import _environment
        return {name: sha for name, sha in {**end['hashes'], **auxiliary}.items()
                if sha is not None and not _environment(name)}

    def prepare(self, end, auxiliary):
        if self.prepared or self.sealed:
            raise ValueError('Queued input capture already prepared')
        from .security import _environment
        for name, sha in auxiliary.items():
            if sha is None or _environment(name):
                continue
            if name not in self.hashes:
                self.put(name, _read_file(self.store.root/name, 1_000_000))
            if self.hashes[name] != sha:
                raise ValueError('Source changed during queued input capture')
        if self.expected(end, auxiliary) != self.hashes:
            raise ValueError('Queued input source capture incomplete')
        # The guarded writes already retained these exact source bytes. Check
        # their signed reservation and directory here; the worker's mandatory
        # open validates the complete tree and every hash before any scanner
        # or cached scanner fact can consume it. A queued job is not a scan.
        current = self.store.read(self.ref)
        if current != self.row or current['expires_at'] <= self.store.now():
            raise ValueError('Queued input preparation changed')
        self.store._directory(self.ref, current)
        self.auxiliary = dict(auxiliary)
        self.prepared = True

    def seal(self, end, auxiliary, *, snapshot=None, record=None):
        if (not self.prepared or self.sealed or auxiliary != self.auxiliary
                or self.expected(end, auxiliary) != self.hashes):
            raise ValueError('Queued input prepared version changed')
        binding = dict(hashes=self.hashes)
        if snapshot is not None:
            from .closeout_pages import scope
            binding = dict(snapshot_scope=scope(record, snapshot), auxiliary=auxiliary)
        with self.store.transaction() as db:
            current = self.store._get(db, self.ref)
            if current != self.row or current['expires_at'] <= self.store.now():
                raise ValueError('Queued input preparation changed')
            ready = dict(current, state='READY', reserved_bytes=self.size, **binding)
            if snapshot is not None:
                # Preserve compact queue storage: no full hashes alongside the
                # authenticated snapshot reference, including the empty draft.
                ready.pop('hashes', None)
            self.store._put(db, self.ref, ready)
        self.sealed = True
        return self.ref

    def discard(self):
        if self.row is not None:
            try:
                self.store.discard(self.ref)
            except (OSError, ValueError, sqlite3.DatabaseError):
                pass  # Keep uncertain signed reservations; preserve the original error.
