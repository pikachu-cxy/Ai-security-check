"""L1 private paged byte storage; never reads or recreates a live source.

Source/owner claims come from the caller, not host attestation. Logical retained
bytes and SQLite's physical page ceiling are independent administrative quotas.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from types import MappingProxyType
import uuid

from .hook_state import no_links, native_io_path
from .local_evidence import _relative
from .snapshot_contract import (BaselineKind, CaptureBatchBudget,
                                SnapshotCompleteness, SourceConsistency, CONTRACT)
from .tasks.ownership import valid_owner


TASK_PAGES_GC_DOMAIN = 'TASK_PAGES_GC_V1'


class SnapshotStoreError(ValueError):
    def __init__(self, reason):
        self.reason_code = reason
        super().__init__(reason)


def _fail(reason):
    raise SnapshotStoreError(reason)


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def _text(value, maximum=4096):
    if (not isinstance(value, str) or not value or len(value.encode()) > maximum
            or any(ord(char) < 32 for char in value)):
        _fail('SNAPSHOT_BINDING_INVALID')
    return value


def _gc_canonical_path(path):
    # Equivalent to _relative(path) == path for a string. Avoid pathlib's
    # interned path components while validating a full stored inventory.
    return (path != '[outside workspace]' and '\\' not in path
            and all(part and part not in {'.', '..'} and ':' not in part and '\0' not in part
                    and not part.endswith((' ', '.')) for part in path.split('/')))


@dataclass(frozen=True)
class SnapshotBinding:
    task_ref: str
    owner: dict
    source_ref: str
    representation_version: int
    kind: str = BaselineKind.PRODUCT_COMPARISON.value
    consistency: SourceConsistency = SourceConsistency.OBSERVED_ONLY
    captured_before_edit: bool = False
    retention_domain: str | None = None

    def __post_init__(self):
        _text(self.task_ref)
        _text(self.source_ref)
        if self.retention_domain is not None:
            _text(self.retention_domain, 128)
        owner = dict(self.owner)
        if (not valid_owner(owner) or type(self.representation_version) is not int
                or self.representation_version < 1 or self.kind not in
                {*map(str, BaselineKind), 'TASK_END'}
                or not isinstance(self.consistency, SourceConsistency)
                or type(self.captured_before_edit) is not bool):
            _fail('SNAPSHOT_BINDING_INVALID')
        object.__setattr__(self, 'owner', MappingProxyType(owner))


class SnapshotStore:
    def __init__(self, private_directory, *, workspace_root, key,
                 max_storage_bytes=128_000_000, max_database_bytes=128_000_000,
                 batch_budget=None):
        if not isinstance(key, bytes) or len(key) != 32:
            _fail('SNAPSHOT_KEY_UNAVAILABLE')
        if (type(max_storage_bytes) is not int or max_storage_bytes < 1
                or type(max_database_bytes) is not int or max_database_bytes < 32768):
            _fail('SNAPSHOT_CAPACITY_INVALID')
        root, directory = Path(workspace_root).absolute(), Path(private_directory).absolute()
        no_links(root)
        no_links(directory)
        self.root, self.directory = root.resolve(strict=True), directory.resolve()
        if self.directory == self.root or self.directory.is_relative_to(self.root):
            _fail('SNAPSHOT_PRIVATE_DIRECTORY_REQUIRED')
        info = self.root.stat()
        self.root_identity = [info.st_dev, info.st_ino]
        self.key, self.quota, self.database_quota = key, max_storage_bytes, max_database_bytes
        self.batch_budget = batch_budget or CaptureBatchBudget()
        if not isinstance(self.batch_budget, CaptureBatchBudget):
            _fail('SNAPSHOT_CAPACITY_INVALID')
        self.path, self.marker = self.directory/'snapshots.db', self.directory/'store.identity'
        self.storage_identity = None
        if self.directory.exists():
            info = self.directory.stat()
            self.storage_identity = [info.st_dev, info.st_ino]

    def _mac(self, value):
        return hmac.new(self.key, _encode(value), hashlib.sha256).hexdigest()

    def _identity(self):
        return dict(contract=CONTRACT, root=str(self.root), root_identity=self.root_identity)

    def _store_identity(self):
        return dict(self._identity(), directory=str(self.directory), storage_identity=self.storage_identity)

    def _binding(self, binding):
        if not isinstance(binding, SnapshotBinding):
            _fail('SNAPSHOT_BINDING_INVALID')
        value = dict(self._identity(), task_ref=binding.task_ref, owner=dict(binding.owner),
            source_ref=binding.source_ref, representation_version=binding.representation_version,
            kind=str(binding.kind), consistency=str(binding.consistency),
            captured_before_edit=binding.captured_before_edit)
        if binding.retention_domain is not None:
            value['retention_domain'] = binding.retention_domain
        return value

    def _paths(self):
        no_links(self.root)
        if [self.root.stat().st_dev, self.root.stat().st_ino] != self.root_identity:
            _fail('SNAPSHOT_ROOT_REPLACED')
        for path in (self.directory, self.path, self.marker,
                     *(Path(str(self.path)+suffix) for suffix in ('-journal', '-wal', '-shm'))):
            no_links(path)
            if path.exists():
                info = path.stat()
                valid = stat.S_ISDIR(info.st_mode) if path == self.directory else (
                    stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
                if not valid or (os.name != 'nt' and info.st_mode & 0o077):
                    _fail('SNAPSHOT_PRIVATE_STORAGE_UNAVAILABLE')
                if path == self.directory and self.storage_identity is not None and [info.st_dev, info.st_ino] != self.storage_identity:
                    _fail('SNAPSHOT_PRIVATE_STORAGE_UNAVAILABLE')
                if path == self.path and info.st_size > self.database_quota:
                    _fail('SNAPSHOT_WAITING_CAPACITY')

    @contextmanager
    def _db(self, *, write=False, initialize=False):
        self._paths()
        exists = self.path.exists()
        if exists != self.marker.exists() or (not exists and not initialize):
            _fail('SNAPSHOT_HISTORY_UNAVAILABLE')
        if not exists:
            self.directory.parent.mkdir(parents=True, exist_ok=True)
            no_links(self.directory.parent)
            if os.name == 'nt':
                from .private_directories import windows_private_directory
                windows_private_directory(self.directory)
            else:
                self.directory.mkdir(mode=0o700, exist_ok=True)
            info = self.directory.stat()
            self.storage_identity = [info.st_dev, info.st_ino]
            self._paths()
            fd = os.open(native_io_path(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        else:
            if self.storage_identity is None:
                info = self.directory.stat()
                self.storage_identity = [info.st_dev, info.st_ino]
            with self.marker.open('rb') as stream:
                identity = stream.read(65)
            if not hmac.compare_digest(identity, self._mac(self._store_identity()).encode()):
                _fail('SNAPSHOT_KEY_OR_WORKSPACE_MISMATCH')
        db = None
        try:
            uri = self.path.as_uri() + ('?mode=rw' if write else '?mode=ro')
            db = sqlite3.connect(uri, uri=True, timeout=2)
            db.execute('PRAGMA trusted_schema=OFF')
            if write:
                db.execute('PRAGMA synchronous=FULL')
                page_size = db.execute('PRAGMA page_size').fetchone()[0]
                db.execute(f'PRAGMA max_page_count={self.database_quota//page_size}')
                db.execute('BEGIN IMMEDIATE')
            else:
                db.execute('PRAGMA query_only=ON')
            if not exists:
                db.execute('CREATE TABLE captures (ref TEXT PRIMARY KEY, task TEXT UNIQUE, data BLOB, mac TEXT)')
                db.execute('CREATE TABLE entries (ref TEXT, seq INTEGER, path TEXT, data BLOB, mac TEXT, '
                           'PRIMARY KEY(ref,seq), UNIQUE(ref,path))')
                db.execute('CREATE TABLE objects (hash TEXT PRIMARY KEY, body BLOB NOT NULL)')
                db.execute('CREATE TABLE usage (id INTEGER PRIMARY KEY CHECK(id=1), bytes INTEGER, mac TEXT)')
                db.execute('INSERT INTO usage VALUES(1,0,?)', (self._mac(dict(used=0)),))
                db.commit()
                fd = os.open(native_io_path(self.marker), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(self._mac(self._store_identity()).encode())
                    stream.flush()
                    os.fsync(stream.fileno())
                db.execute('BEGIN IMMEDIATE')
            yield db
            if write:
                self._paths()
                db.commit()
        except sqlite3.Error as exc:
            if db is not None:
                db.rollback()
            reason = ('SNAPSHOT_WAITING_CAPACITY' if getattr(exc, 'sqlite_errorcode', None) == sqlite3.SQLITE_FULL
                      else 'SNAPSHOT_STORAGE_UNAVAILABLE')
            _fail(reason)
        finally:
            if db is not None:
                db.close()

    def _decode(self, data, mac):
        if not isinstance(data, bytes) or len(data) > 65536:
            _fail('SNAPSHOT_RECORD_INVALID')
        try:
            value = json.loads(data)
        except (ValueError, UnicodeError):
            _fail('SNAPSHOT_RECORD_INVALID')
        if not isinstance(value, dict) or not isinstance(mac, str) or not hmac.compare_digest(mac, self._mac(value)):
            _fail('SNAPSHOT_RECORD_INVALID')
        return value

    def _get(self, db, ref, binding):
        if not isinstance(ref, str) or re.fullmatch(r'ws2-[a-f0-9]{32}', ref) is None:
            _fail('SNAPSHOT_REFERENCE_INVALID')
        row = db.execute('SELECT data,mac FROM captures WHERE ref=?', (ref,)).fetchone()
        if row is None:
            _fail('SNAPSHOT_HISTORY_UNAVAILABLE')
        header = self._decode(*row)
        if header.get('ref') != ref or header.get('binding') != self._binding(binding):
            _fail('SNAPSHOT_BINDING_MISMATCH')
        return header

    def _save(self, db, header):
        raw = _encode(header)
        if len(raw) > 65536:
            _fail('SNAPSHOT_HEADER_BUDGET')
        db.execute('INSERT OR REPLACE INTO captures VALUES(?,?,?,?)',
            (header['ref'], header['binding']['task_ref'], raw, self._mac(header)))

    def _usage(self, db):
        row = db.execute('SELECT bytes,mac FROM usage WHERE id=1').fetchone()
        if not row or type(row[0]) is not int or row[0] < 0 or not hmac.compare_digest(row[1], self._mac(dict(used=row[0]))):
            _fail('SNAPSHOT_RECORD_INVALID')
        return row[0]

    def _set_usage(self, db, used):
        db.execute('UPDATE usage SET bytes=?,mac=? WHERE id=1', (used, self._mac(dict(used=used))))

    def create(self, binding):
        value = self._binding(binding)
        with self._db(write=True, initialize=True) as db:
            prior = db.execute('SELECT ref FROM captures WHERE task=?', (binding.task_ref,)).fetchone()
            if prior:
                return self._get(db, prior[0], binding)
            header = dict(ref='ws2-'+uuid.uuid4().hex, binding=value, state='CAPTURING',
                cursor=None, entry_count=0, source_bytes=0, gap_count=0, last_page=None,
                expected_files=None, inventory_complete=False, root_digest=self._mac(value))
            used = self._usage(db)+65536  # Reserve the entire bounded mutable header.
            if used > self.quota:
                _fail('SNAPSHOT_WAITING_CAPACITY')
            self._save(db, header)
            self._set_usage(db, used)
            return header

    def resume(self, ref, binding):
        with self._db() as db:
            return self._get(db, ref, binding)

    get = resume

    def append_page(self, ref, binding, entries, *, expected_cursor, cursor):
        if expected_cursor is not None:
            _text(expected_cursor)
        _text(cursor)
        prepared, bodies, seen, cost = [], {}, set(), 0
        for item in entries:
            if len(prepared) >= self.batch_budget.files:
                _fail('SNAPSHOT_PAGE_FILE_BUDGET')
            if not isinstance(item, (tuple, list)) or len(item) not in (2, 3):
                _fail('SNAPSHOT_ENTRY_INVALID')
            name, raw = item[:2]
            if (not isinstance(name, str) or len(name.encode()) > 4096 or _relative(name) != name
                    or name in {'', '.'} or name in seen or not isinstance(raw, bytes)):
                _fail('SNAPSHOT_ENTRY_INVALID')
            metadata = item[2] if len(item) == 3 else {}
            try:
                encoded_metadata = _encode(metadata)
            except (TypeError, ValueError, RecursionError):
                _fail('SNAPSHOT_ENTRY_INVALID')
            if not isinstance(metadata, dict) or len(encoded_metadata) > 8192:
                _fail('SNAPSHOT_ENTRY_METADATA_BUDGET')
            metadata = json.loads(encoded_metadata)  # Detach caller-owned mutable references.
            sha = hashlib.sha256(raw).hexdigest()
            entry = dict(path=name, sha256=sha, size=len(raw), metadata=metadata)
            cost += len(raw)+len(_encode(entry))
            if cost > self.batch_budget.bytes:
                _fail('SNAPSHOT_PAGE_BYTE_BUDGET')
            prepared.append(entry)
            bodies[sha] = raw
            seen.add(name)
        page_digest = self._mac(dict(entries=prepared, previous=expected_cursor, cursor=cursor))
        with self._db(write=True) as db:
            header = self._get(db, ref, binding)
            if header['state'] == 'SEALED':
                _fail('SNAPSHOT_IMMUTABLE')
            last = dict(previous=expected_cursor, cursor=cursor, digest=page_digest)
            if header['cursor'] != expected_cursor:
                if header['last_page'] == last:
                    return header
                _fail('SNAPSHOT_CURSOR_CONFLICT')
            if cursor == expected_cursor or not prepared:
                _fail('SNAPSHOT_CURSOR_CONFLICT')
            for entry in prepared:
                if db.execute('SELECT 1 FROM entries WHERE ref=? AND path=?', (ref, entry['path'])).fetchone():
                    _fail('SNAPSHOT_ENTRY_IMMUTABLE')
            added = 0
            for sha, raw in bodies.items():
                existing = db.execute('SELECT CASE WHEN length(body)=? THEN body END FROM objects WHERE hash=?',
                                      (len(raw), sha)).fetchone()
                if existing is None:
                    added += len(raw)
                elif existing[0] != raw:
                    _fail('SNAPSHOT_CONTENT_UNAVAILABLE')
            added += sum(len(_encode(entry))+len(entry['path'].encode())+160 for entry in prepared)
            used = self._usage(db)
            if used+added > self.quota:
                header.update(state='WAITING_CAPACITY', required_storage_bytes=used+added)
                self._save(db, header)
                return header
            for sha, raw in bodies.items():
                db.execute('INSERT OR IGNORE INTO objects VALUES(?,?)', (sha, raw))
            for index, entry in enumerate(prepared, header['entry_count']+1):
                entry = dict(entry, ref=ref, seq=index)
                db.execute('INSERT INTO entries VALUES(?,?,?,?,?)',
                    (ref, index, entry['path'], _encode(entry), self._mac(entry)))
            header.update(state='CAPTURING', cursor=cursor, last_page=last,
                entry_count=header['entry_count']+len(prepared),
                source_bytes=header['source_bytes']+sum(entry['size'] for entry in prepared),
                root_digest=self._mac([header['root_digest'], page_digest]))
            header.pop('required_storage_bytes', None)
            self._save(db, header)
            self._set_usage(db, used+added)
            return header

    def page(self, ref, binding, *, after_seq=0, limit=256, include_content=False):
        """Read one bounded page, optionally verifying its bodies in this connection.

        Body pages obey both file and byte budgets. A read may therefore return
        fewer entries than requested; only its returned cursor advances.
        """
        if (type(after_seq) is not int or after_seq < 0 or type(limit) is not int
                or not 1 <= limit <= self.batch_budget.files or type(include_content) is not bool):
            _fail('SNAPSHOT_PAGE_REQUEST_INVALID')
        with self._db() as db:
            header = self._get(db, ref, binding)
            if after_seq > header['entry_count']:
                _fail('SNAPSHOT_PAGE_REQUEST_INVALID')
            rows = db.execute('SELECT seq,path,data,mac FROM entries WHERE ref=? AND seq>? AND seq<=? ORDER BY seq LIMIT ?',
                              (ref, after_seq, header['entry_count'], limit)).fetchall()
            if len(rows) != min(limit, header['entry_count']-after_seq):
                _fail('SNAPSHOT_HISTORY_UNAVAILABLE')
            result, consumed = [], 0
            for expected, (seq, path, data, mac) in enumerate(rows, after_seq+1):
                item = self._decode(data, mac)
                if seq != expected or item['seq'] != seq or item['path'] != path or item['ref'] != ref:
                    _fail('SNAPSHOT_RECORD_INVALID')
                if include_content:
                    size = item.get('size')
                    if type(size) is not int or not 0 <= size <= self.database_quota:
                        _fail('SNAPSHOT_CONTENT_UNAVAILABLE')
                    # Match append_page's payload budget. Stored ref/seq are
                    # bounded envelope fields, not a larger representation of
                    # an otherwise valid original body at the write boundary.
                    payload = {key:value for key,value in item.items() if key not in {'ref', 'seq'}}
                    cost = size + len(_encode(payload))
                    if consumed + cost > self.batch_budget.bytes:
                        if not result:
                            _fail('SNAPSHOT_PAGE_BYTE_BUDGET')
                        break
                    item = dict(item, content=self._content(db, item))
                    consumed += cost
                result.append(item)
            next_seq = after_seq+len(result)
            return dict(entries=result, next_seq=next_seq,
                        complete=next_seq == header['entry_count'], state=header['state'])

    def read_content(self, ref, binding, path):
        with self._db() as db:
            self._get(db, ref, binding)
            row = db.execute('SELECT data,mac FROM entries WHERE ref=? AND path=?', (ref, path)).fetchone()
            if row is None:
                _fail('SNAPSHOT_HISTORY_UNAVAILABLE')
            entry = self._decode(*row)
            if entry['ref'] != ref or entry['path'] != path:
                _fail('SNAPSHOT_RECORD_INVALID')
            return self._content(db, entry)

    def _content(self, db, entry):
        size, sha = entry.get('size'), entry.get('sha256')
        if (type(size) is not int or not 0 <= size <= self.database_quota
                or not isinstance(sha, str) or re.fullmatch(r'[a-f0-9]{64}', sha) is None):
            _fail('SNAPSHOT_CONTENT_UNAVAILABLE')
        row = db.execute('SELECT CASE WHEN length(body)=? THEN body END FROM objects WHERE hash=?',
                         (size, sha)).fetchone()
        if not row or not isinstance(row[0], bytes) or len(row[0]) != size or hashlib.sha256(row[0]).hexdigest() != sha:
            _fail('SNAPSHOT_CONTENT_UNAVAILABLE')
        return row[0]

    def seal(self, ref, binding, *, expected_files, inventory_complete, gap_count=0):
        with self._db(write=True) as db:
            header = self._get(db, ref, binding)
            coverage = SnapshotCompleteness(header['entry_count'], expected_files, inventory_complete,
                header['entry_count'], header['entry_count'], header['entry_count'], gap_count)
            if header['state'] == 'SEALED':
                if (header['expected_files'], header['inventory_complete'], header['gap_count']) != (expected_files, inventory_complete, gap_count):
                    _fail('SNAPSHOT_IMMUTABLE')
                return header
            if header['state'] == 'WAITING_CAPACITY':
                _fail('SNAPSHOT_WAITING_CAPACITY')
            if db.execute('SELECT count(*) FROM entries WHERE ref=?', (ref,)).fetchone()[0] != header['entry_count']:
                _fail('SNAPSHOT_HISTORY_UNAVAILABLE')
            header.update(state='SEALED', expected_files=expected_files,
                inventory_complete=inventory_complete, gap_count=gap_count, coverage_complete=coverage.complete)
            self._save(db, header)
            return header

    def collect_unreferenced(self, protected_refs, *, retention_domain=TASK_PAGES_GC_DOMAIN,
                             max_captures=32):
        """Collect only opted-in sealed captures under the caller's OS fence.

        The caller must keep pack-through-task-publication and readers fenced
        against this operation. Timestamps, expired leases and absence from a
        partial inventory cannot establish that a capture is unreferenced.
        Legacy and unfinished captures remain intact. Validation precedes every
        delete, and the deletion plus quota update commit in one transaction.
        SQLite can reuse freed pages; no physical compaction is performed.
        Full inventories live in disk-backed temporary indices, with bounded
        cache and Python state; this does not shorten the validation transaction.
        """
        if (not isinstance(protected_refs, (set, frozenset, list, tuple))
                or type(max_captures) is not int or not 1 <= max_captures <= 256):
            _fail('SNAPSHOT_GC_REQUEST_INVALID')
        if (not isinstance(retention_domain, str) or not retention_domain
                or len(retention_domain.encode()) > 128
                or any(ord(char) < 32 for char in retention_domain)):
            _fail('SNAPSHOT_GC_REQUEST_INVALID')
        if any(not isinstance(ref, str) or re.fullmatch(r'ws2-[a-f0-9]{32}', ref) is None
               for ref in protected_refs):
            _fail('SNAPSHOT_REFERENCE_INVALID')
        protected = set(protected_refs)

        def outcome(before, after, removed=0, remaining=0):
            return dict(collected_captures=removed, released_logical_bytes=before-after,
                        logical_bytes_before=before, logical_bytes_after=after,
                        remaining_candidates=remaining, has_more=remaining > 0,
                        physical_compaction_performed=False)

        self._paths()
        if not self.path.exists() and not self.marker.exists():
            if protected:
                _fail('SNAPSHOT_HISTORY_UNAVAILABLE')
            return outcome(0, 0)
        with self._db(write=True) as db:
            db.execute('PRAGMA secure_delete=ON')
            # TEMP_STORE=3 ignores a FILE request. Fail closed rather than
            # silently rebuilding the full inventory in process memory.
            if any(option == 'TEMP_STORE=3' for option, in db.execute('PRAGMA compile_options')):
                _fail('SNAPSHOT_STORAGE_UNAVAILABLE')
            db.execute('PRAGMA temp_store=FILE')
            db.execute('PRAGMA temp.cache_size=-2048')
            db.execute('PRAGMA temp.cache_spill=ON')
            page_size = db.execute('PRAGMA temp.page_size').fetchone()[0]
            # Independent scratch-database ceiling, not a total disk budget:
            # main database, journals and any SQLite sorter files are additional.
            db.execute(f'PRAGMA temp.max_page_count={self.database_quota//page_size}')
            # Authenticated expected counts are TEXT: even a damaged header's
            # arbitrary-size positive integer must not escape as OverflowError.
            db.execute('CREATE TEMP TABLE gc_captures (ref TEXT PRIMARY KEY, count TEXT, '
                       'source_bytes TEXT, selected INTEGER, seen INTEGER DEFAULT 0) WITHOUT ROWID')
            db.execute('CREATE TEMP TABLE gc_objects (hash TEXT PRIMARY KEY, size TEXT, '
                       'keep INTEGER, verified INTEGER DEFAULT 0) WITHOUT ROWID')
            db.execute('CREATE TEMP TABLE gc_delete_objects (hash TEXT PRIMARY KEY) WITHOUT ROWID')
            db.execute('CREATE TEMP TABLE gc_paths (ref TEXT, path TEXT, PRIMARY KEY(ref,path)) WITHOUT ROWID')
            before = self._usage(db)
            header_count, eligible_count, selected = 0, 0, []
            missing_protected = set(protected)
            rows = db.execute('SELECT ref,task,CASE WHEN length(data)<=65536 THEN data END,'
                              'CASE WHEN length(mac)=64 THEN mac END FROM captures ORDER BY rowid')
            for ref, task, data, mac in rows:
                header = self._decode(data, mac)
                binding = header.get('binding')
                try:
                    if not isinstance(binding, dict):
                        raise ValueError()
                    expected = self._binding(SnapshotBinding(
                        task_ref=binding['task_ref'], owner=binding['owner'],
                        source_ref=binding['source_ref'],
                        representation_version=binding['representation_version'],
                        kind=binding['kind'], consistency=SourceConsistency(binding['consistency']),
                        captured_before_edit=binding['captured_before_edit'],
                        retention_domain=binding.get('retention_domain')))
                    valid = (isinstance(ref, str) and re.fullmatch(r'ws2-[a-f0-9]{32}', ref)
                        and header.get('ref') == ref and task == binding['task_ref']
                        and binding == expected
                        and header.get('state') in {'CAPTURING', 'WAITING_CAPACITY', 'SEALED'}
                        and type(header.get('entry_count')) is int and header['entry_count'] >= 0
                        and type(header.get('source_bytes')) is int and header['source_bytes'] >= 0)
                    if header.get('state') == 'SEALED':
                        coverage = SnapshotCompleteness(header['entry_count'], header['expected_files'],
                            header['inventory_complete'], header['entry_count'], header['entry_count'],
                            header['entry_count'], header['gap_count'])
                        valid = valid and type(header.get('coverage_complete')) is bool
                        valid = valid and header['coverage_complete'] == coverage.complete
                    if not valid:
                        raise ValueError()
                except (ValueError, TypeError, KeyError, OverflowError):
                    _fail('SNAPSHOT_RECORD_INVALID')
                candidate = (header['state'] == 'SEALED' and ref not in protected
                             and binding.get('retention_domain') == retention_domain)
                chosen = candidate and len(selected) < max_captures
                if candidate:
                    eligible_count += 1
                if chosen:
                    selected.append(ref)
                db.execute('INSERT INTO temp.gc_captures(ref,count,source_bytes,selected) VALUES(?,?,?,?)',
                           (ref, str(header['entry_count']), str(header['source_bytes']), int(chosen)))
                header_count += 1
                missing_protected.discard(ref)
            if missing_protected:
                _fail('SNAPSHOT_HISTORY_UNAVAILABLE')

            current_ref, state = None, None
            seen, seen_bytes, entry_bytes, selected_entry_bytes = 0, 0, 0, 0

            def finish_capture():
                if state is not None:
                    if seen != int(state[0]) or seen_bytes != int(state[1]):
                        _fail('SNAPSHOT_HISTORY_UNAVAILABLE')
                    db.execute('UPDATE temp.gc_captures SET seen=1 WHERE ref=?', (current_ref,))

            rows = db.execute('SELECT ref,seq,path,CASE WHEN length(data)<=65536 THEN data END,'
                              'CASE WHEN length(mac)=64 THEN mac END FROM entries ORDER BY ref,seq')
            for ref, seq, path, data, mac in rows:
                if state is None or ref != current_ref:
                    finish_capture()
                    state = db.execute('SELECT count,source_bytes,selected FROM temp.gc_captures '
                                       'WHERE ref=?', (ref,)).fetchone()
                    if state is None:
                        _fail('SNAPSHOT_RECORD_INVALID')
                    current_ref, seen, seen_bytes = ref, 0, 0
                entry = self._decode(data, mac)
                try:
                    valid = (type(seq) is int and seq == seen+1
                        and isinstance(path, str) and len(path.encode()) <= 4096
                        and _gc_canonical_path(path)
                        and set(entry) == {'ref', 'seq', 'path', 'sha256', 'size', 'metadata'}
                        and entry['ref'] == ref and entry['seq'] == seq and entry['path'] == path
                        and isinstance(entry['sha256'], str) and re.fullmatch(r'[a-f0-9]{64}', entry['sha256'])
                        and type(entry['size']) is int and 0 <= entry['size'] <= self.database_quota
                        and isinstance(entry['metadata'], dict) and len(_encode(entry['metadata'])) <= 8192)
                    if not valid:
                        raise ValueError()
                except (ValueError, TypeError, KeyError, OverflowError):
                    _fail('SNAPSHOT_RECORD_INVALID')
                # Preserve duplicate detection if the persistent UNIQUE index
                # was lost, without creating an independently budgeted sort.
                try:
                    db.execute('INSERT INTO temp.gc_paths VALUES(?,?)', (ref, path))
                except sqlite3.IntegrityError:
                    _fail('SNAPSHOT_RECORD_INVALID')
                updated = db.execute('INSERT INTO temp.gc_objects(hash,size,keep) VALUES(?,?,?) '
                    'ON CONFLICT(hash) DO UPDATE SET keep=max(keep,excluded.keep) '
                    'WHERE size=excluded.size', (entry['sha256'], str(entry['size']), int(not state[2])))
                if updated.rowcount != 1:
                    _fail('SNAPSHOT_CONTENT_UNAVAILABLE')
                seen += 1
                seen_bytes += entry['size']
                original = {key: value for key, value in entry.items() if key not in {'ref', 'seq'}}
                cost = len(_encode(original)) + len(path.encode()) + 160
                entry_bytes += cost
                if state[2]:
                    selected_entry_bytes += cost
            finish_capture()
            if db.execute("SELECT 1 FROM temp.gc_captures WHERE seen=0 AND "
                          "(count!='0' OR source_bytes!='0') LIMIT 1").fetchone():
                _fail('SNAPSHOT_HISTORY_UNAVAILABLE')

            object_bytes, deleted_object_bytes = 0, 0
            objects = db.execute('SELECT rowid,hash,length(body),typeof(body) FROM objects')
            while batch := objects.fetchmany(256):
                # CPython retains Blob weakrefs until its connection closes.
                # Bound their lifetime as well as each 64 KiB read. The outer
                # IMMEDIATE transaction excludes writers, and no main-table
                # mutation occurs until every byte reader has closed.
                with self._db() as reader:
                    for rowid, sha, size, kind in batch:
                        if (not isinstance(sha, str) or re.fullmatch(r'[a-f0-9]{64}', sha) is None
                                or kind != 'blob' or type(size) is not int or not 0 <= size <= self.database_quota):
                            _fail('SNAPSHOT_CONTENT_UNAVAILABLE')
                        actual = hashlib.sha256()
                        with reader.blobopen('objects', 'body', rowid, readonly=True) as body:
                            while chunk := body.read(65536):
                                actual.update(chunk)
                        if actual.hexdigest() != sha:
                            _fail('SNAPSHOT_CONTENT_UNAVAILABLE')
                        reference = db.execute('SELECT size,keep FROM temp.gc_objects WHERE hash=?', (sha,)).fetchone()
                        if reference is not None:
                            if int(reference[0]) != size:
                                _fail('SNAPSHOT_CONTENT_UNAVAILABLE')
                            db.execute('UPDATE temp.gc_objects SET verified=1 WHERE hash=?', (sha,))
                        if reference is None or not reference[1]:
                            db.execute('INSERT INTO temp.gc_delete_objects VALUES(?)', (sha,))
                            deleted_object_bytes += size
                        object_bytes += size
            if db.execute('SELECT 1 FROM temp.gc_objects WHERE verified=0 LIMIT 1').fetchone():
                _fail('SNAPSHOT_CONTENT_UNAVAILABLE')
            if before != 65536*header_count + entry_bytes + object_bytes:
                _fail('SNAPSHOT_USAGE_MISMATCH')

            for ref in selected:
                db.execute('DELETE FROM entries WHERE ref=?', (ref,))
                db.execute('DELETE FROM captures WHERE ref=?', (ref,))
            db.execute('DELETE FROM objects WHERE hash IN (SELECT hash FROM temp.gc_delete_objects)')
            after = before - 65536*len(selected) - selected_entry_bytes - deleted_object_bytes
            self._set_usage(db, after)
            return outcome(before, after, len(selected), eligible_count-len(selected))
