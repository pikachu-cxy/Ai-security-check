"""Opt-in typed metadata validation with bounded, explicitly writable scratch.

Successful entry means the stored maps/list representation matches its source
digest. It does not establish project inventory coverage, task-before authority,
native host ownership, or availability of external preimage/body references.
"""
from __future__ import annotations

import base64
from contextlib import ExitStack
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import sys
import time

from ..snapshot_store import SnapshotStore, SnapshotStoreError, _gc_canonical_path
from ..tasks.snapshot_pages import MAPS, LISTS
from .metadata_store import ReviewMetadataBinding
from .paged_task_store import source_binding
from .typed_source_scratch import ScratchSlot, TypedSnapshotSourceError, fail

CONTRACT = 'typed-task-snapshot-source-v1'
MAX_INTEGER = (1 << 53) - 1


def _encode(value):
    # Equal to closeout_state.encode for the finite JSON domain admitted here.
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode()


def _path(value):
    try:
        return isinstance(value, str) and 0 < len(value.encode()) <= 4096 and _gc_canonical_path(value)
    except (UnicodeError, ValueError):
        return False


@dataclass(frozen=True)
class TypedSourceBudget:
    body_bytes: int = 65536
    entry_bytes: int = 65536
    source_bytes: int = 96_000_000
    scratch_bytes: int = 128_000_000
    elapsed_seconds: float = 120.0

    def __post_init__(self):
        if (any(type(value) is not int or not 1 <= value <= maximum for value, maximum in (
                (self.body_bytes, 8_000_000), (self.entry_bytes, 8_000_000),
                (self.source_bytes, 128_000_000), (self.scratch_bytes, 128_000_000)))
                or type(self.elapsed_seconds) not in {int, float}
                or not math.isfinite(self.elapsed_seconds) or not 0 < self.elapsed_seconds <= 3600):
            fail('INVALID_ARGUMENT')


def _pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            fail('INVALID_PAYLOAD')
        result[key] = value
    return result


def _constant(value):
    fail('INVALID_PAYLOAD')


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        fail('INVALID_PAYLOAD')
    return number


def _parse(raw):
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        fail('INVALID_PAYLOAD')


def _sqlite_failure(error):
    if getattr(error, 'sqlite_errorcode', 0) & 255 == sqlite3.SQLITE_FULL:
        fail('WAITING_SCRATCH_CAPACITY')
    fail('STORAGE_UNAVAILABLE')


class TypedSnapshotSource:
    def __init__(self, store, pointer, *, review_binding, field, scratch_directory,
                 budget=TypedSourceBudget()):
        # Validation and detachment here are pure; construction never stats,
        # opens SQLite, creates a directory, or changes permissions.
        try:
            if (not isinstance(store, SnapshotStore) or not isinstance(budget, TypedSourceBudget)
                    or not isinstance(pointer, dict) or set(pointer) != {'ref', 'source'}
                    or not isinstance(pointer['ref'], str) or re.fullmatch('ws2-[a-f0-9]{32}', pointer['ref']) is None
                    or not isinstance(pointer['source'], str) or re.fullmatch('[a-f0-9]{64}', pointer['source']) is None
                    or not isinstance(review_binding, ReviewMetadataBinding)):
                fail('INVALID_ARGUMENT')
            owner = json.loads(_encode(review_binding.owner))
            binding = ReviewMetadataBinding(review_binding.task_ref, owner, review_binding.revision,
                review_binding.snapshot_id, review_binding.representation_version)
            raw_binding = source_binding(binding, field, pointer['source'])
            directory = Path(scratch_directory)
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            fail('INVALID_ARGUMENT')
        self.store, self.budget, self.field = store, budget, field
        self._pointer, self._review_binding, self._raw_binding = dict(pointer), binding, raw_binding
        self._scratch_directory = directory
        self._stack, self._db, self._reader, self._scratch = None, None, None, None
        self._closed, self._verified, self._start = False, False, None
        self._pid = os.getpid()

    def _tick(self):
        if time.monotonic() - self._start > self.budget.elapsed_seconds:
            fail('WAITING_TIME_BUDGET')

    def _scratch_budget(self):
        self._tick()
        total = 0
        for name in ('scratch.db', 'scratch.db-journal'):
            path = self._scratch.directory / name
            try:
                total += path.lstat().st_size
            except FileNotFoundError:
                pass
        if total > self.budget.scratch_bytes:
            fail('WAITING_SCRATCH_CAPACITY')

    def _close_database(self, kind, error, traceback):
        db, self._db = self._db, None
        if db is not None:
            try:
                # Nothing is published: closing rolls back the one scratch
                # transaction, then slot cleanup removes its private files.
                db.close()
            except sqlite3.Error as cleanup_error:
                if error is None:
                    _sqlite_failure(cleanup_error)
                if hasattr(error, 'add_note'):
                    error.add_note('Typed source scratch connection close failed')
        return False

    def __enter__(self):
        if self._closed or self._stack is not None or os.getpid() != self._pid:
            fail('CLOSED')
        self._start = time.monotonic()
        stack = self._stack = ExitStack()
        try:
            self._reader = stack.enter_context(self.store.sealed_reader(self._pointer['ref'], self._raw_binding))
            header = self._reader.header
            self._tick()
            if header['source_bytes'] > self.budget.source_bytes:
                fail('WAITING_SOURCE_BUDGET')
            self._bound = dict(contract=CONTRACT, pointer=self._pointer, review_binding=asdict(self._review_binding),
                field=self.field, root=self.store._identity(), store=self.store._store_identity(),
                representation_version=self._review_binding.representation_version,
                root_digest_anchor=header['root_digest'], entry_count=header['entry_count'], order='PATH_BINARY_V1')
            self._bound_digest = hashlib.sha256(_encode(self._bound)).hexdigest()
            self._scratch = stack.enter_context(ScratchSlot(self.store, self._scratch_directory))
            page_limit = (self.budget.scratch_bytes // 3) // 4096
            if page_limit < 1:
                fail('WAITING_SCRATCH_CAPACITY')
            self._db = sqlite3.connect(self._scratch.path.as_uri() + '?mode=rw', uri=True, timeout=1)
            stack.push(self._close_database)
            self._db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, max(73728, self.budget.entry_bytes + 8192))
            self._db.execute('PRAGMA trusted_schema=OFF')
            if self._db.execute('PRAGMA journal_mode=DELETE').fetchone() != ('delete',):
                fail('STORAGE_UNAVAILABLE')
            self._db.execute('PRAGMA page_size=4096')
            self._db.execute(f'PRAGMA max_page_count={page_limit}')
            self._db.execute('PRAGMA synchronous=FULL')
            self._db.execute('PRAGMA cache_size=-1024')
            self._db.execute('PRAGMA cache_spill=ON')
            self._db.execute('PRAGMA journal_size_limit=0')
            self._db.execute('PRAGMA temp_store=MEMORY')
            self._db.execute('BEGIN IMMEDIATE')
            self._db.execute('CREATE TABLE files (path TEXT PRIMARY KEY, data BLOB NOT NULL, mac TEXT NOT NULL)')
            self._db.execute('CREATE TABLE map_values (name TEXT, path TEXT, value BLOB NOT NULL, '
                             'PRIMARY KEY(name,path)) WITHOUT ROWID')
            self._db.execute('CREATE TABLE list_positions (name TEXT, pos INTEGER, path TEXT, '
                             'PRIMARY KEY(name,pos), UNIQUE(name,path)) WITHOUT ROWID')
            maps, lists = dict.fromkeys(MAPS, 0), dict.fromkeys(LISTS, 0)
            count, source_bytes, cursor = 0, 0, None
            while True:
                page = self._reader.entries_page(cursor=cursor)
                for item in page['entries']:
                    self._tick()
                    if item['size'] > self.budget.body_bytes:
                        fail('WAITING_BODY_BUDGET')
                    source_bytes += item['size']
                    if source_bytes > self.budget.source_bytes:
                        fail('WAITING_SOURCE_BUDGET')
                    raw = self._reader.read_content(item['path'], max_bytes=self.budget.body_bytes)
                    entry = self._typed_entry(item['path'], _parse(raw))
                    encoded = _encode(entry)
                    if len(encoded) > self.budget.entry_bytes:
                        fail('WAITING_ENTRY_BUDGET')
                    self._db.execute('INSERT INTO files VALUES(?,?,?)',
                                     (item['path'], encoded, self._mac(item['path'], encoded)))
                    for name, value in entry['maps'].items():
                        self._db.execute('INSERT INTO map_values VALUES(?,?,?)', (name, item['path'], _encode(value)))
                        maps[name] += 1
                    for name, position in entry['positions'].items():
                        try:
                            self._db.execute('INSERT INTO list_positions VALUES(?,?,?)', (name, position, item['path']))
                        except sqlite3.IntegrityError:
                            fail('POSITION_INVALID')
                        lists[name] += 1
                    count += 1
                    self._scratch_budget()
                if page['complete']:
                    break
                cursor = page['next_cursor']
            if count != header['entry_count'] or source_bytes != header['source_bytes']:
                fail('INVALID_PAYLOAD')
            if self._source_digest() != self._pointer['source']:
                fail('SOURCE_MISMATCH')
            self._scratch_budget()
            # Keep this exact transaction/view through all public reads. No
            # proof is cached across a commit, reconnect, or later context.
            self._db.execute('PRAGMA query_only=ON')
            self._summary = dict(state='VERIFIED', metadata_verified=True, source_digest_verified=True,
                ref=self._pointer['ref'], source=self._pointer['source'], task_ref=self._review_binding.task_ref,
                review_revision=self._review_binding.revision, snapshot_id=self._review_binding.snapshot_id,
                representation_version=self._review_binding.representation_version, field=self.field,
                entry_count=count, source_bytes=source_bytes, map_counts=maps, list_counts=lists,
                project_coverage='UNKNOWN', external_bodies_available=False, budget=asdict(self.budget))
            self._verified = True
            return self
        except BaseException as error:
            stack.__exit__(*sys.exc_info())
            self._stack, self._closed, self._verified = None, True, False
            if isinstance(error, (TypedSnapshotSourceError, SnapshotStoreError)):
                raise
            if isinstance(error, sqlite3.Error):
                _sqlite_failure(error)
            if isinstance(error, OSError):
                fail('SCRATCH_UNSAFE')
            if isinstance(error, (ValueError, TypeError, KeyError, RecursionError)):
                fail('INVALID_PAYLOAD')
            raise

    def _typed_entry(self, path, value):
        if (not isinstance(value, dict) or set(value) != {'maps', 'positions'}
                or not isinstance(value['maps'], dict) or not set(value['maps']) <= set(MAPS)
                or not isinstance(value['positions'], dict) or not set(value['positions']) <= set(LISTS)
                or not value['maps'] and not value['positions']):
            fail('INVALID_PAYLOAD')
        if any(type(index) is not int or not 0 <= index <= MAX_INTEGER for index in value['positions'].values()):
            fail('POSITION_INVALID')
        return dict(path=path, maps=value['maps'], positions=value['positions'])

    def _mac(self, path, raw):
        return self.store._mac([CONTRACT, self._bound_digest, path, hashlib.sha256(raw).hexdigest()])

    def _source_digest(self):
        digest = hashlib.sha256()
        digest.update(b'{"lists":{')
        for number, name in enumerate(sorted(LISTS)):
            if number:
                digest.update(b',')
            digest.update(_encode(name) + b':[')
            expected = 0
            for position, path in self._db.execute('SELECT pos,path FROM list_positions WHERE name=? ORDER BY pos', (name,)):
                self._tick()
                if position != expected:
                    fail('POSITION_INVALID')
                if expected:
                    digest.update(b',')
                digest.update(_encode(path))
                expected += 1
            digest.update(b']')
        digest.update(b'},"maps":{')
        for number, name in enumerate(sorted(MAPS)):
            if number:
                digest.update(b',')
            digest.update(_encode(name) + b':{')
            for index, (path, raw) in enumerate(self._db.execute(
                    'SELECT path,value FROM map_values WHERE name=? ORDER BY path COLLATE BINARY', (name,))):
                self._tick()
                if index:
                    digest.update(b',')
                digest.update(_encode(path) + b':' + raw)
            digest.update(b'}')
        digest.update(b'}}')
        return digest.hexdigest()

    def _active(self):
        if self._closed or not self._verified or self._db is None or os.getpid() != self._pid:
            fail('CLOSED')
        self._tick()
        # Preserve the original source/root identity throughout the context.
        self._reader.header
        self._scratch._stable()

    @property
    def summary(self):
        self._active()
        return json.loads(_encode(self._summary))

    @property
    def scope(self):
        """Detached identity for internal consumers of this verified view.

        This is authenticated typed metadata within the current context, not
        native host attestation or permission to adopt another task's source.
        """
        self._active()
        return json.loads(_encode(dict(task_ref=self._review_binding.task_ref,
            owner=self._review_binding.owner, workspace=str(self.store.root),
            root_identity=self.store.root_identity, field=self.field,
            source=self._pointer['source'], ref=self._pointer['ref'],
            representation_version=self._review_binding.representation_version,
            review_revision=self._review_binding.revision,
            snapshot_id=self._review_binding.snapshot_id)))

    def _read_entry(self, row):
        path, raw, mac = row
        if (not _path(path) or not isinstance(raw, bytes) or len(raw) > self.budget.entry_bytes
                or not isinstance(mac, str) or not hmac.compare_digest(mac, self._mac(path, raw))):
            fail('SCRATCH_UNSAFE')
        value = _parse(raw)
        if not isinstance(value, dict) or set(value) != {'path', 'maps', 'positions'} or value['path'] != path:
            fail('SCRATCH_UNSAFE')
        return self._typed_entry(path, dict(maps=value['maps'], positions=value['positions']))

    def _select(self):
        return ("CASE WHEN typeof(path)='text' AND length(CAST(path AS BLOB))<=4096 THEN path END,"
            f"CASE WHEN typeof(data)='blob' AND length(data)<={self.budget.entry_bytes} THEN data END,"
            "CASE WHEN typeof(mac)='text' AND length(mac)=64 THEN mac END")

    def entry(self, path):
        self._active()
        if not _path(path):
            fail('INVALID_ARGUMENT')
        try:
            row = self._db.execute(f'SELECT {self._select()} FROM files WHERE path=?', (path,)).fetchone()
            return None if row is None else self._read_entry(row)
        except sqlite3.Error as error:
            _sqlite_failure(error)

    def _cursor(self, path):
        value = dict(binding=self._bound_digest, last_path=path)
        return base64.urlsafe_b64encode(_encode(dict(value=value, mac=self.store._mac(value)))).decode().rstrip('=')

    def _after(self, cursor):
        if cursor is None:
            return None
        try:
            if not isinstance(cursor, str) or not 0 < len(cursor) <= 32768:
                raise ValueError()
            raw = base64.b64decode(cursor + '=' * (-len(cursor) % 4), altchars=b'-_', validate=True)
            if base64.urlsafe_b64encode(raw).decode().rstrip('=') != cursor:
                raise ValueError()
            packet = _parse(raw)
            value = packet['value']
            if (set(packet) != {'value', 'mac'} or not isinstance(packet['mac'], str)
                    or not hmac.compare_digest(packet['mac'], self.store._mac(value))
                    or not isinstance(value, dict) or set(value) != {'binding', 'last_path'}
                    or value['binding'] != self._bound_digest or not _path(value['last_path'])):
                raise ValueError()
            return value['last_path']
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            fail('CURSOR_INVALID')

    def entries_page(self, cursor=None, limit_items=256, limit_bytes=65536):
        self._active()
        if (type(limit_items) is not int or not 1 <= limit_items <= 256
                or type(limit_bytes) is not int or not 1 <= limit_bytes <= 65536):
            fail('INVALID_ARGUMENT')
        after = self._after(cursor)
        try:
            clause, args = ('', (limit_items + 1,)) if after is None else (
                ' WHERE path COLLATE BINARY>?', (after, limit_items + 1))
            rows = iter(self._db.execute(f'SELECT {self._select()} FROM files{clause} '
                'ORDER BY path COLLATE BINARY LIMIT ?', args))
            row = next(rows, None)
            result = dict(entries=[], next_cursor=None, complete=True)
            while row is not None and len(result['entries']) < limit_items:
                self._tick()
                value, following = self._read_entry(row), next(rows, None)
                candidate = dict(entries=[*result['entries'], value], complete=following is None,
                                 next_cursor=self._cursor(value['path']) if following is not None else None)
                if len(_encode(candidate)) > limit_bytes:
                    if not result['entries']:
                        fail('PAGE_BYTE_BUDGET')
                    return result
                result, row = candidate, following
            if len(_encode(result)) > limit_bytes:
                fail('PAGE_BYTE_BUDGET')
            return result
        except sqlite3.Error as error:
            _sqlite_failure(error)

    def close(self):
        if os.getpid() != self._pid:
            fail('CLOSED')
        self.__exit__(None, None, None)

    def __exit__(self, kind, error, traceback):
        # SQLite contexts are not fork-transferable. A child must not actively
        # roll back or clean the parent's uncommitted scratch transaction.
        # At-fork cleanup protects only this module's own lock descriptors.
        if os.getpid() != self._pid:
            return False
        self._closed, self._verified = True, False
        stack, self._stack = self._stack, None
        if stack is not None:
            return stack.__exit__(kind, error, traceback)
        return False
