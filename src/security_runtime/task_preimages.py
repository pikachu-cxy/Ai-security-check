"""Private, immutable task preimages, separate from task/control JSON.

Only the existing source sanitizer's output and private keyed comparison tokens
are retained. A reference commits to the original bytes without retaining them;
it is not authority to join another task. TaskSecurityService must still enforce
its workspace/session ownership. Optional tokens never leave this private store.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

from .closeout_state import digest, encode, readonly_uri
from .hook_state import identity, no_links
from .local_evidence import MAX_FILE_BYTES, MAX_LINE_CHARS, _relative, safe_source

CONTRACT = 'task-preimage-v1'
SOURCE = 'SANITIZED_WORKSPACE_BEFORE_TASK'
REF = re.compile(r'ts1-[a-f0-9]{32}')
SHA256 = re.compile(r'[a-f0-9]{64}')
TTL = 24 * 3600
MAX_FILE_BODY_BYTES = 2_000_000
MAX_TASK_BYTES = 24_000_000
MAX_WORKSPACE_BYTES = 96_000_000
MAX_DATABASE_BYTES = 128_000_000
MAX_TASK_FILES = 1000
MAX_TASKS = 32
MAX_REFERENCE_BYTES = 8192
MAX_PATH_BYTES = 4096
REFERENCE_FIELDS = frozenset({'contract', 'workspace_id', 'task_ref', 'path',
    'raw_sha256', 'body_sha256', 'body_bytes', 'line_count', 'source',
    'redaction_version', 'created_at', 'expires_at'})


class TaskPreimageUnavailable(ValueError):
    """Closed diagnostic; never includes an exception or source payload."""
    def __init__(self, reason_code):
        self.reason_code = self.reason = reason_code
        super().__init__(reason_code)


def _fail(reason):
    raise TaskPreimageUnavailable(reason)


def _task_ref(value):
    if not isinstance(value, str) or REF.fullmatch(value) is None:
        _fail('TASK_PREIMAGE_TASK_REJECTED')
    return value


def _path(value):
    if not isinstance(value, str):
        _fail('TASK_PREIMAGE_PATH_REJECTED')
    try:
        name = _relative(value)
    except ValueError:
        _fail('TASK_PREIMAGE_PATH_REJECTED')
    try:
        size = len(name.encode('utf-8'))
    except UnicodeError:
        _fail('TASK_PREIMAGE_PATH_REJECTED')
    if (name != value or name in {'', '.', '..'} or size > MAX_PATH_BYTES
            or Path(name).name == '.env' or Path(name).name.startswith('.env.')):
        _fail('TASK_PREIMAGE_PATH_REJECTED')
    return name


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _body(lines):
    return json.dumps(lines, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def _valid_lines(lines):
    return (isinstance(lines, list) and all(isinstance(line, str)
            and '\n' not in line and '\r' not in line and len(line) <= MAX_LINE_CHARS
            for line in lines))


class TaskPreimageStore:
    """Bounded local evidence store sharing the workspace's existing key.

    The caller initializes hooks.key(root) under its existing workspace lock.
    This store uses an independent SQLite transaction, never nests that lock.
    One successful writer seals a task's preimages. Returned references become
    valid only after the writer context commits. Reads create no state.
    """
    def __init__(self, hooks, root, *, now=time.time):
        self.hooks, self.root, self.now = hooks, Path(root), now
        self.workspace_id = identity(os.path.normcase(str(self.root)))
        self.path = hooks.workspace_directory(self.root) / 'task-preimages.db'

    def _time(self):
        value = self.now()
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            _fail('TASK_PREIMAGE_CLOCK_UNAVAILABLE')
        return value

    def _paths(self):
        # Sidecars cannot redirect SQLite's otherwise private writes either.
        for path in (self.path, *(Path(str(self.path)+suffix) for suffix in ('-journal', '-wal', '-shm'))):
            try:
                no_links(path)
            except ValueError:
                _fail('TASK_PREIMAGE_STATE_PATH_REJECTED')
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                _fail('TASK_PREIMAGE_STATE_PATH_REJECTED')
            if path == self.path and info.st_size > MAX_DATABASE_BYTES:
                _fail('TASK_PREIMAGE_DATABASE_BUDGET')

    def _key(self):
        path = self.path.parent / 'snapshot.key'
        try:
            no_links(path)
        except ValueError:
            _fail('TASK_PREIMAGE_STATE_PATH_REJECTED')
        try:
            if path.stat().st_size != 32:
                _fail('TASK_PREIMAGE_KEY_UNAVAILABLE')
            with path.open('rb') as stream:
                key = stream.read(33)
        except OSError:
            _fail('TASK_PREIMAGE_KEY_UNAVAILABLE')
        if len(key) != 32:
            _fail('TASK_PREIMAGE_KEY_UNAVAILABLE')
        return key

    def _writable(self):
        self._paths()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # SQLite inherits private permissions for its rollback journal. Avoid
        # creating a briefly world-readable initial DB on permissive POSIX umasks.
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        self._paths()
        db = sqlite3.connect(self.path, timeout=2)
        try:
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA secure_delete=ON')
            db.execute('PRAGMA temp_store=MEMORY')
            db.execute('PRAGMA journal_mode=DELETE')
            db.execute('PRAGMA synchronous=FULL')
            page_size = db.execute('PRAGMA page_size').fetchone()[0]
            db.execute(f'PRAGMA max_page_count={max(1, MAX_DATABASE_BYTES//page_size)}')
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS task_preimage_batches '
                       '(task_ref TEXT PRIMARY KEY, created REAL NOT NULL, expires REAL NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS task_preimages '
                       '(task_ref TEXT NOT NULL, path TEXT NOT NULL, created REAL NOT NULL, '
                       'expires REAL NOT NULL, metadata TEXT NOT NULL, mac TEXT NOT NULL, '
                       'body BLOB NOT NULL, PRIMARY KEY(task_ref,path))')
            db.execute('CREATE TABLE IF NOT EXISTS task_preimage_semantics '
                       '(task_ref TEXT NOT NULL, path TEXT NOT NULL, created REAL NOT NULL, '
                       'expires REAL NOT NULL, metadata TEXT NOT NULL, mac TEXT NOT NULL, '
                       'body BLOB NOT NULL, PRIMARY KEY(task_ref,path))')
            self._paths()
            return db
        except BaseException:
            db.close()
            raise

    @contextmanager
    def writer(self, task_ref):
        """Atomically collect one immutable batch; never recapture a task later."""
        task_ref = _task_ref(task_ref)
        db = None
        writer = None
        try:
            key, created = self._key(), self._time()
            db = self._writable()
            db.execute('DELETE FROM task_preimages WHERE expires<=?', (created,))
            db.execute('DELETE FROM task_preimage_semantics WHERE expires<=?', (created,))
            db.execute('DELETE FROM task_preimage_batches WHERE expires<=?', (created,))
            if db.execute('SELECT 1 FROM task_preimage_batches WHERE task_ref=?', (task_ref,)).fetchone():
                _fail('TASK_PREIMAGE_TASK_ALREADY_CAPTURED')
            if db.execute('SELECT count(*) FROM task_preimage_batches').fetchone()[0] >= MAX_TASKS:
                _fail('TASK_PREIMAGE_TASK_COUNT_BUDGET')
            db.execute('INSERT INTO task_preimage_batches VALUES(?,?,?)', (task_ref, created, created+TTL))
            writer = _PreimageWriter(self, db, key, task_ref, created)
            yield writer
            if writer.closed:
                _fail('TASK_PREIMAGE_STORE_UNAVAILABLE')
            self._paths()
            db.commit()
        except (sqlite3.Error, OSError):
            if db is not None:
                db.rollback()
            _fail('TASK_PREIMAGE_STORE_UNAVAILABLE')
        except BaseException:
            if db is not None:
                db.rollback()
            raise
        finally:
            if writer is not None:
                writer.closed = True
            if db is not None:
                db.close()

    def _reference(self, task_ref, path, expected_hash, reference, key):
        if (not isinstance(expected_hash, str) or SHA256.fullmatch(expected_hash) is None
                or not isinstance(reference, dict) or set(reference) != REFERENCE_FIELDS | {'mac'}):
            _fail('TASK_PREIMAGE_REFERENCE_UNVERIFIED')
        try:
            if len(encode(reference)) > MAX_REFERENCE_BYTES:
                _fail('TASK_PREIMAGE_REFERENCE_UNVERIFIED')
            metadata = {k: v for k, v in reference.items() if k != 'mac'}
            valid = (metadata['contract'] == CONTRACT and metadata['workspace_id'] == self.workspace_id
                and metadata['task_ref'] == task_ref and metadata['path'] == path
                and metadata['raw_sha256'] == expected_hash and metadata['source'] == SOURCE
                and metadata['redaction_version'] == 1
                and isinstance(metadata['body_sha256'], str) and SHA256.fullmatch(metadata['body_sha256'])
                and type(metadata['body_bytes']) is int and 0 < metadata['body_bytes'] <= MAX_FILE_BODY_BYTES
                and type(metadata['line_count']) is int and 0 <= metadata['line_count'] <= MAX_FILE_BYTES
                and type(metadata['created_at']) in (int, float) and math.isfinite(metadata['created_at'])
                and metadata['created_at'] >= 0
                and type(metadata['expires_at']) in (int, float) and math.isfinite(metadata['expires_at'])
                and metadata['expires_at'] == metadata['created_at']+TTL
                and isinstance(reference['mac'], str) and SHA256.fullmatch(reference['mac'])
                and hmac.compare_digest(reference['mac'], digest(key, metadata)))
        except (TypeError, ValueError, OverflowError, RecursionError):
            valid = False
        if not valid:
            _fail('TASK_PREIMAGE_REFERENCE_UNVERIFIED')
        now = self._time()
        if now < metadata['created_at'] or now >= metadata['expires_at']:
            _fail('TASK_PREIMAGE_EXPIRED')
        return metadata

    def read(self, task_ref, path, expected_hash, reference):
        """Return authentic sanitized lines for exactly the signed before hash."""
        task_ref, path = _task_ref(task_ref), _path(path)
        try:
            self._paths()
            key = self._key()
            metadata = self._reference(task_ref, path, expected_hash, reference, key)
            if not self.path.is_file():
                _fail('TASK_PREIMAGE_SOURCE_UNAVAILABLE')
            with closing(sqlite3.connect(readonly_uri(self.path), uri=True, timeout=2)) as db:
                db.execute('PRAGMA query_only=ON')
                db.execute('PRAGMA trusted_schema=OFF')
                if db.execute("SELECT 1 FROM sqlite_schema WHERE name='task_preimages' AND type='table'").fetchone() is None:
                    # A first capture that rolled back leaves no committed
                    # schema or source; it is not a corrupt successful capture.
                    _fail('TASK_PREIMAGE_SOURCE_UNAVAILABLE')
                # Bound materialization even if the local DB has been replaced
                # by a row with a huge body/metadata value.
                db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_FILE_BODY_BYTES+MAX_REFERENCE_BYTES+MAX_PATH_BYTES+1024)
                row = db.execute('SELECT CASE WHEN length(metadata)<=? THEN metadata END, '
                    'CASE WHEN length(mac)=64 THEN mac END, '
                    'CASE WHEN length(body)<=? THEN body END,created,expires FROM task_preimages '
                    'WHERE task_ref=? AND path=?',
                    (MAX_REFERENCE_BYTES, MAX_FILE_BODY_BYTES, task_ref, path)).fetchone()
            if row is None:
                _fail('TASK_PREIMAGE_SOURCE_UNAVAILABLE')
            raw_metadata, mac, body, created, expires = row
            if (not isinstance(raw_metadata, str) or len(raw_metadata.encode()) > MAX_REFERENCE_BYTES
                    or not isinstance(mac, str) or SHA256.fullmatch(mac) is None
                    or not hmac.compare_digest(mac, reference['mac'])
                    or raw_metadata != encode(metadata).decode('utf-8')
                    or created != metadata['created_at'] or expires != metadata['expires_at']
                    or not isinstance(body, bytes) or len(body) != metadata['body_bytes']
                    or not hmac.compare_digest(_sha(body), metadata['body_sha256'])):
                _fail('TASK_PREIMAGE_CONTENT_UNVERIFIED')
            lines = json.loads(body)
            if not _valid_lines(lines) or len(lines) != metadata['line_count']:
                _fail('TASK_PREIMAGE_CONTENT_UNVERIFIED')
            self._paths()
            return lines
        except (sqlite3.Error, OSError):
            _fail('TASK_PREIMAGE_STORE_UNAVAILABLE')
        except (json.JSONDecodeError, UnicodeError, RecursionError):
            _fail('TASK_PREIMAGE_CONTENT_UNVERIFIED')

    def semantic_proof(self, task_ref, path, raw_bytes):
        """Current private comparison material; never a source/ownership proof."""
        from .task_preimage_fingerprints import make_proof
        task_ref, path = _task_ref(task_ref), _path(path)
        if (not isinstance(raw_bytes, bytes) or len(raw_bytes) > MAX_FILE_BYTES
                or any(byte < 32 and byte not in (9, 10, 12, 13) for byte in raw_bytes)):
            _fail('TASK_PREIMAGE_SOURCE_REJECTED')
        try:
            return make_proof(self._key(), self.workspace_id, task_ref, path, raw_bytes)
        except UnicodeError:
            _fail('TASK_PREIMAGE_SOURCE_REJECTED')

    def read_semantic_proof(self, task_ref, path, expected_hash, reference):
        """Authenticate the original body/reference before its optional proof."""
        from . import task_preimage_fingerprints as fingerprints
        task_ref, path = _task_ref(task_ref), _path(path)
        lines = self.read(task_ref, path, expected_hash, reference)
        missing = fingerprints.incomplete(len(lines))
        key = self._key()
        # Recheck TTL/reference against the same key used for the side-table MAC.
        self._reference(task_ref, path, expected_hash, reference, key)
        try:
            self._paths()
            with closing(sqlite3.connect(readonly_uri(self.path), uri=True, timeout=2)) as db:
                db.execute('PRAGMA query_only=ON')
                db.execute('PRAGMA trusted_schema=OFF')
                if db.execute("SELECT 1 FROM sqlite_schema WHERE name='task_preimage_semantics' AND type='table'").fetchone() is None:
                    return missing
                db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,
                    fingerprints.MAX_FILE_PROOF_BYTES + MAX_REFERENCE_BYTES + MAX_PATH_BYTES + 1024)
                row = db.execute('SELECT CASE WHEN length(metadata)<=? THEN metadata END, '
                    'CASE WHEN length(mac)=64 THEN mac END, '
                    'CASE WHEN length(body)<=? THEN body END,created,expires FROM task_preimage_semantics '
                    'WHERE task_ref=? AND path=?',
                    (MAX_REFERENCE_BYTES, fingerprints.MAX_FILE_PROOF_BYTES, task_ref, path)).fetchone()
            if row is None:
                return missing
            raw_metadata, mac, body, created, expires = row
            if (not isinstance(raw_metadata, str) or len(raw_metadata.encode()) > MAX_REFERENCE_BYTES
                    or not isinstance(mac, str) or SHA256.fullmatch(mac) is None
                    or not isinstance(body, bytes) or len(body) > fingerprints.MAX_FILE_PROOF_BYTES):
                _fail('TASK_PREIMAGE_SEMANTICS_UNVERIFIED')
            metadata = dict(contract=fingerprints.CONTRACT, workspace_id=self.workspace_id,
                task_ref=task_ref, path=path, raw_sha256=reference['raw_sha256'],
                body_sha256=reference['body_sha256'], reference_mac=reference['mac'],
                line_count=reference['line_count'], created_at=reference['created_at'],
                expires_at=reference['expires_at'], proof_sha256=_sha(body), proof_bytes=len(body))
            if (raw_metadata != encode(metadata).decode('utf-8')
                    or not hmac.compare_digest(mac, digest(key, metadata))
                    or created != metadata['created_at'] or expires != metadata['expires_at']):
                _fail('TASK_PREIMAGE_SEMANTICS_UNVERIFIED')
            proof = fingerprints.decode_proof(body, len(lines))
            self._paths()
            return proof
        except (sqlite3.Error, OSError):
            _fail('TASK_PREIMAGE_STORE_UNAVAILABLE')
        except (ValueError, UnicodeError, RecursionError) as exc:
            if isinstance(exc, TaskPreimageUnavailable):
                raise
            _fail('TASK_PREIMAGE_SEMANTICS_UNVERIFIED')

    def discard(self, task_ref):
        """Remove one task's bodies; never touches another task or creates a DB."""
        task_ref = _task_ref(task_ref)
        try:
            self._paths()
            if not self.path.is_file():
                return
            with closing(self._writable()) as db, db:
                db.execute('DELETE FROM task_preimages WHERE task_ref=?', (task_ref,))
                db.execute('DELETE FROM task_preimage_semantics WHERE task_ref=?', (task_ref,))
                db.execute('DELETE FROM task_preimage_batches WHERE task_ref=?', (task_ref,))
        except (sqlite3.Error, OSError):
            _fail('TASK_PREIMAGE_STORE_UNAVAILABLE')


class _PreimageWriter:
    def __init__(self, store, db, key, task_ref, created):
        self.store, self.db, self.key = store, db, key
        self.task_ref, self.created, self.closed = task_ref, created, False
        self.references = {}
        self.task_bytes = 0
        self.workspace_bytes = db.execute('SELECT coalesce(sum(length(body)),0) FROM task_preimages').fetchone()[0]
        self.proof_bytes = 0
        from .task_preimage_fingerprints import ROW_FRAMING_BYTES
        self.workspace_proof_bytes = db.execute(
            'SELECT coalesce(sum(length(body)+length(CAST(metadata AS BLOB))+'
            'length(CAST(path AS BLOB))+length(mac)+?),0) FROM task_preimage_semantics',
            (ROW_FRAMING_BYTES,)).fetchone()[0]

    def put(self, path, raw_bytes, sanitized_lines):
        if self.closed:
            _fail('TASK_PREIMAGE_WRITER_CLOSED')
        path = _path(path)
        if not isinstance(raw_bytes, bytes) or len(raw_bytes) > MAX_FILE_BYTES:
            _fail('TASK_PREIMAGE_FILE_BUDGET')
        try:
            if any(byte < 32 and byte not in (9, 10, 12, 13) for byte in raw_bytes):
                _fail('TASK_PREIMAGE_SOURCE_REJECTED')
            # Defense in depth: callers cannot accidentally persist unredacted
            # arguments merely by labelling them sanitized_lines.
            if not _valid_lines(sanitized_lines) or sanitized_lines != safe_source(raw_bytes.decode('utf-8-sig'), source_path=path):
                _fail('TASK_PREIMAGE_SANITIZATION_UNVERIFIED')
            body = _body(sanitized_lines)
        except UnicodeError:
            _fail('TASK_PREIMAGE_SOURCE_REJECTED')
        if len(body) > MAX_FILE_BODY_BYTES:
            _fail('TASK_PREIMAGE_FILE_BUDGET')
        raw_hash = _sha(raw_bytes)
        old = self.references.get(path)
        if old is not None:
            if old['raw_sha256'] != raw_hash or old['body_sha256'] != _sha(body):
                _fail('TASK_PREIMAGE_IMMUTABLE')
            return dict(old)
        if len(self.references) >= MAX_TASK_FILES:
            _fail('TASK_PREIMAGE_FILE_COUNT_BUDGET')
        if self.task_bytes+len(body) > MAX_TASK_BYTES:
            _fail('TASK_PREIMAGE_TASK_BYTE_BUDGET')
        if self.workspace_bytes+len(body) > MAX_WORKSPACE_BYTES:
            _fail('TASK_PREIMAGE_WORKSPACE_BYTE_BUDGET')
        metadata = dict(contract=CONTRACT, workspace_id=self.store.workspace_id,
            task_ref=self.task_ref, path=path, raw_sha256=raw_hash,
            body_sha256=_sha(body), body_bytes=len(body), line_count=len(sanitized_lines),
            source=SOURCE, redaction_version=1, created_at=self.created, expires_at=self.created+TTL)
        mac = digest(self.key, metadata)
        reference = dict(metadata, mac=mac)
        if len(encode(reference)) > MAX_REFERENCE_BYTES:
            _fail('TASK_PREIMAGE_REFERENCE_BUDGET')
        try:
            self.db.execute('INSERT INTO task_preimages VALUES(?,?,?,?,?,?,?)',
                (self.task_ref, path, self.created, self.created+TTL, encode(metadata).decode(), mac, body))
            self._put_semantics(path, raw_bytes, sanitized_lines, reference)
        except sqlite3.Error:
            # A full disk or SQLite rollback must invalidate the whole writer,
            # even if a caller catches this particular file's exception.
            self.closed = True
            raise
        self.references[path] = reference
        self.task_bytes += len(body)
        self.workspace_bytes += len(body)
        return dict(reference)

    def _put_semantics(self, path, raw_bytes, sanitized_lines, reference):
        from . import task_preimage_fingerprints as fingerprints
        proof = fingerprints.make_proof(self.key, self.store.workspace_id, self.task_ref, path,
                                       raw_bytes, sanitized_lines=sanitized_lines)
        body = fingerprints.encode_proof(proof)
        metadata = dict(contract=fingerprints.CONTRACT, workspace_id=self.store.workspace_id,
            task_ref=self.task_ref, path=path, raw_sha256=reference['raw_sha256'],
            body_sha256=reference['body_sha256'], reference_mac=reference['mac'],
            line_count=reference['line_count'], created_at=reference['created_at'],
            expires_at=reference['expires_at'], proof_sha256=_sha(body), proof_bytes=len(body))
        encoded_metadata = encode(metadata)
        mac = digest(self.key, metadata)
        row_bytes = (len(encoded_metadata) + len(body) + len(path.encode('utf-8'))
                     + len(mac.encode('ascii')) + fingerprints.ROW_FRAMING_BYTES)
        if (len(encoded_metadata) > MAX_REFERENCE_BYTES or row_bytes > fingerprints.MAX_FILE_PROOF_BYTES
                or self.proof_bytes + row_bytes > fingerprints.MAX_TASK_PROOF_BYTES
                or self.workspace_proof_bytes + row_bytes > fingerprints.MAX_WORKSPACE_PROOF_BYTES):
            # Include new metadata, indexed path, MAC and bounded row framing;
            # optional proof must not displace the original source body.
            return
        self.db.execute('INSERT INTO task_preimage_semantics VALUES(?,?,?,?,?,?,?)',
            (self.task_ref, path, self.created, self.created+TTL, encoded_metadata.decode(), mac, body))
        self.proof_bytes += row_bytes
        self.workspace_proof_bytes += row_bytes
