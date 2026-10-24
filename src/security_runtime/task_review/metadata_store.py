"""Internal signed review metadata pages; not an enabled review protocol.

The task ledger below is independent of legacy security_tasks JSON. A future
explicit task contract must wire it to the coordinator; old tasks are never
migrated. Reads validate the complete collection with at most one decoded page.
Append validates signed heads, SQL cardinalities and the authenticated tail;
seal/read additionally authenticate every page. Journal admission is a
conservative reservation and existing-file check, not an OS disk hard limit.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile

from ..hook_state import no_links
from ..tasks.ownership import valid_owner

CONTRACT = 'review-metadata-pages-v1'
TABLES = ('rm_registry', 'rm_ledgers', 'rm_collections', 'rm_pages', 'rm_receipts')
SCHEMA = (
    'CREATE TABLE rm_registry (slot INTEGER PRIMARY KEY, data BLOB NOT NULL, mac TEXT NOT NULL)',
    'CREATE TABLE rm_ledgers (task_ref TEXT PRIMARY KEY, generation INTEGER NOT NULL, data BLOB NOT NULL, mac TEXT NOT NULL)',
    'CREATE TABLE rm_collections (ref TEXT PRIMARY KEY, task_ref TEXT NOT NULL, name TEXT NOT NULL, data BLOB NOT NULL, mac TEXT NOT NULL)',
    'CREATE TABLE rm_pages (ref TEXT NOT NULL, page_seq INTEGER NOT NULL, first_item INTEGER NOT NULL, item_count INTEGER NOT NULL, previous_digest TEXT NOT NULL, digest TEXT NOT NULL, data BLOB NOT NULL, mac TEXT NOT NULL, PRIMARY KEY(ref,page_seq))',
    'CREATE TABLE rm_receipts (task_ref TEXT NOT NULL, request_id TEXT NOT NULL, data BLOB NOT NULL, mac TEXT NOT NULL, PRIMARY KEY(task_ref,request_id))',
)
FENCE_TABLE = 'rm_head_fences'
FENCE_SCHEMA = ('CREATE TABLE rm_head_fences (task_ref TEXT PRIMARY KEY, '
                'data BLOB NOT NULL, mac TEXT NOT NULL)')
CATEGORIES = ('source_bytes', 'navigation_bytes', 'control_bytes', 'reads', 'total_bytes')
ZERO = dict.fromkeys(CATEGORIES, 0)
HEADER_BYTES = 65536
ROW_BYTES = 256
MAX_INTEGER = 2**53 - 1


class ReviewMetadataError(ValueError):
    def __init__(self, reason_code):
        self.reason_code = reason_code
        super().__init__(reason_code)


def fail(suffix='HISTORY_UNAVAILABLE'):
    raise ReviewMetadataError('REVIEW_METADATA_' + suffix)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def integer(value, *, minimum=0, maximum=MAX_INTEGER):
    return type(value) is int and minimum <= value <= maximum


def text(value, maximum=128):
    try:
        return isinstance(value, str) and 0 < len(value.encode('utf-8')) <= maximum and '\0' not in value
    except UnicodeError:
        return False


@dataclass(frozen=True)
class ReviewMetadataBinding:
    task_ref: str
    owner: dict
    revision: int
    snapshot_id: str
    representation_version: int = 3


@dataclass(frozen=True)
class ReviewMetadataBudget:
    page_items: int = 256
    page_bytes: int = 65536
    request_items: int = 4096
    request_bytes: int = 1_048_576
    logical_bytes: int = 96_000_000
    database_bytes: int = 128_000_000
    journal_bytes: int = 128_000_000


class ReviewMetadataStore:
    def __init__(self, path, *, workspace_root, key, budget=None):
        self.path = Path(path).absolute()
        self.root = Path(workspace_root).absolute()
        try:
            no_links(self.root)
            self.root = self.root.resolve(strict=True)
            info = self.root.stat()
            if not stat.S_ISDIR(info.st_mode):
                fail('INVALID')
            self.root_identity = [info.st_dev, info.st_ino]
        except (OSError, ValueError):
            fail('INVALID')
        if not isinstance(key, bytes) or len(key) != 32:
            fail('INVALID')
        self.key = key
        self.budget = budget or ReviewMetadataBudget()
        if not isinstance(self.budget, ReviewMetadataBudget):
            fail('INVALID')
        values = asdict(self.budget)
        if (not all(integer(v, minimum=1) for v in values.values())
                or self.budget.page_items > 65536 or self.budget.page_bytes > 1_000_000
                or self.budget.request_items > 65536 or self.budget.request_bytes > 16_777_216):
            fail('INVALID')
        self.marker = self.path.with_name(self.path.name + '.review-metadata.identity')
        self.base = dict(contract=CONTRACT, workspace=str(self.root), root_identity=self.root_identity)

    def _binding(self, binding):
        try:
            owner_valid = isinstance(binding, ReviewMetadataBinding) and valid_owner(binding.owner)
        except (TypeError, ValueError):
            owner_valid = False
        if (not isinstance(binding, ReviewMetadataBinding)
                or not isinstance(binding.task_ref, str)
                or re.fullmatch(r'ts1-[a-f0-9]{32}', binding.task_ref) is None
                or not owner_valid or not integer(binding.revision, minimum=1)
                or not text(binding.snapshot_id) or not integer(binding.representation_version, minimum=1, maximum=255)):
            fail('INVALID')
        return dict(task_ref=binding.task_ref, owner=dict(binding.owner), revision=binding.revision,
                    snapshot_id=binding.snapshot_id, representation_version=binding.representation_version)

    def _task_binding(self, binding):
        return {k: binding[k] for k in ('task_ref', 'owner', 'representation_version')}

    def _counts(self, value):
        if (not isinstance(value, dict) or set(value) != set(CATEGORIES)
                or not all(integer(v) for v in value.values())
                or value['total_bytes'] != sum(value[k] for k in CATEGORIES[:3])):
            fail('INVALID')
        return dict(value)

    def _private(self, path, *, directory=False):
        no_links(path)
        info = path.stat()
        valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        if (not valid or (hasattr(os, 'getuid') and info.st_uid != os.getuid())
                or (os.name != 'nt' and info.st_mode & 0o077)):
            fail()
        return info

    def _paths(self, *, create=False):
        try:
            no_links(self.root)
            info = self.root.stat()
            if [info.st_dev, info.st_ino] != self.root_identity or not stat.S_ISDIR(info.st_mode):
                fail()
            no_links(self.path)
            no_links(self.marker)
            if not self.path.parent.exists() and create and not self.marker.exists():
                self.path.parent.mkdir(mode=0o700, parents=True)
            self._private(self.path.parent, directory=True)
            for candidate in (self.path, self.marker,
                              *(Path(str(self.path) + suffix) for suffix in ('-journal', '-wal', '-shm'))):
                if candidate.exists():
                    self._private(candidate)
            if self.marker.exists() and not self.path.exists():
                fail()
            for suffix in ('-journal', '-wal', '-shm'):
                candidate = Path(str(self.path) + suffix)
                if candidate.exists() and candidate.stat().st_size > self.budget.journal_bytes:
                    fail('WAITING_CAPACITY')
            if self.path.exists() and self.path.stat().st_size > self.budget.database_bytes:
                fail('WAITING_CAPACITY')
        except (OSError, ValueError) as error:
            if isinstance(error, ReviewMetadataError):
                raise
            fail()

    def _mac(self, kind, value):
        return hmac.new(self.key, encode(dict(binding=self.base, kind=kind, value=value)), hashlib.sha256).hexdigest()

    def _decode(self, kind, raw, mac, *, maximum=16384):
        try:
            if not isinstance(raw, bytes) or len(raw) > maximum or not isinstance(mac, str):
                fail()
            value = json.loads(raw)
            if (not isinstance(value, dict) or not hmac.compare_digest(mac, self._mac(kind, value))
                    or encode(value) != raw):
                fail()
            return value
        except (TypeError, ValueError, UnicodeError, RecursionError):
            fail()

    def _marker(self):
        if not self.marker.exists():
            fail()
        self._private(self.marker)
        if self.marker.stat().st_size > 8192:
            fail()
        try:
            value = json.loads(self.marker.read_bytes())
            if (not isinstance(value, dict) or set(value) != {'value', 'mac'}
                    or not isinstance(value['mac'], str)
                    or not hmac.compare_digest(value['mac'], self._mac('identity', value['value']))):
                fail()
        except (ValueError, TypeError, UnicodeError, RecursionError):
            fail()
        return value['value']

    def _publish_marker(self, identity):
        raw = encode(dict(value=identity, mac=self._mac('identity', identity)))
        fd, temporary = tempfile.mkstemp(prefix='.review-metadata-', dir=self.path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, self.marker, follow_symlinks=False)
            parent = os.open(self.path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0))
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def _identity(self):
        info = self._private(self.path)
        return dict(self.base, database_identity=[info.st_dev, info.st_ino], budget=asdict(self.budget))

    def _stats(self, db):
        counts, usage = {}, HEADER_BYTES
        tables = (*TABLES[1:], FENCE_TABLE) if self._fenced_schema(db) else TABLES[1:]
        for table in tables:
            count, size = db.execute(f'SELECT count(*),coalesce(sum(length(data)+length(mac)),0) FROM {table}').fetchone()
            counts[table] = count
            usage += size + ROW_BYTES * count
        return counts, usage

    def _registry(self, db):
        row = db.execute('SELECT slot,data,mac FROM rm_registry').fetchone()
        if not row or row[0] != 1 or db.execute('SELECT count(*) FROM rm_registry').fetchone()[0] != 1:
            fail()
        value = self._decode('registry', row[1], row[2])
        identity = self._identity()
        marker = self._marker()
        if (value.get('identity') != identity or marker != identity
                or value.get('counts') is None or not integer(value.get('logical_bytes'))):
            fail()
        counts, usage = self._stats(db)
        if counts != value['counts'] or usage != value['logical_bytes']:
            fail()
        if usage > self.budget.logical_bytes:
            fail('WAITING_CAPACITY')
        return value

    def _write_registry(self, db):
        counts, usage = self._stats(db)
        if usage > self.budget.logical_bytes:
            fail('WAITING_CAPACITY')
        value = dict(identity=self._identity(), counts=counts, logical_bytes=usage)
        db.execute('INSERT OR REPLACE INTO rm_registry VALUES(1,?,?)', (encode(value), self._mac('registry', value)))

    def _initialize(self, db):
        for statement in SCHEMA:
            db.execute(statement)
        self._write_registry(db)
        # Deliberately before commit: a crash cannot turn an allocated identity
        # into a fresh empty store. Its incomplete allocation fails closed.
        self._publish_marker(self._identity())

    def _schema(self, db):
        expected = dict(zip(TABLES, SCHEMA))
        if self._fenced_schema(db):
            expected[FENCE_TABLE] = FENCE_SCHEMA
        indexes = {f'sqlite_autoindex_{name}_1' for name in TABLES[1:]}
        if FENCE_TABLE in expected:
            indexes.add(f'sqlite_autoindex_{FENCE_TABLE}_1')
        seen, actual_indexes = set(), set()
        for kind, name, table, sql in db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master'):
            if table not in expected:
                continue
            if kind == 'table' and name == table and sql == expected[name]:
                seen.add(name)
            elif kind == 'index' and name in indexes and sql is None:
                actual_indexes.add(name)
            else:
                # trusted_schema does not stop a plain-SQL trigger updating a
                # legacy task. No user trigger/index may extend this domain.
                fail()
        if seen != set(expected) or actual_indexes != indexes:
            fail()

    def _fenced_schema(self, db):
        return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (FENCE_TABLE,)).fetchone() is not None

    def _enable_head_fences(self, db):
        if not self._fenced_schema(db):
            db.execute(FENCE_SCHEMA)
        self._schema(db)

    def _head_fence(self, db, binding):
        if not self._fenced_schema(db):
            return None
        row = db.execute('SELECT task_ref,data,mac FROM rm_head_fences WHERE task_ref=?', (binding['task_ref'],)).fetchone()
        if row is None:
            return None
        value = self._decode('head-fence', row[1], row[2])
        if (row[0] != binding['task_ref'] or value.get('task_ref') != binding['task_ref']
                or value.get('binding') != self._task_binding(binding)
                or value.get('contract') != 'task-security-paged-review-v1'):
            fail()
        return value

    def _standalone(self, db, binding):
        if self._head_fence(db, binding) is not None:
            fail('HEAD_BOUND')

    @contextmanager
    def _db(self, *, write=False, create=False):
        db = None
        try:
            self._paths(create=create)
            if not self.path.exists():
                if not create:
                    fail()
                try:
                    fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
                    os.close(fd)
                except FileExistsError:
                    pass  # Another explicit initializer won; validate below.
            info = self._private(self.path)
            pinned = [info.st_dev, info.st_ino]
            uri = self.path.as_uri() + ('?mode=rw' if write else '?mode=ro')
            db = sqlite3.connect(uri, uri=True, timeout=15, isolation_level=None)
            # Reject corrupt oversized records inside SQLite, before a Python
            # SELECT could materialize them. Legacy task bodies are not read
            # by this connection and retain their original 4 MB contract.
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, max(self.budget.page_bytes + 8192, 32768))
            db.execute('PRAGMA trusted_schema=OFF')
            # WAL opens can create shared-memory state even for reads. This
            # foundation accepts the existing task store's rollback mode only.
            if db.execute('PRAGMA journal_mode').fetchone()[0].lower() != 'delete':
                fail()
            if write:
                db.execute('PRAGMA synchronous=FULL')
                db.execute('PRAGMA secure_delete=ON')
                page_size = db.execute('PRAGMA page_size').fetchone()[0]
                original = db.execute('PRAGMA page_count').fetchone()[0]
                # Reserve an entire existing DB plus conservative per-page
                # journal overhead. Not a filesystem/OS concurrent disk cap.
                reservation = HEADER_BYTES + original * (page_size + 1024)
                if reservation > self.budget.journal_bytes:
                    fail('WAITING_CAPACITY')
                maximum = self.budget.database_bytes // page_size
                if maximum < max(original, 2):
                    fail('WAITING_CAPACITY')
                db.execute(f'PRAGMA max_page_count={maximum}')
                db.execute('BEGIN IMMEDIATE')
            else:
                db.execute('PRAGMA query_only=ON')
                db.execute('BEGIN')
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'rm_%'")}
            if tables not in (set(TABLES), {*TABLES, FENCE_TABLE}):
                if tables or self.marker.exists() or not create or not write:
                    fail()
                self._initialize(db)
                # Allocation has its own small transaction. A later ordinary
                # request/quota failure leaves this authenticated empty domain
                # reusable, rather than rolling it back behind its marker.
                # A process death between marker publication and this commit
                # remains deliberately fail closed.
                db.commit()
                db.execute('BEGIN IMMEDIATE')
            self._schema(db)
            self._registry(db)
            yield db
            # Root and database path identities remain bound throughout use.
            self._paths()
            if self._identity()['database_identity'] != pinned:
                fail()
            if write:
                self._write_registry(db)
                if db.execute('PRAGMA page_count').fetchone()[0] * db.execute('PRAGMA page_size').fetchone()[0] > self.budget.database_bytes:
                    fail('WAITING_CAPACITY')
            db.commit()
        except sqlite3.Error as error:
            if db is not None and db.in_transaction:
                db.rollback()
            primary = (getattr(error, 'sqlite_errorcode', 0) or 0) & 255
            if primary == sqlite3.SQLITE_FULL:
                fail('WAITING_CAPACITY')
            if primary in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
                fail('BUSY')
            fail()
        except OSError:
            if db is not None and db.in_transaction:
                db.rollback()
            fail()
        except BaseException:
            if db is not None and db.in_transaction:
                db.rollback()
            raise
        finally:
            if db is not None:
                db.close()

    def _ledger(self, db, binding, *, optional=False):
        row = db.execute('SELECT task_ref,generation,data,mac FROM rm_ledgers WHERE task_ref=?', (binding['task_ref'],)).fetchone()
        if row is None:
            if optional:
                return None
            fail()
        value = self._decode('ledger', row[2], row[3])
        if (value.get('binding') != self._task_binding(binding) or row[:2] != (binding['task_ref'], value.get('generation'))
                or not integer(value.get('generation'), minimum=1)):
            fail()
        for name in ('limits', 'spent'):
            try:
                self._counts(value[name])
            except (ReviewMetadataError, KeyError):
                fail()
        if any(value['spent'][k] > value['limits'][k] for k in CATEGORIES):
            fail()
        return value

    def _public_ledger(self, value):
        return dict(generation=value['generation'], limits=dict(value['limits']), spent=dict(value['spent']))

    def ledger(self, binding):
        binding = self._binding(binding)
        with self._db() as db:
            return self._public_ledger(self._ledger(db, binding))

    def _collection(self, db, ref, binding):
        self._ref(ref)
        row = db.execute('SELECT ref,task_ref,name,data,mac FROM rm_collections WHERE ref=?', (ref,)).fetchone()
        if row is None:
            fail()
        value = self._decode('collection', row[3], row[4])
        if (value.get('binding') != binding or row[:3] != (value.get('ref'), binding['task_ref'], value.get('name'))
                or value.get('state') not in {'STAGING', 'SEALED'}
                or not all(integer(value.get(k)) for k in ('page_count', 'item_count'))
                or not isinstance(value.get('tail_digest'), str) or re.fullmatch('[a-f0-9]{64}', value['tail_digest']) is None):
            fail()
        return value

    def _head(self, value, ledger):
        return {k: value[k] for k in ('ref', 'state', 'page_count', 'item_count', 'tail_digest')} | {
            'generation': ledger['generation'], 'ledger': self._public_ledger(ledger)}

    def _page_value(self, row, ref):
        seq, first, count, previous, digest, raw, mac = row
        value = self._decode('page', raw, mac, maximum=self.budget.page_bytes + 4096)
        if (value.get('ref') != ref or tuple(value.get(k) for k in ('page_seq', 'first_item', 'item_count', 'previous_digest')) != row[:4]
                or not integer(seq, minimum=1) or not integer(first) or not integer(count, minimum=1, maximum=self.budget.page_items)
                or not isinstance(value.get('items'), list) or len(value['items']) != count
                or len(encode(value['items'])) > self.budget.page_bytes
                or digest != hashlib.sha256(raw).hexdigest()):
            fail()
        return value

    def _validate(self, db, value, *, full):
        ref, expected_pages, expected_items = value['ref'], value['page_count'], value['item_count']
        aggregate = db.execute('SELECT count(*),coalesce(min(page_seq),0),coalesce(max(page_seq),0),coalesce(sum(item_count),0) FROM rm_pages WHERE ref=?', (ref,)).fetchone()
        if aggregate != (expected_pages, 1 if expected_pages else 0, expected_pages, expected_items):
            fail()
        if full:
            previous, first = '0' * 64, 0
            for seq, row in enumerate(db.execute('SELECT page_seq,first_item,item_count,previous_digest,digest,data,mac FROM rm_pages WHERE ref=? ORDER BY page_seq', (ref,)), 1):
                page = self._page_value(row, ref)
                if page['page_seq'] != seq or page['first_item'] != first or page['previous_digest'] != previous:
                    fail()
                previous, first = row[4], first + page['item_count']
                del page
            if previous != value['tail_digest'] or first != expected_items:
                fail()
        elif expected_pages:
            row = db.execute('SELECT page_seq,first_item,item_count,previous_digest,digest,data,mac FROM rm_pages WHERE ref=? AND page_seq=?', (ref, expected_pages)).fetchone()
            page = self._page_value(row, ref)
            if row[4] != value['tail_digest'] or page['first_item'] + page['item_count'] != expected_items:
                fail()
        elif value['tail_digest'] != '0' * 64 or expected_items:
            fail()

    def manifest(self, ref, binding):
        binding = self._binding(binding)
        with self._db() as db:
            ledger = self._ledger(db, binding)
            value = self._collection(db, ref, binding)
            self._validate(db, value, full=True)
            return self._head(value, ledger)

    @contextmanager
    def reader(self, ref, binding):
        """One validated SQLite snapshot; a writer can wait until it closes.

        Nothing is cached across transactions. A deleted or damaged page is
        rejected before the first result. The reader must be closed promptly;
        it exposes no DB connection and retains at most one decoded page.
        """
        binding = self._binding(binding)
        with self._db() as db:
            ledger = self._ledger(db, binding)
            value = self._collection(db, ref, binding)
            if value['state'] != 'SEALED':
                fail('NOT_SEALED')
            self._validate(db, value, full=True)
            reader = _ReviewMetadataReader(self, db, value, ledger)
            try:
                yield reader
            finally:
                reader.close()

    def page(self, ref, binding, *, after_page=0):
        with self.reader(ref, binding) as reader:
            return reader.page(after_page=after_page)

    def _item_raw(self, item):
        remaining = self.budget.page_bytes - 2  # Single-item array framing.

        def check(value, depth=0):
            nonlocal remaining
            if depth > 16:
                fail('PAGE_BUDGET')
            if value is None or type(value) is bool:
                remaining -= len(encode(value))
            elif type(value) is int and -MAX_INTEGER <= value <= MAX_INTEGER:
                remaining -= len(encode(value))
            elif type(value) is float and math.isfinite(value):
                remaining -= len(encode(value))
            elif isinstance(value, str):
                if len(value) > self.budget.page_bytes:
                    fail('PAGE_BUDGET')
                remaining -= len(encode(value))
            elif isinstance(value, (list, dict)):
                if len(value) > self.budget.page_bytes:
                    fail('PAGE_BUDGET')
                remaining -= 2 + max(0, len(value) - 1)
                if remaining < 0:
                    fail('PAGE_BUDGET')
                for key, part in value.items() if isinstance(value, dict) else enumerate(value):
                    if isinstance(value, dict):
                        if not isinstance(key, str) or len(key) > 256:
                            fail('INVALID')
                        remaining -= len(encode(key)) + 1
                    check(part, depth + 1)
            else:
                fail('INVALID')
            if remaining < 0:
                fail('PAGE_BUDGET')
        if not isinstance(item, dict):
            fail('INVALID')
        try:
            check(item)
            raw = encode(item)
            if len(raw) + 2 > self.budget.page_bytes:
                fail('PAGE_BUDGET')
            return raw
        except (ValueError, UnicodeError, RecursionError, RuntimeError) as error:
            if isinstance(error, ReviewMetadataError):
                raise
            fail('INVALID')

    def _request(self, kind, binding, request_id, payload, charge, items=None):
        if not text(request_id):
            fail('INVALID')
        hashed = hashlib.sha256(encode(dict(kind=kind, binding=binding, payload=payload, charge=charge)))
        if items is not None:
            for raw in items:
                hashed.update(len(raw).to_bytes(8, 'big'))
                hashed.update(raw)
        return hashed.hexdigest()

    def _freeze_items(self, items):
        if not isinstance(items, (list, tuple)) or not items:
            fail('INVALID')
        if len(items) > self.budget.request_items:
            fail('PAGE_BUDGET')
        frozen, size = [], 2
        for item in items:
            if len(frozen) >= self.budget.request_items:
                fail('PAGE_BUDGET')
            raw = self._item_raw(item)
            size += len(raw) + bool(frozen)
            if size > self.budget.request_bytes:
                fail('PAGE_BUDGET')
            frozen.append(raw)
        return tuple(frozen)

    def _ref(self, ref):
        if not isinstance(ref, str) or re.fullmatch('rm1-[a-f0-9]{32}', ref) is None:
            fail('INVALID')

    def _receipt(self, db, binding, request_id, request_hash):
        row = db.execute('SELECT task_ref,request_id,data,mac FROM rm_receipts WHERE task_ref=? AND request_id=?', (binding['task_ref'], request_id)).fetchone()
        if row is None:
            return None
        value = self._decode('receipt', row[2], row[3])
        if row[:2] != (value.get('task_ref'), value.get('request_id')) or value.get('binding') != self._task_binding(binding):
            fail()
        if value.get('request_hash') != request_hash:
            fail('IDEMPOTENCY_CONFLICT')
        result = value.get('result')
        if (not isinstance(result, dict) or result.get('state') not in {'STAGING', 'SEALED'}
                or not isinstance(result.get('ledger'), dict)
                or not all(integer(result.get(k)) for k in ('generation', 'page_count', 'item_count'))):
            fail()
        return result

    def _cas(self, ledger, expected_generation, charge):
        if not integer(expected_generation):
            fail('INVALID')
        if (ledger['generation'] if ledger else 0) != expected_generation:
            fail('CAS_CONFLICT')
        if ledger is None:
            return
        if any(ledger['spent'][k] + charge[k] > ledger['limits'][k] for k in CATEGORIES):
            fail('WAITING_CAPACITY')

    def _save_receipt(self, db, binding, request_id, request_hash, result):
        receipt = dict(task_ref=binding['task_ref'], request_id=request_id,
                       binding=self._task_binding(binding), request_hash=request_hash, result=result)
        raw = encode(receipt)
        if len(raw) > 16384:
            fail('PAGE_BUDGET')
        db.execute('INSERT INTO rm_receipts VALUES(?,?,?,?)',
                   (binding['task_ref'], request_id, raw, self._mac('receipt', receipt)))

    def _finish(self, db, binding, ledger, value, request_id, request_hash, charge, *, receipt=True):
        ledger = dict(ledger, generation=ledger['generation'] + 1,
                      spent={k: ledger['spent'][k] + charge[k] for k in CATEGORIES})
        if any(ledger['spent'][k] > ledger['limits'][k] for k in CATEGORIES):
            fail('WAITING_CAPACITY')
        db.execute('INSERT OR REPLACE INTO rm_collections VALUES(?,?,?,?,?)',
                   (value['ref'], binding['task_ref'], value['name'], encode(value), self._mac('collection', value)))
        db.execute('INSERT OR REPLACE INTO rm_ledgers VALUES(?,?,?,?)',
                   (binding['task_ref'], ledger['generation'], encode(ledger), self._mac('ledger', ledger)))
        result = self._head(value, ledger)
        if receipt:
            self._save_receipt(db, binding, request_id, request_hash, result)
        return result

    def create(self, binding, name, *, limits, request_id, expected_generation=0):
        binding, limits = self._binding(binding), self._counts(limits)
        if not text(name):
            fail('INVALID')
        request_hash = self._request('create', binding, request_id, dict(name=name, limits=limits), ZERO)
        with self._db(write=True, create=True) as db:
            self._standalone(db, binding)
            # Verify task owner/representation even for a receipt replay.
            ledger = self._ledger(db, binding, optional=True)
            receipt = self._receipt(db, binding, request_id, request_hash)
            if receipt is not None:
                return receipt
            if ledger and ledger['limits'] != limits:
                fail('INVALID')
            self._cas(ledger, expected_generation, ZERO)
            ref = 'rm1-' + hashlib.sha256(encode(dict(binding=binding, name=name))).hexdigest()[:32]
            if db.execute('SELECT 1 FROM rm_collections WHERE ref=?', (ref,)).fetchone():
                fail('IDEMPOTENCY_CONFLICT')
            value = dict(ref=ref, name=name, binding=binding, state='STAGING', page_count=0,
                         item_count=0, tail_digest='0' * 64)
            ledger = ledger or dict(binding=self._task_binding(binding), generation=0, limits=limits, spent=dict(ZERO))
            return self._finish(db, binding, ledger, value, request_id, request_hash, ZERO)

    def append(self, ref, binding, items, *, expected_generation, request_id, charge=None):
        binding, charge = self._binding(binding), self._counts(dict(ZERO) if charge is None else charge)
        self._ref(ref)
        frozen = self._freeze_items(items)
        request_hash = self._request('append', binding, request_id, dict(ref=ref), charge, frozen)
        with self._db(write=True) as db:
            self._standalone(db, binding)
            ledger = self._ledger(db, binding)
            value = self._collection(db, ref, binding)
            receipt = self._receipt(db, binding, request_id, request_hash)
            if receipt is not None:
                return receipt
            self._cas(ledger, expected_generation, charge)
            if value['state'] != 'STAGING':
                fail('INVALID')
            self._validate(db, value, full=False)
            self._append_pages(db, value, frozen)
            return self._finish(db, binding, ledger, value, request_id, request_hash, charge)

    def seal(self, ref, binding, *, expected_generation, expected_items, request_id, charge=None):
        binding, charge = self._binding(binding), self._counts(dict(ZERO) if charge is None else charge)
        self._ref(ref)
        if not integer(expected_items):
            fail('INVALID')
        request_hash = self._request('seal', binding, request_id, dict(ref=ref, expected_items=expected_items), charge)
        with self._db(write=True) as db:
            self._standalone(db, binding)
            ledger = self._ledger(db, binding)
            value = self._collection(db, ref, binding)
            receipt = self._receipt(db, binding, request_id, request_hash)
            if receipt is not None:
                return receipt
            self._cas(ledger, expected_generation, charge)
            if value['state'] != 'STAGING' or value['item_count'] != expected_items:
                fail('INVALID')
            self._validate(db, value, full=True)
            value['state'] = 'SEALED'
            return self._finish(db, binding, ledger, value, request_id, request_hash, charge)

    def _append_pages(self, db, value, frozen):
        batch, size, ref = [], 2, value['ref']

        def write_page():
            page = dict(ref=ref, page_seq=value['page_count'] + 1, first_item=value['item_count'],
                        item_count=len(batch), previous_digest=value['tail_digest'], items=batch)
            raw = encode(page)
            hashed = hashlib.sha256(raw).hexdigest()
            db.execute('INSERT INTO rm_pages VALUES(?,?,?,?,?,?,?,?)',
                (ref, page['page_seq'], page['first_item'], len(batch), page['previous_digest'],
                 hashed, raw, self._mac('page', page)))
            value.update(page_count=page['page_seq'], item_count=value['item_count'] + len(batch), tail_digest=hashed)

        for raw in frozen:
            extra = len(raw) + bool(batch)
            if batch and (len(batch) == self.budget.page_items or size + extra > self.budget.page_bytes):
                write_page()
                batch, size, extra = [], 2, len(raw)
            batch.append(json.loads(raw))
            size += extra
        if batch:
            write_page()


class _ReviewMetadataReader:
    def __init__(self, store, db, value, ledger):
        self._store, self._db, self._value, self._ledger = store, db, value, ledger

    def close(self):
        self._db = None

    def page(self, *, after_page=0):
        if self._db is None or not integer(after_page):
            fail('INVALID')
        value, store = self._value, self._store
        if after_page >= value['page_count'] and (value['page_count'] or after_page):
            fail('INVALID')
        row = self._db.execute('SELECT page_seq,first_item,item_count,previous_digest,digest,data,mac FROM rm_pages WHERE ref=? AND page_seq=?',
                               (value['ref'], after_page + 1)).fetchone()
        items = store._page_value(row, value['ref'])['items'] if row else []
        seq = after_page + 1 if row else 0
        return dict(items=items, page_seq=seq,
                    next_cursor=seq if seq < value['page_count'] else None,
                    manifest=store._head(value, self._ledger))
