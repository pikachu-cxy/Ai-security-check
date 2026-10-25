"""Bounded, signed baseline-publication control beside the original task head.

Only a fresh task INSERT may acquire an intent. This is not a review ledger,
host attestation, source recapture, or a grant to adopt an older task. Source
objects retain the original store quota; this module never deletes them.
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
import uuid

from ..closeout_state import digest, encode
from ..hook_state import no_links
from .ownership import record_owner, valid_owner
from .snapshot_page_guard import guard_held, page_guard

CONTRACT = 'task-baseline-capture-publication-v1'
STORAGE_CONTRACT = 'task-capture-publication-storage-v1'
MARKER_FIELD = 'capture_publication'
MARKER_SUFFIX = '.capture-publication.identity'
MAX_ACTIVE = 32
MAX_SLOTS = 64
MAX_ROW_BYTES = 8192
MAX_LOGICAL_BYTES = 2 * 1024 * 1024
HEADER_BYTES = 65536
TABLES = ('cp_registry', 'cp_owners', 'cp_intents', 'cp_receipts')
SCHEMA = (
    'CREATE TABLE cp_registry (slot INTEGER PRIMARY KEY, data BLOB NOT NULL, mac TEXT NOT NULL)',
    'CREATE TABLE cp_owners (task_ref TEXT PRIMARY KEY, data BLOB NOT NULL, mac TEXT NOT NULL)',
    'CREATE TABLE cp_intents (task_ref TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL, generation INTEGER NOT NULL, data BLOB NOT NULL, mac TEXT NOT NULL)',
    'CREATE TABLE cp_receipts (task_ref TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL, data BLOB NOT NULL, mac TEXT NOT NULL)',
)
TASK_SCHEMA = ('CREATE TABLE security_tasks (ref TEXT PRIMARY KEY, task_key TEXT NOT NULL, '
               'phase TEXT NOT NULL, created REAL NOT NULL, data TEXT NOT NULL, mac TEXT NOT NULL)')
_BUDGET = dict(active_slots=MAX_ACTIVE, total_slots=MAX_SLOTS, row_bytes=MAX_ROW_BYTES,
               logical_bytes=MAX_LOGICAL_BYTES)


class CapturePublicationError(ValueError):
    def __init__(self, suffix='HISTORY_UNAVAILABLE'):
        self.reason_code = 'CAPTURE_PUBLICATION_' + suffix
        super().__init__(self.reason_code)


def _fail(suffix='HISTORY_UNAVAILABLE'):
    raise CapturePublicationError(suffix)


def _hash(value):
    return hashlib.sha256(encode(value)).hexdigest()


def _hex(value, prefix, length):
    return isinstance(value, str) and re.fullmatch(re.escape(prefix) + '[a-f0-9]{' + str(length) + '}', value) is not None


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value <= 2**63 - 1


def _private(path, *, directory=False):
    no_links(path)
    info = path.lstat()
    if (os.name != 'posix' or info.st_uid != os.getuid()
            or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1) or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)):
        _fail('STATE_UNAVAILABLE')
    return info


def _base(state):
    no_links(state.root)
    root = state.root.lstat()
    if not stat.S_ISDIR(root.st_mode):
        _fail('STATE_UNAVAILABLE')
    _private(state.path.parent, directory=True)
    database = _private(state.path)
    key_path = state.path.parent / 'snapshot.key'
    if _private(key_path).st_size != 32:
        _fail('STATE_UNAVAILABLE')
    key = state.key()
    return dict(contract=STORAGE_CONTRACT, workspace=str(state.root),
        root_identity=[root.st_dev, root.st_ino], database_identity=[database.st_dev, database.st_ino],
        key_digest=hashlib.sha256(key).hexdigest(), budget=dict(_BUDGET))


def _mac(state, kind, value, identity=None):
    return hmac.new(state.key(), encode(dict(domain=STORAGE_CONTRACT, kind=kind,
        identity=identity, value=value)), hashlib.sha256).hexdigest()


def _decode(state, kind, raw, mac, identity):
    try:
        if not isinstance(raw, bytes) or len(raw) > MAX_ROW_BYTES or not isinstance(mac, str) or len(mac) != 64:
            _fail()
        value = json.loads(raw)
        if not isinstance(value, dict) or encode(value) != raw or not hmac.compare_digest(mac, _mac(state, kind, value, identity)):
            _fail()
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _fail()


def _marker_path(state):
    return state.path.with_name(state.path.name + MARKER_SUFFIX)


def _read_marker(state, path=None):
    path = path or _marker_path(state)
    before = _private(path)
    if before.st_size > MAX_ROW_BYTES:
        _fail()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0))
    try:
        pinned = os.fstat(fd)
        if (pinned.st_dev, pinned.st_ino) != (before.st_dev, before.st_ino):
            _fail()
        raw = os.read(fd, MAX_ROW_BYTES + 1)
        after = _private(path)
        if (after.st_dev, after.st_ino) != (pinned.st_dev, pinned.st_ino) or len(raw) != before.st_size:
            _fail()
        packet = json.loads(raw)
        if (not isinstance(packet, dict) or set(packet) != {'payload', 'mac'}
                or not isinstance(packet['payload'], dict) or set(packet['payload']) != {'state', 'identity'}
                or packet['payload']['state'] not in {'ALLOCATING', 'READY'}
                or not isinstance(packet['mac'], str) or encode(packet) != raw
                or not hmac.compare_digest(packet['mac'], _mac(state, 'allocation', packet['payload']))):
            _fail()
        identity = packet['payload']['identity']
        expected = _base(state)
        if (not isinstance(identity, dict) or set(identity) != {*expected, 'allocation_id'}
                or not _hex(identity.get('allocation_id'), '', 32)
                or any(identity.get(key) != value for key, value in expected.items())):
            _fail()
        return packet['payload']
    except (ValueError, TypeError, OSError, UnicodeError, RecursionError):
        _fail()
    finally:
        os.close(fd)


def _publish_marker(state, payload):
    """One fixed staging name; an unrecognizable interrupted stage is not erased."""
    destination = _marker_path(state)
    stage = destination.with_name(destination.name + '.next')
    packet = dict(payload=payload, mac=_mac(state, 'allocation', payload))
    raw = encode(packet)
    if stage.exists():
        previous = _read_marker(state, stage)
        if previous != payload:
            _fail()
    else:
        fd = os.open(stage, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    os.replace(stage, destination)
    parent = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _objects(db):
    return list(db.execute("SELECT type,CASE WHEN length(name)<=128 THEN name END,"
                           "CASE WHEN length(tbl_name)<=128 THEN tbl_name END,CASE WHEN length(sql)<=65536 THEN sql END "
                           "FROM sqlite_master WHERE name GLOB 'cp_*' OR tbl_name GLOB 'cp_*' LIMIT 17"))


def _schema(db):
    expected = dict(zip(TABLES, SCHEMA))
    indexes = {'sqlite_autoindex_cp_owners_1', 'sqlite_autoindex_cp_intents_1',
               'sqlite_autoindex_cp_intents_2', 'sqlite_autoindex_cp_receipts_1', 'sqlite_autoindex_cp_receipts_2'}
    seen, found = set(), set()
    for kind, name, table, sql in _objects(db):
        if kind == 'table' and name == table and table in expected and sql == expected[table]:
            seen.add(table)
        elif kind == 'index' and name in indexes and sql is None and table in expected:
            found.add(name)
        else:
            _fail()
    if seen != set(TABLES) or found != indexes:
        _fail()


def _task_schema(db, *, create=False):
    rows = list(db.execute("SELECT type,name,CASE WHEN length(sql)<=65536 THEN sql END "
                           "FROM sqlite_master WHERE tbl_name='security_tasks' LIMIT 4"))
    if not rows and create:
        db.execute(TASK_SCHEMA)
        rows = list(db.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name='security_tasks'"))
    if (len(rows) != 2 or ('table', 'security_tasks', TASK_SCHEMA) not in rows
            or ('index', 'sqlite_autoindex_security_tasks_1', None) not in rows):
        _fail()


def _transaction_owner(state, db, *, allocated=True):
    if (allocated and not guard_held(state.path.parent)) or not db.in_transaction:
        _fail('TRANSACTION_REQUIRED')
    database = next((row[2] for row in db.execute('PRAGMA database_list') if row[1] == 'main'), None)
    if database is None or Path(database).absolute() != state.path.absolute():
        _fail('TRANSACTION_REQUIRED')
    no_links(state.path)
    if allocated:
        _base(state)


def _rows(state, db, table, identity):
    columns = "CASE WHEN typeof(task_ref)='text' AND length(CAST(task_ref AS BLOB))=36 THEN task_ref END,"
    request = "CASE WHEN typeof(request_id)='text' AND length(CAST(request_id AS BLOB))=68 THEN request_id END,"
    if table in {'cp_intents', 'cp_receipts'}:
        columns += request
    if table == 'cp_intents':
        columns += "CASE WHEN typeof(generation)='integer' AND generation>=1 THEN generation END,"
    for row in db.execute(f'SELECT {columns}CASE WHEN typeof(data)=\'blob\' AND length(data)<=? THEN data END,'
                          f"CASE WHEN typeof(mac)='text' AND length(mac)=64 THEN mac END "
                          f'FROM {table} ORDER BY task_ref COLLATE BINARY LIMIT ?', (MAX_ROW_BYTES, MAX_SLOTS + 1)):
        value = _decode(state, table, row[-2], row[-1], identity)
        if not _hex(row[0], 'ts1-', 32) or value.get('task_ref') != row[0]:
            _fail()
        if table != 'cp_owners' and (row[1] != value.get('request_id') or not _hex(row[1], 'cp1-', 64)):
            _fail()
        if table == 'cp_intents' and (row[2] != value.get('generation') or not _integer(row[2], 1)):
            _fail()
        yield row, value


def _statistics(state, db, identity):
    counts, logical, inventory = {}, HEADER_BYTES, hashlib.sha256()
    for table in TABLES[1:]:
        count = 0
        for row, value in _rows(state, db, table, identity):
            count += 1
            if count > MAX_SLOTS:
                _fail('WAITING_CAPACITY')
            logical += len(row[-2]) + len(row[-1]) + sum(len(str(item).encode()) for item in row[:-2]) + 160
            inventory.update(encode([table, *row[:-2], hashlib.sha256(row[-2]).hexdigest(), row[-1]]))
        counts[table] = count
    if logical > MAX_LOGICAL_BYTES:
        _fail('WAITING_CAPACITY')
    return dict(counts=counts, logical_bytes=logical, inventory_digest=inventory.hexdigest())


def _put(state, db, table, value, identity):
    raw = encode(value)
    if len(raw) > MAX_ROW_BYTES:
        _fail('WAITING_CAPACITY')
    mac = _mac(state, table, value, identity)
    if table == 'cp_owners':
        db.execute('INSERT OR REPLACE INTO cp_owners VALUES(?,?,?)', (value['task_ref'], raw, mac))
    elif table == 'cp_intents':
        db.execute('INSERT OR REPLACE INTO cp_intents VALUES(?,?,?,?,?)',
                   (value['task_ref'], value['request_id'], value['generation'], raw, mac))
    elif table == 'cp_receipts':
        db.execute('INSERT OR REPLACE INTO cp_receipts VALUES(?,?,?,?)',
                   (value['task_ref'], value['request_id'], raw, mac))
    else:
        _fail()


def _write_registry(state, db, identity, generation):
    value = dict(identity=identity, generation=generation, **_statistics(state, db, identity))
    db.execute('INSERT OR REPLACE INTO cp_registry VALUES(1,?,?)',
               (encode(value), _mac(state, 'registry', value, identity)))


def _registry(state, db, identity):
    row = db.execute("SELECT slot,CASE WHEN typeof(data)='blob' AND length(data)<=? THEN data END,"
                     "CASE WHEN typeof(mac)='text' AND length(mac)=64 THEN mac END FROM cp_registry LIMIT 2",
                     (MAX_ROW_BYTES,)).fetchall()
    if len(row) != 1 or row[0][0] != 1:
        _fail()
    value = _decode(state, 'registry', row[0][1], row[0][2], identity)
    if (set(value) != {'identity', 'generation', 'counts', 'logical_bytes', 'inventory_digest'}
            or value['identity'] != identity or not _integer(value['generation'], 1)
            or any(value.get(key) != item for key, item in _statistics(state, db, identity).items())):
        _fail()
    return value


def _raw_witness(state):
    from .snapshot_pages import _store
    store = _store(state)
    # Neither constructor nor this absent case initializes the raw store.
    if not store.path.exists() and not store.marker.exists():
        return False
    return store.has_retention_domain('TASK_CAPTURE_SOURCE_V2')


def prepare_storage(state):
    """Explicit writer allocation, before the caller's task BEGIN/GC.

    ALLOCATING plus no tables is a retryable first-allocation rollback. READY
    never permits recreation. No task/owner may exist until READY is durable.
    """
    try:
        _base(state)
        if guard_held(state.path.parent):
            # A direct _save can already hold the shared page fence. It must
            # never upgrade that lock or allocate inside its task transaction.
            if not _marker_path(state).exists() or _read_marker(state)['state'] != 'READY':
                _fail('WAITING_STORAGE')
            with _db(state) as db:
                validate_inventory(state, db=db)
            return dict(state='READY', budget=dict(_BUDGET))
        with page_guard(state.path.parent, exclusive=True, create=True):
            path = _marker_path(state)
            marker = _read_marker(state) if path.exists() else None
            stage = path.with_name(path.name + '.next')
            staged = _read_marker(state, stage) if stage.exists() else None
            if marker is None and staged is not None:
                if staged['state'] != 'ALLOCATING':
                    _fail()
                marker = staged
            elif marker is not None and marker['state'] == 'READY' and staged is not None:
                _fail()
            with closing(sqlite3.connect(state.path, timeout=2, isolation_level=None)) as db:
                db.execute('PRAGMA trusted_schema=OFF')
                if db.execute('PRAGMA journal_mode').fetchone()[0].lower() != 'delete':
                    _fail('STATE_UNAVAILABLE')
                db.execute('PRAGMA synchronous=FULL')
                db.execute('BEGIN IMMEDIATE')
                objects = _objects(db)
                if marker is None and not objects and _raw_witness(state):
                    _fail()
                _task_schema(db, create=not objects and (marker is None or marker['state'] == 'ALLOCATING'))
                if marker is None:
                    if objects or _raw_witness(state):
                        _fail()
                    # A missing allocation cannot adopt a previously marked head.
                    _heads(state, db, check=lambda head: _fail() if MARKER_FIELD in head
                           or 'capture_source' in head.get('baseline', {}) else None)
                    identity = dict(_base(state), allocation_id=uuid.uuid4().hex)
                    marker = dict(state='ALLOCATING', identity=identity)
                    _publish_marker(state, marker)
                identity = marker['identity']
                if marker['state'] == 'ALLOCATING':
                    if _raw_witness(state):
                        _fail()
                    _heads(state, db, check=lambda head: _fail() if MARKER_FIELD in head
                           or 'capture_source' in head.get('baseline', {}) else None)
                    if not path.exists():
                        if objects:
                            _fail()
                        _heads(state, db, check=lambda head: _fail() if MARKER_FIELD in head
                               or 'capture_source' in head.get('baseline', {}) else None)
                        _publish_marker(state, marker)
                    if not objects:
                        for statement in SCHEMA:
                            db.execute(statement)
                        _write_registry(state, db, identity, 1)
                    else:
                        _schema(db)
                        registry = _registry(state, db, identity)
                        if any(registry['counts'].values()):
                            _fail()
                    db.commit()
                    _publish_marker(state, dict(state='READY', identity=identity))
                else:
                    _schema(db)
                    _registry(state, db, identity)
                    db.commit()
        return dict(state='READY', budget=dict(_BUDGET))
    except CapturePublicationError:
        raise
    except sqlite3.Error as error:
        _sql_error(error)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        _fail('STATE_UNAVAILABLE')


def _heads(state, db, *, check):
    from .security_state import MAX_HISTORY_RECORDS, MAX_RECORD_BYTES
    count = 0
    for row in db.execute("SELECT CASE WHEN typeof(ref)='text' AND length(CAST(ref AS BLOB))=36 THEN ref END,"
            "CASE WHEN typeof(task_key)='text' AND length(CAST(task_key AS BLOB))<=1024 THEN task_key END,"
            "CASE WHEN typeof(phase)='text' AND length(CAST(phase AS BLOB))<=32 THEN phase END,"
            "CASE WHEN typeof(created) IN ('integer','real') THEN created END,CASE WHEN typeof(data)='text' AND "
            'length(CAST(data AS BLOB))<=? THEN data END, '
            "CASE WHEN typeof(mac)='text' AND length(mac)=64 THEN mac END FROM security_tasks ORDER BY ref LIMIT ?",
            (MAX_RECORD_BYTES, MAX_HISTORY_RECORDS + 1)):
        count += 1
        if count > MAX_HISTORY_RECORDS:
            _fail('WAITING_CAPACITY')
        try:
            head = state.retention_head(row[4:])
            if not head or row[:4] != tuple(head.get(key) for key in ('task_ref', 'task_key', 'phase', 'created_at')):
                _fail()
            check(head)
        except CapturePublicationError:
            raise
        except (ValueError, TypeError, KeyError, AttributeError):
            _fail()


def _marker(state, owner, identity):
    payload = dict(contract=CONTRACT, task_ref=owner['task_ref'], request_id=owner['request_id'],
                   identity_digest=_hash({key: owner[key] for key in _OWNER_BASIS}))
    return dict(payload=payload, mac=_mac(state, 'parent-marker', payload, identity))


_OWNER_BASIS = ('task_ref', 'owner', 'field', 'capture_ref', 'representation_version',
                'donor', 'donor_header', 'context_digest', 'baseline_digest', 'created_at', 'request_id')


def _baseline_digest(head):
    baseline = dict(head['baseline'])
    baseline.pop('capture_source', None)
    if 'paged_entries' in baseline:
        from .snapshot_pages import MAPS, LISTS
        for name in (*MAPS, *LISTS):
            baseline.pop(name, None)
    return _hash(baseline)


def _matches(state, head, owner, identity):
    from .capture_source_profile import POLICY, PROFILE, PROFILE_FIELD
    from .frozen_body_context import CONTEXT_FIELD
    if (head.get('capture_policy') != POLICY or head.get(PROFILE_FIELD) != PROFILE
            or head.get('task_ref') != owner['task_ref'] or record_owner(head) != owner['owner']
            or not _integer(head.get('generation'), 1)
            or head.get('created_at') != owner['created_at']
            or _baseline_digest(head) != owner['baseline_digest']
            or _hash(head['baseline'].get(CONTEXT_FIELD)) != owner['context_digest']
            or head['baseline'].get('paged_entries') != owner['donor']
            or head['baseline'].get('redaction_version') != owner['representation_version']
            or head.get(MARKER_FIELD) != _marker(state, owner, identity)):
        _fail()


def _read_inventory(state, db):
    _transaction_owner(state, db, allocated=False)
    objects, path = _objects(db), _marker_path(state)
    stage = path.with_name(path.name + '.next')
    if not objects and not path.exists() and not stage.exists():
        _task_schema(db)
        if _raw_witness(state):
            _fail()
        _heads(state, db, check=lambda head: _fail() if MARKER_FIELD in head
               or 'capture_source' in head.get('baseline', {}) else None)
        return None
    _transaction_owner(state, db)
    if not path.exists() and stage.exists() and not objects:
        if _read_marker(state, stage)['state'] == 'ALLOCATING':
            _fail('WAITING_STORAGE')
        _fail()
    marker = _read_marker(state)
    if marker['state'] != 'READY':
        _fail('WAITING_STORAGE')
    if stage.exists():
        _fail()
    _task_schema(db)
    identity = marker['identity']
    _schema(db)
    registry = _registry(state, db, identity)
    owners = {row[0]: value for row, value in _rows(state, db, 'cp_owners', identity)}
    intents = {row[0]: value for row, value in _rows(state, db, 'cp_intents', identity)}
    receipts = {row[0]: value for row, value in _rows(state, db, 'cp_receipts', identity)}
    if owners.keys() != intents.keys() or not receipts.keys() <= owners.keys():
        _fail()
    active = set()
    from ..task_review.capture_source_binding import CaptureSourceBinding, validate_descriptor
    for ref, owner in owners.items():
        intent, receipt = intents[ref], receipts.get(ref)
        if (set(owner) != {*_OWNER_BASIS, 'state', 'retired_at'}
                or not valid_owner(owner.get('owner')) or owner.get('field') != 'baseline'
                or owner.get('capture_ref') != ref or not _integer(owner.get('representation_version'), 1)
                or owner['representation_version'] > 255 or owner.get('state') not in {'ACTIVE', 'RETIRED'}
                or not isinstance(owner.get('donor'), dict) or set(owner['donor']) != {'ref', 'source'}
                or not _hex(owner['donor'].get('ref'), 'ws2-', 32) or not _hex(owner['donor'].get('source'), '', 64)
                or not isinstance(owner.get('donor_header'), dict)
                or set(owner['donor_header']) != {'root_digest', 'entry_count', 'source_bytes'}
                or not _hex(owner['donor_header'].get('root_digest'), '', 64)
                or not _integer(owner['donor_header'].get('entry_count'))
                or not _integer(owner['donor_header'].get('source_bytes'))
                or not all(_hex(owner.get(name), '', 64) for name in ('context_digest', 'baseline_digest'))
                or type(owner.get('created_at')) not in {int, float} or not math.isfinite(owner['created_at']) or owner['created_at'] < 0
                or not _hex(owner.get('request_id'), 'cp1-', 64)
                or intent.get('request_id') != owner['request_id']
                or set(intent) != {'task_ref', 'request_id', 'generation', 'state', 'target_ref', 'progress'}
                or intent.get('state') not in {'RESERVED', 'COPYING', 'PUBLISHED', 'RETIRED'}
                or (intent.get('target_ref') is not None and not _hex(intent['target_ref'], 'ws2-', 32))
                or (intent['state'] == 'RESERVED' and intent['target_ref'] is not None)
                or (intent['state'] in {'COPYING', 'PUBLISHED'} and intent['target_ref'] is None)
                or not isinstance(intent.get('progress'), (dict, type(None)))):
            _fail()
        progress = intent['progress']
        if progress is not None and (set(progress) != {'state', 'cursor', 'entry_count', 'source_bytes', 'root_digest'}
                or progress.get('state') not in {'CAPTURING', 'WAITING_CAPACITY', 'SEALED'}
                or not _integer(progress.get('entry_count')) or not _integer(progress.get('source_bytes'))
                or not _hex(progress.get('root_digest'), '', 64)
                or progress.get('cursor') is not None and (not isinstance(progress['cursor'], str)
                    or len(progress['cursor'].encode()) > 8192)):
            _fail()
        if intent['state'] in {'COPYING', 'PUBLISHED'} and progress is None:
            _fail()
        if owner['state'] == 'RETIRED':
            if (intent['state'] != 'RETIRED' or type(owner['retired_at']) not in {int, float}
                    or not math.isfinite(owner['retired_at']) or owner['retired_at'] < owner['created_at']):
                _fail()
        elif intent['state'] == 'RETIRED' or owner['retired_at'] is not None:
            _fail()
        else:
            active.add(ref)
        request_basis = {key: owner[key] for key in _OWNER_BASIS if key != 'request_id'}
        if owner['request_id'] != 'cp1-' + _mac(state, 'request', request_basis, identity):
            _fail()
        if (intent['state'] == 'PUBLISHED') != (receipt is not None) and owner['state'] != 'RETIRED':
            _fail()
        if receipt is not None:
            if (set(receipt) != {'contract', 'task_ref', 'request_id', 'state', 'publication_generation', 'descriptor'}
                    or receipt.get('contract') != CONTRACT or receipt.get('state') != 'PUBLISHED'
                    or receipt.get('request_id') != owner['request_id']
                    or not _integer(receipt.get('publication_generation'), 1)):
                _fail()
            binding = CaptureSourceBinding(ref, owner['owner'], 'baseline', ref, owner['representation_version'])
            try:
                descriptor = validate_descriptor(binding, receipt['descriptor'])
            except ValueError:
                _fail()
            if descriptor['ref'] != intent['target_ref'] or descriptor['source'] != owner['donor']['source']:
                _fail()
    if len(active) > MAX_ACTIVE:
        _fail('WAITING_CAPACITY')
    seen = set()
    def check(head):
        ref = head['task_ref']
        if ref in owners:
            if owners[ref]['state'] != 'ACTIVE':
                _fail()
            _matches(state, head, owners[ref], identity)
            receipt = receipts.get(ref)
            descriptor = head['baseline'].get('capture_source')
            if receipt is None and descriptor is not None:
                _fail()
            if receipt is not None and (receipt['descriptor'] != {'capture_source': descriptor}
                    or receipt['publication_generation'] > head.get('generation', 0)):
                _fail()
            seen.add(ref)
        elif MARKER_FIELD in head or 'capture_source' in head.get('baseline', {}):
            _fail()
    _heads(state, db, check=check)
    if seen != active:
        _fail()
    return dict(identity=identity, registry=registry, owners=owners, intents=intents, receipts=receipts)


def validate_inventory(state, *, db):
    """Complete both directions before authorizing any source/control deletion."""
    try:
        inventory = _read_inventory(state, db)
        if inventory is None:
            return dict(allocated=False, active_count=0, total_count=0)
        return dict(allocated=True, generation=inventory['registry']['generation'],
            active_count=sum(owner['state'] == 'ACTIVE' for owner in inventory['owners'].values()),
            total_count=len(inventory['owners']))
    except CapturePublicationError:
        raise
    except sqlite3.Error as error:
        _sql_error(error)
    except (OSError, ValueError, TypeError, KeyError, RecursionError, AttributeError):
        _fail()


def birth_in_transaction(state, db, packed_head, value):
    """Register beside the caller's fresh generation-one head INSERT.

    The caller must INSERT the returned packed head in this same transaction.
    Rolling back that INSERT rolls back owner, intent and registry as well.
    """
    from .capture_source_profile import POLICY, PROFILE, PROFILE_FIELD
    from .frozen_body_context import CONTEXT_FIELD, verify_context
    try:
        inventory = _read_inventory(state, db)
        if inventory is None:
            _fail('WAITING_STORAGE')
        if (not isinstance(value, dict) or not isinstance(packed_head, dict)
                or type(packed_head.get('generation')) is not int or packed_head['generation'] != 1
                or type(value.get('generation')) is not int or value['generation'] != 1
                or type(packed_head.get('created_at')) not in {int, float}
                or not math.isfinite(packed_head['created_at']) or packed_head['created_at'] < 0
                or packed_head.get('capture_policy') != POLICY or packed_head.get(PROFILE_FIELD) != PROFILE
                or packed_head.get('task_ref') != value.get('task_ref') or record_owner(packed_head) != record_owner(value)
                or encode({key: item for key, item in packed_head.items() if key != 'baseline'})
                    != encode({key: item for key, item in value.items() if key != 'baseline'})
                or MARKER_FIELD in packed_head or MARKER_FIELD in value
                or 'capture_source' in packed_head.get('baseline', {}) or 'capture_source' in value.get('baseline', {})):
            _fail('INVALID')
        ref, owner = packed_head['task_ref'], record_owner(packed_head)
        if not _hex(ref, 'ts1-', 32) or not valid_owner(owner):
            _fail('INVALID')
        if db.execute('SELECT 1 FROM security_tasks WHERE ref=?', (ref,)).fetchone() or ref in inventory['owners']:
            _fail('ALREADY_EXISTS')
        if len(inventory['owners']) >= MAX_SLOTS or sum(v['state'] == 'ACTIVE' for v in inventory['owners'].values()) >= MAX_ACTIVE:
            _fail('WAITING_CAPACITY')
        baseline = packed_head['baseline']
        if baseline.get(CONTEXT_FIELD) != value.get('baseline', {}).get(CONTEXT_FIELD):
            _fail('INVALID')
        pointer = baseline.get('paged_entries')
        if not isinstance(pointer, dict) or set(pointer) != {'ref', 'source'} or not _hex(pointer.get('ref'), 'ws2-', 32) or not _hex(pointer.get('source'), '', 64):
            _fail('INVALID')
        context = verify_context(state.hooks, state.root, baseline[CONTEXT_FIELD], task_ref=ref, owner=owner, now=state.now)
        if context['source'] != pointer['source'] or context['representation_version'] != baseline['redaction_version']:
            _fail('INVALID')
        from .snapshot_pages import _binding, _store
        donor = _store(state).strict_header(pointer['ref'], _binding(packed_head, 'baseline', pointer['source']))
        if donor['state'] != 'SEALED' or donor['coverage_complete'] is not True:
            _fail('SOURCE_UNAVAILABLE')
        basis = dict(task_ref=ref, owner=dict(owner), field='baseline', capture_ref=ref,
            representation_version=baseline['redaction_version'], donor=dict(pointer),
            donor_header={key: donor[key] for key in ('root_digest', 'entry_count', 'source_bytes')},
            context_digest=_hash(baseline[CONTEXT_FIELD]), baseline_digest=_baseline_digest(packed_head),
            created_at=packed_head['created_at'])
        request_id = 'cp1-' + _mac(state, 'request', basis, inventory['identity'])
        registration = dict(basis, request_id=request_id, state='ACTIVE', retired_at=None)
        marker = _marker(state, registration, inventory['identity'])
        intent = dict(task_ref=ref, request_id=request_id, generation=1, state='RESERVED', target_ref=None, progress=None)
        _put(state, db, 'cp_owners', registration, inventory['identity'])
        _put(state, db, 'cp_intents', intent, inventory['identity'])
        _write_registry(state, db, inventory['identity'], inventory['registry']['generation'] + 1)
        return dict(packed_head, **{MARKER_FIELD: marker}), dict(value, **{MARKER_FIELD: json.loads(encode(marker))})
    except CapturePublicationError:
        raise
    except sqlite3.Error as error:
        _sql_error(error)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        _fail('INVALID')


def validate_transition(old, value, *, new):
    """Ordinary task saves cannot acquire or change publication authority."""
    try:
        current = ((MARKER_FIELD in value, value.get(MARKER_FIELD)),
                   ('capture_source' in value.get('baseline', {}), value.get('baseline', {}).get('capture_source')))
        if new:
            if current[0][0] or current[1][0]:
                _fail('INVALID')
            return
        previous = ((MARKER_FIELD in old, old.get(MARKER_FIELD)),
                    ('capture_source' in old.get('baseline', {}), old.get('baseline', {}).get('capture_source')))
        if encode(current) != encode(previous):
            _fail('INVALID_TRANSITION')
    except CapturePublicationError:
        raise
    except (ValueError, TypeError, AttributeError):
        _fail('INVALID')


def _sql_error(error):
    code = getattr(error, 'sqlite_errorcode', 0) & 255
    _fail('BUSY' if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED} else
          'WAITING_CAPACITY' if code == sqlite3.SQLITE_FULL else 'STATE_UNAVAILABLE')


@contextmanager
def _db(state, *, write=False):
    caller_failed = False
    try:
        _base(state)
        with page_guard(state.path.parent):
            if not write:
                from .frozen_body_context import readonly_database
                from .security_state import MAX_RECORD_BYTES
                with readonly_database(state.path, maximum=MAX_RECORD_BYTES) as db:
                    yield db
                return
            with closing(sqlite3.connect(state.path.as_uri() + ('?mode=rw' if write else '?mode=ro'),
                                         uri=True, timeout=2, isolation_level=None)) as db:
                db.execute('PRAGMA locking_mode=EXCLUSIVE') if not write else None
                db.execute('PRAGMA trusted_schema=OFF')
                if db.execute('PRAGMA journal_mode').fetchone()[0].lower() != 'delete':
                    _fail('STATE_UNAVAILABLE')
                db.execute('PRAGMA secure_delete=ON') if write else db.execute('PRAGMA query_only=ON')
                db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
                try:
                    yield db
                except BaseException:
                    caller_failed = True
                    db.rollback()
                    raise
                else:
                    _read_marker(state)
                    db.commit() if write else db.rollback()
    except CapturePublicationError:
        raise
    except sqlite3.Error as error:
        _sql_error(error)
    except (OSError, ValueError, TypeError):
        if caller_failed:
            raise
        _fail('STATE_UNAVAILABLE')


def _current(state, db, task_ref, owner, request_id=None):
    if not _hex(task_ref, 'ts1-', 32) or not valid_owner(owner):
        _fail('INVALID')
    inventory = _read_inventory(state, db)
    if inventory is None or task_ref not in inventory['owners']:
        _fail('UNAVAILABLE')
    registration, intent = inventory['owners'][task_ref], inventory['intents'][task_ref]
    if registration['owner'] != owner:
        _fail('OWNER_MISMATCH')
    if registration['state'] != 'ACTIVE':
        _fail('RETIRED')
    if request_id is not None and request_id != intent['request_id']:
        _fail('REQUEST_CONFLICT')
    from .security_state import MAX_RECORD_BYTES
    row = db.execute("SELECT CASE WHEN typeof(data)='text' AND length(CAST(data AS BLOB))<=? THEN data END,"
                     "CASE WHEN typeof(mac)='text' AND length(mac)=64 THEN mac END FROM security_tasks WHERE ref=?",
                     (MAX_RECORD_BYTES, task_ref)).fetchone()
    head = state.head(row)
    if head is None or _expired_readonly(state, head):
        _fail('UNAVAILABLE')
    return inventory, registration, intent, head


def _expired_readonly(state, head):
    """Original lifecycle formula, with no journal recovery/WAL side effects."""
    from .activity import ActivityStore, deferred, HARD_TTL, IDLE_TTL
    from .frozen_body_context import readonly_database, FrozenBodyContextUnavailable
    from .security_state import TTL
    try:
        if not deferred(head):
            return state.now() > head['created_at'] + TTL
        activity = ActivityStore(state.hooks, state.root, now=state.now)
        activity._paths()
        summary = {}
        if activity.path.exists():
            with readonly_database(activity.path, maximum=160000) as db:
                summary = activity._get(db, 'task:' + head['task_ref']) or {}
        last = max(head['created_at'], head.get('activity_at', 0), summary.get('last_activity', 0))
        return state.now() > min(head['created_at'] + HARD_TTL, last + IDLE_TTL)
    except FrozenBodyContextUnavailable as error:
        _fail('BUSY' if error.reason_code.endswith('_BUSY') else 'STATE_UNAVAILABLE')
    except sqlite3.Error as error:
        _sql_error(error)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        _fail('STATE_UNAVAILABLE')


def _status(inventory, owner, intent, head):
    return json.loads(encode(dict(task_ref=owner['task_ref'], request_id=owner['request_id'],
        state=intent['state'], intent_generation=intent['generation'], task_generation=head['generation'],
        head_generation=head['generation'], intent=intent,
        donor=owner['donor'], source=owner['donor']['source'], target_ref=intent['target_ref'],
        donor_header=owner['donor_header'],
        progress=intent['progress'], representation_version=owner['representation_version'],
        receipt=inventory['receipts'].get(owner['task_ref']))))


def status(state, task_ref, *, owner):
    with _db(state) as db:
        return _status(*_current(state, db, task_ref, owner))


def _target(state, owner, ref, previous=None):
    from ..task_review.capture_source_binding import CaptureSourceBinding, raw_source_binding
    from .snapshot_pages import _store
    binding = CaptureSourceBinding(owner['task_ref'], owner['owner'], 'baseline', owner['task_ref'], owner['representation_version'])
    header = _store(state).strict_header(ref, raw_source_binding(binding, owner['donor']['source']))
    if header.get('state') not in {'CAPTURING', 'WAITING_CAPACITY', 'SEALED'}:
        _fail()
    current = {key: header[key] for key in ('state', 'cursor', 'entry_count', 'source_bytes', 'root_digest')}
    anchor = owner['donor_header']
    if (current['entry_count'] > anchor['entry_count'] or current['source_bytes'] > anchor['source_bytes']
            or current['state'] == 'SEALED' and (current['entry_count'] != anchor['entry_count']
                or current['source_bytes'] != anchor['source_bytes'] or header['coverage_complete'] is not True)):
        _fail('PROGRESS_CONFLICT')
    if previous is not None:
        delta = current['entry_count'] - previous['entry_count']
        byte_delta = current['source_bytes'] - previous['source_bytes']
        budget = _store(state).batch_budget
        if (delta < 0 or byte_delta < 0 or delta > budget.files or byte_delta > budget.bytes
                or previous['state'] == 'SEALED' and current['state'] != 'SEALED'
                or delta == 0 and any(current[key] != previous[key]
                    for key in ('cursor', 'source_bytes', 'root_digest'))):
            _fail('PROGRESS_CONFLICT')
    return current


def admit_target(state, task_ref, *, owner, request_id, expected_intent_generation, target_ref):
    if not _hex(target_ref, 'ws2-', 32) or not _integer(expected_intent_generation, 1):
        _fail('INVALID')
    with _db(state, write=True) as db:
        inventory, registration, intent, head = _current(state, db, task_ref, owner, request_id)
        if intent['target_ref'] is not None:
            if intent['target_ref'] != target_ref:
                _fail('REQUEST_CONFLICT')
            return _status(inventory, registration, intent, head)
        if intent['generation'] != expected_intent_generation:
            _fail('CAS_CONFLICT')
        progress = _target(state, registration, target_ref)
        intent = dict(intent, state='COPYING', target_ref=target_ref, progress=progress, generation=intent['generation'] + 1)
        _put(state, db, 'cp_intents', intent, inventory['identity'])
        _write_registry(state, db, inventory['identity'], inventory['registry']['generation'] + 1)
        return _status(inventory, registration, intent, head)


def checkpoint(state, task_ref, *, owner, request_id, expected_intent_generation):
    if not _integer(expected_intent_generation, 1):
        _fail('INVALID')
    with _db(state, write=True) as db:
        inventory, registration, intent, head = _current(state, db, task_ref, owner, request_id)
        if intent['state'] == 'PUBLISHED':
            return _status(inventory, registration, intent, head)
        if intent['generation'] != expected_intent_generation:
            _fail('CAS_CONFLICT')
        if intent['target_ref'] is None:
            _fail('UNAVAILABLE')
        progress = _target(state, registration, intent['target_ref'], intent['progress'])
        if progress != intent['progress']:
            intent = dict(intent, progress=progress, generation=intent['generation'] + 1)
            _put(state, db, 'cp_intents', intent, inventory['identity'])
            _write_registry(state, db, inventory['identity'], inventory['registry']['generation'] + 1)
        return _status(inventory, registration, intent, head)


def finalize(state, task_ref, *, owner, request_id, expected_generation, expected_intent_generation, verified_view):
    """Publish only an active canonical view, retaining its raw SQL snapshot.

    Original task fields, activity times, leases, raw-body TTLs and ledgers are
    copied verbatim. Only the locator and original head generation are changed.
    """
    from ..task_review.capture_source_binding import source_descriptor, CaptureSourceBinding
    from ..task_review.snapshot_source import CaptureCanonicalView
    from .snapshot_pages import _store
    if (type(verified_view) is not CaptureCanonicalView or not _integer(expected_generation, 1)
            or not _integer(expected_intent_generation, 1)
            or verified_view.store.path.absolute() != _store(state).path.absolute()):
        _fail('VERIFICATION_REQUIRED')
    with _db(state, write=True) as db:
        inventory, registration, intent, head = _current(state, db, task_ref, owner, request_id)
        if intent['state'] == 'PUBLISHED':
            return json.loads(encode(inventory['receipts'][task_ref]))
        if head.get('generation') != expected_generation or intent['generation'] != expected_intent_generation:
            _fail('CAS_CONFLICT')
        scope, summary = verified_view.scope, verified_view.summary
        expected = dict(task_ref=task_ref, owner=owner, field='baseline', capture_ref=task_ref,
            representation_version=registration['representation_version'],
            workspace=str(state.root), root_identity=inventory['identity']['root_identity'],
            ref=intent['target_ref'], source=registration['donor']['source'], source_domain='TASK_CAPTURE_SOURCE_V2')
        if scope != expected or summary.get('state') != 'VERIFIED' or summary.get('source_digest_verified') is not True:
            _fail('VERIFICATION_REQUIRED')
        binding = CaptureSourceBinding(task_ref, owner, 'baseline', task_ref, registration['representation_version'])
        descriptor = source_descriptor(binding, scope['ref'], scope['source'])
        value = dict(head, generation=head['generation'] + 1,
                     baseline=dict(head['baseline'], **descriptor))
        raw = encode(value)
        from .security_state import MAX_RECORD_BYTES
        if len(raw) > MAX_RECORD_BYTES:
            _fail('WAITING_CAPACITY')
        changed = db.execute('UPDATE security_tasks SET data=?,mac=? WHERE ref=? AND data=? AND mac=?',
            (raw.decode(), digest(state.key(), value), task_ref, encode(head).decode(), digest(state.key(), head)))
        if changed.rowcount != 1:
            _fail('CAS_CONFLICT')
        progress = _target(state, registration, intent['target_ref'], intent['progress'])
        if progress['state'] != 'SEALED':
            _fail('VERIFICATION_REQUIRED')
        intent = dict(intent, state='PUBLISHED', progress=progress, generation=intent['generation'] + 1)
        receipt = dict(contract=CONTRACT, task_ref=task_ref, request_id=request_id, state='PUBLISHED',
                       publication_generation=value['generation'], descriptor=descriptor)
        _put(state, db, 'cp_intents', intent, inventory['identity'])
        _put(state, db, 'cp_receipts', receipt, inventory['identity'])
        _write_registry(state, db, inventory['identity'], inventory['registry']['generation'] + 1)
        return json.loads(encode(receipt))


def replay_receipt(state, task_ref, *, owner, request_id):
    with _db(state) as db:
        inventory, registration, intent, head = _current(state, db, task_ref, owner, request_id)
        return json.loads(encode(inventory['receipts'].get(task_ref)))


def iter_source_pins(state, *, db):
    """Validate the whole control inventory before yielding any bounded pins."""
    inventory = _read_inventory(state, db)
    if inventory is None:
        return
    from .snapshot_pages import _binding
    from ..task_review.capture_source_binding import CaptureSourceBinding, raw_source_binding
    for ref, owner in inventory['owners'].items():
        # Retired targets are conservatively kept too: this phase has no V2
        # content retirement/reclamation. Their donor's old lifecycle is intact.
        intent = inventory['intents'][ref]
        if owner['state'] == 'ACTIVE':
            record = dict(task_ref=ref, task_owner=owner['owner'], contract='task-security-paged-gc-v1',
                          capture_policy='BATCHED_FILES_GC_SOURCE_V2',
                          baseline=dict(redaction_version=owner['representation_version']))
            yield dict(task_ref=ref, owner=dict(owner['owner']), role='donor', ref=owner['donor']['ref'],
                       binding=_binding(record, 'baseline', owner['donor']['source']), expected_states=('SEALED',),
                       expected_header=dict(owner['donor_header']))
        if intent['target_ref'] is not None:
            binding = CaptureSourceBinding(ref, owner['owner'], 'baseline', ref, owner['representation_version'])
            states = ('SEALED',) if intent['state'] == 'PUBLISHED' or ref in inventory['receipts'] else ('CAPTURING', 'WAITING_CAPACITY', 'SEALED')
            yield dict(task_ref=ref, owner=dict(owner['owner']), role='target', ref=intent['target_ref'],
                       binding=raw_source_binding(binding, owner['donor']['source']), expected_states=states)


def retire_for_task(state, record, *, db):
    """Call immediately before the original head DELETE in the same SQL TX."""
    inventory = _read_inventory(state, db)
    if inventory is None or MARKER_FIELD not in record:
        return
    ref = record.get('task_ref')
    if ref not in inventory['owners']:
        _fail()
    owner, intent = inventory['owners'][ref], inventory['intents'][ref]
    _matches(state, record, owner, inventory['identity'])
    if not _expired_readonly(state, record):
        _fail('INVALID_TRANSITION')
    _put(state, db, 'cp_owners', dict(owner, state='RETIRED', retired_at=state.now()), inventory['identity'])
    _put(state, db, 'cp_intents', dict(intent, state='RETIRED', generation=intent['generation'] + 1), inventory['identity'])
    _write_registry(state, db, inventory['identity'], inventory['registry']['generation'] + 1)
