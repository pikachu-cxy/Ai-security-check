"""Explicit internal paged-review heads and atomic metadata publication.

This is not a production task lifecycle or an enabled MCP route. Existing task
heads are never adopted. The source catalog retains signed references to each
revision's sealed snapshot pages; separate raw-body stores keep their own TTL.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import sqlite3
import stat

from ..closeout_state import digest, encode as head_encode
from ..hook_state import no_links
from ..snapshot_store import SnapshotBinding, SnapshotStore, SnapshotStoreError
from ..tasks.ownership import valid_owner
from ..tasks.snapshot_page_guard import guard_held, page_guard
from ..tasks.snapshot_pages import GC_POLICY
from .metadata_store import (FENCE_TABLE, TABLES, ReviewMetadataBinding, ReviewMetadataBudget, ReviewMetadataError,
                             ReviewMetadataStore, ZERO, encode, fail, integer, text)

CONTRACT = 'task-security-paged-review-v1'
SOURCE_RETENTION_DOMAIN = 'TASK_PAGED_REVIEW_V1'
MAX_HEAD_BYTES = 32768
PHASES = frozenset({'READY', 'REVIEWING'})
CATALOG = '__source_catalog__'
TASK_SCHEMA = ('CREATE TABLE security_tasks (ref TEXT PRIMARY KEY, task_key TEXT NOT NULL, '
               'phase TEXT NOT NULL, created REAL NOT NULL, data TEXT NOT NULL, mac TEXT NOT NULL)')
HEAD_FIELDS = frozenset({'contract', 'workspace', 'root_identity', 'task_ref', 'task_key', 'task_owner',
    'review_protocol', 'capture_policy', 'phase', 'generation', 'metadata_generation', 'review_revision',
    'snapshot_id', 'representation_version', 'created_at', 'activity_at', 'baseline', 'end', 'source_catalog'})


def _snapshot(value, representation):
    if (not isinstance(value, dict) or set(value) != {'paged_entries', 'redaction_version'}
            or type(value.get('redaction_version')) is not int or value.get('redaction_version') != representation):
        fail('INVALID')
    pointer = value.get('paged_entries')
    if (not isinstance(pointer, dict) or set(pointer) != {'ref', 'source'}
            or not isinstance(pointer.get('ref'), str) or re.fullmatch(r'ws2-[a-f0-9]{32}', pointer['ref']) is None
            or not isinstance(pointer.get('source'), str) or re.fullmatch(r'[a-f0-9]{64}', pointer['source']) is None):
        fail('INVALID')
    return dict(paged_entries=dict(pointer), redaction_version=representation)


def _descriptor(value):
    if (not isinstance(value, dict) or set(value) != {'ref', 'revision', 'snapshot_id', 'tail_digest', 'item_count'}
            or not isinstance(value.get('ref'), str) or re.fullmatch(r'rm1-[a-f0-9]{32}', value['ref']) is None
            or not integer(value.get('revision'), minimum=1) or not text(value.get('snapshot_id'))
            or not isinstance(value.get('tail_digest'), str) or re.fullmatch(r'[a-f0-9]{64}', value['tail_digest']) is None
            or value.get('item_count') != (2 if value['revision'] == 1 else 3)):
        fail()
    return dict(value)


def source_binding(binding, field, source):
    """Bind new source pages to a domain that legacy collectors cannot own.

    These are caller-provided internal claims, not native host attestation or
    an edit grant. Existing old-domain captures cannot be relabelled/adopted.
    """
    try:
        if (not isinstance(binding, ReviewMetadataBinding)
                or not isinstance(binding.task_ref, str) or re.fullmatch(r'ts1-[a-f0-9]{32}', binding.task_ref) is None
                or not valid_owner(binding.owner) or not integer(binding.revision, minimum=1)
                or not text(binding.snapshot_id) or not integer(binding.representation_version, minimum=1, maximum=255)
                or not isinstance(field, str) or field not in {'baseline', 'end'}
                or not isinstance(source, str) or re.fullmatch(r'[a-f0-9]{64}', source) is None):
            fail('INVALID')
    except (TypeError, ValueError):
        fail('INVALID')
    return SnapshotBinding(task_ref=binding.task_ref + ':' + field + ':' + source,
        owner=binding.owner, source_ref=source,
        representation_version=binding.representation_version,
        kind='TASK_BEFORE_EDIT' if field == 'baseline' else 'TASK_END',
        captured_before_edit=field == 'baseline', retention_domain=SOURCE_RETENTION_DOMAIN)


def _source_binding(head, field, source):
    return source_binding(ReviewMetadataBinding(head['task_ref'], head['task_owner'],
        head['review_revision'], head['snapshot_id'], head['representation_version']), field, source)


def _security_schema(db, *, create=False):
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='security_tasks'").fetchone()
    if row is None:
        if not create:
            fail()
        db.execute(TASK_SCHEMA)
        row = (TASK_SCHEMA,)
    if ' '.join(row[0].split()) != ' '.join(TASK_SCHEMA.split()):
        fail()
    index = False
    for kind, name, sql in db.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name='security_tasks'"):
        if kind == 'table' and name == 'security_tasks':
            continue
        if kind == 'index' and name == 'sqlite_autoindex_security_tasks_1' and sql is None:
            index = True
        else:
            fail()
    if not index:
        fail()


def verify_paged_head(state, row):
    """Authenticate only a bounded head. Does not hydrate sources or metadata."""
    try:
        if not row or len(row) != 2:
            fail()
        raw, mac = row
        raw = raw.encode() if isinstance(raw, str) else raw
        if not isinstance(raw, bytes) or len(raw) > MAX_HEAD_BYTES or not isinstance(mac, str):
            fail()
        head = json.loads(raw)
        if (not isinstance(head, dict) or set(head) != HEAD_FIELDS or head.get('contract') != CONTRACT
                or head.get('workspace') != str(state.root)
                or not hmac.compare_digest(mac, digest(state.key(), head)) or head_encode(head) != raw
                or not isinstance(head.get('task_ref'), str) or re.fullmatch(r'ts1-[a-f0-9]{32}', head['task_ref']) is None
                or not valid_owner(head.get('task_owner')) or not text(head.get('task_key'))
                or head.get('review_protocol') != 3 or head.get('capture_policy') != GC_POLICY
                or head.get('phase') not in PHASES
                or not integer(head.get('generation'), minimum=1)
                or not integer(head.get('metadata_generation'), minimum=1)
                or head.get('metadata_generation') != head['generation']
                or not integer(head.get('review_revision'), minimum=1)
                or not integer(head.get('representation_version'), minimum=1, maximum=255)
                or not text(head.get('snapshot_id'))):
            fail()
        no_links(state.root)
        info = state.root.stat()
        if not stat.S_ISDIR(info.st_mode) or head.get('root_identity') != [info.st_dev, info.st_ino]:
            fail()
        for key in ('created_at', 'activity_at'):
            if type(head.get(key)) not in {int, float} or not math.isfinite(head[key]) or head[key] < 0:
                fail()
        if head['activity_at'] < head['created_at']:
            fail()
        for field in ('baseline', 'end'):
            _snapshot(head[field], head['representation_version'])
        descriptor = _descriptor(head['source_catalog'])
        if descriptor['revision'] != head['review_revision'] or descriptor['snapshot_id'] != head['snapshot_id']:
            fail()
        return head
    except (ValueError, TypeError, KeyError, OSError, UnicodeError, RecursionError):
        fail()


def _allocated_metadata(state):
    store = ReviewMetadataStore(state.path, workspace_root=state.root, key=state.key())
    allocated = store._marker()
    return ReviewMetadataStore(state.path, workspace_root=state.root, key=state.key(),
                               budget=ReviewMetadataBudget(**allocated['budget']))


def validate_head_inventory(state, *, db):
    """Authenticate both directions of the complete bounded head/fence set.

    A missing task row is never an implicit retirement. The caller must hold
    the page guard and the same SQLite transaction used for collection or
    admission, and must do no deletion until this function and all source-pin
    validation succeed. Legacy-only databases allocate no metadata state.
    """
    from ..tasks.security_state import MAX_HISTORY_RECORDS, MAX_RECORD_BYTES
    if not guard_held(state.path.parent) or not db.in_transaction:
        fail()
    original_limit = None
    try:
        main = next(row[2] for row in db.execute('PRAGMA database_list') if row[1] == 'main')
        if Path(main).resolve() != state.path.resolve():
            fail()
        objects = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE name GLOB 'rm_*' LIMIT ?",
                                              (len(TABLES) + 2,))}
        marker = state.path.with_name(state.path.name + '.review-metadata.identity')
        no_links(marker)
        store = None
        if objects or marker.exists():
            store = _allocated_metadata(state)
            store._paths()
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name GLOB 'rm_*' LIMIT ?",
                                                 (len(TABLES) + 2,))}
            if tables not in (set(TABLES), {*TABLES, FENCE_TABLE}) or objects != tables:
                fail()
            original_limit = db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,
                max(store.budget.page_bytes + 8192, MAX_HEAD_BYTES + 8192))
            store._schema(db)
            store._registry(db)
            _security_schema(db)
        fences = 0
        if store is not None and store._fenced_schema(db):
            for task_ref, raw, mac in db.execute('SELECT task_ref,data,mac FROM rm_head_fences ORDER BY task_ref LIMIT ?',
                                               (MAX_HISTORY_RECORDS + 1,)):
                fences += 1
                if fences > MAX_HISTORY_RECORDS:
                    fail()
                fence = store._decode('head-fence', raw, mac)
                if set(fence) != {'task_ref', 'binding', 'contract'} or not isinstance(fence.get('binding'), dict):
                    fail()
                binding = store._binding(ReviewMetadataBinding(fence['task_ref'], fence['binding'].get('owner'),
                    1, 'inventory', fence['binding'].get('representation_version')))
                if task_ref != binding['task_ref'] or store._head_fence(db, binding) != fence:
                    fail()
                row = db.execute('SELECT ref,task_key,phase,created,data,mac FROM security_tasks WHERE ref=?',
                                 (task_ref,)).fetchone()
                head = verify_paged_head(state, row[4:] if row else None)
                if (row[:4] != tuple(head.get(k) for k in ('task_ref', 'task_key', 'phase', 'created_at'))
                        or head['task_owner'] != binding['owner']
                        or head['representation_version'] != binding['representation_version']
                        or store._ledger(db, binding)['generation'] != head['metadata_generation']):
                    fail()
        # Old signed heads keep their original bound, one authenticated row at
        # a time. No source maps are unpacked and no full inventory is retained.
        old_limit = db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_RECORD_BYTES + 8192)
        if original_limit is None:
            original_limit = old_limit
        heads, count = 0, 0
        for row in db.execute('SELECT ref,task_key,phase,created,data,mac FROM security_tasks ORDER BY rowid LIMIT ?',
                              (MAX_HISTORY_RECORDS + 1,)):
            count += 1
            if count > MAX_HISTORY_RECORDS:
                fail()
            head = state.retention_head(row[4:])
            if row[:4] != tuple(head.get(k) for k in ('task_ref', 'task_key', 'phase', 'created_at')):
                fail()
            if head.get('contract') == CONTRACT:
                if store is None:
                    fail()
                binding = store._binding(ReviewMetadataBinding(head['task_ref'], head['task_owner'],
                    head['review_revision'], head['snapshot_id'], head['representation_version']))
                if (store._head_fence(db, binding) is None
                        or store._ledger(db, binding)['generation'] != head['metadata_generation']):
                    fail()
                heads += 1
            del head
        if heads != fences:
            fail()
        return dict(heads=heads, fences=fences)
    except ReviewMetadataError:
        raise
    except (sqlite3.Error, ValueError, TypeError, KeyError, AttributeError, OSError, UnicodeError, StopIteration):
        fail()
    finally:
        if original_limit is not None:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, original_limit)


def iter_source_pins(state, head, *, db):
    """Stream all revision pins using the caller's task-DB transaction/guard.

    No snapshot body is loaded. Consumers must authenticate/seal-check every
    returned SnapshotBinding before deleting any source pages. The strict
    decreasing revision replaces an unbounded visited-reference set.
    """
    if not guard_held(state.path.parent) or not db.in_transaction:
        fail()
    try:
        databases = db.execute('PRAGMA database_list').fetchall()
        main = next(row[2] for row in databases if row[1] == 'main')
        if Path(main).resolve() != state.path.resolve():
            fail()
        _security_schema(db)
        # Only the authenticated original allocation can supply this budget.
        # No caller-proposed budget can raise an already allocated domain.
        store = _allocated_metadata(state)
        actual = verify_paged_head(state, db.execute('SELECT data,mac FROM security_tasks WHERE ref=?',
                                                     (head['task_ref'],)).fetchone())
        if actual != head:
            fail()
        # The caller may also read old 4 MB heads. Restore its connection limit
        # even on a failed/abandoned generator rather than caching validation.
        maximum = max(store.budget.page_bytes + 8192, MAX_HEAD_BYTES + 8192)
        original_limit = db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, maximum)
        try:
            store._paths()
            store._schema(db)
            store._registry(db)
            binding = store._binding(ReviewMetadataBinding(head['task_ref'], head['task_owner'],
                head['review_revision'], head['snapshot_id'], head['representation_version']))
            if store._head_fence(db, binding) is None:
                fail()
            ledger = store._ledger(db, binding)
            if ledger['generation'] != head['metadata_generation']:
                fail()
            descriptor = _descriptor(head['source_catalog'])
            revision = head['review_revision']
            original_before = head['baseline']['paged_entries']
            while revision:
                if descriptor['revision'] != revision:
                    fail()
                binding = store._binding(ReviewMetadataBinding(head['task_ref'], head['task_owner'], revision,
                    descriptor['snapshot_id'], head['representation_version']))
                catalog = store._collection(db, descriptor['ref'], binding)
                if (catalog['name'] != CATALOG or catalog['state'] != 'SEALED'
                        or catalog['tail_digest'] != descriptor['tail_digest']
                        or catalog['item_count'] != descriptor['item_count']):
                    fail()
                store._validate(db, catalog, full=True)
                fields, previous = set(), None
                for row in db.execute('SELECT page_seq,first_item,item_count,previous_digest,digest,data,mac FROM rm_pages WHERE ref=? ORDER BY page_seq', (catalog['ref'],)):
                    page = store._page_value(row, catalog['ref'])
                    for item in page['items']:
                        if not isinstance(item, dict):
                            fail()
                        if item.get('kind') == 'PREVIOUS_CATALOG':
                            if set(item) != {'kind', 'catalog'} or previous is not None:
                                fail()
                            previous = _descriptor(item['catalog'])
                            continue
                        if (set(item) != {'kind', 'field', 'revision', 'ref', 'source'}
                                or item.get('kind') != 'SOURCE_PIN' or item.get('field') not in {'baseline', 'end'}
                                or not integer(item.get('revision'), minimum=1)
                                or item.get('revision') != revision or item['field'] in fields):
                            fail()
                        field = item['field']
                        pointer = _snapshot(dict(paged_entries=dict(ref=item['ref'], source=item['source']),
                            redaction_version=head['representation_version']), head['representation_version'])['paged_entries']
                        if field == 'baseline' and pointer != original_before:
                            fail()
                        if revision == head['review_revision'] and pointer != head[field]['paged_entries']:
                            fail()
                        fields.add(field)
                        yield dict(ref=item['ref'], source=item['source'], field=field, revision=revision,
                                   binding=_source_binding(head, field, item['source']))
                    del page
                if fields != {'baseline', 'end'} or (previous is None) != (revision == 1):
                    fail()
                if previous is not None and previous['revision'] != revision - 1:
                    fail()
                descriptor, revision = previous, revision - 1
        finally:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, original_limit)
    except (sqlite3.Error, ValueError, TypeError, KeyError, OSError, UnicodeError, StopIteration):
        fail()


class PagedReviewTaskStore:
    def __init__(self, state, *, budget=None):
        self.state = state
        self.metadata = ReviewMetadataStore(state.path, workspace_root=state.root, key=state.key(), budget=budget)

    def _head(self, db, ref, owner):
        _security_schema(db)
        try:
            owner_valid = valid_owner(owner)
        except (ValueError, TypeError):
            owner_valid = False
        if not owner_valid or not isinstance(ref, str) or re.fullmatch('ts1-[a-f0-9]{32}', ref) is None:
            fail('INVALID')
        row = db.execute('SELECT data,mac FROM security_tasks WHERE ref=?', (ref,)).fetchone()
        head = verify_paged_head(self.state, row)
        if head['task_ref'] != ref or head['task_owner'] != owner:
            fail()
        return head

    def get(self, task_ref, owner):
        with page_guard(self.state.path.parent), self.metadata._db() as db:
            head = self._head(db, task_ref, owner)
            for pin in iter_source_pins(self.state, head, db=db):
                self._sealed(pin)
            return head

    def _sealed(self, pin):
        try:
            source = SnapshotStore(self.state.path.parent / 'snapshot-pages',
                                   workspace_root=self.state.root, key=self.state.key())
            if source.resume(pin['ref'], pin['binding'])['state'] != 'SEALED':
                fail()
        except SnapshotStoreError:
            fail()

    def _sources(self, head):
        for field in ('baseline', 'end'):
            pointer = head[field]['paged_entries']
            self._sealed(dict(ref=pointer['ref'], binding=_source_binding(head, field, pointer['source'])))

    def _empty(self, binding, name):
        if not text(name):
            fail('INVALID')
        ref = 'rm1-' + hashlib.sha256(encode(dict(binding=binding, name=name))).hexdigest()[:32]
        return dict(ref=ref, name=name, binding=binding, state='STAGING', page_count=0,
                    item_count=0, tail_digest='0' * 64)

    def _catalog(self, db, binding, head, previous):
        value = self._empty(binding, CATALOG)
        if db.execute('SELECT 1 FROM rm_collections WHERE ref=?', (value['ref'],)).fetchone():
            fail('IDEMPOTENCY_CONFLICT')
        items = [dict(kind='SOURCE_PIN', field=field, revision=binding['revision'],
                      **head[field]['paged_entries']) for field in ('baseline', 'end')]
        if previous is not None:
            items.append(dict(kind='PREVIOUS_CATALOG', catalog=previous))
        self.metadata._append_pages(db, value, self.metadata._freeze_items(items))
        value['state'] = 'SEALED'
        self.metadata._validate(db, value, full=True)
        head['source_catalog'] = dict(ref=value['ref'], revision=binding['revision'],
            snapshot_id=binding['snapshot_id'], tail_digest=value['tail_digest'], item_count=value['item_count'])
        return value

    def _receipt(self, db, binding, request_id, request_hash, head):
        row = db.execute('SELECT task_ref,request_id,data,mac FROM rm_receipts WHERE task_ref=? AND request_id=?',
                         (binding['task_ref'], request_id)).fetchone()
        if row is None:
            return None
        value = self.metadata._decode('receipt', row[2], row[3])
        result = value.get('result')
        if (row[:2] != (value.get('task_ref'), value.get('request_id'))
                or value.get('binding') != self.metadata._task_binding(binding)):
            fail()
        if value.get('request_hash') != request_hash:
            fail('IDEMPOTENCY_CONFLICT')
        if (not isinstance(result, dict) or result.get('task_ref') != binding['task_ref']
                or not integer(result.get('head_generation'), minimum=1)
                or result['head_generation'] > head['generation']):
            fail()
        return result

    def _publish(self, db, binding, head, manifest, request_id, request_hash):
        raw = head_encode(head)
        if len(raw) > MAX_HEAD_BYTES:
            fail('PAGE_BUDGET')
        mac = digest(self.state.key(), head)
        verify_paged_head(self.state, (raw, mac))
        db.execute('INSERT OR REPLACE INTO security_tasks VALUES(?,?,?,?,?,?)',
            (head['task_ref'], head['task_key'], head['phase'], head['created_at'], raw.decode(), mac))
        result = dict(task_ref=head['task_ref'], head_generation=head['generation'], head_digest=mac, metadata=manifest)
        self.metadata._save_receipt(db, binding, request_id, request_hash, result)
        return result

    def _admission(self, db):
        """Keep original task slots without hydrating source page dictionaries.

        Legacy signed JSON has its original 4 MB bound. Authenticate one row
        at a time, temporarily using that bound only for this inventory; all
        metadata reads retain their smaller SQLite row limit afterwards.
        """
        from ..tasks.security_state import MAX_HISTORY_RECORDS, MAX_RECORD_BYTES, MAX_V3_RECORDS
        from .protocol import is_v3_record
        original_limit = db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_RECORD_BYTES + 8192)
        count, v3 = 0, 0
        try:
            validate_head_inventory(self.state, db=db)
            for row in db.execute('SELECT ref,task_key,phase,created,data,mac FROM security_tasks ORDER BY rowid LIMIT ?',
                                  (MAX_HISTORY_RECORDS + 1,)):
                value = self.state.retention_head(row[4:])
                if row[:4] != tuple(value.get(k) for k in ('task_ref', 'task_key', 'phase', 'created_at')):
                    fail()
                count += 1
                v3 += is_v3_record(value)
                del value
            if count >= MAX_HISTORY_RECORDS or v3 >= MAX_V3_RECORDS:
                fail('WAITING_CAPACITY')
        except ReviewMetadataError:
            raise
        except (ValueError, TypeError, KeyError, AttributeError):
            fail()
        finally:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, original_limit)

    def create(self, binding, *, task_key, baseline, end, limits, request_id):
        model, store = binding, self.metadata
        binding = store._binding(model)
        if binding['revision'] != 1 or not text(task_key):
            fail('INVALID')
        baseline = _snapshot(baseline, binding['representation_version'])
        end = _snapshot(end, binding['representation_version'])
        limits = store._counts(limits)
        payload = dict(task_key=task_key, baseline=baseline, end=end, limits=limits)
        request_hash = store._request('paged-head-create', binding, request_id, payload, ZERO)
        with page_guard(self.state.path.parent, create=True), store._db(write=True, create=True) as db:
            _security_schema(db, create=True)
            row = db.execute('SELECT data,mac FROM security_tasks WHERE ref=?', (binding['task_ref'],)).fetchone()
            if row is not None:
                head = self._head(db, binding['task_ref'], binding['owner'])
                if store._head_fence(db, binding) is None:
                    fail()
                ledger = store._ledger(db, binding)
                if ledger['generation'] != head['metadata_generation']:
                    fail()
                receipt = self._receipt(db, binding, request_id, request_hash, head)
                if receipt is not None:
                    return receipt
                fail('CAS_CONFLICT')
            self._admission(db)
            if store._ledger(db, binding, optional=True) is not None or store._head_fence(db, binding) is not None:
                fail()
            now = self.state.now()
            head = dict(contract=CONTRACT, workspace=str(self.state.root), root_identity=store.root_identity,
                task_ref=binding['task_ref'], task_key=task_key, task_owner=binding['owner'], review_protocol=3,
                capture_policy=GC_POLICY, phase='READY', generation=1, metadata_generation=1,
                review_revision=1, snapshot_id=binding['snapshot_id'], representation_version=binding['representation_version'],
                created_at=now, activity_at=now, baseline=baseline, end=end)
            self._sources(head)
            store._enable_head_fences(db)
            fence = dict(task_ref=binding['task_ref'], binding=store._task_binding(binding), contract=CONTRACT)
            db.execute(f'INSERT INTO {FENCE_TABLE} VALUES(?,?,?)',
                       (binding['task_ref'], encode(fence), store._mac('head-fence', fence)))
            catalog = self._catalog(db, binding, head, None)
            ledger = dict(binding=store._task_binding(binding), generation=0, limits=limits, spent=dict(ZERO))
            manifest = store._finish(db, binding, ledger, catalog, request_id, request_hash, ZERO, receipt=False)
            return self._publish(db, binding, head, manifest, request_id, request_hash)

    def mutate(self, binding, mutation, *, expected_generation, expected_metadata_generation,
               request_id, charge=None, phase=None):
        store = self.metadata
        binding = store._binding(binding)
        charge = store._counts(dict(ZERO) if charge is None else charge)
        if (not isinstance(mutation, dict)
                or phase is not None and (not isinstance(phase, str) or phase not in PHASES)):
            fail('INVALID')
        kind = mutation.get('kind')
        frozen = None
        if kind == 'create' and set(mutation) == {'kind', 'name'}:
            if not text(mutation['name']) or mutation['name'] == CATALOG:
                fail('INVALID')
            payload = dict(mutation)
        elif kind == 'append' and set(mutation) == {'kind', 'ref', 'items'}:
            store._ref(mutation['ref'])
            frozen = store._freeze_items(mutation['items'])
            payload = dict(kind=kind, ref=mutation['ref'])
        elif kind == 'seal' and set(mutation) == {'kind', 'ref', 'expected_items'}:
            store._ref(mutation['ref'])
            if not integer(mutation['expected_items']):
                fail('INVALID')
            payload = dict(mutation)
        elif kind == 'revision' and set(mutation) == {'kind', 'end'}:
            payload = dict(kind=kind, end=_snapshot(mutation['end'], binding['representation_version']))
        else:
            fail('INVALID')
        request_hash = store._request('paged-head-mutate', binding, request_id, dict(mutation=payload, phase=phase), charge, frozen)
        with page_guard(self.state.path.parent), store._db(write=True) as db:
            head = self._head(db, binding['task_ref'], binding['owner'])
            if (head['representation_version'] != binding['representation_version']
                    or store._head_fence(db, binding) is None):
                fail()
            ledger = store._ledger(db, binding)
            if ledger['generation'] != head['metadata_generation']:
                fail()
            receipt = self._receipt(db, binding, request_id, request_hash, head)
            if receipt is not None:
                return receipt
            if not integer(expected_generation) or head['generation'] != expected_generation:
                fail('CAS_CONFLICT')
            store._cas(ledger, expected_metadata_generation, charge)
            for pin in iter_source_pins(self.state, head, db=db):
                self._sealed(pin)
            if kind == 'revision':
                if binding['revision'] != head['review_revision'] + 1 or binding['snapshot_id'] == head['snapshot_id']:
                    fail('INVALID')
                previous = head['source_catalog']
                head = dict(head, review_revision=binding['revision'], snapshot_id=binding['snapshot_id'], end=payload['end'])
                self._sources(head)
                value = self._catalog(db, binding, head, previous)
            else:
                if binding['revision'] != head['review_revision'] or binding['snapshot_id'] != head['snapshot_id']:
                    fail()
                if kind == 'create':
                    value = self._empty(binding, payload['name'])
                    if db.execute('SELECT 1 FROM rm_collections WHERE ref=?', (value['ref'],)).fetchone():
                        fail('IDEMPOTENCY_CONFLICT')
                else:
                    value = store._collection(db, payload['ref'], binding)
                    if value['state'] != 'STAGING' or value['name'] == CATALOG:
                        fail('INVALID')
                    store._validate(db, value, full=kind == 'seal')
                    if kind == 'append':
                        store._append_pages(db, value, frozen)
                    elif value['item_count'] != payload['expected_items']:
                        fail('INVALID')
                    else:
                        value['state'] = 'SEALED'
            manifest = store._finish(db, binding, ledger, value, request_id, request_hash, charge, receipt=False)
            head = dict(head, generation=head['generation'] + 1, metadata_generation=manifest['generation'],
                        phase=phase or head['phase'], activity_at=self.state.now())
            return self._publish(db, binding, head, manifest, request_id, request_hash)
