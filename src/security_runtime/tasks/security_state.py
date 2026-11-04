"""Signed task snapshots. Private bounded local state, never a repair grant."""
from __future__ import annotations

from contextlib import closing
import hmac
import json
import math
from pathlib import Path
import re
import sqlite3
import time

from ..closeout_state import digest, encode, readonly_uri
from ..hook_state import atomic_bytes, no_links
from ..snapshot_store import SnapshotStoreError
from ..task_review.protocol import require_record_protocol, is_v3_record
from .snapshot_page_guard import guarded_read, page_guard, guard_held
from .snapshot_pages import GC_CONTRACT, REVIEW_CONTRACT, batched, managed

CONTRACT = 'task-security-v1'
REF = re.compile(r'ts1-[a-f0-9]{32}')
MAX_RECORD_BYTES = 4_000_000
TTL = 24 * 3600
MAX_V3_RECORDS = 32
MAX_HISTORY_RECORDS = MAX_V3_RECORDS * 2  # Preserve up to 32 retired records without using v3 slots.
MAX_RETAINED_PROJECTIONS = 32
HOOK_FAILURE_CONTRACT = 'task-hook-recording-failure-v1'
MAX_HOOK_FAILURE_BYTES = 160_000
MAX_HOOK_FAILURE_FILES = 1000
MAX_HOOK_FAILURE_PATH_BYTES = 128_000
MAX_HOOK_FAILURE_MARKERS = 32


def persistent_record(value):
    """Keep one authoritative v3 ledger; do not mutate caller or legacy bytes."""
    from .closeout_index import compact
    value = compact(value)
    plan = value.get('review_plan')
    if (is_v3_record(value) and isinstance(plan, dict)
            and plan.get('contract') == 'task-review-plan-v3'
            and isinstance(value.get('review_ledger'), dict)):
        return dict(value, review_plan={key: item for key, item in plan.items() if key != 'budget'})
    return value


def stored_record_projection(value):
    """Pure capacity view of the encoding used by the authenticated writer."""
    from .snapshot_pages import control_projection
    return control_projection(persistent_record(value))


class _PagedReviewHead(ValueError):
    """Route internal retention to the new verifier, never a legacy reader."""


class TaskSecurityStore:
    def __init__(self, hooks, root, *, now=time.time, birth_publication=False):
        if type(birth_publication) is not bool:
            raise ValueError('Invalid baseline publication option')
        self.root, self.hooks, self.now = root, hooks, now
        self.birth_publication = birth_publication
        self.path = hooks.workspace_directory(root) / 'task-security.db'

    def key(self):
        path = self.path.parent / 'snapshot.key'
        no_links(path)
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError('Task key cannot be verified')
        return key

    def _authenticated_head(self, row):
        """Authenticate only control bytes, including before writer admission."""
        if not row:
            return None
        raw, mac = row
        if not isinstance(raw, str) or not isinstance(mac, str) or len(raw.encode()) > MAX_RECORD_BYTES:
            raise ValueError('Task record budget exceeded')
        value = json.loads(raw)
        if isinstance(value, dict) and value.get('contract') == REVIEW_CONTRACT:
            raise _PagedReviewHead('Paged review heads require their bounded task reader')
        if (not isinstance(value, dict) or value.get('contract') not in {CONTRACT, GC_CONTRACT}
                or not REF.fullmatch(value.get('task_ref', ''))
                or value.get('workspace') != str(self.root)
                or not hmac.compare_digest(mac, digest(self.key(), value))):
            raise ValueError('Task state cannot be verified')
        from .capture_source_profile import validate_record
        validate_record(value)
        if value.get('contract') == GC_CONTRACT and not managed(value):
            raise ValueError('Snapshot collection contract mismatch')
        return value

    def head(self, row):
        """Authenticate the control record without opening its source pages."""
        value = self._authenticated_head(row)
        if value is None:
            return None
        if managed(value) and not guard_held(self.path.parent):
            raise ValueError('Snapshot collection guard unavailable')
        return value

    def _preflight_capture_transition(self, value, *, new):
        """Reject policy changes before chmod, collection or source-page I/O.

        This control-only read needs no source guard and can inspect owned old
        permissions before explicit writer admission. The write CAS repeats it.
        """
        if new:
            from .capture_publication_store import validate_transition
            validate_transition(None, value, new=True)
            return
        ref = value.get('task_ref')
        if not isinstance(ref, str) or REF.fullmatch(ref) is None:
            raise ValueError('Invalid task reference')
        no_links(self.path)
        old = None
        if self.path.is_file():
            from .frozen_body_context import readonly_database
            with readonly_database(self.path, maximum=MAX_RECORD_BYTES) as db:
                row = db.execute("SELECT CASE WHEN typeof(data)='text' AND "
                    'length(CAST(data AS BLOB))<=? THEN data END, '
                    "CASE WHEN typeof(mac)='text' AND length(mac)=64 THEN mac END "
                    'FROM security_tasks WHERE ref=? LIMIT 1', (MAX_RECORD_BYTES, ref)).fetchone()
                old = self._authenticated_head(row)
        if not old or old['task_ref'] != ref:
            raise ValueError('Task changed concurrently; read current task first')
        from .capture_source_profile import CaptureSourceProfileError, validate_transition
        try:
            validate_transition(old, value, new=False)
        except CaptureSourceProfileError:
            if old['generation'] != value.get('generation'):
                raise ValueError('Task changed concurrently; read current task first') from None
            raise
        from .capture_publication_store import validate_transition as validate_publication
        validate_publication(old, value, new=False)

    def _prepare_publication_birth(self, value, *, new):
        from .capture_source_profile import POLICY
        if (new and self.birth_publication and value.get('capture_policy') == POLICY
                and not guard_held(self.path.parent)):
            # Allocation has its own durable marker and SQL transaction. It
            # must finish before the task transaction or shared source guard.
            self.hooks.prepare_database(self.root, 'task-security.db')
            from .capture_publication_store import prepare_storage
            prepare_storage(self)

    def _validate_publication_retention(self, db):
        from .capture_publication_store import validate_inventory, iter_source_pins
        inventory = validate_inventory(self, db=db)
        if not inventory['allocated']:
            return
        from .snapshot_pages import _store
        store = _store(self)
        pins = list(iter_source_pins(self, db=db))
        if pins or store.path.exists():
            store.validate_contents()
        for pin in pins:
            header = store.strict_header(pin['ref'], pin['binding'])
            if (header['state'] not in pin['expected_states']
                    or any(header.get(key) != value for key, value in pin.get('expected_header', {}).items())):
                from ..snapshot_store import SnapshotStoreError
                raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID')

    def retention_head(self, row):
        """Authenticate small heads for retention only; never project new data.

        A new contract has its own reader and atomic writer. Legacy consumers
        must not mistake absent inline maps for an empty completed snapshot.
        """
        try:
            return self.head(row)
        except _PagedReviewHead:
            from ..task_review.paged_task_store import verify_paged_head
            return verify_paged_head(self, row)

    @guarded_read
    def decode(self, row):
        value = self.head(row)
        if value is None:
            return None
        from .snapshot_pages import unpack
        return unpack(self, value)

    def expired(self, record):
        from .lifecycle import expires_at
        return self.now() > expires_at(record, self.hooks, self.root, now=self.now)

    @guarded_read
    def records(self, *, active=False, headers=False):
        """Authenticate task controls; source consumers use the default full read.

        Header-only results contain no source coverage proof. They are suitable
        for time-window/owner checks, never for scanning or source review.
        """
        if type(headers) is not bool:
            raise ValueError('Invalid task header read option')
        no_links(self.path)
        if not self.path.is_file(): return []
        with closing(sqlite3.connect(readonly_uri(self.path),uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            # Per-edit routing need not deserialize completed tasks' source
            # packets. Keep the signed phase/TTL checks below as well.
            predicate="WHERE phase IN ('ACTIVE','STATIC_RUNNING','READY','REVIEWING')" if active else ''
            rows=db.execute(f'SELECT data,mac FROM security_tasks {predicate} ORDER BY rowid DESC LIMIT {MAX_HISTORY_RECORDS}').fetchall()
        from .ownership import ACTIVE
        reader = self.head if headers else self.decode
        records=[reader(row) for row in rows]
        return [v for v in records if v and not self.expired(v) and (not active or v['phase'] in ACTIVE)]

    @guarded_read
    def get(self, ref=None, *, active=False, task_key=None, owner=None, headers=False):
        if type(headers) is not bool:
            raise ValueError('Invalid task header read option')
        no_links(self.path)
        if ref is not None and (not isinstance(ref, str) or not REF.fullmatch(ref)):
            raise ValueError('Invalid task reference')
        if not self.path.is_file():
            return None
        if active and ref is None:
            from .ownership import record_owner
            values=[v for v in self.records(active=True, headers=headers) if is_v3_record(v)
                    and (owner is None or record_owner(v)==owner)]
            return values[0] if len(values)==1 else None
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            if ref:
                row = db.execute('SELECT data,mac FROM security_tasks WHERE ref=?', (ref,)).fetchone()
            else:
                row = db.execute('SELECT data,mac FROM security_tasks WHERE task_key=? ORDER BY rowid DESC LIMIT 1', (task_key,)).fetchone()
            value = self.head(row) if headers else self.decode(row)
            if value and self.expired(value):
                return None
            return value

    def _frozen_body_record(self, ref, *, owner):
        """Read one authenticated head and its original TTL without hydration."""
        from .frozen_body_context import (FrozenBodyContextUnavailable,
            readonly_database, unavailable)
        from .ownership import valid_owner, record_owner
        if not isinstance(ref, str) or REF.fullmatch(ref) is None or not valid_owner(owner):
            unavailable('INVALID')
        try:
            with page_guard(self.path.parent):
                no_links(self.path)
                if not self.path.is_file():
                    unavailable()
                with readonly_database(self.path, maximum=MAX_RECORD_BYTES) as db:
                    row = db.execute("SELECT CASE WHEN typeof(data)='text' AND "
                        'length(CAST(data AS BLOB))<=? THEN data END, '
                        "CASE WHEN typeof(mac)='text' AND length(mac)=64 THEN mac END "
                        'FROM security_tasks WHERE ref=? LIMIT 1', (MAX_RECORD_BYTES, ref)).fetchone()
                    if row is None:
                        unavailable()
                    if not isinstance(row[0], str) or not isinstance(row[1], str):
                        unavailable('STATE_UNAVAILABLE')
                    value = self.head(row)
                    if value is None or value['task_ref'] != ref:
                        unavailable('STATE_UNAVAILABLE')
                    if record_owner(value) != owner:
                        unavailable('OWNER_MISMATCH')
                    from .activity import ActivityStore, deferred, HARD_TTL, IDLE_TTL
                    if deferred(value):
                        activity = ActivityStore(self.hooks, self.root, now=self.now)
                        activity._paths()
                        summary = {}
                        if activity.path.exists():
                            with readonly_database(activity.path, maximum=160000) as activity_db:
                                summary = activity._get(activity_db, 'task:' + ref) or {}
                        # Keep lifecycle.expires_at's original idle/hard rule,
                        # but do not let its legacy reader recover a journal or
                        # create WAL sidecars during this read-only operation.
                        last = max(value['created_at'], value.get('activity_at', 0),
                                   summary.get('last_activity', 0))
                        expiry = min(value['created_at'] + HARD_TTL, last + IDLE_TTL)
                        expired = self.now() > expiry
                    else:
                        expired = self.expired(value)
                    if expired:
                        unavailable()
                    return value
        except FrozenBodyContextUnavailable:
            raise
        except SnapshotStoreError as error:
            unavailable('BUSY' if error.reason_code == 'SNAPSHOT_PAGE_STORE_BUSY' else 'STATE_UNAVAILABLE')
        except sqlite3.Error as error:
            code = getattr(error, 'sqlite_errorcode', 0) & 255
            unavailable('BUSY' if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED} else 'STATE_UNAVAILABLE')
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
            unavailable('STATE_UNAVAILABLE')

    def get_frozen_body_context(self, ref, *, owner):
        """Read the original small baseline context, never all source pages."""
        from .frozen_body_context import (PROFILE, PROFILE_FIELD, CONTEXT_FIELD,
            unavailable, verify_context)
        value = self._frozen_body_record(ref, owner=owner)
        if value.get(PROFILE_FIELD) != PROFILE:
            unavailable()
        baseline = value.get('baseline')
        if not isinstance(baseline, dict):
            unavailable('STATE_UNAVAILABLE')
        packet = baseline.get(CONTEXT_FIELD)
        if packet is None:
            unavailable()
        payload = verify_context(self.hooks, self.root, packet, task_ref=ref, owner=owner, now=self.now)
        pointer = baseline.get('paged_entries')
        if not isinstance(pointer, dict) or pointer.get('source') != payload['source']:
            unavailable('INVALID')
        return json.loads(encode(packet))

    def get_frozen_end_body_context(self, ref, *, owner, expected_version_ref,
                                    expected_source=None):
        """Read only the specified current end version; never choose latest."""
        from .frozen_body_context import PROFILE, PROFILE_FIELD, FrozenBodyContextUnavailable
        from .frozen_end_context import (END_CONTEXT_FIELD, unavailable as end_unavailable,
            verify_end_context)
        if (not isinstance(expected_version_ref, str) or REF.fullmatch(expected_version_ref) is None
                or expected_source is not None and (not isinstance(expected_source, str)
                    or re.fullmatch('[a-f0-9]{64}', expected_source) is None)):
            end_unavailable('INVALID')
        try:
            value = self._frozen_body_record(ref, owner=owner)
        except FrozenBodyContextUnavailable as error:
            end_unavailable(error.reason_code[len('FROZEN_BODY_CONTEXT_'):])
        if value.get(PROFILE_FIELD) != PROFILE:
            end_unavailable()
        end = value.get('end')
        if not isinstance(end, dict) or not end.get('version_ref'):
            end_unavailable()
        if end['version_ref'] != expected_version_ref:
            end_unavailable('SUPERSEDED')
        packet = end.get(END_CONTEXT_FIELD)
        if packet is None:
            end_unavailable()
        payload = verify_end_context(self.hooks, self.root, packet, task_ref=ref,
            owner=owner, version_ref=expected_version_ref, now=self.now)
        pointer = end.get('paged_entries')
        from .closeout_index import indexed, CONTENT_SOURCE
        if not isinstance(pointer, dict):
            end_unavailable('INVALID')
        source = end.get(CONTENT_SOURCE) if indexed(end) else pointer.get('source')
        if source != payload['source']:
            end_unavailable('INVALID')
        if expected_source is not None and payload['source'] != expected_source:
            end_unavailable('SOURCE_MISMATCH')
        return json.loads(encode(packet))

    def for_hook(self, host, session):
        from .activity import ActivityStore
        from .ownership import valid_owner, record_owner
        owner = {'host':host, 'session':session}
        focus = ActivityStore(self.hooks, self.root, now=self.now).focus(owner) if valid_owner(owner) else None
        if focus:
            selected = self.get(focus['task_ref']) if focus.get('task_ref') else None
            return selected if selected and record_owner(selected) == owner else None
        values=[v for v in self.records(active=True) if is_v3_record(v)]
        owned=[v for v in values if record_owner(v)=={'host':host,'session':session}]
        if len(owned)==1: return owned[0]
        # A single unowned v3 embedding is retained, never a newest-task guess.
        if not owned and len(values)==1 and record_owner(values[0]) is None: return values[0]
        return None

    def _retain_pending(self, db):
        """Archive pending obligations before task TTL pruning, never source bodies."""
        import copy
        from .projection import status
        db.execute('CREATE TABLE IF NOT EXISTS retained_task_projections '
                   '(ref TEXT PRIMARY KEY, data TEXT NOT NULL, mac TEXT NOT NULL, created REAL NOT NULL)')
        archived = db.execute('SELECT ref,data,mac,created FROM retained_task_projections LIMIT ?',
                              (MAX_RETAINED_PROJECTIONS+1,)).fetchall()
        if len(archived) > MAX_RETAINED_PROJECTIONS:
            raise ValueError('Pending task projection retention capacity exceeded')
        for ref, raw, mac, created in archived:
            if self.retention_head((raw, mac)).get('contract') == REVIEW_CONTRACT:
                raise ValueError('Paged review heads cannot use legacy risk projections')
            value = self.decode((raw, mac))
            if created < self.now()-TTL and not status(value)['pending']:
                db.execute('DELETE FROM retained_task_projections WHERE ref=?', (ref,))
        expired = db.execute('SELECT ref,data,mac FROM security_tasks WHERE created<?',
                             (self.now()-TTL,)).fetchall()
        for ref, raw, mac in expired:
            if self.retention_head((raw, mac)).get('contract') == REVIEW_CONTRACT:
                # The new coordinator/lifecycle must retire its own catalog.
                # Until connected, do not erase sources via old TTL/projection.
                continue
            value = self.decode((raw, mac))
            if not self.expired(value):
                continue
            if not status(value)['pending']:
                continue
            previous = db.execute('SELECT data,mac FROM retained_task_projections WHERE ref=?', (ref,)).fetchone()
            if previous:
                retained = self.decode(previous)
                if retained['ledger_projection'].get('projection_id') != value['ledger_projection'].get('projection_id'):
                    raise ValueError('Retained task projection identity changed')
                continue
            if db.execute('SELECT count(*) FROM retained_task_projections').fetchone()[0] >= MAX_RETAINED_PROJECTIONS:
                raise ValueError('Pending task projection retention capacity exceeded')
            retained = copy.deepcopy(value)
            retained.pop('capture_publication', None)
            for field in ('baseline', 'end'):
                snapshot = retained.get(field)
                if isinstance(snapshot, dict):
                    snapshot.pop('capture_source', None)
                    if batched(value):
                        from .snapshot_pages import MAPS, LISTS, POINTER
                        # Ledger basis and original risk anchors depend on end
                        # hashes. Retain those facts, without source references.
                        end_hashes = snapshot.get('hashes', {}) if field == 'end' else {}
                        for key in (*MAPS, *LISTS, POINTER):
                            snapshot.pop(key, None)
                        # A retained ledger is not a resumable source snapshot.
                        snapshot.update(hashes=end_hashes, inventory=[], preimages={}, texts={})
                    for body in ('texts', 'semantic_proofs', 'text_truncations'):
                        snapshot.pop(body, None)
            retained.pop('packet', None)
            retained['retained_for_projection'] = True
            retained_raw = encode(retained)
            if len(retained_raw) > MAX_RECORD_BYTES:
                raise ValueError('Retained task projection budget exceeded')
            db.execute('INSERT INTO retained_task_projections VALUES(?,?,?,?)',
                       (ref, retained_raw.decode(), digest(self.key(), retained), self.now()))

    @guarded_read
    def pending_projections(self, limit=8):
        """Read authenticated expired obligations without reviving tasks or evidence."""
        if type(limit) is not int or not 1 <= limit <= MAX_RETAINED_PROJECTIONS:
            raise ValueError('Invalid pending task projection limit')
        no_links(self.path)
        if not self.path.is_file(): return []
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='retained_task_projections'").fetchone():
                return []
            rows = db.execute('SELECT data,mac FROM retained_task_projections ORDER BY created,ref LIMIT ?',
                              (MAX_RETAINED_PROJECTIONS+1,)).fetchall()
        if len(rows) > MAX_RETAINED_PROJECTIONS:
            raise ValueError('Pending task projection retention capacity exceeded')
        from .projection import status
        selected = []
        for row in rows:
            value = self.decode(row)
            if value.get('retained_for_projection') is not True:
                raise ValueError('Retained task projection cannot be verified')
            if status(value)['pending']:
                selected.append(value)
                if len(selected) == limit: break
        return selected

    @guarded_read
    def ack_retained_projection(self, candidate):
        """Acknowledge only the original signed obligation; no task is rewritten."""
        from .projection import status
        if (candidate.get('retained_for_projection') is not True
                or status(candidate)['state'] not in {'APPLIED', 'SUPERSEDED'}):
            raise ValueError('Invalid retained task projection acknowledgement')
        self.hooks.prepare_database(self.root, 'task-security.db')
        no_links(self.path)
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT data,mac FROM retained_task_projections WHERE ref=?',
                             (candidate['task_ref'],)).fetchone()
            current = self.decode(row)
            if (not current or current.get('retained_for_projection') is not True
                    or current['ledger_projection'].get('projection_id') != candidate['ledger_projection'].get('projection_id')):
                raise ValueError('Retained task projection changed')
            if not status(current)['pending']: return current
            updated = dict(current, ledger_projection=dict(candidate['ledger_projection']))
            raw = encode(updated)
            db.execute('UPDATE retained_task_projections SET data=?,mac=? WHERE ref=? AND data=? AND mac=?',
                       (raw.decode(), digest(self.key(), updated), updated['task_ref'], row[0], row[1]))
            return updated

    def save(self, value, *, new=False, session_idle=False):
        if value.get('contract') == REVIEW_CONTRACT:
            raise _PagedReviewHead('Paged review heads require their atomic task store')
        from .capture_source_profile import validate_record
        validate_record(value)
        if new:
            require_record_protocol(value)
        self._preflight_capture_transition(value, new=new)
        # Collection itself reads strict metadata permissions. An explicit
        # writer must admit old owned storage before entering that path.
        self.hooks.prepare_private_writer(self.root)
        self._prepare_publication_birth(value, new=new)
        if managed(value):
            from .snapshot_gc import collect_pages
            # No lock upgrade: collection completes before shared publication.
            collect_pages(self, prune=True)
        with page_guard(self.path.parent, create=managed(value)):
            return self._save(value, new=new, session_idle=session_idle)

    def save_review(self, value):
        from .review_control import save
        return save(self, value)

    def save_projection(self, value):
        from .review_control import save_projection
        return save_projection(self, value)

    def _save(self, value, *, new=False, session_idle=False):
        # Keep direct callers under the same source/GC fence as save(). First
        # allocation must precede a shared fence, including on this path.
        self._preflight_capture_transition(value, new=new)
        self.hooks.prepare_private_writer(self.root)
        self._prepare_publication_birth(value, new=new)
        with page_guard(self.path.parent, create=managed(value)):
            return self._save_impl(value, new=new, session_idle=session_idle)

    def _save_impl(self, value, *, new=False, session_idle=False):
        if value.get('contract') == REVIEW_CONTRACT:
            raise _PagedReviewHead('Paged review heads require their atomic task store')
        from .capture_source_profile import validate_record, validate_transition as validate_capture_transition
        validate_record(value)
        if new:
            require_record_protocol(value)
        self._preflight_capture_transition(value, new=new)
        self.hooks.prepare_private_writer(self.root)
        self._prepare_publication_birth(value, new=new)
        # Object/page I/O completes before taking the task/control write lock.
        from .snapshot_pages import pack
        packed = pack(self, value)
        self.hooks.prepare_database(self.root, 'task-security.db')
        no_links(self.path)
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            db.execute('PRAGMA secure_delete=ON')
            db.execute('CREATE TABLE IF NOT EXISTS security_tasks (ref TEXT PRIMARY KEY, task_key TEXT NOT NULL, phase TEXT NOT NULL, created REAL NOT NULL, data TEXT NOT NULL, mac TEXT NOT NULL)')
            db.execute('BEGIN IMMEDIATE')
            self._validate_publication_retention(db)
            self._retain_pending(db)
            for expired_ref, raw, mac in db.execute('SELECT ref,data,mac FROM security_tasks WHERE created<?', (self.now()-TTL,)).fetchall():
                if self.retention_head((raw, mac)).get('contract') == REVIEW_CONTRACT:
                    continue
                expired_record = self.decode((raw, mac))
                if self.expired(expired_record):
                    self.expire_queued_task(expired_record)
                    from .capture_publication_store import retire_for_task
                    retire_for_task(self, expired_record, db=db)
                    db.execute('DELETE FROM security_tasks WHERE ref=?', (expired_ref,))
            old = self.decode(db.execute('SELECT data,mac FROM security_tasks WHERE ref=?', (value['task_ref'],)).fetchone())
            if (new and old) or (not new and (not old or old['generation'] != value['generation'])):
                raise ValueError('Task changed concurrently; read current task first')
            validate_capture_transition(old, value, new=new)
            from .capture_publication_store import validate_transition as validate_publication
            validate_publication(old, value, new=new)
            from .frozen_body_context import validate_transition
            validate_transition(self.hooks, self.root, old, value, new=new, now=self.now)
            from .frozen_end_context import validate_end_transition
            validate_end_transition(self.hooks, self.root, old, value, new=new, now=self.now)
            if new:
                rows = db.execute('SELECT data,mac FROM security_tasks LIMIT ?',
                                  (MAX_HISTORY_RECORDS+1,)).fetchall()
                # Protocol classification must use authenticated records. Old
                # history retains its bytes and its own bounded reserve; it
                # cannot consume the unchanged v3 task allowance.
                records = [self.retention_head(row) for row in rows]
                if (len(records) >= MAX_HISTORY_RECORDS or
                        sum(is_v3_record(item) for item in records) >= MAX_V3_RECORDS):
                    raise ValueError('Task history budget exceeded')
            from .ownership import ACTIVE, LEASE_SECONDS
            value = dict(value, generation=value['generation']+1, activity_at=self.now())
            value.pop('session_idle', None)
            if session_idle:
                from .ownership import record_owner, valid_owner
                owner = record_owner(value)
                if (not is_v3_record(value) or value['phase'] != 'ACTIVE'
                        or not valid_owner(owner) or owner['host'] not in {'codex', 'cursor'}):
                    raise ValueError('Invalid task session idle checkpoint')
                value['session_idle'] = dict(contract='task-session-idle-v1',
                    observed_at=value['activity_at'], generation=value['generation'])
            if value['phase'] in ACTIVE:
                value['lease_until']=self.now()+LEASE_SECONDS
                value.pop('closed_at',None)
            else: value.setdefault('closed_at',self.now())
            value = persistent_record(value)
            stored = dict(value)
            for field in ('baseline', 'end'):
                if field in packed:
                    stored[field] = packed[field]
            if new and self.birth_publication:
                from .capture_source_profile import POLICY
                if value.get('capture_policy') == POLICY:
                    from .capture_publication_store import birth_in_transaction
                    stored, value = birth_in_transaction(self, db, stored, value)
            raw = encode(stored)
            if len(raw) > MAX_RECORD_BYTES:
                raise ValueError('Task record budget exceeded')
            db.execute('INSERT OR REPLACE INTO security_tasks VALUES(?,?,?,?,?,?)',
                       (value['task_ref'], value['task_key'], value['phase'], value['created_at'], raw.decode(), digest(self.key(), stored)))
        try:
            from ..product_metrics import task_record_observed
            task_record_observed(value)
        except Exception:
            pass  # Already committed; optional observation never controls it.
        from .activity import deferred, ActivityStore
        if deferred(value):
            ActivityStore(self.hooks, self.root, now=self.now).touch(value['task_ref'], value['activity_at'], value['phase'])
        return value

    def expire_queued_task(self, record):
        if managed(record):
            from .closeout_queue import CloseoutQueue
            CloseoutQueue(self.hooks, self.root, now=self.now).expire_for_task(record)

    @guarded_read
    def for_scan(self, scan_id):
        """Bounded read-only migration lookup, retaining signed legacy facts."""
        no_links(self.path)
        if not self.path.is_file():
            return []
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            rows = db.execute(f'SELECT data,mac FROM security_tasks ORDER BY rowid DESC LIMIT {MAX_HISTORY_RECORDS}').fetchall()
        values = [self.decode(row) for row in rows]
        return [v for v in values if v and not self.expired(v)
                and v.get('end') and (v.get('static') or {}).get('scan_id') == scan_id]

    def _hook_failure_path(self, ref):
        if not isinstance(ref, str) or not REF.fullmatch(ref):
            raise ValueError('Invalid task reference')
        path = self.path.parent / f'task-hook-{ref}.failed'
        no_links(path)
        return path

    def get_hook_failure(self, ref):
        """Read a same-workspace/task failure receipt, never an edit grant.

        Missing/expired receipts return None. Invalid, oversized or linked
        state raises; callers must preserve a coverage gap instead of silently
        treating unreadable failure evidence as absence of a failure.
        """
        path = self._hook_failure_path(ref)
        if not path.exists():
            return None
        if not path.is_file():
            raise ValueError('Hook failure record is not a file')
        if path.stat().st_size > MAX_HOOK_FAILURE_BYTES:
            raise ValueError('Hook failure record budget exceeded')
        with path.open('rb') as stream:
            raw = stream.read(MAX_HOOK_FAILURE_BYTES+1)
        if len(raw) > MAX_HOOK_FAILURE_BYTES:
            raise ValueError('Hook failure record budget exceeded')
        envelope = json.loads(raw)
        if not isinstance(envelope, dict) or set(envelope) != {'data', 'mac'}:
            raise ValueError('Hook failure record cannot be verified')
        value = envelope['data']
        fields = {'contract', 'version', 'workspace', 'task_ref', 'task_created_at', 'updated_at',
                  'revision', 'failure_count', 'scope_files', 'scope_paths_omitted', 'scan_ids', 'scan_ids_omitted'}
        if (not isinstance(value, dict) or set(value) != fields or value['contract'] != HOOK_FAILURE_CONTRACT
                or type(value['version']) is not int or value['version'] != 1
                or value['workspace'] != str(self.root) or value['task_ref'] != ref
                or not isinstance(envelope['mac'], str)
                or not re.fullmatch(r'[a-f0-9]{64}', envelope['mac'])
                or not hmac.compare_digest(envelope['mac'], digest(self.key(), value))):
            raise ValueError('Hook failure record cannot be verified')
        if any(type(value[key]) is not int or value[key] < (1 if key in {'revision','failure_count'} else 0)
               for key in ('revision','failure_count','scope_paths_omitted','scan_ids_omitted')):
            raise ValueError('Invalid Hook failure record counters')
        if (any(type(value[key]) not in (int, float) or not math.isfinite(value[key])
                or value[key] < 0 for key in ('task_created_at', 'updated_at'))
                or value['updated_at'] < value['task_created_at']):
            raise ValueError('Invalid Hook failure record time')
        from ..hook_runtime import safe_path
        paths = value['scope_files']
        if (not isinstance(paths, list) or len(paths) > MAX_HOOK_FAILURE_FILES
                or any(not isinstance(name, str) for name in paths)
                or len(set(paths)) != len(paths)
                or sum(len(safe_path(name).encode('utf-8')) for name in paths) > MAX_HOOK_FAILURE_PATH_BYTES):
            raise ValueError('Invalid Hook failure record scope')
        scan_ids = value['scan_ids']
        if (not isinstance(scan_ids, list) or len(scan_ids) > 8
                or any(not isinstance(scan_id, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,100}', scan_id)
                       for scan_id in scan_ids) or len(set(scan_ids)) != len(scan_ids)):
            raise ValueError('Invalid Hook failure scan references')
        if self.now() - value['task_created_at'] > TTL:
            return None
        return value

    def record_hook_failure(self, ref, *, task_created_at, scope_files=(), scan_id=None):
        """Independent bounded receipt if the task DB cannot record an edit.

        Reuse the workspace lock/key and task TTL. Concurrent failed edits
        merge their scopes before one atomic replacement; an unavailable lock
        or unverified existing receipt must remain a visible Host gap.
        """
        path = self._hook_failure_path(ref)
        if (type(task_created_at) not in (int, float) or not math.isfinite(task_created_at)
                or not 0 <= self.now()-task_created_at <= TTL):
            raise ValueError('Hook failure task lifetime cannot be verified')
        if scan_id is not None and (not isinstance(scan_id, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,100}', scan_id)):
            raise ValueError('Invalid Hook failure scan reference')
        from ..hook_runtime import safe_path
        proposed = {safe_path(name) for name in scope_files}
        with self.hooks.lock(self.root, wait_seconds=2) as acquired:
            if not acquired:
                raise ValueError('Hook failure record is busy')
            previous = self.get_hook_failure(ref)
            if previous and previous['task_created_at'] != task_created_at:
                raise ValueError('Hook failure task lifetime changed')
            if not path.is_file():
                # Retention follows the existing task TTL, without a new job
                # or lifecycle. Never hand these files to generic *.json GC.
                retained = 0
                for old in self.path.parent.glob('task-hook-ts1-*.failed'):
                    old_ref = old.name[len('task-hook-'):-len('.failed')]
                    if not REF.fullmatch(old_ref):
                        continue
                    if self.get_hook_failure(old_ref) is None:
                        no_links(old)
                        old.unlink(missing_ok=True)
                    else:
                        retained += 1
                        if retained >= MAX_HOOK_FAILURE_MARKERS:
                            raise ValueError('Hook failure history budget exceeded')
            ordered = sorted(proposed | set(previous['scope_files'] if previous else ()))
            selected, size = [], 0
            for name in ordered:
                cost = len(name.encode('utf-8'))
                if len(selected) >= MAX_HOOK_FAILURE_FILES or size+cost > MAX_HOOK_FAILURE_PATH_BYTES:
                    break
                selected.append(name)
                size += cost
            scans = list(previous['scan_ids'] if previous else ())
            if scan_id and scan_id not in scans:
                scans.append(scan_id)
            value = dict(contract=HOOK_FAILURE_CONTRACT, version=1, workspace=str(self.root), task_ref=ref,
                task_created_at=task_created_at, updated_at=self.now(), revision=(previous['revision'] if previous else 0)+1,
                failure_count=(previous['failure_count'] if previous else 0)+1, scope_files=selected,
                scope_paths_omitted=(previous['scope_paths_omitted'] if previous else 0)+len(ordered)-len(selected),
                scan_ids=scans[-8:], scan_ids_omitted=(previous['scan_ids_omitted'] if previous else 0)+max(0,len(scans)-8))
            raw = json.dumps({'data':value, 'mac':digest(self.key(), value)}, ensure_ascii=False,
                             separators=(',', ':')).encode('utf-8')
            if len(raw) > MAX_HOOK_FAILURE_BYTES:
                raise ValueError('Hook failure record budget exceeded')
            atomic_bytes(path, raw)
            return value
