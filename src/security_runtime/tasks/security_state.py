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
from ..task_review.protocol import require_record_protocol, is_v3_record

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
    plan = value.get('review_plan')
    if (is_v3_record(value) and isinstance(plan, dict)
            and plan.get('contract') == 'task-review-plan-v3'
            and isinstance(value.get('review_ledger'), dict)):
        return dict(value, review_plan={key: item for key, item in plan.items() if key != 'budget'})
    return value


class TaskSecurityStore:
    def __init__(self, hooks, root, *, now=time.time):
        self.root, self.hooks, self.now = root, hooks, now
        self.path = hooks.workspace_directory(root) / 'task-security.db'

    def key(self):
        path = self.path.parent / 'snapshot.key'
        no_links(path)
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError('Task key cannot be verified')
        return key

    def decode(self, row):
        if not row:
            return None
        raw, mac = row
        if len(raw.encode()) > MAX_RECORD_BYTES:
            raise ValueError('Task record budget exceeded')
        value = json.loads(raw)
        if (value.get('contract') != CONTRACT or not REF.fullmatch(value.get('task_ref', ''))
                or value.get('workspace') != str(self.root)
                or not hmac.compare_digest(mac, digest(self.key(), value))):
            raise ValueError('Task state cannot be verified')
        return value

    def records(self, *, active=False):
        """Bounded signed inventory; never selects a newest foreign task."""
        no_links(self.path)
        if not self.path.is_file(): return []
        with closing(sqlite3.connect(readonly_uri(self.path),uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            # Per-edit routing need not deserialize completed tasks' source
            # packets. Keep the signed phase/TTL checks below as well.
            predicate="WHERE phase IN ('ACTIVE','STATIC_RUNNING','READY','REVIEWING')" if active else ''
            rows=db.execute(f'SELECT data,mac FROM security_tasks {predicate} ORDER BY rowid DESC LIMIT {MAX_HISTORY_RECORDS}').fetchall()
        from .ownership import ACTIVE
        records=[self.decode(row) for row in rows]
        return [v for v in records if v and self.now()-v['created_at']<=TTL and (not active or v['phase'] in ACTIVE)]

    def get(self, ref=None, *, active=False, task_key=None, owner=None):
        no_links(self.path)
        if ref is not None and (not isinstance(ref, str) or not REF.fullmatch(ref)):
            raise ValueError('Invalid task reference')
        if not self.path.is_file():
            return None
        if active and ref is None:
            from .ownership import record_owner
            values=[v for v in self.records(active=True) if is_v3_record(v)
                    and (owner is None or record_owner(v)==owner)]
            return values[0] if len(values)==1 else None
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            if ref:
                row = db.execute('SELECT data,mac FROM security_tasks WHERE ref=?', (ref,)).fetchone()
            else:
                row = db.execute('SELECT data,mac FROM security_tasks WHERE task_key=? ORDER BY rowid DESC LIMIT 1', (task_key,)).fetchone()
            value = self.decode(row)
            if value and self.now() - value['created_at'] > TTL:
                return None
            return value

    def for_hook(self, host, session):
        from .ownership import record_owner
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
            value = self.decode((raw, mac))
            if created < self.now()-TTL and not status(value)['pending']:
                db.execute('DELETE FROM retained_task_projections WHERE ref=?', (ref,))
        expired = db.execute('SELECT ref,data,mac FROM security_tasks WHERE created<?',
                             (self.now()-TTL,)).fetchall()
        for ref, raw, mac in expired:
            value = self.decode((raw, mac))
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
            for field in ('baseline', 'end'):
                snapshot = retained.get(field)
                if isinstance(snapshot, dict):
                    for body in ('texts', 'semantic_proofs', 'text_truncations'):
                        snapshot.pop(body, None)
            retained.pop('packet', None)
            retained['retained_for_projection'] = True
            retained_raw = encode(retained)
            if len(retained_raw) > MAX_RECORD_BYTES:
                raise ValueError('Retained task projection budget exceeded')
            db.execute('INSERT INTO retained_task_projections VALUES(?,?,?,?)',
                       (ref, retained_raw.decode(), digest(self.key(), retained), self.now()))

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

    def ack_retained_projection(self, candidate):
        """Acknowledge only the original signed obligation; no task is rewritten."""
        from .projection import status
        if (candidate.get('retained_for_projection') is not True
                or status(candidate)['state'] not in {'APPLIED', 'SUPERSEDED'}):
            raise ValueError('Invalid retained task projection acknowledgement')
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
        if new:
            require_record_protocol(value)
        no_links(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            db.execute('PRAGMA secure_delete=ON')
            db.execute('CREATE TABLE IF NOT EXISTS security_tasks (ref TEXT PRIMARY KEY, task_key TEXT NOT NULL, phase TEXT NOT NULL, created REAL NOT NULL, data TEXT NOT NULL, mac TEXT NOT NULL)')
            db.execute('BEGIN IMMEDIATE')
            self._retain_pending(db)
            db.execute('DELETE FROM security_tasks WHERE created<?', (self.now()-TTL,))
            old = self.decode(db.execute('SELECT data,mac FROM security_tasks WHERE ref=?', (value['task_ref'],)).fetchone())
            if (new and old) or (not new and (not old or old['generation'] != value['generation'])):
                raise ValueError('Task changed concurrently; read current task first')
            if new:
                rows = db.execute('SELECT data,mac FROM security_tasks LIMIT ?',
                                  (MAX_HISTORY_RECORDS+1,)).fetchall()
                # Protocol classification must use authenticated records. Old
                # history retains its bytes and its own bounded reserve; it
                # cannot consume the unchanged v3 task allowance.
                records = [self.decode(row) for row in rows]
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
            raw = encode(value)
            if len(raw) > MAX_RECORD_BYTES:
                raise ValueError('Task record budget exceeded')
            db.execute('INSERT OR REPLACE INTO security_tasks VALUES(?,?,?,?,?,?)',
                       (value['task_ref'], value['task_key'], value['phase'], value['created_at'], raw.decode(), digest(self.key(), value)))
        try:
            from ..product_metrics import task_record_observed
            task_record_observed(value)
        except Exception:
            pass  # Already committed; optional observation never controls it.
        return value

    def for_scan(self, scan_id):
        """Bounded read-only migration lookup, retaining signed legacy facts."""
        no_links(self.path)
        if not self.path.is_file():
            return []
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            rows = db.execute(f'SELECT data,mac FROM security_tasks ORDER BY rowid DESC LIMIT {MAX_HISTORY_RECORDS}').fetchall()
        values = [self.decode(row) for row in rows]
        return [v for v in values if v and self.now()-v['created_at'] <= TTL
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
