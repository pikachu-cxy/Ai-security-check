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

from .closeout_state import digest, encode, readonly_uri
from .hook_state import atomic_bytes, no_links

CONTRACT = 'task-security-v1'
REF = re.compile(r'ts1-[a-f0-9]{32}')
MAX_RECORD_BYTES = 4_000_000
TTL = 24 * 3600
HOOK_FAILURE_CONTRACT = 'task-hook-recording-failure-v1'
MAX_HOOK_FAILURE_BYTES = 160_000
MAX_HOOK_FAILURE_FILES = 1000
MAX_HOOK_FAILURE_PATH_BYTES = 128_000
MAX_HOOK_FAILURE_MARKERS = 32


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

    def get(self, ref=None, *, active=False, task_key=None):
        no_links(self.path)
        if ref is not None and (not isinstance(ref, str) or not REF.fullmatch(ref)):
            raise ValueError('Invalid task reference')
        if not self.path.is_file():
            return None
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            if ref:
                row = db.execute('SELECT data,mac FROM security_tasks WHERE ref=?', (ref,)).fetchone()
            elif active:
                row = db.execute("SELECT data,mac FROM security_tasks WHERE phase IN ('ACTIVE','STATIC_RUNNING','READY','REVIEWING') ORDER BY rowid DESC LIMIT 1").fetchone()
            else:
                row = db.execute('SELECT data,mac FROM security_tasks WHERE task_key=? ORDER BY rowid DESC LIMIT 1', (task_key,)).fetchone()
            value = self.decode(row)
            if value and self.now() - value['created_at'] > TTL:
                return None
            return value

    def save(self, value, *, new=False):
        no_links(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            db.execute('PRAGMA secure_delete=ON')
            db.execute('CREATE TABLE IF NOT EXISTS security_tasks (ref TEXT PRIMARY KEY, task_key TEXT NOT NULL, phase TEXT NOT NULL, created REAL NOT NULL, data TEXT NOT NULL, mac TEXT NOT NULL)')
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM security_tasks WHERE created<?', (self.now()-TTL,))
            old = self.decode(db.execute('SELECT data,mac FROM security_tasks WHERE ref=?', (value['task_ref'],)).fetchone())
            if (new and old) or (not new and (not old or old['generation'] != value['generation'])):
                raise ValueError('Task changed concurrently; read current task first')
            if new and db.execute('SELECT count(*) FROM security_tasks').fetchone()[0] >= 32:
                raise ValueError('Task history budget exceeded')
            value = dict(value, generation=value['generation']+1)
            raw = encode(value)
            if len(raw) > MAX_RECORD_BYTES:
                raise ValueError('Task record budget exceeded')
            db.execute('INSERT OR REPLACE INTO security_tasks VALUES(?,?,?,?,?,?)',
                       (value['task_ref'], value['task_key'], value['phase'], value['created_at'], raw.decode(), digest(self.key(), value)))
            return value

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
        from .hook_runtime import safe_path
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
        from .hook_runtime import safe_path
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
