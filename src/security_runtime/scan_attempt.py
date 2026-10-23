"""Signed workspace scan leases and bounded private-input cleanup obligations.

Leases coordinate execution only. They grant no editing, repair or review
authority. Every mutation requires the real cross-process workspace lock;
queries never initialize state or renew a lease.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import stat
import threading
import time
import uuid

from .hook_state import atomic_bytes, native_io_path, no_links
from .progress import NullProgressReporter, ScanCancelled

CONTRACT = 'workspace-scan-attempt-v1'
STATE_CONTRACT = 'workspace-scan-attempt-v2'
MAX_DIRECTORIES = 64
MAX_BYTES = 131072
_HEX = re.compile('[a-f0-9]{64}')
_INPUT_NAME = re.compile('(?:runtime-input-|i-)[a-f0-9]{32}')
_INPUT_NAMESPACE = 'STATE_ROOT_V2'


def _input_parent(hooks):
    """Keep raw bytes in the state boundary without repeating workspace hashes.

    The global adapter owns <state>/global-workspaces/<id>/hooks. Other Hook
    stores own their supplied directory. Only that exact known global shape
    is shortened; arbitrary configured directories never escape their root.
    """
    directory = Path(hooks.directory).resolve()
    anchor = directory
    if directory.name == 'hooks':
        anchor = directory.parent
        if _HEX.fullmatch(anchor.name) and anchor.parent.name == 'global-workspaces':
            anchor = anchor.parent.parent
    return anchor / 'i'


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def source_binding(value, *, source_kind='WORKTREE'):
    """Bind caller-owned snapshot metadata, never substitute it for byte checks."""
    if source_kind not in {'WORKTREE', 'INDEX'}:
        raise ValueError('Invalid scan source kind')
    return dict(contract='scan-attempt-source-v1', source_kind=source_kind,
                revision=hashlib.sha256(_encode(value)).hexdigest())


@dataclass(frozen=True)
class AttemptLease:
    attempt_id: str
    generation: int
    lease_owner: str
    cancel_generation: int

    @property
    def receipt(self):
        return dict(contract=CONTRACT, attempt_id=self.attempt_id,
                    generation=self.generation, cancel_generation=self.cancel_generation)


class ScanAttemptLost(ScanCancelled):
    """The worker has no publication fence; retain pending work and its baseline."""


class ScanAttemptStore:
    def __init__(self, hooks, root, *, now=time.time):
        self.hooks, self.root, self.now = hooks, Path(root).resolve(), now
        directory = hooks.workspace_directory(self.root)
        no_links(directory)
        # Capture canonicalizes its private parent (including Windows TEMP 8.3
        # aliases). Compare one checked namespace, never lexical alias strings.
        self.path = directory.resolve() / 'scan-attempt.state'
        self.legacy_private_parent = self.path.parent / 'scan-inputs'
        self.private_parent = _input_parent(hooks)

    def _locked(self):
        if not self.hooks.lock_held(self.root):
            raise ValueError('Scan attempt workspace lock required')

    def _key(self):
        path = self.path.parent / 'snapshot.key'
        no_links(path)
        key = path.read_bytes()
        if len(key) != 32: raise ValueError('Scan attempt key cannot be verified')
        return key

    def read(self):
        no_links(self.path)
        if not self.path.exists():
            return dict(contract=STATE_CONTRACT, workspace=str(self.root), generation=0, lane=None, directories=[])
        if not self.path.is_file() or self.path.stat().st_size > MAX_BYTES:
            raise ValueError('Scan attempt state cannot be verified')
        raw = self.path.read_bytes()
        if len(raw) > MAX_BYTES: raise ValueError('Scan attempt state budget exceeded')
        envelope = json.loads(raw)
        if not isinstance(envelope, dict) or set(envelope) != {'content', 'mac'}:
            raise ValueError('Scan attempt envelope cannot be verified')
        value = envelope['content']
        if (not isinstance(value, dict) or value.get('contract') not in {CONTRACT, STATE_CONTRACT}
                or value.get('workspace') != str(self.root)
                or type(value.get('generation')) is not int or value['generation'] < 0
                or not isinstance(value.get('directories'), list) or len(value['directories']) > MAX_DIRECTORIES
                or not isinstance(envelope['mac'], str)
                or not hmac.compare_digest(envelope['mac'], hmac.new(self._key(), _encode(value), hashlib.sha256).hexdigest())):
            raise ValueError('Scan attempt signature cannot be verified')
        return value

    def _save(self, value):
        self._locked()
        self.hooks.key(self.root)
        # New directory obligations cannot be read safely by the v1 writer:
        # it assumes every name belongs to the legacy scan-inputs directory.
        # Upgrade signed v1 state only on a real mutation; queries stay pure.
        value = dict(value, contract=STATE_CONTRACT)
        raw = _encode(dict(content=value, mac=hmac.new(self._key(), _encode(value), hashlib.sha256).hexdigest()))
        if len(raw) > MAX_BYTES: raise ValueError('Scan attempt state budget exceeded')
        atomic_bytes(self.path, raw)

    @staticmethod
    def _matches(row, lease):
        return isinstance(lease, AttemptLease) and row is not None and all(row.get(key) == getattr(lease, key)
            for key in ('attempt_id', 'generation', 'lease_owner', 'cancel_generation'))

    def _current(self, value, lease, input_id=None):
        row = value['lane']
        return (self._matches(row, lease) and row.get('state') == 'ACTIVE'
                and self.now() < row['expires_at']
                and (input_id is None or row.get('input_id') == input_id))

    def is_current(self, lease, input_id=None):
        return self._current(self.read(), lease, input_id)

    def claim(self, kind, scope_key, source_binding, owner=None, lease_seconds=600):
        self._locked()
        if (kind not in {'TASK', 'HOOK', 'CLOSEOUT', 'MANUAL', 'VERIFY'} or not isinstance(scope_key, str)
                or not 1 <= len(scope_key) <= 128 or any(ord(c) < 32 for c in scope_key)
                or type(lease_seconds) not in {int, float} or not 1 <= lease_seconds <= 3600
                or not isinstance(source_binding, dict)
                or set(source_binding) != {'contract', 'revision', 'source_kind'}
                or source_binding['contract'] != 'scan-attempt-source-v1'
                or source_binding['source_kind'] not in {'WORKTREE', 'INDEX'}
                or not isinstance(source_binding['revision'], str)
                or _HEX.fullmatch(source_binding['revision']) is None):
            raise ValueError('Invalid bounded scan attempt request')
        if owner is not None:
            from .tasks.ownership import valid_owner
            if not valid_owner(owner): raise ValueError('Invalid scan attempt owner')
        no_links(self.private_parent)
        if self.private_parent.resolve().is_relative_to(self.root):
            raise ValueError('Private scan input cannot be stored inside source workspace')
        value = self.read()
        if value['lane'] and value['lane']['state'] == 'ACTIVE' and self.now() < value['lane']['expires_at']:
            return None
        if len(value['directories']) >= MAX_DIRECTORIES:
            raise ValueError('Private input cleanup pending; scan attempt capacity exceeded')
        # Initialize before publishing ACTIVE. A failed mkdir must not occupy
        # the shared lane for the entire lease after its underlying cause ends.
        from .scan_input import check_private_input_parent
        check_private_input_parent(self.private_parent)
        no_links(self.private_parent)
        self.private_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        no_links(self.private_parent)
        # Windows package redirection/8.3 spelling may canonicalize differently
        # only after creation. Capture and cleanup must share that exact root.
        self.private_parent = self.private_parent.resolve(strict=True)
        no_links(self.private_parent)
        check_private_input_parent(self.private_parent)
        if self.private_parent.is_relative_to(self.root):
            raise ValueError('Private scan input cannot be stored inside source workspace')
        if not self.private_parent.is_dir():
            raise ValueError('Private scan input parent is not a directory')
        value['generation'] += 1
        lease = AttemptLease('sa1-' + uuid.uuid4().hex, value['generation'], uuid.uuid4().hex, 0)
        row = dict(lease.__dict__, kind=kind, scope_key=scope_key, source_binding=dict(source_binding),
                   owner=owner, state='ACTIVE', created_at=self.now(), expires_at=self.now()+lease_seconds,
                   lease_seconds=lease_seconds, input_id=None, source_revision=None, scan_id=None)
        value['lane'] = row
        self._save(value)
        return lease

    def bind_input(self, lease, view):
        self._locked()
        value = self.read()
        if not self._current(value, lease): return False
        row = value['lane']
        if row['input_id'] not in {None, view.input_id}: return False
        if view.request.workspace_root != self.root or str(view.request.source_kind) != row['source_binding']['source_kind']:
            return False
        row.update(input_id=view.input_id, source_revision=view.source_revision)
        self._save(value)
        return True

    def renew(self, lease):
        self._locked()
        value = self.read()
        if not self._current(value, lease): return False
        value['lane']['expires_at'] = self.now() + value['lane']['lease_seconds']
        self._save(value)
        return True

    def finish(self, lease, *, input_id=None, scan_id=None, outcome='COMPLETED'):
        self._locked()
        if outcome not in {'COMPLETED', 'STALE', 'FAILED', 'CANCELLED'}:
            raise ValueError('Invalid scan attempt outcome')
        value = self.read()
        if not self._current(value, lease, input_id): return False
        value['lane'].update(state=outcome, scan_id=scan_id, finished_at=self.now())
        self._save(value)
        return True

    def cancel(self, lease):
        self._locked()
        value = self.read()
        if not self._current(value, lease): return False
        value['lane'].update(state='CANCELLED', cancel_generation=lease.cancel_generation+1, finished_at=self.now())
        self._save(value)
        return True

    def retire(self, lease, *, outcome='FAILED'):
        """Retire this exact abandoned lane, even after expiry; never publish."""
        self._locked()
        if outcome not in {'FAILED', 'STALE'}:
            raise ValueError('Invalid abandoned scan attempt outcome')
        value = self.read()
        if not self._matches(value['lane'], lease) or value['lane'].get('state') != 'ACTIVE':
            return False
        value['lane'].update(state=outcome, finished_at=self.now())
        self._save(value)
        return True

    def _directory_parent(self, row):
        namespace = row.get('input_namespace')
        if namespace is None:
            # Pre-upgrade signed obligations always belong to the old root.
            return self.legacy_private_parent
        if namespace == _INPUT_NAMESPACE:
            return self.private_parent
        raise ValueError('Unknown private input cleanup namespace')

    def register_directory(self, lease, path):
        self._locked()
        path = Path(path)
        no_links(path)
        if path.parent != self.private_parent or _INPUT_NAME.fullmatch(path.name) is None:
            raise ValueError('Private input cleanup path is outside managed namespace')
        value = self.read()
        if not self._current(value, lease): return False
        if len(value['directories']) >= MAX_DIRECTORIES: raise ValueError('Private input cleanup capacity exceeded')
        info = path.stat()
        value['directories'].append(dict(name=path.name, input_namespace=_INPUT_NAMESPACE, attempt_id=lease.attempt_id,
            generation=lease.generation, device=info.st_dev, inode=info.st_ino))
        self._save(value)
        return True

    def release_directory(self, lease, path):
        self._locked()
        path = Path(path)
        no_links(path)
        if path.parent != self.private_parent or path.exists(): return False
        value = self.read()
        rows = value['directories']
        value['directories'] = [row for row in rows if not (row['name'] == path.name
            and self._directory_parent(row) == path.parent
            and row['attempt_id'] == lease.attempt_id and row['generation'] == lease.generation)]
        if rows != value['directories']: self._save(value)
        return True

    def recover_cleanup(self, limit=4):
        """Claim metadata briefly; private bytes are removed outside the lock.

        Cleanup claims have their own owner/expiry. They cannot renew a scan,
        grant publication authority, or erase another worker's live input.
        """
        if self.hooks.lock_held(self.root):
            raise ValueError('Private input cleanup must run outside workspace lock')
        if type(limit) is not int or not 1 <= limit <= 8:
            raise ValueError('Invalid cleanup limit')
        selected = []
        with self.hooks.lock(self.root) as acquired:
            if not acquired: return dict(cleaned=0, pending=True)
            value = self.read()
            active = value['lane']
            for row in value['directories']:
                live = (active and active['state']=='ACTIVE' and self.now()<active['expires_at']
                    and row['attempt_id']==active['attempt_id'] and row['generation']==active['generation'])
                if live or self.now()<row.get('cleanup_expires_at',0): continue
                row.update(cleanup_owner=uuid.uuid4().hex, cleanup_expires_at=self.now()+600)
                selected.append(dict(row))
                if len(selected)==limit: break
            if selected: self._save(value)
        cleaned = []
        for row in selected:
            try:
                parent = self._directory_parent(row)
                path = parent/row['name']
                if (_INPUT_NAME.fullmatch(row['name']) is None or
                        row.get('input_namespace') is None and not row['name'].startswith('runtime-input-')):
                    raise ValueError('Unknown private input namespace')
                no_links(path)
                if path.exists():
                    info=path.stat()
                    if (info.st_dev,info.st_ino)!=(row['device'],row['inode']):
                        raise ValueError('Private input directory replaced')
                    count=0
                    for directory,children,files in os.walk(path,followlinks=False):
                        count+=len(children)+len(files)
                        if count>30000: raise ValueError('Private input cleanup inventory budget exceeded')
                        no_links(Path(directory))
                        for name in (*children,*files): no_links(Path(directory)/name)
                    def writable(function,name,error):
                        os.chmod(name,stat.S_IREAD|stat.S_IWRITE)
                        function(name)
                    shutil.rmtree(native_io_path(path),onexc=writable)
                cleaned.append(row['cleanup_owner'])
            except (ValueError,OSError):
                pass  # Keep signed obligations and unrelated/replaced bytes.
        with self.hooks.lock(self.root,wait_seconds=2) as acquired:
            if not acquired: return dict(cleaned=len(cleaned),pending=True)
            value=self.read()
            by_owner={row['cleanup_owner']:row for row in selected}
            retained=[]
            for row in value['directories']:
                token=row.get('cleanup_owner')
                if token not in by_owner:
                    retained.append(row)
                elif token not in cleaned:
                    row.pop('cleanup_owner',None)
                    row.pop('cleanup_expires_at',None)
                    retained.append(row)
            if retained!=value['directories'] or selected:
                value['directories']=retained
                self._save(value)
            return dict(cleaned=len(cleaned),pending=len(retained))


class ScanAttemptExecution:
    """Runtime port: lease checkpoints, fixed-input binding and raw-input lifetime."""
    artifact_cache = True
    def __init__(self, store, lease, *, validator=None, after_scan=None, progress=None):
        self.store, self.lease = store, lease
        self.validator, self._after_scan = validator, after_scan
        self.progress = progress or NullProgressReporter()
        self.private_parent = store.private_parent
        self.input_id = None
        self.source_revision = None
        self._next_check = 0.0
        self._renew_interval = min(30, max(0.2, (store.read()['lane'] or {}).get('lease_seconds',600)/3))
        self._next_renew = time.monotonic()+self._renew_interval
        self._lock = threading.Lock()

    def emit(self, *args, **kwargs):
        return self.progress.emit(*args, **kwargs)

    def cancel(self):
        self.progress.cancel()
        with self.store.hooks.lock(self.store.root, wait_seconds=1) as acquired:
            if acquired: self.store.cancel(self.lease)

    def checkpoint(self, *, force=False):
        self.progress.checkpoint()
        with self._lock:
            now = time.monotonic()
            if not force and now < self._next_check: return
            if not self.store.is_current(self.lease, self.input_id): raise ScanAttemptLost('SCAN_ATTEMPT_SUPERSEDED')
            self._next_check = now+0.1
            if now >= self._next_renew:
                with self.store.hooks.lock(self.store.root) as acquired:
                    if acquired:
                        if not self.store.renew(self.lease): raise ScanAttemptLost('SCAN_ATTEMPT_EXPIRED')
                        self._next_renew = now+self._renew_interval

    def input_created(self, path):
        with self.store.hooks.lock(self.store.root, wait_seconds=2) as acquired:
            if not acquired or not self.store.register_directory(self.lease, path):
                raise ScanAttemptLost('SCAN_ATTEMPT_INPUT_REGISTRATION_FAILED')

    def input_removed(self, path):
        with self.store.hooks.lock(self.store.root, wait_seconds=2) as acquired:
            if acquired: self.store.release_directory(self.lease, path)

    def input_ready(self, view):
        self.checkpoint(force=True)
        if self.validator is not None and self.validator(view) is not True:
            raise ScanAttemptLost('SCAN_ATTEMPT_SOURCE_MISMATCH')
        with self.store.hooks.lock(self.store.root, wait_seconds=2) as acquired:
            if not acquired or not self.store.bind_input(self.lease, view):
                raise ScanAttemptLost('SCAN_ATTEMPT_INPUT_BINDING_FAILED')
        self.input_id = view.input_id
        self.source_revision = view.source_revision

    def applicability(self, view):
        return view.check_current()

    def after_scan(self, view, result):
        self.checkpoint(force=True)
        if self._after_scan is not None: self._after_scan(view, result)

    @property
    def receipt(self):
        return dict(self.lease.receipt, input_id=self.input_id, source_revision=self.source_revision,
                    publication='PENDING', applicability_scope='CAPTURED_SOURCE',
                    provider_freshness='EXECUTION_TIME_ONLY')
