"""Workspace-shared finite observation epochs, never task before images."""
from contextlib import contextmanager
import hashlib
import math
from pathlib import Path
import stat
import time
import uuid

from .hook_state import HookStateStore
from .product_epoch_capture import DirectoryObservation, ObservationError, StableHashReader, platform_supported
from .product_epoch_store import ProductEpochError, ProductEpochStore, encode, fail
from .snapshot_store import _gc_canonical_path
from .tasks.ownership import valid_owner


DEFAULT_POLICY = dict(version=1, scope_seconds=30.0, step_files=256,
                      step_bytes=8_000_000, step_seconds=0.2,
                      ignored_names=['.git', '.venv', 'node_modules', '__pycache__'])


def normalized_policy(policy):
    if policy is not None and (not isinstance(policy, dict) or set(policy)-set(DEFAULT_POLICY)):
        fail('PRODUCT_EPOCH_POLICY_INVALID')
    value = dict(DEFAULT_POLICY, **(policy or {}))
    if (type(value['version']) is not int or value['version'] != 1
            or type(value['step_files']) is not int or not 1 <= value['step_files'] <= 256
            or type(value['step_bytes']) is not int or not 1 <= value['step_bytes'] <= 8_000_000
            or any(type(value[name]) not in {int, float} or not math.isfinite(value[name])
                   for name in ('scope_seconds', 'step_seconds'))
            or not 0 <= value['scope_seconds'] <= 3600 or not 0 < value['step_seconds'] <= 0.2
            or not isinstance(value['ignored_names'], (list, tuple)) or len(value['ignored_names']) > 128
            or any(not isinstance(name, str) or not name or len(name.encode()) > 256
                   or '/' in name or '\\' in name or '\0' in name for name in value['ignored_names'])):
        fail('PRODUCT_EPOCH_POLICY_INVALID')
    value['ignored_names'] = sorted(set(value['ignored_names']))
    value['scope_seconds'], value['step_seconds'] = float(value['scope_seconds']), float(value['step_seconds'])
    return value


class ProductEpochService:
    def __init__(self, hooks, root, *, now=time.time, policy=None):
        self.hooks, self.root, self.now = hooks, Path(root).absolute(), now
        self.policy = normalized_policy(policy)
        self.policy_digest = hashlib.sha256(encode(self.policy)).hexdigest()
        self.store = ProductEpochStore(hooks, self.root)
        self.root = self.store.root
        # Product source IO must never acquire the task/workspace lock. This
        # sibling namespace also exists independently of store allocation.
        self._writer_locks = HookStateStore(self.store.directory.parent/'product-epoch-writers')
        self._worker = uuid.uuid4().hex
        self._directory = self._directory_seq = None
        self._reader = self._reader_seq = None
        self._reader_factory = StableHashReader
        self._resumed = False

    @contextmanager
    def _locked(self):
        if self._writer_locks.lock_held(self.root):
            yield True
        else:
            with self._writer_locks.lock(self.root) as acquired:
                yield acquired

    def close(self):
        directory, reader = self._directory, self._reader
        if directory is not None or reader is not None:
            self._resumed = True
        self._directory = self._directory_seq = None
        self._reader = self._reader_seq = None
        try:
            if directory is not None:
                directory.close()
        finally:
            if reader is not None:
                reader.close()

    def __del__(self):
        try:
            self.close()
        except (AttributeError, OSError):
            pass

    def _status(self, header):
        counts = dict(members=0, observed=0, gaps=0, directories=0,
                      pending_directories=0, pending_files=0)
        value = dict(epoch_ref=None, policy_digest=self.policy_digest, state='NOT_STARTED',
                     workspace_id=self.store.workspace_id, root_identity=list(self.store.root_identity),
                     scope_closed=False, project_inventory_complete=False,
                     counts=counts, gaps=dict(count=0, reasons={}, unknown_denominator=True),
                     comparison_available=False, consistency='OBSERVED_ONLY', representation='HASH_ONLY',
                     body_retained=False, source_bodies_available=False,
                     progress=dict(enumerated_entries=0, directories_done=0, file_cursor=0,
                                   pending_file_seq=None, pending_file_bytes=0),
                     platform_supported=platform_supported(),
                     platform_support='POSIX_NOFOLLOW_DIRFD' if platform_supported() else 'UNSUPPORTED',
                     strict_task_preimage_eligible=False, hash_algorithm='HMAC_SHA256_HOOK_FILE_V1')
        if header is None:
            return value
        counts.update(members=header['members'], observed=header['observed'],
            gaps=header['file_gaps']+header['directory_gaps'], directories=header['directories'],
            pending_directories=0 if header['scope_closed'] else header['directories']-header['directories_done'],
            pending_files=header['members']-header['file_cursor'])
        value.update(epoch_ref=header['epoch_ref'], policy_digest=header['policy_digest'], state=header['state'],
            scope_ref=header['scope_ref'], observations_ref=header['observations_ref'],
            scope_closed=header['scope_closed'], scope_close_reason=header.get('scope_close_reason'),
            comparison_available=header['state'] == 'SEALED' and header['observed'] > 0,
            gaps=dict(count=counts['gaps'], reasons=dict(header['gap_reasons']), unknown_denominator=True,
                      observation_intervals=header['observation_intervals']),
            created_at=header['created_at'], sealed_at=header.get('sealed_at'),
            max_unstable_attempts=3, current_path_attempts=header['file_attempts'])
        value['progress'].update(enumerated_entries=header.get('enumerated_entries', 0),
            directories_done=header['directories_done'], file_cursor=header['file_cursor'],
            pending_file_seq=header['pending_file_seq'], pending_file_bytes=header['pending_file_bytes'])
        return value

    def status(self, epoch_ref=None):
        self.store.check_root()
        self.store.check_presence()
        if not self.store.directory.exists():
            if epoch_ref is not None:
                fail()
            return self._status(None)
        with self.store.db() as (db, key):
            header = self.store.load(db, key, ref=epoch_ref, policy=self.policy_digest)
            if header is None and epoch_ref is not None:
                fail()
            return self._status(header)

    def verify(self, epoch_ref):
        return self.status(epoch_ref=epoch_ref)

    def ensure(self, owner):
        if not valid_owner(owner):
            fail('PRODUCT_EPOCH_OWNER_INVALID')
        self.store.check_root()
        if not platform_supported():
            return dict(self.status(), state='PLATFORM_UNSUPPORTED', reason='PRODUCT_EPOCH_PLATFORM_UNSUPPORTED')
        with self._locked() as acquired:
            if not acquired:
                return dict(self.status(), state='BUSY')
            with self.store.db(write=True, create=True) as (db, key):
                header = self.store.load(db, key, policy=self.policy_digest)
                if header is None:
                    instant = self.now()
                    if type(instant) not in {int, float} or not math.isfinite(instant):
                        fail('PRODUCT_EPOCH_CLOCK_INVALID')
                    ref = 'pe1-'+uuid.uuid4().hex
                    header = dict(self.store.binding, epoch_ref=ref, policy_digest=self.policy_digest,
                        policy=self.policy, issuer_owner=dict(owner), created_at=instant,
                        scope_ref='pes1-'+uuid.uuid4().hex, observations_ref='peo1-'+uuid.uuid4().hex,
                        state='ENUMERATING', scope_closed=False, scope_deadline=instant+self.policy['scope_seconds'],
                        scope_work_seconds=0.0, directories=1, directories_done=0, members=0,
                        enumerated_entries=0,
                        observed=0, file_gaps=0, directory_gaps=0, file_cursor=0, file_attempts=0,
                        pending_file_seq=None, pending_file_bytes=0,
                        excluded_links=0, excluded_special=0, ignored=0, gap_reasons={},
                        worker_token=self._worker, observation_intervals=1)
                    self.store.insert(db, key, header, 'directories',
                                      dict(seq=1, path='', identity=list(self.store.root_identity), done=False))
                    self.store.save(db, key, header)
                return self._status(header)

    def _gap(self, header, reason, *, directory=False):
        header['directory_gaps' if directory else 'file_gaps'] += 1
        header['gap_reasons'][reason] = header['gap_reasons'].get(reason, 0)+1

    def _close_scope(self, header, reason):
        if self._directory is not None:
            self._directory.close()
            self._directory = self._directory_seq = None
        header.update(scope_closed=True, state='OBSERVING', scope_close_reason=reason,
                      scope_closed_at=self.now())
        if reason == 'DEADLINE':
            self._gap(header, 'SCOPE_DEADLINE', directory=True)

    def _scope_expired(self, header):
        return (self.now() >= header['scope_deadline']
                or header['scope_work_seconds'] >= self.policy['scope_seconds'])

    def _enumerate(self, db, key, header, deadline, units):
        # Scope expiry is control progress even if no source IO time remains.
        if self._scope_expired(header):
            self._close_scope(header, 'DEADLINE')
            return units
        while units < self.policy['step_files'] and time.monotonic() < deadline:
            if self._scope_expired(header):
                self._close_scope(header, 'DEADLINE')
                break
            directory = self.store.row(db, key, header, 'directories', pending=True)
            if directory is None:
                if header['directories_done'] != header['directories']:
                    fail()
                self._close_scope(header, 'ENUMERATION_ENDED')
                break
            try:
                if self._directory_seq != directory['seq']:
                    if self._directory is not None:
                        self._directory.close()
                    self._directory = DirectoryObservation(self.root, directory['path'], directory['identity'],
                        expected_root_identity=self.store.root_identity)
                    self._directory_seq = directory['seq']
                self._directory.verify()
                name, info = self._directory.next()
                units += 1
                header['enumerated_entries'] = header.get('enumerated_entries', 0)+1
            except StopIteration:
                self._directory.close()
                self._directory = self._directory_seq = None
                self.store.finish_directory(db, key, header, directory)
                units += 1
                continue
            except (OSError, ValueError) as exc:
                if isinstance(exc, ObservationError) and exc.reason_code == 'PLATFORM_UNSUPPORTED':
                    fail('PRODUCT_EPOCH_PLATFORM_UNSUPPORTED')
                if self._directory is not None:
                    self._directory.close()
                    self._directory = self._directory_seq = None
                self._gap(header, 'DIRECTORY_UNAVAILABLE', directory=True)
                self.store.finish_directory(db, key, header, directory)
                units += 1
                continue
            if name in self.policy['ignored_names']:
                header['ignored'] += 1
                continue
            path = directory['path']+'/'+name if directory['path'] else name
            try:
                supported = len(path.encode()) <= 4096 and _gc_canonical_path(path)
            except UnicodeError:
                supported = False
            if not supported:
                self._gap(header, 'PATH_UNSUPPORTED', directory=True)
                continue
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                header['excluded_links'] += 1
            elif stat.S_ISDIR(info.st_mode):
                existing = db.execute('SELECT seq FROM directories WHERE epoch=? AND '
                                      '(path=? OR (dev=? AND ino=?)) LIMIT 1',
                                      (header['epoch_ref'], path, info.st_dev, info.st_ino)).fetchone()
                if existing is None:
                    header['directories'] += 1
                    self.store.insert(db, key, header, 'directories',
                        dict(seq=header['directories'], path=path, identity=[info.st_dev, info.st_ino], done=False))
                elif self.store.row(db, key, header, 'directories', seq=existing[0]) is None:
                    fail()
            elif stat.S_ISREG(info.st_mode):
                if self.store.row(db, key, header, 'members', path=path) is None:
                    header['members'] += 1
                    self.store.insert(db, key, header, 'members', dict(seq=header['members'], path=path))
            else:
                header['excluded_special'] += 1
        return units

    def _observe(self, db, key, header, deadline, units):
        consumed = 0
        while (units < self.policy['step_files'] and consumed < self.policy['step_bytes']
               and time.monotonic() < deadline and header['file_cursor'] < header['members']):
            seq = header['file_cursor']+1
            member = self.store.row(db, key, header, 'members', seq=seq)
            if member is None:
                fail()
            if self.store.row(db, key, header, 'observations', seq=seq) is not None:
                fail()
            try:
                if header['file_attempts'] >= 3:
                    result = dict(state='UNSTABLE', reason='OBSERVATION_INTERRUPTED', bytes_read=0)
                elif self._reader_seq != seq:
                    if self._reader is not None:
                        self._reader.close()
                    self._reader = self._reader_factory(self.root, key, member['path'],
                        expected_root_identity=self.store.root_identity)
                    self._reader_seq = seq
                    result = self._reader.advance(self.policy['step_bytes']-consumed, deadline)
                else:
                    result = self._reader.advance(self.policy['step_bytes']-consumed, deadline)
            except (OSError, ObservationError, ValueError):
                result = dict(state='UNSTABLE', reason='SOURCE_UNAVAILABLE', bytes_read=0)
            consumed += result['bytes_read']
            units += 1
            if result['state'] == 'PENDING':
                header.update(pending_file_seq=seq, pending_file_bytes=self._reader.read_bytes)
                break
            header.update(pending_file_seq=None, pending_file_bytes=0)
            if self._reader is not None:
                self._reader.close()
                self._reader = self._reader_seq = None
            if result['state'] != 'OBSERVED':
                if header['file_attempts'] < 3:
                    header['file_attempts'] += 1
                if header['file_attempts'] < 3:
                    continue
                observation = dict(seq=seq, path=member['path'], state='GAP', reason='SOURCE_UNSTABLE', attempts=3)
                self._gap(header, 'SOURCE_UNSTABLE')
            else:
                observation = dict(seq=seq, path=member['path'], state='OBSERVED', hash=result['hash'],
                                   size=result['size'], observed_at=self.now())
                header['observed'] += 1
            self.store.insert(db, key, header, 'observations', observation)
            header['file_cursor'] += 1
            header['file_attempts'] = 0
        if header['file_cursor'] == header['members']:
            header.update(state='SEALED', sealed_at=self.now())

    def step(self, owner):
        if not valid_owner(owner):
            fail('PRODUCT_EPOCH_OWNER_INVALID')
        if not platform_supported():
            return dict(self.status(), state='PLATFORM_UNSUPPORTED', reason='PRODUCT_EPOCH_PLATFORM_UNSUPPORTED')
        if not self.store.directory.exists():
            return self.ensure(owner)
        self.store.check_root()
        started = time.monotonic()
        with self._locked() as acquired:
            if not acquired:
                return dict(self.status(), state='BUSY')
            try:
                with self.store.db(write=True) as (db, key):
                    header = self.store.load(db, key, policy=self.policy_digest)
                    if header is None:
                        fail('PRODUCT_EPOCH_NOT_STARTED')
                    if header['state'] == 'SEALED':
                        return self._status(header)
                    if header['worker_token'] != self._worker or self._resumed:
                        self.close()
                        if (header['pending_file_seq'] == header['file_cursor']+1
                                and header['pending_file_bytes'] > 0):
                            header['file_attempts'] += 1
                        header.update(pending_file_seq=None, pending_file_bytes=0)
                        header['observation_intervals'] += 1
                        header['worker_token'] = self._worker
                        self._resumed = False
                    # Signature/index validation can exceed a source time slice.
                    # It must not consume every subsequent turn's IO allowance.
                    deadline = time.monotonic()+self.policy['step_seconds']
                    units = self._enumerate(db, key, header, deadline, 0) if not header['scope_closed'] else 0
                    if not header['scope_closed']:
                        header['scope_work_seconds'] += time.monotonic()-started
                    else:
                        self._observe(db, key, header, deadline, units)
                    self.store.check_root()
                    self.store.save(db, key, header)
                    return self._status(header)
            except BaseException as exc:
                # Rollback cannot rewind scandir or a partial hash. Discard
                # them while still owning this writer guard; a BUSY caller
                # must never close another thread's in-flight contexts.
                try:
                    self.close()
                except Exception:
                    pass  # Preserve the original failure after invalidation.
                self._resumed = True
                if isinstance(exc, ProductEpochError):
                    if exc.reason_code == 'PRODUCT_EPOCH_WAITING_CAPACITY':
                        return dict(self.status(), state='WAITING_CAPACITY', reason=exc.reason_code)
                    if exc.reason_code == 'PRODUCT_EPOCH_PLATFORM_UNSUPPORTED':
                        return dict(self.status(), state='PLATFORM_UNSUPPORTED', reason=exc.reason_code)
                raise

    def lookup(self, epoch_ref, paths):
        if (not isinstance(paths, (list, tuple)) or len(paths) > 256
                or any(not isinstance(path, str) or len(path.encode()) > 4096
                       or not _gc_canonical_path(path) for path in paths)):
            fail('PRODUCT_EPOCH_LOOKUP_INVALID')
        with self.store.db() as (db, key):
            header = self.store.load(db, key, ref=epoch_ref)
            if header is None:
                fail()
            rows = []
            for path in paths:
                member = self.store.row(db, key, header, 'members', path=path)
                observation = self.store.row(db, key, header, 'observations', path=path)
                if observation is not None and (member is None or member['seq'] != observation['seq']):
                    fail()
                row = dict(path=path, observed=False, sha256=None, status='FIRST_OBSERVED_ORDER_UNKNOWN',
                           order='FIRST_OBSERVED_ORDER_UNKNOWN', hash_algorithm='HMAC_SHA256_HOOK_FILE_V1')
                if observation is not None:
                    if observation['state'] == 'OBSERVED':
                        row.update(observed=True, status='OBSERVED', hash=observation['hash'],
                                   sha256=observation['hash'], observed_at=observation['observed_at'])
                    else:
                        row.update(status='GAP', reason=observation['reason'], attempts=observation['attempts'])
                rows.append(row)
            return dict(epoch_ref=epoch_ref, policy_digest=header['policy_digest'], results=rows,
                        consistency='OBSERVED_ONLY', representation='HASH_ONLY',
                        body_retained=False, strict_task_preimage_eligible=False)
