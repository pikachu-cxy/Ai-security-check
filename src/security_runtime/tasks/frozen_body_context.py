"""Small opt-in baseline body bindings, never body or host-attestation proof.

Only a successfully closed original closeout preimage writer can publish a new
context. Existing references, namespace keys and their TTLs remain unchanged.
The task/control commit is separate; unpublished body batches retain old limits.
"""
from contextlib import contextmanager
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

from ..closeout_state import encode, digest, readonly_uri
from ..hook_state import HookStateStore, no_links
from ..source_redaction import SUPPORTED_VERSIONS
from .ownership import valid_owner, record_owner
from .snapshot_pages import MAPS, LISTS

PROFILE = 'FROZEN_BODY_CONTEXT_V1'
PROFILE_FIELD = 'frozen_body_profile'
CONTEXT_FIELD = 'frozen_body_context'
MAX_CONTEXT_BYTES = 32768
CONTRACT = 'task-frozen-body-context-v1'
_DOMAIN = b'task-frozen-body-context-signing-v1'
_COMPLETENESS = ('inventory_count_complete', 'hash_complete', 'body_requested', 'body_complete')
_FIELDS = frozenset({'contract', 'profile', 'task_ref', 'owner', 'workspace', 'root_identity',
    'field', 'source', 'preimage_namespace', 'preimage_task_ref', 'created_at', 'expires_at',
    'ttl_seconds', 'representation_version', 'preimage_contract', 'consistency', 'capture_completeness'})


class FrozenBodyContextUnavailable(ValueError):
    def __init__(self, reason_code):
        self.reason_code = reason_code
        super().__init__(reason_code)


def unavailable(suffix='UNAVAILABLE'):
    raise FrozenBodyContextUnavailable('FROZEN_BODY_CONTEXT_' + suffix)


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode()


def root_identity(root):
    try:
        root = Path(root)
        no_links(root)
        root = root.resolve(strict=True)
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode):
            unavailable('ROOT_MISMATCH')
        return root, [info.st_dev, info.st_ino]
    except (OSError, ValueError):
        unavailable('ROOT_MISMATCH')


def _key(hooks, root):
    try:
        if not isinstance(hooks, HookStateStore):
            unavailable('STATE_UNAVAILABLE')
        path = hooks.workspace_directory(root) / 'snapshot.key'
        no_links(path)
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0)
                     | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        try:
            info, actual = os.fstat(fd), path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != 32
                    or (info.st_dev, info.st_ino) != (actual.st_dev, actual.st_ino)):
                unavailable('STATE_UNAVAILABLE')
            key = os.read(fd, 33)
        finally:
            os.close(fd)
        if len(key) != 32:
            unavailable('STATE_UNAVAILABLE')
        return hmac.new(key, _DOMAIN, hashlib.sha256).digest()
    except (OSError, ValueError):
        unavailable('STATE_UNAVAILABLE')


@contextmanager
def readonly_database(path, *, maximum=65536):
    """No state initialization, body selection, WAL allocation or hot recovery."""
    db, fd, caller_failed = None, None, False
    path = Path(path)
    try:
        no_links(path)
        for suffix in ('-wal', '-shm', '-journal'):
            sidecar = Path(str(path) + suffix)
            no_links(sidecar)
            if sidecar.exists():
                unavailable('BUSY')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0)
                     | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        info, actual = os.fstat(fd), path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or (info.st_dev, info.st_ino) != (actual.st_dev, actual.st_ino)):
            unavailable('STATE_UNAVAILABLE')
        raw = os.read(fd, 100)
        if len(raw) != 100 or raw[:16] != b'SQLite format 3\0' or raw[18:20] != b'\x01\x01':
            unavailable('STATE_UNAVAILABLE')
        db = sqlite3.connect(readonly_uri(path), uri=True, timeout=2)
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, maximum + 8192)
        if db.execute('PRAGMA locking_mode=EXCLUSIVE').fetchone() != ('exclusive',):
            unavailable('STATE_UNAVAILABLE')
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        try:
            yield db
        except BaseException:
            caller_failed = True
            raise
        no_links(path)
        actual = path.lstat()
        if (info.st_dev, info.st_ino) != (actual.st_dev, actual.st_ino):
            unavailable('STATE_UNAVAILABLE')
    except sqlite3.Error as error:
        if caller_failed:
            raise
        code = getattr(error, 'sqlite_errorcode', 0) & 255
        unavailable('BUSY' if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED} else 'STATE_UNAVAILABLE')
    except (OSError, ValueError) as error:
        if caller_failed:
            raise
        if isinstance(error, FrozenBodyContextUnavailable):
            raise
        unavailable('STATE_UNAVAILABLE')
    finally:
        try:
            if db is not None:
                db.close()
        finally:
            if fd is not None:
                os.close(fd)


def baseline_source(baseline):
    try:
        return hashlib.sha256(encode(dict(maps={key: baseline.get(key, {}) for key in MAPS},
            lists={key: baseline.get(key, []) for key in LISTS}))).hexdigest()
    except (ValueError, TypeError, RecursionError):
        unavailable('INVALID')


def verify_context(hooks, root, packet, *, task_ref=None, owner=None, now=time.time):
    """Authenticate only the small binding; no task lookup or body is loaded."""
    try:
        if (not isinstance(packet, dict) or set(packet) != {'payload', 'mac'}
                or len(_encode(packet)) > MAX_CONTEXT_BYTES):
            unavailable('INVALID')
        packet = json.loads(_encode(packet))
        value, mac = packet['payload'], packet['mac']
        if (not isinstance(value, dict) or set(value) != _FIELDS
                or not isinstance(mac, str) or re.fullmatch('[a-f0-9]{64}', mac) is None
                or value['contract'] != CONTRACT or value['profile'] != PROFILE
                or not isinstance(value['task_ref'], str) or re.fullmatch('ts1-[a-f0-9]{32}', value['task_ref']) is None
                or not valid_owner(value['owner']) or value['preimage_task_ref'] != value['task_ref']
                or value['field'] != 'baseline' or value['preimage_namespace'] != 'closeout'
                or value['preimage_contract'] != 'task-preimage-paged-v1'
                or value['consistency'] != 'OBSERVED_ONLY'
                or not isinstance(value['source'], str) or re.fullmatch('[a-f0-9]{64}', value['source']) is None
                or type(value['representation_version']) is not int or value['representation_version'] not in SUPPORTED_VERSIONS
                or type(value['ttl_seconds']) is not int or value['ttl_seconds'] != 30 * 86400
                or not isinstance(value['root_identity'], list) or len(value['root_identity']) != 2
                or any(type(item) is not int or item < 0 for item in value['root_identity'])
                or not isinstance(value['capture_completeness'], dict) or set(value['capture_completeness']) != set(_COMPLETENESS)
                or any(item is not None and type(item) is not bool for item in value['capture_completeness'].values())
                or any(type(value[name]) not in {int, float} or not math.isfinite(value[name]) or value[name] < 0
                       for name in ('created_at', 'expires_at'))
                or value['expires_at'] != value['created_at'] + value['ttl_seconds']
                or value['expires_at'] <= value['created_at']):
            unavailable('INVALID')
        canonical, identity = root_identity(root)
        if value['workspace'] != str(canonical):
            unavailable('ROOT_MISMATCH')
        expected = hmac.new(_key(hooks, canonical), _encode(value), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected):
            unavailable('INVALID')
        from ..persisted_file_identity import historical_identity_matches
        if not historical_identity_matches(value['root_identity'], canonical.stat(),
                                           captured_at=value['created_at']):
            unavailable('ROOT_MISMATCH')
        if task_ref is not None and value['task_ref'] != task_ref:
            unavailable('TASK_MISMATCH')
        if owner is not None and (not valid_owner(owner) or value['owner'] != owner):
            unavailable('OWNER_MISMATCH')
        instant = now() if callable(now) else now
        if type(instant) not in {int, float} or not math.isfinite(instant) or instant < 0:
            unavailable('INVALID')
        if instant >= value['expires_at']:
            unavailable('EXPIRED')
        if instant < value['created_at']:
            unavailable('NOT_YET_VALID')
        return value
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:
        if isinstance(error, FrozenBodyContextUnavailable):
            raise
        unavailable('INVALID')


def build_context(hooks, root, baseline, *, writer, task_ref, owner, expected_root_identity, now=time.time):
    """Call only after the actual original paged writer exits successfully."""
    from .preimages import PAGED_CONTRACT
    canonical, identity = root_identity(root)
    if identity != expected_root_identity:
        unavailable('ROOT_MISMATCH')
    if (not writer.closed or not writer.paged or writer.task_ref != task_ref
            or writer.store.namespace != 'closeout' or writer.store.root != canonical
            or not valid_owner(owner)):
        unavailable('INVALID')
    store, created, ttl = writer.store, writer.created, writer.store.ttl
    store._paths()
    try:
        with readonly_database(store.path) as db:
            row = db.execute('SELECT created,expires FROM task_preimage_batches WHERE task_ref=?', (task_ref,)).fetchone()
            seal = db.execute("SELECT sealed,CASE WHEN typeof(mac)='text' AND length(mac)=64 THEN mac END "
                              'FROM task_preimage_seals WHERE task_ref=?', (task_ref,)).fetchone()
            if (row != (created, created + ttl) or seal is None or seal[0] != 1 or not isinstance(seal[1], str)
                    or not hmac.compare_digest(seal[1], digest(store._key(), dict(task_ref=task_ref, sealed=1)))):
                unavailable('STATE_UNAVAILABLE')
    except sqlite3.Error as error:
        code = getattr(error, 'sqlite_errorcode', 0) & 255
        unavailable('BUSY' if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED} else 'STATE_UNAVAILABLE')
    stats = baseline.get('capture_stats', {})
    completeness = {name: stats.get(name) for name in _COMPLETENESS}
    if any(value is not None and type(value) is not bool for value in completeness.values()):
        unavailable('INVALID')
    payload = dict(contract=CONTRACT, profile=PROFILE, task_ref=task_ref, owner=owner,
        workspace=str(canonical), root_identity=identity, field='baseline', source=baseline_source(baseline),
        preimage_namespace=store.namespace, preimage_task_ref=writer.task_ref, created_at=created,
        expires_at=created + ttl, ttl_seconds=ttl, representation_version=writer.redaction_version,
        preimage_contract=PAGED_CONTRACT, consistency='OBSERVED_ONLY', capture_completeness=completeness)
    packet = dict(payload=payload, mac=hmac.new(_key(hooks, canonical), _encode(payload), hashlib.sha256).hexdigest())
    verify_context(hooks, canonical, packet, task_ref=task_ref, owner=owner, now=now)
    return json.loads(_encode(packet))


def validate_transition(hooks, root, old, value, *, new, now):
    """Run inside the existing task CAS transaction; never upgrade an old head."""
    try:
        previous = old or {}
        old_baseline, baseline = previous.get('baseline'), value.get('baseline')
        old_present = (PROFILE_FIELD in previous or
            isinstance(old_baseline, dict) and CONTEXT_FIELD in old_baseline)
        present = (PROFILE_FIELD in value or
            isinstance(baseline, dict) and CONTEXT_FIELD in baseline)
        if not old_present and not present:
            return  # The legacy save contract is unchanged.
        old_context = old_baseline.get(CONTEXT_FIELD) if isinstance(old_baseline, dict) else None
        new_context = baseline.get(CONTEXT_FIELD) if isinstance(baseline, dict) else None
        old_profile = (old or {}).get(PROFILE_FIELD)
        profile = value.get(PROFILE_FIELD)
        if old_present:
            if (old_profile != PROFILE or profile != PROFILE or old_context is None
                    or _encode(old_context) != _encode(new_context)
                    or old_context['payload']['source'] != baseline_source(baseline)):
                unavailable('INVALID')
        elif not new and present:
            unavailable('INVALID')
        if new and present:
            from .activity import POLICY
            owner = record_owner(value)
            if (profile != PROFILE or new_context is None or value.get('check_policy') != POLICY
                    or value.get('native_repair') is not None or not valid_owner(owner)):
                unavailable('INVALID')
            payload = verify_context(hooks, root, new_context, task_ref=value['task_ref'], owner=owner, now=now)
            if payload['source'] != baseline_source(value['baseline']):
                unavailable('INVALID')
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as error:
        if isinstance(error, FrozenBodyContextUnavailable):
            raise
        unavailable('INVALID')
