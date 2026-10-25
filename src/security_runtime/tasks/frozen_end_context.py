"""Opt-in bindings for the original sealed end-version body namespace.

These packets bind metadata, not an atomic project snapshot or retained history.
Body and task/control commits remain separate and keep their original TTLs.
"""
import hashlib
import hmac
import json
import math
import re
import sqlite3
import time

from ..closeout_state import digest
from ..source_redaction import SUPPORTED_VERSIONS
from . import frozen_body_context as before
from .activity import POLICY
from .ownership import record_owner, valid_owner
from .snapshot_pages import batched

END_CONTRACT = 'task-frozen-end-body-context-v1'
END_PROFILE = 'FROZEN_END_BODY_CONTEXT_V1'
END_CONTEXT_FIELD = 'frozen_end_body_context'
MAX_CONTEXT_BYTES = before.MAX_CONTEXT_BYTES
_DOMAIN = b'task-frozen-end-body-context-signing-v1'
_COMPLETENESS = ('inventory_count_complete', 'hash_complete', 'body_requested', 'body_complete')
_FIELDS = frozenset({'contract', 'profile', 'task_ref', 'owner', 'workspace', 'root_identity',
    'field', 'source', 'preimage_namespace', 'preimage_task_ref', 'version_ref', 'created_at',
    'expires_at', 'ttl_seconds', 'representation_version', 'preimage_contract', 'consistency',
    'capture_completeness'})


class FrozenEndBodyContextUnavailable(ValueError):
    def __init__(self, reason_code):
        self.reason_code = reason_code
        super().__init__(reason_code)


def unavailable(suffix='UNAVAILABLE'):
    raise FrozenEndBodyContextUnavailable('FROZEN_END_BODY_CONTEXT_' + suffix)


def _translate(error):
    unavailable(error.reason_code.removeprefix('FROZEN_BODY_CONTEXT_'))


def _identity(root):
    try:
        return before.root_identity(root)
    except before.FrozenBodyContextUnavailable as error:
        _translate(error)


def _source(snapshot):
    try:
        return before.baseline_source(snapshot)
    except before.FrozenBodyContextUnavailable as error:
        _translate(error)


def _key(hooks, root):
    try:
        return hmac.new(before._key(hooks, root), _DOMAIN, hashlib.sha256).digest()
    except before.FrozenBodyContextUnavailable as error:
        _translate(error)


def _ref(value):
    return isinstance(value, str) and re.fullmatch('ts1-[a-f0-9]{32}', value) is not None


def verify_end_context(hooks, root, packet, *, task_ref=None, owner=None,
                       version_ref=None, now=time.time):
    """Verify a small END packet without loading a task, page or body."""
    try:
        if (not isinstance(packet, dict) or set(packet) != {'payload', 'mac'}
                or len(before._encode(packet)) > MAX_CONTEXT_BYTES):
            unavailable('INVALID')
        packet = json.loads(before._encode(packet))
        value, mac = packet['payload'], packet['mac']
        if (not isinstance(value, dict) or set(value) != _FIELDS
                or not isinstance(mac, str) or re.fullmatch('[a-f0-9]{64}', mac) is None
                or value['contract'] != END_CONTRACT or value['profile'] != END_PROFILE
                or not _ref(value['task_ref']) or not valid_owner(value['owner'])
                or not _ref(value['version_ref']) or value['preimage_task_ref'] != value['version_ref']
                or value['field'] != 'end' or value['preimage_namespace'] != 'end'
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
        canonical, identity = _identity(root)
        if value['workspace'] != str(canonical):
            unavailable('ROOT_MISMATCH')
        expected = hmac.new(_key(hooks, canonical), before._encode(value), hashlib.sha256).hexdigest()
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
        if version_ref is not None and value['version_ref'] != version_ref:
            unavailable('VERSION_MISMATCH')
        instant = now() if callable(now) else now
        if type(instant) not in {int, float} or not math.isfinite(instant) or instant < 0:
            unavailable('INVALID')
        if instant >= value['expires_at']:
            unavailable('EXPIRED')
        if instant < value['created_at']:
            unavailable('NOT_YET_VALID')
        return value
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:
        if isinstance(error, FrozenEndBodyContextUnavailable):
            raise
        unavailable('INVALID')


def _parent(hooks, root, record, now):
    owner = record_owner(record)
    if (record.get(before.PROFILE_FIELD) != before.PROFILE or record.get('check_policy') != POLICY
            or record.get('native_repair') is not None or not batched(record) or not valid_owner(owner)):
        unavailable('INVALID')
    try:
        payload = before.verify_context(hooks, root, record['baseline'].get(before.CONTEXT_FIELD),
                                        task_ref=record['task_ref'], owner=owner, now=now)
    except before.FrozenBodyContextUnavailable as error:
        _translate(error)
    if payload['source'] != _source(record['baseline']):
        unavailable('INVALID')
    return owner


def build_end_context(hooks, root, end, *, writer, parent_record,
                      expected_root_identity, now=time.time):
    """Call after successful original writer seal and preview consistency."""
    from .preimages import PAGED_CONTRACT
    owner = _parent(hooks, root, parent_record, now)
    canonical, identity = _identity(root)
    if identity != expected_root_identity:
        unavailable('ROOT_MISMATCH')
    if (not writer.closed or not writer.paged or writer.store.namespace != 'end'
            or writer.store.root != canonical or writer.task_ref != end.get('version_ref')):
        unavailable('INVALID')
    store, ref, created, ttl = writer.store, writer.task_ref, writer.created, writer.store.ttl
    store._paths()
    try:
        with before.readonly_database(store.path) as db:
            row = db.execute('SELECT created,expires FROM task_preimage_batches WHERE task_ref=?', (ref,)).fetchone()
            seal = db.execute("SELECT sealed,CASE WHEN typeof(mac)='text' AND length(mac)=64 THEN mac END "
                              'FROM task_preimage_seals WHERE task_ref=?', (ref,)).fetchone()
            if (row != (created, created + ttl) or seal is None or seal[0] != 1 or not isinstance(seal[1], str)
                    or not hmac.compare_digest(seal[1], digest(store._key(), dict(task_ref=ref, sealed=1)))):
                unavailable('STATE_UNAVAILABLE')
    except before.FrozenBodyContextUnavailable as error:
        _translate(error)
    except sqlite3.Error as error:
        code = getattr(error, 'sqlite_errorcode', 0) & 255
        unavailable('BUSY' if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED} else 'STATE_UNAVAILABLE')
    stats = end.get('capture_stats', {})
    payload = dict(contract=END_CONTRACT, profile=END_PROFILE, task_ref=parent_record['task_ref'],
        owner=owner, workspace=str(canonical), root_identity=identity, field='end', source=_source(end),
        preimage_namespace='end', preimage_task_ref=ref, version_ref=ref, created_at=created,
        expires_at=created + ttl, ttl_seconds=ttl, representation_version=writer.redaction_version,
        preimage_contract=PAGED_CONTRACT, consistency='OBSERVED_ONLY',
        capture_completeness={name: stats.get(name) for name in _COMPLETENESS})
    packet = dict(payload=payload, mac=hmac.new(_key(hooks, canonical), before._encode(payload), hashlib.sha256).hexdigest())
    verify_end_context(hooks, canonical, packet, task_ref=parent_record['task_ref'], owner=owner, version_ref=ref, now=now)
    return json.loads(before._encode(packet))


def validate_end_transition(hooks, root, old, value, *, new, now):
    """Apply within the original task CAS; never supplement an old version."""
    try:
        previous, end = (old or {}).get('end'), value.get('end')
        old_present = isinstance(previous, dict) and END_CONTEXT_FIELD in previous
        present = isinstance(end, dict) and END_CONTEXT_FIELD in end
        if not old_present and not present:
            return
        if (not isinstance(end, dict) or not _ref(end.get('version_ref'))
                or not isinstance(previous, (dict, type(None)))):
            unavailable('INVALID')
        same = isinstance(previous, dict) and previous.get('version_ref') == end.get('version_ref')
        if same:
            if (not old_present or not present
                    or before._encode(previous[END_CONTEXT_FIELD]) != before._encode(end[END_CONTEXT_FIELD])
                    or previous[END_CONTEXT_FIELD]['payload']['source'] != _source(end)):
                unavailable('INVALID')
        elif present:
            owner = _parent(hooks, root, value, now)
            payload = verify_end_context(hooks, root, end[END_CONTEXT_FIELD], task_ref=value['task_ref'],
                owner=owner, version_ref=end.get('version_ref'), now=now)
            if payload['source'] != _source(end):
                unavailable('INVALID')
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as error:
        if isinstance(error, (FrozenEndBodyContextUnavailable, before.FrozenBodyContextUnavailable)):
            raise
        unavailable('INVALID')
