"""Narrow control CAS updates which never repack or collect source pages.

The original head remains authoritative for every non-review field. This
changes no task format or allowance and does not adopt old paged-review heads.
"""
from contextlib import closing
import hashlib
import sqlite3

from ..closeout_state import database_uri, digest, encode
from ..hook_state import no_links
from ..task_review.protocol import require_record_protocol
from .activity import ActivityStore, deferred
from .ownership import ACTIVE, LEASE_SECONDS
from .snapshot_page_guard import guard_held, page_guard
from .snapshot_pages import LISTS, POINTER, managed, snapshot_fields


FIELDS = frozenset({'review_plan', 'review_ledger', 'review_transport', 'evidence',
    'context_requests', 'context_bytes', 'review_deadline', 'related_files',
    'context_gaps', 'review_delivery_blocker', 'limitations'})


class ReviewControlError(ValueError):
    def __init__(self, suffix):
        self.reason_code = 'REVIEW_CONTROL_' + suffix
        super().__init__(self.reason_code)


def _snapshot(original, candidate):
    if not isinstance(original, dict) or not isinstance(candidate, dict):
        return original == candidate
    if POINTER not in original:
        return original == candidate
    if candidate.get(POINTER) != original[POINTER]:
        return False
    maps = snapshot_fields(candidate)
    header = {key: value for key, value in candidate.items() if key not in (*maps, *LISTS)}
    if header != original:
        return False
    body = dict(maps={key: candidate.get(key, {}) for key in maps},
                lists={key: candidate.get(key, []) for key in LISTS})
    return hashlib.sha256(encode(body)).hexdigest() == original[POINTER]['source']


def _validate_projection(original, candidate):
    from .projection import CONTRACT
    before, after = original.get('ledger_projection'), candidate.get('ledger_projection')
    if (not isinstance(before, dict) or not isinstance(after, dict)
            or before.get('contract') != CONTRACT or before.get('state') != 'PENDING'
            or after.get('state') not in {'APPLIED', 'SUPERSEDED'}):
        raise ReviewControlError('INVALID_PROJECTION_TRANSITION')
    expected = dict(before, state=after['state'])
    for key in ('host_updates', 'expected_versions', 'sync_failure'):
        expected.pop(key, None)
    if after != expected:
        raise ReviewControlError('INVALID_PROJECTION_TRANSITION')


def _validate(original, candidate, *, projection=False):
    if (type(original.get('generation')) is not int or type(candidate.get('generation')) is not int
            or original.get('generation') != candidate.get('generation')
            or original.get('phase') != candidate.get('phase')
            or not projection and candidate.get('phase') != 'REVIEWING'):
        raise ReviewControlError('CAS_CONFLICT')
    require_record_protocol(original)
    require_record_protocol(candidate)
    for key in original.keys() | candidate.keys():
        if key in ({'ledger_projection'} if projection else FIELDS):
            continue
        if (key in original) != (key in candidate):
            raise ReviewControlError('IMMUTABLE_FIELD')
        equal = _snapshot(original[key], candidate[key]) if key in {'baseline', 'end'} else original[key] == candidate[key]
        if not equal:
            raise ReviewControlError('IMMUTABLE_FIELD')
    if projection:
        _validate_projection(original, candidate)
        return
    old, new = original.get('review_ledger', {}), candidate.get('review_ledger', {})
    for key in ('source_bytes', 'navigation_bytes', 'control_bytes', 'total_bytes', 'reads'):
        if (key in old and (type(new.get(key)) is not int or new[key] < old[key])):
            raise ReviewControlError('LEDGER_REGRESSION')


def save(state, value):
    return _save(state, value, projection=False)


def save_projection(state, value):
    """Acknowledge an already persisted intent, without changing source/result."""
    return _save(state, value, projection=True)


def _save(state, value, *, projection):
    from .security_state import MAX_RECORD_BYTES, persistent_record
    if not managed(value):
        return state.save(value)
    if not projection and value.get('phase') != 'REVIEWING':
        raise ReviewControlError('INVALID_PHASE')
    state._preflight_capture_transition(value, new=False)
    no_links(state.path)
    if not state.path.is_file():
        raise ReviewControlError('HISTORY_UNAVAILABLE')
    state.hooks.prepare_private_writer(state.root)
    with page_guard(state.path.parent):
        if not guard_held(state.path.parent):
            raise ReviewControlError('HISTORY_UNAVAILABLE')
        with closing(sqlite3.connect(database_uri(state.path, mode='rw'), uri=True, timeout=2)) as db, db:
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA secure_delete=ON')
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT CASE WHEN typeof(data)='text' AND length(CAST(data AS BLOB))<=? THEN data END,"
                "CASE WHEN typeof(mac)='text' AND length(mac)=64 THEN mac END FROM security_tasks WHERE ref=?",
                (MAX_RECORD_BYTES, value['task_ref'])).fetchone()
            original = state.head(row)
            if original is None:
                raise ReviewControlError('HISTORY_UNAVAILABLE')
            if projection and state.expired(original):
                raise ReviewControlError('HISTORY_EXPIRED')
            candidate = persistent_record(value)
            _validate(original, candidate, projection=projection)
            if 'capture_publication' in original:
                from .capture_publication_store import validate_inventory
                validate_inventory(state, db=db)
            from .frozen_body_context import validate_transition
            from .frozen_end_context import validate_end_transition
            validate_transition(state.hooks, state.root, original, candidate, new=False, now=state.now)
            validate_end_transition(state.hooks, state.root, original, candidate, new=False, now=state.now)
            stored = dict(original)
            for key in ({'ledger_projection'} if projection else FIELDS):
                if key in candidate:
                    stored[key] = candidate[key]
                else:
                    stored.pop(key, None)
            stored.update(generation=original['generation'] + 1, activity_at=state.now())
            stored.pop('session_idle', None)
            if stored['phase'] in ACTIVE:
                stored['lease_until'] = state.now() + LEASE_SECONDS
                stored.pop('closed_at', None)
            else:
                stored.setdefault('closed_at', state.now())
            raw = encode(stored)
            if len(raw) > MAX_RECORD_BYTES:
                raise ReviewControlError('WAITING_CAPACITY')
            changed = db.execute('UPDATE security_tasks SET data=?,mac=? WHERE ref=? AND data=? AND mac=?',
                (raw.decode(), digest(state.key(), stored), value['task_ref'], row[0], row[1]))
            if changed.rowcount != 1:
                raise ReviewControlError('CAS_CONFLICT')
    result = dict(value, generation=stored['generation'], activity_at=stored['activity_at'])
    result.pop('session_idle', None)
    for key in ('lease_until', 'closed_at'):
        if key in stored:
            result[key] = stored[key]
        else:
            result.pop(key, None)
    if deferred(result):
        ActivityStore(state.hooks, state.root, now=state.now).touch(result['task_ref'], result['activity_at'], result['phase'])
    return result
