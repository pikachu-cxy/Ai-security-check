"""Ledger acknowledgement is control-only and cannot rewrite task evidence."""
import copy
import sqlite3

import pytest

from security_runtime.tasks.projection import enqueue
from security_runtime.tasks.review_control import ReviewControlError
from security_runtime.tasks.snapshot_pages import _store
from test_task_snapshot_gc import sample, record


def pending(sample):
    state = sample[4]
    value = dict(record(sample), phase='COMPLETE',
                 static={'findings': [], 'status': 'SUCCESS'},
                 review={'findings': [], 'coverage': 'REVIEWED'})
    state.save(enqueue(value), new=True)
    return state.get(value['task_ref'])


def acknowledged(value, state='APPLIED'):
    result = copy.deepcopy(value)
    projection = result['ledger_projection']
    projection['state'] = state
    for key in ('host_updates', 'expected_versions', 'sync_failure'):
        projection.pop(key, None)
    return result


@pytest.mark.parametrize('status', ['APPLIED', 'SUPERSEDED'])
def test_ack_never_repacks_or_collects_sources(sample, monkeypatch, status):
    state = sample[4]
    original = pending(sample)
    raw = _store(state).path
    before = raw.read_bytes(), raw.stat().st_mtime_ns
    def forbidden(*args, **kwargs):
        pytest.fail('Acknowledging a projection touched the source store')
    monkeypatch.setattr('security_runtime.tasks.snapshot_pages.pack', forbidden)
    monkeypatch.setattr('security_runtime.tasks.snapshot_gc.collect_pages', forbidden)
    saved = state.save_projection(acknowledged(original, status))
    assert saved['ledger_projection']['state'] == status
    assert saved['generation'] == original['generation'] + 1
    assert saved['closed_at'] == original['closed_at']
    assert saved['phase'] == 'COMPLETE'
    assert (raw.read_bytes(), raw.stat().st_mtime_ns) == before
    assert state.get(saved['task_ref']) == saved


@pytest.mark.parametrize('field', ['owner', 'source', 'phase', 'review', 'projection_id', 'basis', 'state'])
def test_ack_cannot_change_original_evidence_or_projection_identity(sample, field):
    state = sample[4]
    original = pending(sample)
    candidate = acknowledged(original)
    if field == 'owner':
        candidate['task_owner']['session'] = 'f' * 64
    elif field == 'source':
        candidate['baseline']['hashes']['source.py'] = '0' * 64
    elif field == 'phase':
        candidate['phase'] = 'ACTIVE'
    elif field == 'review':
        candidate['review']['coverage'] = 'PARTIAL'
    else:
        candidate['ledger_projection'][field] = 'changed'
    before = state.path.read_bytes(), _store(state).path.read_bytes()
    with pytest.raises((ValueError, ReviewControlError)):
        state.save_projection(candidate)
    assert (state.path.read_bytes(), _store(state).path.read_bytes()) == before


def test_stale_ack_cannot_overwrite_a_new_generation(sample):
    state = sample[4]
    original = pending(sample)
    state.save_projection(acknowledged(original))
    before = state.path.read_bytes()
    with pytest.raises(ReviewControlError, match='CAS_CONFLICT'):
        state.save_projection(acknowledged(original))
    assert state.path.read_bytes() == before


def test_expired_ack_cannot_refresh_or_revive_the_original_task(sample):
    state, clock = sample[4], sample[2]
    original = pending(sample)
    clock[0] += 31 * 86400
    before = state.path.read_bytes()
    with pytest.raises(ReviewControlError, match='HISTORY_EXPIRED'):
        state.save_projection(acknowledged(original))
    assert state.path.read_bytes() == before
    assert state.get(original['task_ref'], headers=True) is None


def test_ack_rollback_preserves_pending_intent_and_source_bytes(sample):
    state = sample[4]
    original = pending(sample)
    with sqlite3.connect(state.path) as db:
        db.execute("CREATE TRIGGER reject_ack BEFORE UPDATE ON security_tasks "
                   "BEGIN SELECT RAISE(ABORT, 'isolated ack failure'); END")
    before = state.path.read_bytes(), _store(state).path.read_bytes()
    with pytest.raises(sqlite3.IntegrityError, match='isolated ack failure'):
        state.save_projection(acknowledged(original))
    assert (state.path.read_bytes(), _store(state).path.read_bytes()) == before
    assert state.get(original['task_ref'])['ledger_projection']['state'] == 'PENDING'
