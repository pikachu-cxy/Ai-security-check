"""Real review updates preserve source pages and the original cumulative ledger."""
import copy
import json
import sqlite3

import pytest

from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.review_control import ReviewControlError
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.snapshot_pages import _store
from test_task_security import service
from task_review_helpers import review_all


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'runtime-state'))


def prepared(service, *, capture=False):
    import os
    if capture and os.name != 'posix':
        pytest.skip('Opt-in capture publication requires POSIX private-state guarantees')
    old, root, engine = service
    task = TaskSecurityService(engine, old.hooks, owner=session_owner('codex', 'review-control'),
        frozen_body_contexts=capture, capture_sources=capture)
    ref = task.begin(root, 'original-review', check_policy=POLICY)['task_ref']
    (root / 'routes.py').write_text('def get_order(order_id, user):\n    return load_order(order_id)\n')
    assert task.finish(root, ref)['status'] == 'READY'
    packet = task.prepare(root, ref)
    assert packet['status'] == 'REVIEW_REQUIRED'
    return task, root, ref, packet['review_session'], engine


def images(task, root):
    state = task.store(root)
    raw = _store(state)
    with sqlite3.connect(state.path) as db:
        control = tuple(db.iterdump())
    return control, raw.path.read_bytes()


@pytest.mark.parametrize('capture', [False, True])
def test_read_navigation_and_submission_never_repack_or_collect_original_sources(service, monkeypatch, capture):
    task, root, ref, session, engine = prepared(service, capture=capture)
    original = copy.deepcopy(task.load(root, ref))
    raw = _store(task.store(root))
    before = raw.path.read_bytes(), raw.path.stat().st_mtime_ns
    def forbidden(*args, **kwargs):
        pytest.fail('A review-only update repacked or collected the source inventory')
    monkeypatch.setattr('security_runtime.tasks.snapshot_pages.pack', forbidden)
    monkeypatch.setattr('security_runtime.tasks.snapshot_gc.collect_pages', forbidden)
    first = task.read(root, ref, session, 'routes.py', 1, 2)
    assert first['lines'][0].startswith('def get_order')
    duplicate = task.read(root, ref, session, 'routes.py', 1, 2)
    assert duplicate['status'] == 'ALREADY_DELIVERED'
    plan = task.review_plan(root, ref, session)
    assert plan['unit_count'] == 1
    task.submit_batch(root, ref, session, [plan['units'][0]['unit_id']], 'PARTIAL', ['before not yet read'])
    current = task.load(root, ref)
    assert current['baseline'] == original['baseline'] and current['end'] == original['end']
    assert current['review_ledger']['source_bytes'] > original['review_ledger']['source_bytes']
    assert current['review_ledger']['reads'] > original['review_ledger']['reads']
    assert (raw.path.read_bytes(), raw.path.stat().st_mtime_ns) == before
    assert len(engine.calls) == 1


@pytest.mark.parametrize('field', ['owner', 'source', 'donor', 'phase', 'revision'])
def test_review_only_writer_rejects_changes_to_original_identity_without_page_io(service, monkeypatch, field):
    task, root, ref, _, _ = prepared(service)
    state = task.store(root)
    candidate = task.load(root, ref)
    if field == 'owner':
        candidate['task_owner'] = session_owner('codex', 'other')
    elif field == 'source':
        candidate['baseline']['hashes']['routes.py'] = '0' * 64
    elif field == 'donor':
        candidate['baseline']['paged_entries']['ref'] = 'ws2-' + 'f' * 32
    elif field == 'phase':
        candidate['phase'] = 'COMPLETE'
    else:
        candidate['review_revision'] = candidate.get('review_revision', 1) + 1
    before = images(task, root)
    def forbidden(*args, **kwargs):
        pytest.fail('Rejected metadata update attempted a source write')
    monkeypatch.setattr('security_runtime.tasks.snapshot_pages.pack', forbidden)
    with pytest.raises(ReviewControlError):
        state.save_review(candidate)
    assert images(task, root) == before


def test_stale_generation_and_ledger_regression_do_not_lose_original_progress(service):
    task, root, ref, _, _ = prepared(service)
    state = task.store(root)
    record = task.load(root, ref)
    saved = state.save_review(record)
    before = images(task, root)
    with pytest.raises(ReviewControlError, match='REVIEW_CONTROL_CAS_CONFLICT'):
        state.save_review(record)
    regressed = copy.deepcopy(saved)
    regressed['review_ledger']['reads'] -= 1
    with pytest.raises(ReviewControlError, match='REVIEW_CONTROL_LEDGER_REGRESSION'):
        state.save_review(regressed)
    assert images(task, root) == before


@pytest.mark.parametrize('capture', [False, True])
def test_final_submission_collects_once_and_acknowledges_without_rewriting_sources(service, monkeypatch, capture):
    task, root, ref, session, engine = prepared(service, capture=capture)
    packet = task.prepare(root, ref)
    review_all(task, root, ref, packet)
    before = task.load(root, ref)
    from security_runtime.tasks import snapshot_gc
    original = snapshot_gc.collect_pages
    collected = []
    def collect(*args, **kwargs):
        collected.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(snapshot_gc, 'collect_pages', collect)
    done = task.submit(root, ref, session, [], 'REVIEWED', [])
    assert done['status'] == 'COMPLETE'
    assert len(collected) == 1
    saved = task.load(root, ref)
    assert saved['ledger_projection']['state'] == 'APPLIED'
    assert saved['baseline'] == before['baseline']
    assert saved['end'] == before['end']
    assert len(engine.calls) == 1
    result = task.get(root, ref, completion_revision=done['next_action']['completion_revision'])
    assert result['review_progress']['coverage'] == 'REVIEWED'
    assert result['development_summary'] == ''


@pytest.mark.parametrize('capture', [False, True])
def test_final_ack_sql_failure_keeps_saved_review_and_retry_never_rescans(service, monkeypatch, capture):
    task, root, ref, session, engine = prepared(service, capture=capture)
    packet = task.prepare(root, ref)
    review_all(task, root, ref, packet)
    connect = sqlite3.connect
    class FailAck(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith('UPDATE security_tasks SET data=') and parameters:
                value = json.loads(parameters[0])
                if (value.get('task_ref') == ref
                        and value.get('ledger_projection', {}).get('state') == 'APPLIED'):
                    # Raise a real SQL error inside the acknowledgement's
                    # transaction without adding unsupported main-schema objects.
                    return super().execute('UPDATE __fixture_missing_ack_table SET value=1')
            return super().execute(sql, parameters)
    def fail_ack_connection(*args, **kwargs):
        return connect(*args, **dict(kwargs, factory=FailAck))
    with monkeypatch.context() as fault:
        fault.setattr(sqlite3, 'connect', fail_ack_connection)
        done = task.submit(root, ref, session, [], 'REVIEWED', [])
    assert done['status'] == 'COMPLETE' and done['risk_ledger_sync']['pending']
    saved = task.load(root, ref)
    assert saved['phase'] == 'COMPLETE'
    assert saved['ledger_projection']['state'] == 'PENDING'
    resumed = task.submit(root, ref, session, [], 'REVIEWED', [])
    assert resumed['risk_ledger_sync']['state'] == 'APPLIED'
    current = task.load(root, ref)
    assert current['review'] == saved['review']
    assert current['baseline'] == saved['baseline'] and current['end'] == saved['end']
    assert current['review_ledger'] == saved['review_ledger']
    assert len(engine.calls) == 1


def test_real_sql_rollback_preserves_review_progress_and_all_raw_bytes(service):
    task, root, ref, _, _ = prepared(service)
    state = task.store(root)
    candidate = task.load(root, ref)
    candidate['context_bytes'] += 1
    with sqlite3.connect(state.path) as db:
        db.execute("CREATE TRIGGER review_update_fault BEFORE UPDATE ON security_tasks "
                   "BEGIN SELECT RAISE(ABORT, 'isolated control write failure'); END")
    before = images(task, root)
    with pytest.raises(sqlite3.IntegrityError, match='isolated control write failure'):
        state.save_review(candidate)
    assert images(task, root) == before


def test_record_capacity_failure_does_not_charge_or_create_source_pages(service):
    task, root, ref, _, _ = prepared(service)
    state = task.store(root)
    candidate = task.load(root, ref)
    candidate['evidence']['oversized-fixture'] = 'x' * 4_000_000
    before = images(task, root)
    with pytest.raises(ReviewControlError, match='REVIEW_CONTROL_WAITING_CAPACITY'):
        state.save_review(candidate)
    assert images(task, root) == before
