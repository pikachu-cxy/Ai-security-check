"""Faults between signed task commits and ledger projection keep real evidence."""
import copy
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from security_runtime.findings import FindingNormalizer
from security_runtime.tasks.risk_ledger import TaskRiskLedger
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.security_state import TaskSecurityStore
from test_task_security import begin, candidate, prepared, service  # noqa: F401
from task_review_helpers import review_all


def private_bytes(service, root):
    directory = service.hooks.workspace_directory(root)
    return {str(path.relative_to(directory)): path.read_bytes()
            for path in directory.rglob('*') if path.is_file()}


def pending_static(sample):
    tasks, root, runtime = sample
    ref = begin(sample)
    baseline = copy.deepcopy(tasks.load(root, ref)['baseline'])
    (root / 'routes.py').write_text('def get_order(order_id, user):\n    return load_order(order_id)\n')
    runtime.findings = [FindingNormalizer(root).make(
        scanner='fixture-only', category='authorization', title='Owner check candidate',
        description='Fixture signal', severity='MEDIUM', confidence='MEDIUM',
        file_path='routes.py', line=2, evidence='return load_order(order_id)')]
    with patch.object(TaskRiskLedger, 'register', side_effect=OSError('fixture ledger write failure')):
        result = tasks.finish(root, ref)
    assert result['risk_ledger_sync'] == dict(state='PENDING', pending=True)
    return ref, baseline


def fail_ack_for(ref):
    save = TaskSecurityStore.save

    def fail_ack(store, record, **kwargs):
        if (record['task_ref'] == ref
                and record.get('ledger_projection', {}).get('state') == 'APPLIED'):
            raise sqlite3.OperationalError('fixture projection acknowledgement failure')
        return save(store, record, **kwargs)

    return patch.object(TaskSecurityStore, 'save', fail_ack)


def create_host_risk(sample):
    tasks, root, _ = sample
    ref, session, packet = prepared(sample)
    primary = tasks.read(root, ref, session, 'routes.py', 2, 2)
    related = tasks.read(root, ref, session, 'auth.py', 1, 2)
    review_all(tasks, root, ref, packet)
    result = tasks.submit(root, ref, session,
                          [candidate(primary['evidence_id'], related['evidence_id'])], 'REVIEWED', [])
    assert result['result_saved'] is True
    return ref, tasks.get(root, ref)['findings'][0]['detail']['id']


def prepare_resolution(sample, origin, key, code=None):
    tasks, root, _ = sample
    ref = tasks.begin(root, key)['task_ref']
    if code is None:
        code = 'def get_order(order_id, user):\n    return load_owned_order(order_id, user)\n'
    (root / 'routes.py').write_text(code)
    packet = tasks.prepare(root, ref)
    session = packet['review_session']
    primary = tasks.read(root, ref, session, 'routes.py', 1, 2)
    related = tasks.read(root, ref, session, 'auth.py', 1, 2)
    resolution = dict(original_task_ref=origin[0], finding_id=origin[1],
        evidence_refs=[primary['evidence_id'], related['evidence_id']],
        outcome='CODE_REVIEWED_RESOLVED', rationale='The issued source now checks the owner.',
        tests='Host code review only; no independent scanner proof is claimed.')
    review_all(tasks, root, ref, packet)
    return ref, session, resolution


def test_static_result_is_committed_before_ledger_failure_and_retry_reuses_task(service):
    tasks, root, runtime = service
    ref, baseline = pending_static(service)
    saved = tasks.load(root, ref)
    assert saved['phase'] == 'READY' and len(saved['static']['findings']) == 1
    assert saved['baseline'] == baseline
    assert not TaskRiskLedger(tasks.hooks, root).read()
    restarted = TaskSecurityService(runtime, tasks.hooks, owner=tasks.owner)
    result = restarted.finish(root, ref)
    assert result['risk_ledger_sync'] == dict(state='APPLIED', pending=False)
    assert restarted.load(root, ref)['baseline'] == baseline
    assert len(runtime.calls) == 1
    assert len(TaskRiskLedger(tasks.hooks, root).read()) == 1
    assert [row['task_ref'] for row in restarted.store(root).records()] == [ref]


def test_ledger_written_before_ack_failure_replays_without_duplicate_or_replaced_rows(service):
    tasks, root, runtime = service
    ref = begin(service)
    baseline = copy.deepcopy(tasks.load(root, ref)['baseline'])
    (root / 'routes.py').write_text('def get_order(order_id, user):\n    return load_order(order_id)\n')
    runtime.findings = [FindingNormalizer(root).make(
        scanner='fixture-only', category='authorization', title='Owner check candidate',
        description='Fixture signal', severity='MEDIUM', confidence='MEDIUM',
        file_path='routes.py', line=2)]
    with fail_ack_for(ref):
        result = tasks.finish(root, ref)
    assert result['risk_ledger_sync']['pending']
    assert tasks.load(root, ref)['ledger_projection']['state'] == 'PENDING'
    ledger = TaskRiskLedger(tasks.hooks, root)
    rows = ledger.read()
    assert len(rows) == 1
    next(iter(rows.values()))['audit_fixture'] = 'retain unrelated saved metadata'
    with tasks.hooks.lock(root) as acquired:
        assert acquired
        ledger.save(rows)
    for _ in range(2):
        assert tasks.finish(root, ref)['risk_ledger_sync']['state'] == 'APPLIED'
    assert ledger.read() == rows
    assert tasks.load(root, ref)['baseline'] == baseline
    assert len(runtime.calls) == 1


def test_final_host_review_survives_projection_failure_and_idempotent_submit(service):
    tasks, root, runtime = service
    ref, session, packet = prepared(service)
    baseline = copy.deepcopy(tasks.load(root, ref)['baseline'])
    primary = tasks.read(root, ref, session, 'routes.py', 2, 2)
    related = tasks.read(root, ref, session, 'auth.py', 1, 2)
    findings = [candidate(primary['evidence_id'], related['evidence_id'])]
    review_all(tasks, root, ref, packet)
    with patch.object(TaskRiskLedger, 'register', side_effect=OSError('fixture ledger unavailable')):
        result = tasks.submit(root, ref, session, findings, 'REVIEWED', [])
    assert result['status'] == 'COMPLETE' and result['risk_ledger_sync']['pending']
    saved = tasks.load(root, ref)
    assert len(saved['review']['findings']) == 1 and saved['baseline'] == baseline
    result = tasks.submit(root, ref, session, findings, 'REVIEWED', [])
    assert result['risk_ledger_sync'] == dict(state='APPLIED', pending=False)
    assert tasks.load(root, ref)['review'] == saved['review']
    assert tasks.load(root, ref)['baseline'] == baseline and len(runtime.calls) == 1
    assert len(TaskRiskLedger(tasks.hooks, root).read()) == 1


def test_pending_reads_do_not_replay_or_acknowledge_projection(service):
    tasks, root, runtime = service
    ref, _ = pending_static(service)
    before = private_bytes(tasks, root)
    with patch.object(TaskSecurityStore, 'save', side_effect=AssertionError('read attempted a task write')), \
         patch.object(TaskRiskLedger, 'save', side_effect=AssertionError('read attempted a ledger write')):
        result = tasks.get(root, ref)
        ledger = tasks.risk_ledger(root, ref)
    assert result['risk_ledger_sync']['pending'] and ledger['risk_ledger_sync']['pending']
    assert private_bytes(tasks, root) == before and len(runtime.calls) == 1


def test_changed_source_never_replays_an_old_resolution(service):
    tasks, root, runtime = service
    origin = create_host_risk(service)
    ref, session, resolution = prepare_resolution(service, origin, 'resolve-original')
    with patch.object(TaskRiskLedger, 'record_host', side_effect=OSError('fixture host update failure')):
        result = tasks.submit(root, ref, session, [], 'REVIEWED', [], [resolution])
    assert result['risk_ledger_sync']['pending']
    key = origin[0] + ':' + origin[1]
    ledger = TaskRiskLedger(tasks.hooks, root)
    before = copy.deepcopy(ledger.read()[key])
    (root / 'routes.py').write_text('def get_order(order_id, user):\n    return changed_again(order_id)\n')
    result = tasks.submit(root, ref, session, [], 'REVIEWED', [], [resolution])
    assert result['risk_ledger_sync']['pending']
    assert ledger.read()[key] == before
    assert len(runtime.calls) == 2


def test_ack_retry_for_applied_resolution_does_not_write_the_ledger_again(service):
    tasks, root, runtime = service
    origin = create_host_risk(service)
    ref, session, resolution = prepare_resolution(service, origin, 'resolve-once')
    with fail_ack_for(ref):
        result = tasks.submit(root, ref, session, [], 'REVIEWED', [], [resolution])
    assert result['risk_ledger_sync']['pending']
    before = copy.deepcopy(TaskRiskLedger(tasks.hooks, root).read())
    with patch.object(TaskRiskLedger, 'save', side_effect=AssertionError('applied event rewrote the ledger')):
        result = tasks.submit(root, ref, session, [], 'REVIEWED', [], [resolution])
    assert result['risk_ledger_sync'] == dict(state='APPLIED', pending=False)
    assert TaskRiskLedger(tasks.hooks, root).read() == before
    assert len(runtime.calls) == 2


def test_legacy_records_are_not_migrated_by_read_or_unchanged_finish(service):
    tasks, root, runtime = service
    ref = begin(service)
    (root / 'routes.py').write_text('def get_order(order_id, user):\n    return load_order(order_id)\n')
    tasks.finish(root, ref)
    legacy = tasks.load(root, ref)
    legacy.pop('ledger_projection')
    tasks.store(root).save(legacy)
    before = private_bytes(tasks, root)
    with patch.object(TaskSecurityStore, 'save', side_effect=AssertionError('legacy record was migrated')), \
         patch.object(TaskRiskLedger, 'save', side_effect=AssertionError('legacy ledger was rewritten')):
        assert tasks.get(root, ref)['risk_ledger_sync'] == dict(state='LEGACY_NOT_RECORDED', pending=False)
        assert tasks.risk_ledger(root, ref)['risk_ledger_sync']['state'] == 'LEGACY_NOT_RECORDED'
        assert tasks.finish(root, ref)['risk_ledger_sync']['state'] == 'LEGACY_NOT_RECORDED'
    assert private_bytes(tasks, root) == before and len(runtime.calls) == 1


def test_replaced_task_revision_supersedes_pending_projection_without_writing_ledger(service):
    tasks, root, runtime = service
    ref, baseline = pending_static(service)
    record = tasks.load(root, ref)
    record['review_revision'] = record.get('review_revision', 1) + 1
    tasks.store(root).save(record)
    with patch.object(TaskRiskLedger, 'register', side_effect=AssertionError('superseded revision was replayed')):
        result = tasks.finish(root, ref)
    assert result['risk_ledger_sync'] == dict(state='SUPERSEDED', pending=False)
    assert tasks.load(root, ref)['baseline'] == baseline
    assert not TaskRiskLedger(tasks.hooks, root).read()
    assert len(runtime.calls) == 1


def test_older_ack_retry_does_not_overwrite_a_newer_resolution_for_identical_source(service):
    tasks, root, runtime = service
    origin = create_host_risk(service)
    first_ref, first_session, first_resolution = prepare_resolution(service, origin, 'resolution-A')
    same_source = (root / 'routes.py').read_text()
    with fail_ack_for(first_ref):
        first = tasks.submit(root, first_ref, first_session, [], 'REVIEWED', [], [first_resolution])
    assert first['risk_ledger_sync']['pending']
    ledger = TaskRiskLedger(tasks.hooks, root)
    key = origin[0] + ':' + origin[1]
    assert ledger.read()[key]['review_task_ref'] == first_ref
    # B has a real task delta, ending at exactly the same source hash as A.
    (root / 'routes.py').write_text('def get_order(order_id, user):\n    return intermediate(order_id)\n')
    second_ref, second_session, second_resolution = prepare_resolution(
        service, origin, 'resolution-B', code=same_source)
    second_resolution['outcome'] = 'STILL_PRESENT'
    second_resolution['rationale'] = 'A later review found the helper does not enforce the owner policy.'
    tasks.submit(root, second_ref, second_session, [], 'REVIEWED', [], [second_resolution])
    newer = copy.deepcopy(ledger.read()[key])
    assert newer['review_task_ref'] == second_ref and newer['status'] == 'STILL_PRESENT'
    replay = tasks.submit(root, first_ref, first_session, [], 'REVIEWED', [], [first_resolution])
    assert replay['risk_ledger_sync']['pending']
    assert ledger.read()[key] == newer
    assert len(runtime.calls) == 3
