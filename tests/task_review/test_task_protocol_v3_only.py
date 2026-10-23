"""Retiring execution must not rewrite history, budgets or repair authority."""
import copy
import json

import pytest

from security_runtime.task_review import TaskReviewCoordinator
from security_runtime.task_review.protocol import (
    PROTOCOL_VERSION, UnsupportedTaskReviewProtocol, is_v3_record,
    require_record_protocol, validate_protocol,
)
from security_runtime.tasks.security import method
from security_runtime.tasks.security_state import TaskSecurityStore
from security_runtime.task_review.plan import ReviewPlanError, plan_page
from security_runtime.task_review.revisions import advance_revision, ReviewRevisionError
from test_task_security import service, prepared  # noqa: F401
from task_review_helpers import evidence_id, read_plan, review_all


@pytest.mark.parametrize('value', [None, 1, 2, 0, 4, True, False, 3.0, '3', {}, [],
                                  'secret-protocol-value'])
def test_only_exact_integer_three_executes_and_diagnostics_do_not_echo_inputs(value):
    with pytest.raises(UnsupportedTaskReviewProtocol) as rejected:
        validate_protocol(value)
    result = rejected.value.response()
    assert result['status'] == result['reason_code'] == 'UNSUPPORTED_TASK_REVIEW_PROTOCOL'
    assert result['protocol_version'] == PROTOCOL_VERSION == 3
    assert result['read_only_supported'] and not result['scanner_run']
    assert not result['repair_authorized'] and not result['recoverable']
    assert 'secret-protocol-value' not in json.dumps(result)
    assert not is_v3_record({'review_protocol': value})
    assert validate_protocol(3) == require_record_protocol({'review_protocol': 3}) == 3


def test_new_baseline_persists_protocol_before_prepare_and_does_not_read_plan(service):
    s, root, runtime = service
    ref, session, packet = prepared(service)
    record = s.load(root, ref)
    assert record['review_protocol'] == packet['protocol_version'] == 3
    assert packet['quick_skill']['version'] == 'quick-task-review-v3'
    assert not record['evidence'] and not record['review_plan']['evidence']
    assert all(unit['status'] == 'PENDING' for unit in record['review_plan']['units'])
    assert record['review_session'] == session and len(runtime.calls) == 1


@pytest.mark.parametrize('protocol', [None, 1, 2, True, 3.0, '3'])
@pytest.mark.parametrize('operation', ['finish', 'prepare', 'read', 'plan', 'batch', 'submit', 'method', 'skip'])
def test_historical_execution_is_rejected_before_any_replay_scan_or_persistence(service, monkeypatch,
                                                                              protocol, operation):
    s, root, runtime = service
    ref, session, _ = prepared(service)
    record = s.load(root, ref)
    if protocol is None:
        record.pop('review_protocol')
    else:
        record['review_protocol'] = protocol
    record['native_repair'] = dict(source='fixture', assessment_ref='retained',
        proposal_revision=1, source_binding='binding', authorized_intent='must-remain')
    s.store(root).save(record)
    original = copy.deepcopy(s.load(root, ref))
    source = {path.name: path.read_bytes() for path in root.glob('*.py')}
    db_before = s.store(root).path.read_bytes()
    def forbidden(*args, **kwargs):
        pytest.fail('A historical task must not replay, scan, capture or save')
    monkeypatch.setattr('security_runtime.tasks.projection.drain', forbidden)
    monkeypatch.setattr('security_runtime.tasks.security.capture', forbidden)
    monkeypatch.setattr(TaskSecurityStore, 'save', forbidden)
    monkeypatch.setattr(runtime, 'scan', forbidden)
    actions = dict(finish=lambda: s.finish(root, ref), prepare=lambda: s.prepare(root, ref),
        read=lambda: s.read(root, ref, session, 'routes.py'),
        plan=lambda: s.review_plan(root, ref, session),
        batch=lambda: s.submit_batch(root, ref, session, ['invented'], 'REVIEWED', []),
        submit=lambda: s.submit(root, ref, session, [], 'REVIEWED', []),
        method=lambda: s.review_method(root, ref, session), skip=lambda: s.skip(root, ref, 'legacy'))
    with pytest.raises(UnsupportedTaskReviewProtocol):
        actions[operation]()
    assert s.load(root, ref) == original
    assert s.store(root).path.read_bytes() == db_before
    assert {path.name: path.read_bytes() for path in root.glob('*.py')} == source


@pytest.mark.parametrize('protocol', [None, 1, 2])
def test_history_reads_keep_original_protocol_and_cannot_be_resumed_by_same_key(service, protocol):
    s, root, runtime = service
    old_ref = s.begin(root, 'historical-key')['task_ref']
    old = s.load(root, old_ref)
    if protocol is None:
        old.pop('review_protocol')
    else:
        old['review_protocol'] = protocol
    s.store(root).save(old)
    before = copy.deepcopy(s.load(root, old_ref))
    db_before = s.store(root).path.read_bytes()
    result = s.get(root, old_ref)
    s.risk_ledger(root, old_ref)
    assert result['protocol_version'] is protocol
    assert not result['review_required'] and not result['repair_authorized']
    assert s.store(root).path.read_bytes() == db_before
    with pytest.raises(UnsupportedTaskReviewProtocol):
        s.begin(root, 'historical-key')
    new_ref = s.begin(root, 'new-work-key')['task_ref']
    assert new_ref != old_ref and s.load(root, new_ref)['review_protocol'] == 3
    assert s.load(root, old_ref) == before and runtime.calls == []


def test_latest_legacy_activity_cannot_hide_an_earlier_active_v3_task(service):
    s, root, _ = service
    ref = s.begin(root, 'current-work')['task_ref']
    old = copy.deepcopy(s.load(root, ref))
    old.update(task_ref='ts1-'+'f'*32, task_key='historical-unrelated', generation=0)
    # This signed fixture models an existing older writer; new=True may never
    # publish it. Save first as v3 then retain the historical protocol verbatim.
    old = s.store(root).save(old, new=True)
    old['review_protocol'] = 2
    s.store(root).save(old)
    store = s.store(root)
    assert len(store.records(active=True)) == 2
    assert store.get(active=True)['task_ref'] == ref
    assert store.for_hook('codex', 'fixture-session')['task_ref'] == ref
    assert s.begin(root, 'third-work')['status'] == 'ACTIVE_TASK_EXISTS'


@pytest.mark.parametrize('protocol', [None, 1, 2, True, 3.0])
def test_new_store_records_cannot_publish_historical_or_invalid_protocol(service, protocol):
    s, root, _ = service
    ref = s.begin(root, 'valid-task')['task_ref']
    new = copy.deepcopy(s.load(root, ref))
    new.update(task_ref='ts1-'+'e'*32, task_key='invalid-new', generation=0)
    if protocol is None:
        new.pop('review_protocol')
    else:
        new['review_protocol'] = protocol
    before = s.store(root).path.read_bytes()
    with pytest.raises(UnsupportedTaskReviewProtocol):
        s.store(root).save(new, new=True)
    assert s.store(root).path.read_bytes() == before


@pytest.mark.parametrize('protocol', [1, 2, None, True, 3.0, '3'])
def test_explicit_invalid_prepare_and_method_cannot_silently_upgrade(service, protocol):
    s, root, runtime = service
    ref = s.begin(root, 'explicit-version')['task_ref']
    (root/'routes.py').write_text('changed_before_prepare = True\n')
    before = s.store(root).path.read_bytes()
    with pytest.raises(UnsupportedTaskReviewProtocol):
        s.prepare(root, ref, protocol_version=protocol)
    with pytest.raises(UnsupportedTaskReviewProtocol):
        TaskReviewCoordinator(s).prepare(root, ref, protocol_version=protocol)
    with pytest.raises(UnsupportedTaskReviewProtocol):
        method(protocol)
    assert s.store(root).path.read_bytes() == before and runtime.calls == []


def test_real_v3_helpers_read_both_versions_and_use_actual_duplicate_ids(service):
    s, root, runtime = service
    ref, session, packet = prepared(service)
    before_reads = s.load(root, ref)['review_ledger']['reads']
    units, _ = read_plan(s, root, ref, packet)
    assert units and not s.load(root, ref)['evidence']
    assert s.load(root, ref)['review_ledger']['reads'] == before_reads
    delivered, _ = review_all(s, root, ref, packet)
    stored = s.load(root, ref)
    assert {item['location_version'] for item in stored['evidence'].values()} == {
        'BEFORE_TASK', 'CURRENT_TASK_END'}
    duplicate = s.read(root, ref, session, 'routes.py', 2, 2)
    assert duplicate['status'] == 'ALREADY_DELIVERED'
    assert evidence_id(duplicate) in stored['evidence']
    assert all(evidence_id(item) in stored['evidence'] for item in delivered)
    assert all(unit['status'] == 'REVIEWED' for unit in stored['review_plan']['units'])
    assert len(runtime.calls) == 1


@pytest.mark.parametrize('missing_ledger', [None, {}])
def test_missing_authoritative_ledger_cannot_use_a_plan_budget_shadow(service, missing_ledger):
    s, root, _ = service
    ref, _, _ = prepared(service)
    record = s.load(root, ref)
    record['review_plan']['budget'] = copy.deepcopy(record['review_ledger'])
    if missing_ledger is None:
        record.pop('review_ledger')
    else:
        record['review_ledger'] = missing_ledger
    before = copy.deepcopy(record)
    with pytest.raises(ReviewPlanError) as rejected:
        plan_page(record)
    assert rejected.value.reason_code == 'REVIEW_PLAN_REVISION_INVALID'
    assert record == before


@pytest.mark.parametrize('ledger', [None, {}, {'protocol_version': 1},
                                   {'protocol_version': 2}, {'protocol_version': 3.0}])
def test_revision_cannot_reset_an_invalid_or_missing_existing_ledger(ledger):
    record = dict(review_protocol=3, review_ledger=ledger)
    before = copy.deepcopy(record)
    with pytest.raises(ReviewRevisionError) as rejected:
        advance_revision(record)
    assert rejected.value.reason_code == 'REVIEW_PLAN_REVISION_INVALID'
    assert record == before
