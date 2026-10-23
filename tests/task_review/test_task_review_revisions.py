"""Review revisions retain original proof and spending without old approvals."""
import copy

import pytest

from security_runtime.task_review import budget as adaptive
from security_runtime.task_review import plan as plans
from security_runtime.task_review.revisions import advance_revision, ReviewRevisionError
from test_task_review_plan import task, snapshot
from test_task_security import service  # noqa: F401
from task_review_helpers import review_all


def completed_record():
    record = task()
    record.update(review_protocol=3, evidence={}, context_bytes=0, related_files=[])
    plan = plans.build_plan(record, now=1, protocol_version=3)
    for index, window in enumerate(plan['units'][0]['required_windows']):
        evidence = dict(window, evidence_id=f'first-{index}', total_lines=1)
        record['evidence'][evidence['evidence_id']] = plans.record_read(record, evidence, now=2)
    plans.submit_units(record, [plan['units'][0]['unit_id']], 'REVIEWED', [], now=3)
    record.update(review_session='old-session', phase='COMPLETE',
        review=dict(coverage='REVIEWED', findings=[dict(id='original-risk')]),
        review_completion=plans.finalize_plan(record, now=4))
    plans.charge_packet(record, b'already delivered', now=4)
    return record


def test_revision_archives_original_proof_without_copying_source_or_approval():
    original = completed_record()
    before = copy.deepcopy(original)
    next_record = advance_revision(original)
    assert original == before
    assert next_record['baseline'] == original['baseline']
    assert next_record['review_ledger'] == original['review_ledger']
    assert next_record['review_revision'] == 2
    assert 'review_plan' not in next_record and 'review_session' not in next_record
    assert next_record['evidence'] == {} and next_record['review'] is None
    archive = next_record['review_history'][0]
    assert archive['evidence'] == original['evidence']
    assert archive['review'] == original['review']
    assert archive['completion']['coverage'] == 'REVIEWED'
    assert not {'budget', 'navigation', 'evidence'} & archive['plan'].keys()
    assert not {'baseline', 'end', 'review_session', 'packet'} & archive.keys()


def test_new_plan_keeps_consumption_and_marks_all_units_pending():
    original = completed_record()
    record = advance_revision(original)
    record['end'] = snapshot({'main.py': ['latest = policy.enforce(user)']})
    plan = plans.build_plan(record, now=5, protocol_version=3)
    ledger = record['review_ledger']
    for key in ('source_bytes', 'navigation_bytes', 'control_bytes', 'total_bytes',
                'reads', 'evidence_ids', 'evidence_bindings'):
        assert ledger[key] == original['review_ledger'][key]
    assert ledger['basis']['source_ranges'] > original['review_ledger']['basis']['source_ranges']
    assert ledger['unit_count'] == 2
    assert all(unit['status'] == 'PENDING' for unit in plan['units'])
    assert not plan['evidence']
    assert plan['snapshot_id'] != original['review_plan']['snapshot_id']
    assert plans.finalize_plan(record, now=6)['coverage'] == 'PARTIAL'
    assert 'pending_review_revision' not in record
    assert plans.build_plan(record, now=6) is plan


@pytest.mark.parametrize('field', ['archive', 'ledger', 'revision'])
def test_revision_marker_cannot_replace_original_history_or_spent_budget(field):
    record = advance_revision(completed_record())
    if field == 'archive':
        record['review_history'][0]['completion']['coverage'] = 'PARTIAL'
    elif field == 'ledger':
        record['review_ledger']['total_bytes'] = 0
    else:
        record['review_revision'] += 1
    record['end'] = snapshot({'main.py': ['latest = 3']})
    before = copy.deepcopy(record)
    with pytest.raises(plans.ReviewPlanError) as caught:
        plans.build_plan(record, now=5, protocol_version=3)
    assert caught.value.reason_code == 'REVIEW_PLAN_REVISION_INVALID'
    assert record == before


def test_repeated_refinish_before_preparation_does_not_add_history_or_reset_usage():
    staged = advance_revision(completed_record())
    staged['end'] = snapshot({'main.py': ['latest = 3']})
    assert advance_revision(staged) == staged


def test_reverting_to_an_old_version_still_requires_a_new_review():
    original = completed_record()
    record = advance_revision(original)
    # Even a repeated content hash is a later obligation, not an old approval.
    record['end'] = copy.deepcopy(original['end'])
    plan = plans.build_plan(record, now=5, protocol_version=3)
    assert plan['snapshot_id'] != original['review_plan']['snapshot_id']
    assert plan['units'][0]['unit_id'] != original['review_plan']['units'][0]['unit_id']
    assert plans.finalize_plan(record, now=6)['coverage'] == 'PARTIAL'


def test_archive_capacity_failure_is_atomic_and_never_truncates_history(monkeypatch):
    from security_runtime.task_review import transport as task_review_transport
    original = completed_record()
    before = copy.deepcopy(original)
    monkeypatch.setattr(task_review_transport, 'record_capacity', lambda value: dict(fits=False))
    with pytest.raises(ReviewRevisionError) as caught:
        advance_revision(original)
    assert caught.value.reason_code == 'TASK_REVIEW_REVISION_CAPACITY'
    assert original == before


def test_new_revision_cannot_refresh_hard_budget_ceiling(monkeypatch):
    original = completed_record()
    staged = advance_revision(original)
    staged['end'] = snapshot({'main.py': ['latest = 3']})
    before = copy.deepcopy(staged)
    monkeypatch.setattr(adaptive, 'HARD_FILES', 1)
    with pytest.raises(plans.ReviewPlanError) as caught:
        plans.build_plan(staged, now=5, protocol_version=3)
    assert caught.value.reason_code == 'TASK_REVIEW_CAPACITY_REQUIRED'
    assert staged == before


def test_missing_lifetime_ledger_cannot_turn_a_revision_into_a_new_allowance():
    record = advance_revision(completed_record())
    record.pop('review_ledger')
    before = copy.deepcopy(record)
    with pytest.raises(plans.ReviewPlanError) as caught:
        plans.build_plan(record, now=5, protocol_version=3)
    assert caught.value.reason_code == 'REVIEW_PLAN_REVISION_INVALID'
    assert record == before


def test_new_revision_resumes_idle_activity_without_resetting_task_spending():
    original = completed_record()
    record = advance_revision(original)
    record['end'] = snapshot({'main.py': ['latest = 3']})
    plans.build_plan(record, now=2000, protocol_version=3)
    ledger = record['review_ledger']
    assert ledger['created_at'] == original['review_ledger']['created_at']
    assert ledger['activity_lease']['resumes'] == 1
    assert ledger['deadline'] == 2900
    assert ledger['total_bytes'] == original['review_ledger']['total_bytes']


def test_service_refinish_after_idle_resumes_original_revision_and_ledger(service):
    tasks, root, _ = service
    clock = [tasks.now()]
    tasks.now = lambda: clock[0]
    ref = tasks.begin(root, 'idle-refinish')['task_ref']
    (root/'routes.py').write_text('allowed = policy.check(user)\n')
    first = tasks.prepare(root, ref, protocol_version=3)
    review_all(tasks, root, ref, first)
    original = tasks.load(root, ref)
    clock[0] = original['review_deadline'] + 1
    (root/'routes.py').write_text('allowed = policy.enforce(user)\n')
    assert tasks.finish(root, ref)['status'] == 'READY'
    resumed = tasks.prepare(root, ref, protocol_version=3)
    assert resumed['status'] == 'REVIEW_REQUIRED'
    current = tasks.load(root, ref)
    assert current['baseline'] == original['baseline']
    assert current['review_revision'] == 2
    assert current['review_ledger']['reads'] == original['review_ledger']['reads']
    assert current['review_ledger']['total_bytes'] > original['review_ledger']['total_bytes']
    assert current['review_ledger']['activity_lease']['resumes'] == 1
    assert all(unit['status'] == 'PENDING' for unit in current['review_plan']['units'])
    _review_all(tasks, root, ref, resumed)


def _review_all(tasks, root, ref, packet):
    review_all(tasks, root, ref, packet)
    result = tasks.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    assert result['status'] == 'COMPLETE'
    assert tasks.load(root, ref)['review']['coverage'] == 'REVIEWED'


def test_finish_after_complete_reviews_latest_version_under_same_task_and_baseline(service):
    tasks, root, runtime = service
    original_lines = (root/'routes.py').read_text().splitlines()
    ref = tasks.begin(root, 'same-task-later-edit')['task_ref']
    baseline = copy.deepcopy(tasks.load(root, ref)['baseline'])
    (root/'routes.py').write_text('def get_order(order_id, user):\n    return load_order(order_id)\n')
    first = tasks.prepare(root, ref, protocol_version=3)
    _review_all(tasks, root, ref, first)
    original = tasks.load(root, ref)
    (root/'routes.py').write_text('def get_order(order_id, user):\n    return load_order_for_user(order_id, user)\n')
    assert tasks.finish(root, ref)['status'] == 'READY'
    second = tasks.prepare(root, ref, protocol_version=3)
    current = tasks.load(root, ref)
    assert second['review_revision'] == 2
    assert second['review_session'] != first['review_session']
    assert current['baseline']['hashes'] == baseline['hashes']
    assert current['baseline']['preimages'] == baseline['preimages']
    assert current['review_ledger']['total_bytes'] > original['review_ledger']['total_bytes']
    assert current['review_history'][0]['review']['coverage'] == 'REVIEWED'
    assert tasks.before_lines(root, current, 'routes.py') == original_lines
    with pytest.raises(ValueError, match='session'):
        tasks.submit(root, ref, first['review_session'], [], 'REVIEWED', [])
    before = copy.deepcopy(tasks.load(root, ref))
    assert tasks.finish(root, ref)['status'] == 'REVIEWING'
    assert tasks.load(root, ref) == before and len(runtime.calls) == 2
    _review_all(tasks, root, ref, second)


def test_later_edit_during_review_invalidates_old_session_without_erasing_deliveries(service):
    tasks, root, _ = service
    ref = tasks.begin(root, 'same-task-edit-during-review')['task_ref']
    (root/'added.py').write_text('allowed = policy.check(user)\n')
    first = tasks.prepare(root, ref, protocol_version=3)
    sent = tasks.read(root, ref, first['review_session'], 'added.py', 1, 1)
    original = tasks.load(root, ref)
    (root/'added.py').write_text('allowed = policy.enforce(user)\n')
    tasks.finish(root, ref)
    second = tasks.prepare(root, ref, protocol_version=3)
    current = tasks.load(root, ref)
    assert current['review_history'][0]['evidence'][sent['evidence_id']] == original['evidence'][sent['evidence_id']]
    assert current['review_ledger']['reads'] == original['review_ledger']['reads']
    assert current['review_ledger']['total_bytes'] > original['review_ledger']['total_bytes']
    with pytest.raises(ValueError, match='session'):
        tasks.submit_batch(root, ref, first['review_session'], [first['plan']['units'][0]['unit_id']], 'REVIEWED', [])
    # Even a valid new session cannot mark an old unit as reviewed.
    with pytest.raises(ValueError, match='unit'):
        tasks.submit_batch(root, ref, second['review_session'], [first['plan']['units'][0]['unit_id']], 'REVIEWED', [])
    _review_all(tasks, root, ref, second)


def test_conflicting_archive_save_retains_the_whole_previous_revision(service):
    tasks, root, _ = service
    ref = tasks.begin(root, 'revision-cas')['task_ref']
    (root/'added.py').write_text('allowed = policy.check(user)\n')
    tasks.prepare(root, ref, protocol_version=3)
    original = tasks.load(root, ref)
    staged = advance_revision(original)
    competing = copy.deepcopy(original)
    competing['separate_bookkeeping'] = True
    current = tasks.store(root).save(competing)
    with pytest.raises(ValueError, match='concurrently'):
        tasks.store(root).save(staged)
    assert tasks.load(root, ref) == current
    assert 'review_history' not in tasks.load(root, ref)
    assert tasks.load(root, ref)['review_plan'] == original['review_plan']


def test_returning_to_no_changes_then_editing_again_keeps_original_before_source(service):
    tasks, root, _ = service
    path = root/'routes.py'
    original = path.read_text()
    ref = tasks.begin(root, 'revision-after-revert')['task_ref']
    path.write_text('def get_order(order_id):\n    return load_order_checked(order_id)\n')
    first = tasks.prepare(root, ref, protocol_version=3)
    _review_all(tasks, root, ref, first)
    path.write_text(original)
    assert tasks.finish(root, ref)['status'] == 'NO_CHANGES'
    path.write_text('def get_order(order_id, user):\n    return load_order_for_user(order_id, user)\n')
    tasks.finish(root, ref)
    second = tasks.prepare(root, ref, protocol_version=3)
    current = tasks.load(root, ref)
    assert tasks.before_lines(root, current, 'routes.py') == original.splitlines()
    assert len(current['review_history']) == 1
    assert second['review_revision'] == 2
    _review_all(tasks, root, ref, second)
