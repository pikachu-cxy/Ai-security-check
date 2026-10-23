"""Adaptive quotas follow immutable obligations, not batches or pagination."""
import copy
import json

import pytest

from security_runtime.task_review import budget as adaptive
from security_runtime.task_review.plan import (
    ReviewPlanError, build_plan, charge_packet, finalize_plan, plan_page,
    record_read, register_related, renew_activity, source_binding, submit_units, record_capacity,
)
from test_task_review_plan import task


def added(lines, name='main.py'):
    return task({}, {name: lines}, [dict(path=name, change='ADDED')])


def test_all_changed_files_have_adaptive_capacity_batches_without_one_hundred_file_cutoff():
    files = {f'module_{i}.py': [f'guard_{j} = policy.check(subject_{j})'+ ' # context'*8
                                for j in range(25)] for i in range(130)}
    record = task({}, files, [dict(path=name, change='ADDED') for name in files])
    plan = build_plan(record, protocol_version=3, now=1)
    assert len(plan['units']) == 130
    assert plan['budget']['limits']['total_bytes'] > 256_000
    assert not any(gap['reason'] == 'TASK_CONTEXT_UNIT_BUDGET'
                   for unit in plan['units'] for gap in unit['evidence_gaps'])
    batches = {}
    for unit in plan['units']:
        batches.setdefault(unit['batch_id'], []).append(unit)
    assert len(batches) > 1 and len(next(iter(batches.values()))) != 10
    assert finalize_plan(record, now=2)['coverage'] == 'PARTIAL'
    for unit in plan['units']:
        for index, window in enumerate(unit['required_windows']):
            record_read(record, dict(window, evidence_id=f"{unit['unit_id']}-{index}", total_lines=25), now=2)
    for unit in plan['units']:
        submit_units(record, [unit['unit_id']], 'REVIEWED', [], now=3)
    complete = finalize_plan(record, now=4)
    assert complete['coverage'] == 'REVIEWED' and complete['reviewed_unit_count'] == 130


def test_a_large_source_unit_is_not_cut_off_at_sixty_four_kilobytes():
    record = added(['guard = policy.check(subject) # '+ 'context '*25 for _ in range(1500)])
    plan = build_plan(record, protocol_version=3, now=1)
    batch = plan['units'][0]['batch_id']
    for _ in range(20):
        charge_packet(record, b'x'*10_000, 'source', batch_id=batch, now=2)
    ledger = plan['budget']
    assert ledger['batches'][batch] == ledger['source_bytes'] == 200_000
    assert plan_page(record, 0, 1)['budget']['batch_is_scheduling_only'] is True
    assert ledger['activity_lease']['expires_at'] == 901  # delivery alone is not progress


def test_navigation_and_control_cannot_spend_the_source_allowance_and_rejections_are_atomic():
    record = added(['guard = policy.check(subject)'])
    ledger = build_plan(record, protocol_version=3, now=1)['budget']
    for _ in range(ledger['category_limits']['control']//16_000):
        charge_packet(record, b'c'*16_000, now=2)
    remainder = ledger['category_limits']['control']-ledger['control_bytes']
    if remainder:
        charge_packet(record, b'c'*remainder, now=2)
    before = copy.deepcopy(ledger)
    with pytest.raises(ReviewPlanError) as caught:
        charge_packet(record, b'c', now=2)
    assert caught.value.reason_code == 'TASK_CONTEXT_CONTROL_BUDGET'
    assert ledger == before
    charge_packet(record, b's', 'source', now=2)
    charge_packet(record, b'n', 'navigation', now=2)
    assert ledger['source_bytes'] == ledger['navigation_bytes'] == 1
    assert ledger['total_bytes'] == sum(ledger[key+'_bytes'] for key in ('source', 'control', 'navigation'))


def test_duplicates_are_charged_and_pagination_never_creates_a_new_allowance():
    record = added(['guard = policy.check(subject)'])
    plan = build_plan(record, protocol_version=3, now=1)
    packet = dict(message='actual utf8 元数据')
    size = len(json.dumps(packet, ensure_ascii=False).encode())
    for _ in range(3):
        charge_packet(record, packet, 'navigation', now=2)
    assert plan['budget']['navigation_bytes'] == size*3
    assert build_plan(record, now=3) is plan
    before = copy.deepcopy(plan['budget'])
    plan_page(record, 0, 1)
    plan_page(record, 0, 30)
    assert plan['budget'] == before
    with pytest.raises(ValueError, match='Unknown'):
        charge_packet(record, b'code', 'source', batch_id='invented-new-batch', now=2)


@pytest.mark.parametrize('target', [1, 2])
def test_prepared_v3_cannot_downgrade_or_refresh_limits(target):
    record = added(['guard = policy.check(subject)'])
    build_plan(record, now=1)
    charge_packet(record, b'already delivered', now=2)
    before = copy.deepcopy(record)
    from security_runtime.task_review.protocol import UnsupportedTaskReviewProtocol
    with pytest.raises(UnsupportedTaskReviewProtocol):
        build_plan(record, protocol_version=target, now=3)
    assert record == before


def test_an_adaptive_ledger_cannot_be_rebuilt_after_deleting_its_plan():
    record = added(['guard = policy.check(subject)'])
    build_plan(record, protocol_version=3, now=1)
    charge_packet(record, b'already delivered', now=2)
    record.pop('review_plan')
    before = copy.deepcopy(record['review_ledger'])
    with pytest.raises(ReviewPlanError, match='original plan'):
        build_plan(record, protocol_version=3, now=3)
    assert record['review_ledger'] == before


def test_lease_progress_resume_and_reconnect_keep_exact_evidence_and_spent_quotas():
    record = added(['guard = policy.check(subject)'])
    plan = build_plan(record, protocol_version=3, now=1)
    window = plan['units'][0]['required_windows'][0]
    evidence = dict(window, evidence_id='issued-first', total_lines=1)
    record_read(record, evidence, now=100)
    assert record['review_deadline'] == 1000
    record_read(record, evidence, now=200)
    record_read(record, dict(evidence, evidence_id='same-lines-again'), now=250)
    assert record['review_deadline'] == 1000
    charge_packet(record, b'already delivered', now=300)
    active = renew_activity(record, now=400, resume=True)
    assert active['expires_at'] == 1000
    before = copy.deepcopy(record)
    with pytest.raises(ReviewPlanError) as caught:
        charge_packet(record, b'new', now=1001)
    assert caught.value.reason_code == 'REVIEW_PLAN_IDLE'
    assert record == before
    record = json.loads(json.dumps(record))
    resumed = renew_activity(record, now=1100, resume=True)
    assert resumed['expires_at'] == record['review_deadline'] == 2000
    assert record['review_ledger']['total_bytes'] == before['review_ledger']['total_bytes']
    assert record['review_plan']['evidence'] == before['review_plan']['evidence']
    assert record['review_plan']['snapshot_id'] == before['review_plan']['snapshot_id']


def test_resume_cannot_renew_a_stale_snapshot_or_a_legacy_record():
    record = added(['guard = policy.check(subject)'])
    build_plan(record, protocol_version=3, now=1)
    record['end']['hashes']['main.py'] = 'changed'
    with pytest.raises(ReviewPlanError) as caught:
        renew_activity(record, now=1000, resume=True)
    assert caught.value.reason_code == 'REVIEW_PLAN_STALE'
    old = added(['guard = policy.check(subject)'])
    old.update(review_protocol=2, review_deadline=10, context_bytes=1234)
    saved = copy.deepcopy(old)
    from security_runtime.task_review.protocol import UnsupportedTaskReviewProtocol
    with pytest.raises(UnsupportedTaskReviewProtocol):
        renew_activity(old, now=1000, resume=True)
    assert old == saved


def test_sources_are_registered_once_without_delivery_or_rebind_credit():
    record = added(['guard = policy.check(subject)'])
    plan = build_plan(record, protocol_version=3, now=1)
    window = plan['units'][0]['required_windows'][0]
    before = copy.deepcopy(plan['budget'])
    binding = source_binding(record, window['path'], window['file_sha256'], window['location_version'], 1)
    assert len(plan['sources']) == 1 and binding['source_ref'].startswith('sr1-')
    assert not plan['evidence'] and plan['budget'] == before
    with pytest.raises(ValueError, match='line count'):
        source_binding(record, window['path'], window['file_sha256'], window['location_version'], 2)
    with pytest.raises(ValueError, match='snapshot'):
        source_binding(record, window['path'], 'other-hash', window['location_version'], 1)


def test_one_file_with_eight_hundred_hunks_has_bounded_complete_window_navigation():
    old = [f'guard_{index} = policy.check(subject_{index})' for index in range(16_000)]
    new = old.copy()
    for index in range(10, len(new), 20):
        new[index] += ' + changed'
    record = task({'main.py': old}, {'main.py': new})
    plan = build_plan(record, protocol_version=3, now=1)
    expected = plan['units'][0]['required_windows']
    assert len(expected) >= 1500 and len(plan['sources']) == 2
    actual, cursor = [], 0
    while True:
        page = plan_page(record, cursor, 1)
        assert len(json.dumps(page, ensure_ascii=False).encode()) <= 16_000
        assert page['unit_count'] == 1
        sources = {entry['source_ref']: entry for entry in page['sources']}
        for unit in page['units']:
            for window in unit['required_windows']:
                binding = sources[window['source_ref']]
                actual.append(dict(path=binding['path'], file_sha256=binding['file_sha256'],
                    location_version=binding['location_version'], start_line=window['start_line'], end_line=window['end_line']))
        if page['next_cursor'] is None:
            break
        assert page['next_cursor'] > cursor
        cursor = page['next_cursor']
    assert actual == expected
    assert finalize_plan(record, now=2)['coverage'] == 'PARTIAL'


def test_preflight_capacity_keeps_every_unit_and_identifies_the_finite_resource_need():
    record = added(['guard = policy.check(subject)'])
    record['end']['texts'] = {}
    record['end']['line_counts'] = {'main.py': 100_000}
    plan = build_plan(record, protocol_version=3, now=1)
    assert len(plan['units']) == 1
    assert plan['capacity']['status'] == 'CAPACITY_REQUIRED'
    assert plan['capacity']['maximum_total_bytes'] == 128_000_000
    assert plan['capacity']['reasons']
    assert plan['units'][0]['required_windows'][0]['end_line'] == 100_000
    with pytest.raises(ReviewPlanError) as caught:
        charge_packet(record, b'not issued', 'source', now=2)
    assert caught.value.reason_code == 'TASK_REVIEW_CAPACITY_REQUIRED'
    assert not plan['evidence'] and plan['budget']['total_bytes'] == 0


def test_verified_new_related_ranges_expand_allocation_once_without_resetting_ledger():
    source = [f'guard_{i} = policy.check(subject_{i}) # '+ 'context '*60 for i in range(200)]
    record = task({'main.py': ['old'], 'guard.py': source}, {'main.py': ['new'], 'guard.py': source})
    plan = build_plan(record, protocol_version=3, now=1)
    charge_packet(record, b'already delivered', now=2)
    file_hash = record['end']['hashes']['guard.py']
    source_binding(record, 'guard.py', file_hash, 'CURRENT_TASK_END', len(source))
    record['baseline']['texts'] = record['end']['texts'] = {}
    unit = register_related(record, None, 'guard.py', file_hash, 1, 100, now=3, source_lines=source)
    first = copy.deepcopy(plan['budget'])
    assert first['basis']['source_lines'] == 102
    assert first['total_bytes'] == len(b'already delivered')
    register_related(record, None, 'guard.py', file_hash, 50, 90, now=4, source_lines=source)
    assert plan['budget'] == first
    register_related(record, None, 'guard.py', file_hash, 90, 200, now=5, source_lines=source)
    assert plan['budget']['basis']['source_lines'] == 202
    assert plan['budget']['category_limits']['source'] > first['category_limits']['source']
    assert plan['budget']['total_bytes'] == first['total_bytes']
    assert len(plan['units']) == 2 and plan['units'][-1]['unit_id'] == unit['unit_id']


def test_unaffordable_related_growth_does_not_change_existing_quotas_or_progress():
    record = task({'main.py': ['old'], 'guard.py': ['guard']}, {'main.py': ['new'], 'guard.py': ['guard']})
    plan = build_plan(record, protocol_version=3, now=1)
    record['end']['texts'] = {}
    before = copy.deepcopy(record)
    with pytest.raises(ReviewPlanError) as caught:
        register_related(record, None, 'guard.py', record['end']['hashes']['guard.py'],
                         1, 1_000_000, now=2)
    assert caught.value.reason_code == 'TASK_REVIEW_CAPACITY_REQUIRED'
    assert record == before and len(plan['units']) == 1


@pytest.mark.parametrize('extend_existing', [False, True])
def test_related_future_evidence_capacity_is_checked_before_any_state_changes(extend_existing):
    source = ['guard = 1']*200_000
    record = task({'main.py': ['old'], 'guard.py': source}, {'main.py': ['new'], 'guard.py': source})
    plan = build_plan(record, protocol_version=3, now=1)
    assert plan['capacity']['status'] == 'READY'
    window = plan['units'][0]['required_windows'][0]
    record_read(record, dict(window, evidence_id='real-prior-evidence', total_lines=1), now=2)
    charge_packet(record, b'prior delivery remains charged', now=3)
    file_hash = record['end']['hashes']['guard.py']
    record['baseline']['texts'] = record['end']['texts'] = {}
    if extend_existing:
        register_related(record, None, 'guard.py', file_hash, 1, 80, now=4, source_lines=source)
    plan_page(record, 0, 1)  # Existing navigation is also retained on rejection.
    before = copy.deepcopy(record)
    initial_capacity = record_capacity(record)
    assert initial_capacity['record_bytes'] < 4_000_000
    assert initial_capacity['status'] == 'READY'
    with pytest.raises(ReviewPlanError, match='future evidence growth') as caught:
        register_related(record, None, 'guard.py', file_hash,
                         81 if extend_existing else 1, len(source), now=5, source_lines=source)
    assert caught.value.reason_code == 'TASK_REVIEW_CAPACITY_REQUIRED'
    assert record == before
    assert record['review_ledger']['total_bytes'] > 0
    assert record['review_plan']['evidence']['real-prior-evidence']


def test_small_verified_related_growth_commits_updated_metadata_preflight_without_renewing_lease():
    source = [f'guard_{index} = policy.check(subject_{index})' for index in range(200)]
    record = task({'main.py': ['old'], 'guard.py': source}, {'main.py': ['new'], 'guard.py': source})
    plan = build_plan(record, protocol_version=3, now=1)
    charge_packet(record, b'prior delivery remains charged', now=2)
    before = copy.deepcopy(plan['budget'])
    record['baseline']['texts'] = record['end']['texts'] = {}
    unit = register_related(record, None, 'guard.py', record['end']['hashes']['guard.py'],
                            1, 200, now=3, source_lines=source)
    assert unit in plan['units'] and unit['required_windows'][0]['end_line'] == 200
    assert plan['metadata_capacity']['status'] == 'READY'
    assert plan['metadata_capacity']['expected_evidence_frames'] > 0
    assert plan['budget']['total_bytes'] == before['total_bytes']
    assert plan['budget']['activity_lease'] == before['activity_lease']
    assert record['review_deadline'] == before['deadline']
    assert record['review_ledger'] is plan['budget']


def test_metadata_capacity_uses_the_actual_persistent_shape_without_snapshot_source():
    record = added(['source-body-must-not-be-counted']*100)
    plan = build_plan(record, protocol_version=3, now=1)
    assert plan['metadata_capacity']['record_bytes'] < 100_000
    assert plan['metadata_capacity']['maximum_record_bytes'] == 4_000_000
    assert 'source-body-must-not-be-counted' not in json.dumps(plan['budget'])
