"""Pure planning tests: no scanners, workspace execution or external services."""
import copy
import hashlib
import json

import pytest

from security_runtime.task_review_plan import (
    ReviewPlanError, build_plan, charge_packet, finalize_plan, plan_gaps,
    plan_page, record_read, register_related, submit_units,
)


def snapshot(files):
    return dict(hashes={name: hashlib.sha256('\n'.join(lines).encode()).hexdigest()
                        for name, lines in files.items()}, texts=copy.deepcopy(files))


def task(before=None, after=None, changes=None):
    before = {'main.py': ['old = 1']} if before is None else before
    after = {'main.py': ['new = 2']} if after is None else after
    return dict(task_ref='ts1-' + 'a' * 32, baseline=snapshot(before),
                end=snapshot(after), changes=changes or [dict(path='main.py', change='MODIFIED')],
                static_attempts=1)


def read_requirement(record, requirement, *, low=None, high=None, identifier=None):
    low = requirement['start_line'] if low is None else low
    high = requirement['end_line'] if high is None else high
    identifier = identifier or f"{requirement['path']}:{requirement['location_version']}:{low}:{high}"
    evidence = dict(requirement, evidence_id=identifier, start_line=low, end_line=high)
    source = 'end' if requirement['location_version'] == 'CURRENT_TASK_END' else 'baseline'
    texts = record[source].get('texts', {})
    if requirement['path'] in texts:
        evidence['total_lines'] = len(texts[requirement['path']])
    record_read(record, evidence, now=2)
    return evidence


def satisfy_unit(record, unit):
    for requirement in list(unit['required_windows']):
        read_requirement(record, requirement)
    return submit_units(record, [unit['unit_id']], 'REVIEWED', [], now=3)


def test_plan_contains_all_changes_across_navigation_pages_and_batches():
    names = [f'module_{i}.py' for i in range(25)]
    record = task({}, {name: ['value = 1'] for name in names},
                  [dict(path=name, change='ADDED') for name in names])
    plan = build_plan(record, now=1)
    first = plan_page(record, limit=10)
    second = plan_page(record, first['next_cursor'], 10)
    third = plan_page(record, second['next_cursor'], 10)
    assert [unit['path'] for page in [first, second, third] for unit in page['units']] == names
    assert third['next_cursor'] is None
    assert len(plan_gaps(record)) == 50  # unread source and unsubmitted unit for every file
    for unit in plan['units']:
        assert satisfy_unit(record, unit)['coverage'] == 'REVIEWED'
    result = finalize_plan(record, now=4)
    assert result['coverage'] == 'REVIEWED' and result['reviewed_unit_count'] == 25
    assert record['static_attempts'] == 1


def test_unrequested_units_cannot_disappear_from_coverage():
    record = task({}, {'first.py': ['a'], 'second.py': ['b']},
                  [dict(path=name, change='ADDED') for name in ['first.py', 'second.py']])
    plan = build_plan(record, now=1)
    satisfy_unit(record, plan['units'][0])
    assert finalize_plan(record, now=4)['coverage'] == 'PARTIAL'
    assert any(gap['reason'] == 'UNIT_NOT_SUBMITTED' and gap['path'] == 'second.py'
               for gap in plan_gaps(record))


def test_reading_every_window_still_requires_host_submission():
    record = task()
    unit = build_plan(record, now=1)['units'][0]
    for required in unit['required_windows']:
        read_requirement(record, required)
    assert {gap['reason'] for gap in plan_gaps(record)} == {'UNIT_NOT_SUBMITTED'}
    assert finalize_plan(record, now=4)['coverage'] == 'PARTIAL'


def test_modified_units_require_before_and_current_versions():
    record = task()
    unit = build_plan(record, now=1)['units'][0]
    assert {item['location_version'] for item in unit['required_windows']} == {'BEFORE_TASK', 'CURRENT_TASK_END'}
    read_requirement(record, next(item for item in unit['required_windows']
                                  if item['location_version'] == 'CURRENT_TASK_END'))
    assert submit_units(record, [unit['unit_id']], 'REVIEWED', [], now=3)['coverage'] == 'PARTIAL'
    satisfy_unit(record, unit)
    assert finalize_plan(record, now=4)['coverage'] == 'REVIEWED'


def test_deleted_unit_only_accepts_the_deleted_version():
    record = task({'old.py': ['permission = True']}, {}, [dict(path='old.py', change='DELETED')])
    unit = build_plan(record, now=1)['units'][0]
    assert len(unit['required_windows']) == 1
    assert unit['required_windows'][0]['location_version'] == 'BEFORE_DELETION'
    satisfy_unit(record, unit)
    assert finalize_plan(record, now=4)['coverage'] == 'REVIEWED'


def test_sanitized_identical_versions_still_have_source_obligations():
    record = task({'main.py': ['name = REDACTED']}, {'main.py': ['name = REDACTED']})
    record['end']['hashes']['main.py'] = 'b' * 64  # differing raw literal, same sanitized text
    unit = build_plan(record, now=1)['units'][0]
    assert len(unit['required_windows']) == 2


def test_modified_diff_windows_select_actual_change_and_local_context():
    old = [f'value_{i} = {i}' for i in range(100)]
    new = old.copy()
    new[50] = 'dangerous = call()'
    record = task({'main.py': old}, {'main.py': new})
    unit = build_plan(record, now=1)['units'][0]
    for window in unit['required_windows']:
        assert window['start_line'] <= 51 <= window['end_line']
        assert window['end_line'] - window['start_line'] < 10


def test_known_line_counts_do_not_require_storing_full_snapshot_text():
    record = task()
    for version in ['baseline', 'end']:
        record[version]['texts'] = {}
        record[version]['line_counts'] = {'main.py': 10}
    plan = build_plan(record, now=1)
    assert all(window['end_line'] == 10 for window in plan['units'][0]['required_windows'])


def test_very_large_diff_input_uses_bounded_full_source_obligations():
    from security_runtime.task_review_plan import MAX_DIFF_INPUT_LINES
    old = ['same'] * (MAX_DIFF_INPUT_LINES // 2 + 1)
    new = old.copy()
    new[1] = 'changed'
    record = task({'main.py': old}, {'main.py': new})
    unit = build_plan(record, now=1)['units'][0]
    assert all(window['start_line'] == 1 and window['end_line'] == len(old)
               for window in unit['required_windows'])


def test_unknown_ranges_become_precise_after_a_runtime_read_and_need_completion():
    record = task({}, {'main.py': ['source']}, [dict(path='main.py', change='ADDED')])
    record['end']['texts'] = {}
    unit = build_plan(record, now=1)['units'][0]
    required = unit['required_windows'][0]
    assert required['end_line'] is None
    assert any(item['reason'] == 'SOURCE_RANGE_UNKNOWN' for item in plan_gaps(record))
    record_read(record, dict(required, end_line=80, evidence_id='page1', total_lines=200), now=2)
    assert required['end_line'] == 200
    gaps = plan_gaps(record)
    assert any(item['reason'] == 'SOURCE_RANGE_UNREAD' and item['start_line'] == 81 and item['end_line'] == 200 for item in gaps)
    assert not any(item['reason'] == 'SOURCE_RANGE_UNKNOWN' for item in gaps)


def test_missing_source_version_is_a_real_gap():
    record = task()
    record['baseline']['hashes'] = {}
    unit = build_plan(record, now=1)['units'][0]
    satisfy_unit(record, unit)
    assert finalize_plan(record, now=4)['coverage'] == 'PARTIAL'
    assert any(gap['reason'] == 'SOURCE_VERSION_UNAVAILABLE' for gap in plan_gaps(record))


def test_empty_hashed_files_have_no_impossible_line_one_requirement():
    record = task({}, {'empty.py': []}, [dict(path='empty.py', change='ADDED')])
    unit = build_plan(record, now=1)['units'][0]
    assert not unit['required_windows']
    submit_units(record, [unit['unit_id']], 'REVIEWED', [], now=2)
    assert finalize_plan(record, now=3)['coverage'] == 'REVIEWED'


def test_immutable_plan_and_shared_budget_survive_repeated_prepare_and_batches():
    record = task()
    plan = build_plan(record, now=1, deadline=100)
    charge_packet(record, b'123456', 'control', now=2)
    original = copy.deepcopy(plan)
    assert build_plan(record, now=50) == original
    assert plan_page(record)['budget']['total_bytes'] == 6
    assert record['static_attempts'] == 1
    with pytest.raises(ReviewPlanError, match='original limits'):
        build_plan(record, now=50, limits={'total_bytes': 999_999})
    with pytest.raises(ReviewPlanError, match='original deadline'):
        build_plan(record, now=50, deadline=1000)


def test_snapshot_changes_reject_existing_plan_instead_of_resetting_evidence():
    record = task()
    build_plan(record, now=1)
    charge_packet(record, b'abc', now=2)
    record['end']['hashes']['main.py'] = 'changed'
    with pytest.raises(ReviewPlanError) as failure:
        build_plan(record, now=3)
    assert failure.value.reason_code == 'REVIEW_PLAN_STALE'
    assert record['review_plan']['budget']['total_bytes'] == 3


def test_actual_utf8_packets_and_duplicate_deliveries_are_all_charged():
    record = task()
    budget = build_plan(record, now=1)['budget']
    packet = {'message': '已检查'}
    cost = len(json.dumps(packet, ensure_ascii=False).encode('utf-8'))
    assert charge_packet(record, packet, 'navigation', now=2) == cost
    assert charge_packet(record, packet, 'navigation', now=2) == cost
    assert budget['navigation_bytes'] == budget['total_bytes'] == cost * 2
    charge_packet(record, b'code-and-wrapper', 'source', source_bytes=4, now=2)
    assert budget['source_bytes'] == 4
    assert budget['control_bytes'] == len(b'code-and-wrapper') - 4
    assert budget['total_bytes'] == sum(budget[key] for key in ['control_bytes', 'navigation_bytes', 'source_bytes'])
    assert 'evidence_ids' not in plan_page(record)['budget']
    assert 'batches' not in plan_page(record)['budget']


def test_byte_limit_has_one_task_wide_boundary_and_rejection_preserves_ledger():
    record = task()
    budget = build_plan(record, now=1, limits={'total_bytes': 5})['budget']
    charge_packet(record, b'123', now=2)
    charge_packet(record, b'45', 'navigation', now=2)
    assert budget['total_bytes'] == 5
    with pytest.raises(ReviewPlanError) as failure:
        charge_packet(record, b'6', now=2)
    assert failure.value.reason_code == 'TASK_CONTEXT_BYTE_BUDGET'
    assert budget['total_bytes'] == 5
    assert build_plan(record, now=3)['budget'] is budget


def test_response_limit_is_recoverable_by_smaller_payload_without_material_gap():
    record = task()
    budget = build_plan(record, now=1, limits={'response_bytes': 5})['budget']
    with pytest.raises(ReviewPlanError) as failure:
        charge_packet(record, b'123456', now=2)
    assert failure.value.reason_code == 'TASK_CONTEXT_RESPONSE_BUDGET'
    assert budget['total_bytes'] == 0
    charge_packet(record, b'12345', now=2)
    assert not record['review_plan']['units'][0]['evidence_gaps']


def test_batch_limit_is_fixed_and_source_packet_automatically_selects_unit_batch():
    record = task()
    plan = build_plan(record, now=1, limits={'batch_bytes': 500})
    required = plan['units'][0]['required_windows'][0]
    payload = dict(required, numbered_lines=['1: source'])
    cost = charge_packet(record, payload, 'source', source_bytes=6, now=2)
    batch_id = plan['units'][0]['batch_id']
    assert plan['budget']['batches'][batch_id] == cost
    with pytest.raises(ReviewPlanError) as failure:
        charge_packet(record, b'x' * 500, batch_id=batch_id, now=2)
    assert failure.value.reason_code == 'TASK_CONTEXT_BATCH_BUDGET'
    assert plan_page(record, 0, 1)['batch_id'] == batch_id
    assert plan_page(record, 0, 10)['batch_id'] == batch_id
    assert plan['budget']['batches'][batch_id] == cost


def test_lifetime_ledger_survives_new_plan_snapshot_and_json_roundtrip():
    record = task()
    plan = build_plan(record, now=1, deadline=100, limits={'total_bytes': 1000})
    required = plan['units'][0]['required_windows'][0]
    read_requirement(record, required)
    charge_packet(record, b'123', batch_id=plan['units'][0]['batch_id'], now=2)
    record = json.loads(json.dumps(record))
    record['review_plan']['budget']['total_bytes'] = 0  # stale duplicated view is never authoritative
    assert plan_page(record)['budget']['total_bytes'] == 3
    original = copy.deepcopy(record['review_ledger'])
    record.pop('review_plan')  # root explicitly creates a new end-version plan
    record['end']['hashes']['main.py'] = 'new-version'
    record['context_bytes'] = 0
    record['evidence'] = {}
    new = build_plan(record, now=50)
    assert new['budget'] == original
    assert new['deadline'] == 100
    assert new['budget']['reads'] == 1
    assert new['budget']['limits']['total_bytes'] == 1000


def test_evidence_id_cannot_be_rebound_after_new_snapshot_plan():
    record = task()
    plan = build_plan(record, now=1)
    current = next(window for window in plan['units'][0]['required_windows']
                   if window['location_version'] == 'CURRENT_TASK_END')
    evidence = read_requirement(record, current)
    record.pop('review_plan')
    record['end']['hashes']['main.py'] = 'next-version'
    build_plan(record, now=4)
    with pytest.raises(ValueError, match='cannot change'):
        record_read(record, dict(evidence, file_sha256='next-version'), now=5)


def test_legacy_context_is_migrated_once_without_restarting_deadline():
    record = task()
    record.update(context_bytes=1234, evidence={'old-id': {}}, review_deadline=200)
    plan = build_plan(record, now=10)
    assert plan['budget']['total_bytes'] == 1234
    assert plan['budget']['reads'] == 1
    assert plan['deadline'] == 200
    record.pop('review_plan')
    build_plan(record, now=20)
    assert record['review_ledger']['total_bytes'] == 1234
    assert record['review_ledger']['reads'] == 1


def test_unique_evidence_read_budget_is_shared_and_duplicates_dont_create_proof():
    record = task()
    unit = build_plan(record, now=1, limits={'reads': 1})['units'][0]
    first = read_requirement(record, unit['required_windows'][0])
    record_read(record, first, now=2)
    with pytest.raises(ReviewPlanError) as failure:
        read_requirement(record, unit['required_windows'][1])
    assert failure.value.reason_code == 'TASK_CONTEXT_READ_BUDGET'
    assert record['review_plan']['budget']['reads'] == 1
    assert finalize_plan(record, now=3)['coverage'] == 'PARTIAL'


def test_pagination_gaps_can_be_filled_without_reset_or_permanent_partial():
    record = task({}, {'main.py': [f'value_{i}' for i in range(100)]},
                  [dict(path='main.py', change='ADDED')])
    unit = build_plan(record, now=1)['units'][0]
    required = unit['required_windows'][0]
    read_requirement(record, required, high=80)
    assert submit_units(record, [unit['unit_id']], 'REVIEWED', [], now=3)['coverage'] == 'PARTIAL'
    read_requirement(record, required, low=81)
    assert submit_units(record, [unit['unit_id']], 'REVIEWED', [], now=3)['coverage'] == 'REVIEWED'
    assert not plan_gaps(record)


def test_related_requirements_are_explicit_and_reopen_only_the_affected_unit():
    record = task({'main.py': ['old'], 'guard.py': ['guard']},
                  {'main.py': ['new'], 'guard.py': ['guard']})
    unit = build_plan(record, now=1)['units'][0]
    satisfy_unit(record, unit)
    register_related(record, unit['unit_id'], 'guard.py', record['end']['hashes']['guard.py'], 1, 1, now=4)
    assert unit['status'] == 'PENDING'
    assert finalize_plan(record, now=4)['coverage'] == 'PARTIAL'
    satisfy_unit(record, unit)
    assert finalize_plan(record, now=5)['coverage'] == 'REVIEWED'


def test_related_file_budget_is_global_across_batches():
    before = {'main.py': ['old'], 'guard1.py': ['one'], 'guard2.py': ['two']}
    after = dict(before, **{'main.py': ['new']})
    record = task(before, after)
    unit = build_plan(record, now=1, limits={'related_files': 1})['units'][0]
    register_related(record, unit['unit_id'], 'guard1.py', record['end']['hashes']['guard1.py'], 1, 1, now=2)
    with pytest.raises(ReviewPlanError) as failure:
        register_related(record, unit['unit_id'], 'guard2.py', record['end']['hashes']['guard2.py'], 1, 1, now=2)
    assert failure.value.reason_code == 'TASK_CONTEXT_RELATED_FILE_BUDGET'
    assert record['review_plan']['related_files'] == ['guard1.py']


def test_none_unit_id_creates_discoverable_related_unit_and_extends_same_path():
    record = task({'main.py': ['old'], 'guard.py': ['one', 'two', 'three']},
                  {'main.py': ['new'], 'guard.py': ['one', 'two', 'three']})
    plan = build_plan(record, now=1)
    related = register_related(record, None, 'guard.py', record['end']['hashes']['guard.py'], 1, 1, now=2)
    assert related['change'] == 'RELATED'
    assert related['unit_id'] in [unit['unit_id'] for unit in plan_page(record)['units']]
    repeated = register_related(record, None, 'guard.py', record['end']['hashes']['guard.py'], 2, 3, now=2)
    assert repeated is related and len(plan['units']) == 2
    assert related['required_windows'][0]['start_line'] == 1
    assert related['required_windows'][0]['end_line'] == 3
    satisfy_unit(record, plan['units'][0])
    assert finalize_plan(record, now=3)['coverage'] == 'PARTIAL'
    satisfy_unit(record, related)
    assert finalize_plan(record, now=4)['coverage'] == 'REVIEWED'


def test_more_changed_files_than_policy_remain_visible_and_cannot_claim_full():
    record = task({}, {'one.py': ['one'], 'two.py': ['two']},
                  [dict(path=name, change='ADDED') for name in ['one.py', 'two.py']])
    plan = build_plan(record, now=1, limits={'changed_files': 1})
    for unit in plan['units']:
        satisfy_unit(record, unit)
    assert len(plan['units']) == 2
    assert finalize_plan(record, now=4)['coverage'] == 'PARTIAL'
    assert any(gap['reason'] == 'TASK_CONTEXT_UNIT_BUDGET' and gap['path'] == 'two.py'
               for gap in plan_gaps(record))


def test_unverified_change_scope_prevents_aggregate_reviewed():
    record = task()
    record['unverified_paths'] = ['unreadable.py']
    unit = build_plan(record, now=1)['units'][0]
    satisfy_unit(record, unit)
    assert finalize_plan(record, now=4)['coverage'] == 'PARTIAL'
    assert any(gap['reason'] == 'TASK_CHANGE_COMPARISON_UNAVAILABLE' for gap in plan_gaps(record))


def test_expiry_cannot_be_reset_by_preparing_or_starting_another_batch():
    record = task()
    plan = build_plan(record, now=1, deadline=3)
    assert finalize_plan(record, now=4)['status'] == 'EXPIRED'
    assert build_plan(record, now=5) is plan
    for action in [lambda: charge_packet(record, b'one', now=4),
                   lambda: submit_units(record, [plan['units'][0]['unit_id']], 'REVIEWED', [], now=4)]:
        with pytest.raises(ReviewPlanError) as failure:
            action()
        assert failure.value.reason_code == 'REVIEW_PLAN_EXPIRED'
    assert plan['deadline'] == 3


def test_completed_units_keep_their_historical_result_after_deadline():
    record = task()
    unit = build_plan(record, now=1, deadline=3)['units'][0]
    satisfy_unit(record, unit)
    assert finalize_plan(record, now=4)['status'] == 'COMPLETE'


def test_forged_or_rebound_evidence_is_rejected():
    record = task()
    unit = build_plan(record, now=1)['units'][0]
    first = read_requirement(record, unit['required_windows'][0])
    with pytest.raises(ValueError, match='source version'):
        record_read(record, dict(first, file_sha256='wrong'), now=2)
    with pytest.raises(ValueError, match='cannot change'):
        record_read(record, dict(first, end_line=2, total_lines=2), now=2)


@pytest.mark.parametrize('cursor,limit', [(-1, 1), (True, 1), (0, 0), (0, 31), (0, True)])
def test_plan_page_parameters_cannot_widen_batch(cursor, limit):
    record = task()
    build_plan(record, now=1)
    with pytest.raises(ValueError):
        plan_page(record, cursor, limit)
