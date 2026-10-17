"""Saved task completion and its exact scope survive later project edits."""
import copy
import json

import pytest

from security_runtime.task_review_results import bounded_history_result, history_freshness
from test_task_review_results import record as history_record, assert_bounded
from test_task_review_v2 import review_all, assert_reviewed
from test_task_security import service  # noqa: F401; shared fixture


def complete_task(service, *, related=False):
    s, root, _ = service
    ref = s.begin(root, 'completed-review-history')['task_ref']
    (root/'routes.py').write_text('def route(user):\n    return policy.enforce(user)\n')
    packet = s.prepare(root, ref, protocol_version=2)
    review_all(s, root, ref, packet)
    if related:
        s.read(root, ref, packet['review_session'], 'auth.py', 1, 2)
        page = s.review_plan(root, ref, packet['review_session'])
        related_unit = next(unit for unit in page['units'] if unit['change'] == 'RELATED')
        s.submit_batch(root, ref, packet['review_session'], [related_unit['unit_id']], 'REVIEWED', [])
    assert_reviewed(s, root, ref, packet)
    return s, root, ref


@pytest.mark.parametrize('action', ['modify', 'delete', 'add'])
def test_other_project_changes_preserve_completed_history_and_exact_unchanged_scope(service, action):
    s, root, ref = complete_task(service)
    saved = copy.deepcopy(s.load(root, ref))
    original = s.get(root, ref)
    if action == 'modify':
        (root/'service.py').write_text('def updated_service():\n    return True\n')
        name = 'service.py'
    elif action == 'delete':
        (root/'service.py').unlink()
        name = 'service.py'
    else:
        (root/'later.py').write_text('def later():\n    return True\n')
        name = 'later.py'
    result = s.get(root, ref)
    assert result['status'] == result['historical_status'] == 'COMPLETE'
    assert result['host_review']['coverage'] == 'REVIEWED'
    assert result['development_summary'] == original['development_summary']
    assert result['current_version'] is False
    freshness = result['version_freshness']
    assert freshness['reviewed_sources'] == 'UNCHANGED'
    assert freshness['reviewed_source_changes']['total_count'] == 0
    assert name in freshness['other_project_changes']['items']
    assert 'OTHER_PROJECT_SOURCE_CHANGED' in freshness['reason_codes']
    assert '已检查文件及已读取关联源码的内容没有变化' in result['version_notice']
    assert s.load(root, ref) == saved
    assert_bounded(result)


def test_related_evidence_change_is_named_without_rewriting_historical_completion(service):
    s, root, ref = complete_task(service, related=True)
    (root/'auth.py').write_text('def check(user):\n    return policy.deny(user)\n')
    result = s.get(root, ref)
    assert result['status'] == 'COMPLETE' and result['current_version'] is False
    freshness = result['version_freshness']
    assert freshness['reviewed_sources'] == 'CHANGED'
    assert freshness['related_source_changes']['items'] == ['auth.py']
    assert 'RELATED_SOURCE_CHANGED' in freshness['reason_codes']
    assert result['host_review']['coverage'] == 'REVIEWED'
    assert not result['risk_choices']


def test_rule_configuration_change_has_its_own_current_applicability_reason(service):
    s, root, _ = service
    (root/'rules.yml').write_text('rules: []\n')
    s, root, ref = complete_task(service)
    (root/'rules.yml').write_text('rules: [updated]\n')
    result = s.get(root, ref)
    assert result['status'] == 'COMPLETE' and result['current_version'] is False
    freshness = result['version_freshness']
    assert freshness['reviewed_sources'] == 'UNCHANGED'
    assert freshness['configuration_changes']['items'] == ['rules.yml']
    assert 'PROJECT_CONFIGURATION_CHANGED' in freshness['reason_codes']


def test_changed_reviewed_file_does_not_receive_an_unchanged_source_notice(service):
    s, root, ref = complete_task(service)
    (root/'routes.py').write_text('def route(user):\n    return policy.other(user)\n')
    result = s.get(root, ref)
    assert result['status'] == 'COMPLETE'
    assert result['version_freshness']['reviewed_sources'] == 'CHANGED'
    assert result['version_freshness']['reviewed_source_changes']['items'] == ['routes.py']
    assert '已检查文件或其关联源码后来发生变化' in result['version_notice']


def test_history_retains_saved_elapsed_time_and_unread_ranges_without_charging_or_renewing():
    original = history_record(0, 0)
    original['review'].update(elapsed_wall_ms=2712, submitted_at=100)
    original['evidence'] = {'existing': dict(path='src/service.py', file_sha256='end-hash',
        location_version='CURRENT_TASK_END', start_line=1, end_line=3)}
    original['context_requests'] = {'request': dict(path='src/service.py', file_sha256='end-hash',
        location_version='CURRENT_TASK_END', spans=[[1, 10]])}
    original['context_gaps'] = [dict(path='src/service.py', reason='TASK_CONTEXT_BATCH_BUDGET')]
    original['review_completion']['gaps'] = [dict(path='src/service.py', reason='SOURCE_RANGE_UNREAD',
        start_line=4, end_line=10, location_version='CURRENT_TASK_END')]
    before = copy.deepcopy(original)
    result = bounded_history_result(original, now=999999)
    assert result['host_review']['elapsed_wall_ms'] == 2712
    assert result['host_review']['submitted_at'] == 100
    coverage = result['context_read_coverage']
    assert coverage['unread_range_count'] == coverage['plan_gap_count'] == 1
    assert coverage['unread_ranges']['items'] == [dict(path='src/service.py', start_line=4, end_line=10)]
    assert coverage['plan_gaps']['items'][0]['start_line'] == 4
    assert coverage['used_bytes'] == 250000 and coverage['used_reads'] == 159
    assert original == before
    assert_bounded(result)


def test_missing_historical_measurements_are_unknown_instead_of_invented_zeroes():
    result = bounded_history_result(history_record(0, 0))
    assert result['host_review']['elapsed_wall_ms'] is None
    assert result['host_review']['submitted_at'] is None
    assert result['context_read_coverage']['unread_range_count'] is None
    assert result['context_read_coverage']['plan_gap_count'] is None
    assert result['context_read_coverage']['gaps'] is None


def test_unreadable_source_never_becomes_a_claim_that_reviewed_content_is_unchanged():
    saved = history_record(0, 0)
    current = dict(hashes={}, inventory=['src/service.py'], inventory_complete=True,
                   limitations=[dict(path='src/service.py', reason='SOURCE_UNAVAILABLE')])
    freshness = history_freshness(saved, current)
    assert freshness['workspace_matches_snapshot'] is False
    assert freshness['reviewed_sources'] == 'UNKNOWN'
    assert freshness['unverified_sources']['items'] == ['src/service.py']
    assert 'CURRENT_SOURCE_COMPARISON_INCOMPLETE' in freshness['reason_codes']


def test_freshness_metadata_is_included_before_finding_size_selection():
    original = history_record(0, 3)
    for finding in original['review']['findings']:
        finding['impact'] = '影响' * 4500
    end = dict(hashes={**original['end']['hashes'], **{f'other_{i}.py': str(i) for i in range(1000)}},
               inventory_complete=True, limitations=[])
    freshness = history_freshness(original, end)
    result = bounded_history_result(original, freshness=freshness)
    assert result['status'] == 'COMPLETE' and result['current_version'] is False
    assert result['finding_page']['has_more']
    assert result['version_freshness']['other_project_changes']['total_count'] == 1000
    assert_bounded(result)
    assert len(json.dumps(result, ensure_ascii=False).encode()) <= 64000
