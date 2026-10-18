"""Read-only history pagination stays separate from source-review budgets."""
import copy
import json

import pytest

from security_runtime.task_review_results import (
    bounded_history_result, seal_history_result, MAX_RESULT_BYTES,
)


def finding(identifier, *, impact='A conditional impact'):
    return dict(id=identifier, title='Permission check may be absent', category='AUTHORIZATION',
                severity='HIGH', file_path='src/service.py', line_start=10, line_end=12,
                impact=impact, fix_advice='Check ownership before this operation.',
                preconditions=['The caller reaches this operation.'],
                current_protections=['The observed route has authentication.'],
                counterevidence=['Other middleware might enforce ownership.'],
                unknowns=['Other callers have not been confirmed.'],
                evidence_locations=[dict(path='src/service.py', start_line=10, end_line=12,
                                         location_version='CURRENT_TASK_END')],
                technical_details={'raw_source': 'private scanner source must not leave storage'})


def record(static_count=2, host_count=5):
    return dict(phase='COMPLETE', task_ref='ts1-' + 'a' * 32, review_protocol=3,
        task_owner={'host': 'codex', 'session': 'private-session'},
        baseline={'hashes': {'src/service.py': 'hash'},
                  'texts': {'src/service.py': ['private preimage source']}},
        end={'hashes': {'src/service.py': 'end-hash'},
             'texts': {'src/service.py': ['private current source']}},
        changes=[dict(path='src/service.py', change='MODIFIED')], limitations=[],
        static=dict(status='COMPLETED', coverage='SCOPED', scan_id='scan-id',
                    scope_files=['src/service.py'], actual_files=['src/service.py'],
                    findings=[finding(f'static-{i}') for i in range(static_count)]),
        review=dict(coverage='REVIEWED', source='HOST_TASK_REVIEW',
                    validation='STRUCTURE_AND_SOURCE_VERSION_ONLY', limitations=[],
                    findings=[finding(f'host-{i}') for i in range(host_count)]),
        review_ledger=dict(total_bytes=250_000, reads=159,
                           limits={'total_bytes': 256_000, 'reads': 160},
                           deadline=1, private_data='do not serialize private ledger'),
        review_completion=dict(unit_count=1, reviewed_unit_count=1,
                               coverage='REVIEWED', status='COMPLETE'))


def assert_bounded(packet):
    cost = len(json.dumps(packet, ensure_ascii=False).encode('utf-8'))
    assert packet['response_bytes'] == cost
    assert cost <= MAX_RESULT_BYTES


def test_static_and_host_findings_share_one_accurate_page_order():
    original = record()
    first = bounded_history_result(original, 0, 3)
    assert_bounded(first)
    assert first['finding_page']['total_count'] == 7
    assert first['finding_page']['static_count'] == 2
    assert first['finding_page']['host_count'] == 5
    assert [item['detail']['id'] for item in first['findings']] == ['static-0', 'static-1', 'host-0']
    assert first['finding_page']['next_offset'] == 3
    second = bounded_history_result(original, **{
        'offset': first['next_action']['finding_offset'],
        'limit': first['next_action']['finding_limit']})
    assert [item['detail']['id'] for item in second['findings']] == ['host-1', 'host-2', 'host-3']
    last = bounded_history_result(original, second['finding_page']['next_offset'], 3)
    assert [item['detail']['id'] for item in last['findings']] == ['host-4']
    assert not last['finding_page']['has_more'] and last['finding_page']['next_offset'] is None
    assert 'next_action' not in last


def test_previous_large_host_review_no_longer_repeats_every_risk():
    original = record(0, 10)
    packet = bounded_history_result(original, 4, 1)
    assert [item['detail']['id'] for item in packet['findings']] == ['host-4']
    assert len(packet['risk_choices']) == 1
    assert packet['risk_choices'][0]['finding_id'] == 'host-4'
    assert 'findings' not in packet['host_review']
    assert 'findings' not in packet['static']
    assert 'Permission check' not in packet['development_summary']
    assert_bounded(packet)


def test_limit_is_capped_at_three_complete_findings():
    packet = bounded_history_result(record(10, 10), 0, 30)
    assert packet['finding_page']['returned_count'] == 3
    assert len(packet['findings']) == 3
    assert all(item['details_complete'] for item in packet['findings'])


def test_page_dynamically_shrinks_by_real_utf8_size_and_keeps_the_full_text():
    original = record(0, 3)
    text = '影响' * 5000
    for item in original['review']['findings']:
        item['impact'] = text
    packet = bounded_history_result(original, 0, 3)
    assert 1 <= len(packet['findings']) < 3
    assert packet['finding_page']['next_offset'] == len(packet['findings'])
    assert all(item['detail']['impact'] == text for item in packet['findings'])
    assert_bounded(packet)


def test_extreme_single_finding_is_explicitly_unavailable_without_fake_truncated_detail():
    original = record(0, 2)
    original['review']['findings'][0]['impact'] = '风' * 30_000
    packet = bounded_history_result(original, 0, 1)
    assert packet['reason_code'] == 'RESULT_DETAIL_LIMIT'
    assert packet['details_complete'] is False
    item = packet['findings'][0]
    assert item['details_complete'] is False and 'detail' not in item
    assert item['finding_id'] == 'host-0'
    assert not packet['risk_choices']
    assert packet['next_action']['finding_offset'] == 1
    assert original['review']['findings'][0]['impact'] == '风' * 30_000
    assert_bounded(packet)


def test_condition_protection_uncertainty_and_code_locations_are_preserved():
    packet = bounded_history_result(record(0, 1), 0, 1)
    item = packet['findings'][0]['detail']
    assert item['preconditions'] == ['The caller reaches this operation.']
    assert item['current_protections'] == ['The observed route has authentication.']
    assert item['counterevidence'] == ['Other middleware might enforce ownership.']
    assert item['unknowns'] == ['Other callers have not been confirmed.']
    assert item['evidence_locations'][0]['path'] == 'src/service.py'


@pytest.mark.parametrize('protocol', [3, 1, 2, None])
def test_scope_and_metadata_are_bounded_with_honest_total_counts(protocol):
    original = record(0, 1)
    if protocol is None:
        original.pop('review_protocol')
    else:
        original['review_protocol'] = protocol
    paths = ['long/' + '目录' * 1000 + str(i) + '.py' for i in range(1000)]
    original['static']['scope_files'] = paths
    original['static']['actual_files'] = paths
    original['hook_final_recheck_files'] = paths
    original['changes'] = [dict(path=path, change='MODIFIED') for path in paths]
    original['limitations'] = [dict(reason='SOURCE_UNAVAILABLE', paths=paths, count=1000)]
    before = copy.deepcopy(original)
    packet = bounded_history_result(original, 0, 1)
    assert packet['notice_display']['complete'] is False
    assert 0 < packet['notice_display']['omitted_count'] <= packet['notice_display']['original_count']
    assert packet['findings'][0]['details_complete'] is True
    assert packet['findings'][0]['detail']['impact'] == original['review']['findings'][0]['impact']
    scope = packet['static']['scope_files']
    assert scope['total_count'] == scope['omitted_count'] == 1000
    assert scope['items'] == []
    assert packet['changes']['total_count'] == 1000
    assert packet['file_hook_checks']['current_recheck_files']['total_count'] == 1000
    assert original == before
    assert_bounded(packet)


def test_history_reads_do_not_consume_or_reset_expired_source_review_ledger():
    original = record()
    before = copy.deepcopy(original)
    packet = bounded_history_result(original, 0, 1, now=999_999)
    assert packet['history_read_only'] is True
    assert packet['context_read_coverage']['used_bytes'] == 250_000
    assert packet['context_read_coverage']['used_reads'] == 159
    assert original == before
    assert_bounded(packet)


def test_root_metadata_is_recounted_and_still_enforces_the_hard_result_limit():
    packet = bounded_history_result(record(), 0, 1)
    before = packet['response_bytes']
    packet.update(current_version=False, status='STALE',
                  risk_ledger_next_action=dict(tool='get_task_risk_ledger', task_ref='ts1-' + 'a'*32))
    packet = seal_history_result(packet)
    assert packet['response_bytes'] > before
    assert_bounded(packet)
    packet['oversized'] = 'a' * MAX_RESULT_BYTES
    with pytest.raises(ValueError, match='independent byte limit'):
        seal_history_result(packet)


def test_no_raw_source_or_private_task_state_is_exported():
    packet = bounded_history_result(record(), 0, 3)
    encoded = json.dumps(packet)
    for forbidden in ['private scanner source', 'private preimage source',
                      'private current source', 'private-session',
                      'do not serialize private ledger', 'technical_details']:
        assert forbidden not in encoded


def test_credential_redaction_does_not_silently_cut_public_explanation_length():
    original = record(1, 0)
    text = 'A specific control and counterexample. ' * 100
    original['static']['findings'][0]['impact'] = text
    packet = bounded_history_result(original, 0, 1)
    assert len(text) > 1200
    assert packet['findings'][0]['detail']['impact'] == text


def test_offset_beyond_end_returns_an_empty_page_with_correct_counts():
    packet = bounded_history_result(record(), 100, 1)
    assert packet['finding_page']['total_count'] == 7
    assert packet['finding_page']['returned_count'] == 0
    assert not packet['finding_page']['has_more']
    assert packet['findings'] == []
    assert_bounded(packet)


def test_zero_findings_and_partial_coverage_do_not_claim_a_pass():
    original = record(0, 0)
    original['review']['coverage'] = 'PARTIAL'
    original['review']['limitations'] = ['A source range is unavailable.']
    packet = bounded_history_result(original, 0, 1)
    assert packet['host_review']['coverage'] == 'PARTIAL'
    assert '覆盖受限' in packet['development_summary']
    assert not packet['risk_choices']
    assert_bounded(packet)


def test_incomplete_reason_is_visible_and_long_metadata_declares_its_preview():
    original = record(0, 0)
    original.update(phase='INCOMPLETE', skip_reason='项目准备失败：' + '具体诊断。' * 100)
    packet = bounded_history_result(original, 0, 1)
    note = packet['incomplete_reason']['items'][0]
    assert note['message'].startswith('项目准备失败：')
    assert note['display_truncated'] is True
    assert note['original_char_count'] == len(original['skip_reason'])


@pytest.mark.parametrize('offset,limit', [(-1, 1), (True, 1), (0, 0), (0, True), (0, 31)])
def test_invalid_pages_are_rejected(offset, limit):
    with pytest.raises(ValueError):
        bounded_history_result(record(), offset, limit)
