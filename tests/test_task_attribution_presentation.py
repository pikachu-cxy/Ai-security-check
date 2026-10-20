"""Attribution copy cannot upgrade coverage, alter records or close risks."""
import copy
import hashlib

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.reply_adapters import task_facts
from security_runtime.reply_plan import plan_reply
from security_runtime.reply_render import render_reply
from security_runtime.task_review_results import bounded_history_result
from security_runtime.task_risk_ledger import TaskRiskLedger
from test_task_review_results import record


def overlapping_record(static_count=0, host_count=0):
    value = record(static_count, host_count)
    value['limitations'] = [dict(reason='CONCURRENT_TASK_ATTRIBUTION_UNAVAILABLE', count=1)]
    value['review']['coverage'] = 'PARTIAL'
    value['review']['limitations'] = ['同一工作区的任务时间窗重叠，改动归属未能独立确认（1 项）']
    return value


@pytest.mark.parametrize('delivery', [False, True])
def test_completed_checks_and_unknown_attribution_are_separate_read_only_facts(delivery):
    value = overlapping_record()
    before = copy.deepcopy(value)
    packet = bounded_history_result(value, delivery=delivery)
    assert value == before
    assert packet['host_review']['coverage'] == packet['reply_plan']['check_state'] == 'PARTIAL'
    assert packet['reply_plan']['check_details'] == dict(
        static_check='COMPLETED', source_review='COMPLETED', change_attribution='UNCONFIRMED')
    message = packet['development_summary']
    assert '静态检查和必读代码复核均已完成' in message
    assert '**改动归属待确认**' in message
    assert '**检查未完成**' not in message and '只完成部分安全检查' not in message
    assert '部分代码或检查依据' not in message
    assert not packet['repair_authorized'] and not packet['scanner_run']
    if not delivery:
        assert '本次查询未重新执行检查' in message


@pytest.mark.parametrize('gap', ['static', 'source', 'missing_completion', 'unknown', 'review_note'])
def test_attribution_does_not_hide_real_or_unknown_check_gaps(gap):
    value = overlapping_record()
    if gap == 'static':
        value['static'].update(status='FAILED', coverage='PARTIAL',
            capability_results=dict(CODE_SAST='FAILED'))
    elif gap == 'source':
        value['review_completion'].update(reviewed_unit_count=0, coverage='PARTIAL', status='PARTIAL')
    elif gap == 'missing_completion':
        value.pop('review_completion')
    elif gap == 'unknown':
        value['limitations'].append(dict(reason='UNKNOWN_SCOPE_GAP'))
    else:
        value['review']['limitations'].append('关联文件的当前内容不可用。')
    packet = bounded_history_result(value, delivery=True)
    message = packet['development_summary']
    assert packet['host_review']['coverage'] == packet['reply_plan']['check_state'] == 'PARTIAL'
    assert '**检查未完成**' in message and '**改动归属待确认**' in message
    assert '静态检查和必读代码复核均已完成' not in message
    if gap in {'source', 'missing_completion'}:
        assert packet['reply_plan']['check_details']['source_review'] == 'INCOMPLETE'
    if gap == 'review_note':
        assert '关联文件的当前内容不可用' in message


def test_live_task_reply_and_history_have_the_same_attribution_explanation():
    value = overlapping_record()
    message = render_reply(plan_reply(task_facts(value)))
    assert '静态检查和必读代码复核均已完成' in message
    assert '**改动归属待确认**' in message and '**检查未完成**' not in message


def test_risk_details_choices_and_authority_are_unchanged():
    original = record(1, 1)
    overlapping = overlapping_record(1, 1)
    before = bounded_history_result(original, delivery=True)
    after = bounded_history_result(overlapping, delivery=True)
    for key in ('findings', 'risk_choices', 'risk_counts', 'repair_authorized', 'scanner_run'):
        assert after[key] == before[key]
    assert after['reply_plan']['required_actions'] == before['reply_plan']['required_actions']
    assert after['reply_plan']['check_state'] == 'PARTIAL'
    for label in ('**问题**', '**可能影响**', '**建议修复**', '**尚未确认**'):
        assert label in after['development_summary']


@pytest.mark.parametrize('overlapping,expected', [
    (False, 'CODE_REVIEWED_RESOLVED'), (True, 'INCONCLUSIVE')])
def test_presentation_keeps_the_original_risk_closure_gate(tmp_path, monkeypatch, overlapping, expected):
    value = overlapping_record() if overlapping else record(0, 0)
    path = tmp_path / 'src' / 'service.py'
    path.parent.mkdir()
    path.write_text('def check_owner(): return True\n', encoding='utf-8')
    value['end']['hashes']['src/service.py'] = hashlib.sha256(path.read_bytes()).hexdigest()
    value['evidence'] = {'issued': dict(path='src/service.py', location_version='CURRENT_TASK_END')}
    ledger = TaskRiskLedger(HookStateStore(tmp_path / 'state'), tmp_path)
    monkeypatch.setattr(ledger, 'read_origins', lambda refs: {
        'original:risk': dict(source='HOST_TASK_REVIEW', required_source_paths=['src/service.py'])})
    packet = bounded_history_result(value, delivery=True)
    result = ledger.validate_host(value, [dict(original_task_ref='original', finding_id='risk',
        evidence_refs=['issued'], outcome='CODE_REVIEWED_RESOLVED',
        rationale='The issued code has the ownership check.', tests='Synthetic evidence validation.')],
        packet['host_review']['coverage'])
    assert result['original:risk']['status'] == expected
    assert result['original:risk']['production_safety_verified'] is False
