"""Routine clean delivery is silent; requested results and gaps remain visible."""
import asyncio
import copy

import pytest

from security_runtime.models import ScanResult, ScannerRun, TargetProfile
from security_runtime.reply_adapters import task_facts
from security_runtime.reply_plan import plan_reply
from security_runtime.reply_render import render_reply
from security_runtime.risk import NO_FINDINGS_MESSAGE
from security_runtime.task_review_results import bounded_history_result
from task_review_helpers import review_all
from test_mcp_context_cost import registered
from test_task_review_results import record
from test_task_security import service  # noqa: F401


def test_changed_task_completes_silently_but_history_remains_readable(service):
    tasks, root, runtime = service
    ref = tasks.begin(root, 'quiet-completion')['task_ref']
    (root/'routes.py').write_text('def get_order(order_id):\n    return load_order(str(order_id))\n')
    tasks.finish(root, ref)
    packet = tasks.prepare(root, ref, protocol_version=3)
    review_all(tasks, root, ref, packet)
    tasks.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    saved = copy.deepcopy(tasks.load(root, ref))
    assert saved['phase'] == 'COMPLETE' and len(saved['changes']) == 1

    delivery = tasks.get(root, ref, completion_revision=saved.get('review_revision', 1))
    assert delivery['development_summary'] == ''
    assert delivery['reply_plan']['presentation_policy']['show_security_summary'] is False
    assert delivery['reply_plan']['check_state'] == 'COMPLETE'
    assert delivery['static']['scope_files']['items'] == ['routes.py']
    assert delivery['static']['scope_files']['total_count'] == 1
    assert delivery['host_review']['coverage'] == 'REVIEWED'
    assert not delivery['risk_choices']
    assert tasks.finish(root, ref)['development_summary'] == ''

    history = tasks.get(root, ref)
    assert '没有发现安全线索' in history['development_summary']
    assert history['reply_plan']['presentation_policy']['show_security_summary'] is True
    assert history['history_read_only'] and len(runtime.calls) == 1
    assert tasks.load(root, ref) == saved


@pytest.mark.parametrize('gap', ['static', 'review', 'baseline', 'capability', 'handling', 'incomplete'])
def test_zero_findings_do_not_silence_incomplete_or_unknown_results(gap):
    value = record(0, 0)
    options = {}
    if gap == 'static':
        value['static'].update(status='PARTIAL', coverage='PARTIAL')
    elif gap == 'review':
        value['review'].update(coverage='PARTIAL', limitations=['app.py:10 未取得所需关联源码'])
    elif gap == 'baseline':
        value['limitations'] = [dict(reason='INVENTORY_READ_BUDGET')]
    elif gap == 'capability':
        value['static']['capability_results'] = {'SECRET_SCAN': 'FAILED'}
    elif gap == 'handling':
        options['handling_available'] = False
    else:
        value.update(phase='INCOMPLETE', skip_reason='必要代码复核尚未完成')
    before = copy.deepcopy(value)
    direct = plan_reply(task_facts(value, **options))
    delivery = bounded_history_result(value, delivery=True, **options)
    for message in (render_reply(direct), delivery['development_summary']):
        assert message and ('未完成' in message or '部分' in message or '无法读取' in message)
    assert delivery['reply_plan']['presentation_policy']['show_security_summary'] is True
    assert value == before


@pytest.mark.parametrize('source', ['static', 'review'])
def test_risks_remain_visible_in_normal_development_delivery(source):
    value = record(int(source == 'static'), int(source == 'review'))
    delivery = bounded_history_result(value, delivery=True)
    assert value[source]['findings'][0]['impact'] in delivery['development_summary']
    assert len(delivery['risk_choices']) == 1
    assert delivery['reply_plan']['presentation_policy']['show_security_summary'] is True


def test_empty_risk_page_is_not_a_clean_completion():
    delivery = bounded_history_result(record(1, 0), offset=1, delivery=True)
    assert not delivery['findings'] and delivery['risk_counts']['raw_total'] == 1
    assert delivery['development_summary']
    assert delivery['reply_plan']['presentation_policy']['show_security_summary'] is True


@pytest.mark.parametrize('tool', ['scan_project', 'scan_diff', 'scan_files'])
def test_explicit_zero_finding_scan_still_reports_result_and_scope(tool):
    scan = ScanResult('explicit-clean', 'release', TargetProfile('/synthetic', files=['app.py']),
        'COMPLETED', [], [ScannerRun('fixture', '1', 'SUCCESS', 1)],
        NO_FINDINGS_MESSAGE, 'NO_FINDINGS', 1, coverage='SCOPED',
        capability_results={'CODE_SAST': 'EXECUTED'})
    registry, calls = registered(scan)
    arguments = {'files': ['app.py']} if tool == 'scan_files' else {}
    result = asyncio.run(registry.tool(tool).fn(**arguments))
    assert result['summary'] == NO_FINDINGS_MESSAGE
    assert result['finding_count'] == 0 and result['coverage'] == 'SCOPED'
    assert result['target_selection'] and result['scanner_runs'][0]['status'] == 'SUCCESS'
    assert result['execution']['scanner_run'] is True and len(calls) == 1
