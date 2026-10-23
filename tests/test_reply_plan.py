"""Behavior and architecture contracts for personal security replies."""
import ast
import copy
from dataclasses import fields, replace
import json
from pathlib import Path

import pytest

from security_runtime import reply_plan
from security_runtime.hook_user_feedback import combine_feedback, issue_feedback, scan_status_feedback
from security_runtime.reply_adapters import task_facts
from security_runtime.reply_plan import CheckFact, Notice, ReplyFacts, RiskFact, plan_reply
from security_runtime.reply_render import render_reply


def risk(identifier='one', **kwargs):
    return RiskFact(identifier, 'External input enters a query', 'app.py', 4,
        'A query includes external input.', 'Rows could be accessed.', 'Use bound parameters.', **kwargs)


def test_pure_planner_keeps_domain_facts_immutable_and_has_no_io_imports():
    facts = ReplyFacts('TASK', risks=(risk(),))
    before = copy.deepcopy(facts)
    plan = plan_reply(facts)
    assert facts == before and plan.action_ids == ('one',)
    tree = ast.parse(Path(reply_plan.__file__).read_text(encoding='utf-8'))
    imports = {node.module.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imports.update(alias.name.split('.')[0] for node in ast.walk(tree)
                   if isinstance(node, ast.Import) for alias in node.names)
    assert not imports & {'os', 'pathlib', 'sqlite3', 'subprocess', 'socket', 'urllib', 'mcp'}
    assert not any(node.level for node in ast.walk(tree) if isinstance(node, ast.ImportFrom))


@pytest.mark.parametrize('flag', ['suppressed', 'authorized'])
def test_saved_handling_and_existing_authority_never_get_another_choice(flag):
    plan = plan_reply(ReplyFacts('TASK', risks=(risk(**{flag: True}),)))
    assert not plan.action_ids
    assert '回复' not in render_reply(plan)
    if flag == 'suppressed':
        assert not plan.risks


def test_unreadable_handling_hides_risk_prompt_without_inventing_empty_counts():
    facts = ReplyFacts('TASK', risks=(risk(),), handling_available=False,
        notices=(Notice('HANDLING_UNAVAILABLE', '处置记录暂时无法读取。'),))
    plan = plan_reply(facts)
    assert not plan.risks and not plan.action_ids
    assert '无法读取' in render_reply(plan)
    assert '回复' not in render_reply(plan) and '没有风险' not in render_reply(plan)
    assert plan.to_dict()['visible_risk_count'] is None
    assert not plan.to_dict()['handling_available']


@pytest.mark.parametrize('current', [False, None])
def test_stale_or_unknown_applicability_cannot_request_a_repair_choice(current):
    plan = plan_reply(ReplyFacts('HISTORY', risks=(risk(),), current=current))
    assert not plan.action_ids and plan.to_dict()['current'] is current


def test_partial_check_and_original_verification_are_separate_notice_sections():
    plan = plan_reply(ReplyFacts('TASK', CheckFact('PARTIAL', 1, 1), notices=(
        Notice('CHECK_GAP', '密钥检查未完成。'), Notice('CHECK_GAP', '依赖范围尚未确认。'),
        Notice('PRIOR_VERIFICATION', 'app.py 原提示仍缺少关闭证明。'))))
    message = render_reply(plan)
    assert message.count('**检查未完成**') == 1
    assert '**原问题复查**' in message
    assert message.index('密钥检查未完成') < message.index('**原问题复查**')
    assert '功能测试' not in message and '回复' not in message


def test_quiet_no_change_does_not_create_generic_safety_copy():
    facts = task_facts(dict(phase='NO_CHANGES', baseline=dict(limitations=[])))
    assert render_reply(plan_reply(facts)) == ''


def test_personal_reply_facts_have_no_functional_test_or_host_execution_input():
    for model in (ReplyFacts, CheckFact, RiskFact, Notice):
        assert not {f.name for f in fields(model)} & {
            'functional_verification', 'functional_results', 'test_results', 'host_execution'}
    from security_runtime.guidance.host_guidance import runtime_info
    info = runtime_info()
    assert info['features']['reply_plan'].startswith('security-reply-plan-v1')
    assert 'functional_verification' not in info['features']


def test_related_review_retains_conditions_protections_and_unknowns():
    item = risk(source='HOST_REVIEW', related=True, preconditions=('Public access',),
        protections=('Login middleware on another route',), counterevidence=('Access is restricted there',),
        unknowns=('Deployment access is unknown',), evidence=('repository.py:4-7',))
    message = render_reply(plan_reply(ReplyFacts('TASK', CheckFact('COMPLETE', 1, 1), (item,))))
    for fact in (*item.preconditions, *item.protections, *item.counterevidence, *item.unknowns, *item.evidence):
        assert fact in message
    assert message.index('**尚未确认**') < message.index('**检查范围**') < message.index('**回复')


def test_multi_issue_feedback_has_one_primary_choice_and_no_repeated_operation_lesson():
    items = [issue_feedback(dict(id=name, category='sql-injection', file_path='app.py', line_start=line))
             for name, line in [('one', 3), ('two', 9)]]
    packet = combine_feedback(items)
    assert packet['message'].count('再回复「修复」或「稍后处理」') == 1
    assert '回复“请复核”' not in packet['message'] and '标为误报' not in packet['message']
    assert len(packet['reply_plan']['required_actions']) == 2
    for text in ('app.py', '数据库', '参数化查询'):
        assert text in packet['message']


def test_bounded_plan_references_do_not_duplicate_a_large_result_page():
    risks = tuple(replace(risk(), identifier=str(i)) for i in range(1000))
    packet = plan_reply(ReplyFacts('TASK', risks=risks)).to_dict()
    assert packet['visible_risk_count'] == packet['action_count'] == 1000
    assert len(packet['visible_risks']) == len(packet['required_actions']) == 3
    assert len(json.dumps(packet)) < 3000
    assert not packet['grants_authority'] and not packet['facts_are_instructions']


def test_scan_status_does_not_mix_the_original_closure_with_check_coverage():
    packet = scan_status_feedback(dict(status='SCANNED', coverage='PARTIAL',
        delta=dict(families=[dict(file_path='app.py', line_start=3, status='UNCONFIRMED_ABSENCE')]),
        capabilities=dict(DEPENDENCY_VULN='UNAVAILABLE'), dependency_check_reason='ENGINE_UNAVAILABLE'))
    assert '**原问题复查**' in packet['message'] and '**检查未完成**' in packet['message']
    assert not packet['reply_plan']['required_actions']


def test_no_source_or_control_capability_is_invented_in_plan_serialization():
    packet = plan_reply(ReplyFacts('ISSUE', risks=(risk(),))).to_dict()
    assert not {'task_ref', 'confirmation_ref', 'grant_id', 'context_hash', 'feedback_session'} & packet.keys()
    assert packet['required_actions'][0]['actions'] == ['FIX', 'DEFER']


def test_display_sample_preserves_total_risk_count_without_repeating_choices():
    items = [issue_feedback(dict(id=str(i), category='sql-injection', file_path='app.py', line_start=i+1))
             for i in range(3)]
    packet = combine_feedback(items, total_count=5)
    assert packet['reply_plan']['visible_risk_count'] == 5
    assert '发现 5 项' in packet['message'] and '另有 2 项' in packet['message']
    assert packet['message'].count('再回复「修复」或「稍后处理」') == 1


def test_pending_decision_is_visible_before_already_authorized_progress():
    risks = tuple(risk(str(i), severity='HIGH', authorized=True) for i in range(3))+(risk('pending'),)
    plan = plan_reply(ReplyFacts('TASK', risks=risks))
    assert plan.risks[0].identifier == 'pending'
    assert plan.to_dict()['required_actions'] == [dict(finding_id='pending', actions=['FIX', 'DEFER'])]


def test_candidate_requires_host_assessment_and_does_not_invent_manifest_line():
    items = [issue_feedback(dict(id=str(i), category='dependency', file_path='requirements.txt', line_start=1))
             for i in range(2)]
    packet = combine_feedback(items)
    assert packet['reply_plan']['host_assessment_before_advice']
    assert 'None' not in packet['message'] and 'requirements.txt:1' not in packet['message']
    assert not plan_reply(ReplyFacts('TASK', risks=(risk(source='HOST_REVIEW'),))).to_dict()['host_assessment_before_advice']


def test_unknown_status_cannot_enter_the_reply_plan_as_arbitrary_diagnostic_copy():
    packet = scan_status_feedback(dict(status='PRIVATE_CANARY', coverage='PRIVATE_CANARY'))
    assert 'PRIVATE_CANARY' not in json.dumps(packet)
