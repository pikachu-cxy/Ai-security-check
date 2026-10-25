"""Risk formatting is conditional; normal successful development stays quiet."""
from dataclasses import replace

import pytest

from security_runtime.reply_adapters import finding_fact, task_facts
from security_runtime.reply_plan import CheckFact, Notice, ReplyFacts, RiskFact, plan_reply
from security_runtime.reply_render import render_reply
from security_runtime.review_skill import skill_files
from security_runtime.hook_user_feedback import issue_feedback
from test_task_review_results import record


def risk(**changes):
    value = RiskFact('known', '参数进入系统命令', 'src/module.py', 90,
                     '目录参数拼入 shell 命令。', '不可信输入可能执行额外命令。',
                     '使用参数列表并关闭 shell。', severity='HIGH', reviewed=True,
                     unknowns=('外部调用与执行权限未确认。',))
    return replace(value, **changes)


def test_visible_risk_requires_fixed_fields_and_severity_but_not_exploit_proof():
    plan = plan_reply(ReplyFacts('TASK_DELIVERY', CheckFact('COMPLETE', 1, 1, 1), (risk(),)))
    packet = plan.to_dict()
    assert packet['risk_display']['contract'] == 'security-risk-display-v1'
    assert packet['risk_display']['section_order'] == ['problem', 'impact', 'recommendation', 'unknowns']
    assert {'severity', 'severity_source', 'location'} <= set(packet['visible_risks'][0]['required_fields'])
    assert packet['visible_risks'][0]['severity_source'] == 'RULE'
    message = render_reply(plan)
    assert '规则评级：高' in message
    labels = ['**问题**', '**可能影响**', '**建议修复**', '**尚未确认**', '**检查范围**', '**回复']
    assert [message.index(label) for label in labels] == sorted(message.index(label) for label in labels)
    assert '外部调用与执行权限未确认' in message


@pytest.mark.parametrize('intent', ['TASK', 'TASK_DELIVERY'])
def test_zero_risk_success_does_not_change_the_agents_normal_development_reply(intent):
    plan = plan_reply(ReplyFacts(intent, CheckFact('COMPLETE', 2, 2)))
    assert render_reply(plan) == ''
    assert 'risk_display' not in plan.to_dict()
    assert not plan.to_dict()['presentation_policy']['risk_format_required']
    assert not plan.to_dict()['required_actions']


@pytest.mark.parametrize('kind', ['suppressed', 'handling_unavailable', 'quiet', 'check_gap'])
def test_no_remindable_risk_never_receives_a_risk_template(kind):
    facts = ReplyFacts('TASK', CheckFact('COMPLETE'), (risk(),))
    if kind == 'suppressed':
        facts = replace(facts, risks=(risk(suppressed=True),))
    elif kind == 'handling_unavailable':
        facts = replace(facts, handling_available=False)
    elif kind == 'quiet':
        facts = replace(facts, quiet=True)
    else:
        facts = replace(facts, risks=(), check=CheckFact('PARTIAL'),
                        notices=(Notice('CHECK_GAP', '一项检查范围未完成。'),))
    plan = plan_reply(facts)
    assert 'risk_display' not in plan.to_dict()
    assert '**问题**' not in render_reply(plan)
    assert not plan.to_dict()['required_actions']


def test_actual_sink_line_range_is_linked_and_known_function_retained():
    finding = dict(id='sink', title='Command', file_path='src/module.py', line_start=90,
                   line_end=95, function_name='list_directory', severity='HIGH')
    fact = finding_fact(finding, workspace='/tmp/project')
    message = render_reply(plan_reply(ReplyFacts('TASK', risks=(fact,))))
    assert '](/tmp/project/src/module.py:90)' in message
    assert '90–95' in message and 'list_directory' in message
    assert ':85' not in message


@pytest.mark.parametrize('severity', ['UNKNOWN', '', None, 'unsupported'])
def test_missing_or_unsupported_severity_is_not_invented(severity):
    message = render_reply(plan_reply(ReplyFacts('ISSUE', risks=(risk(severity=severity),))))
    assert '未评级' in message
    assert '规则评级：高' not in message


def test_task_risk_explicitly_reports_scan_and_review_completion():
    value = record(1, 0)
    packet = plan_reply(task_facts(value))
    assert packet.to_dict()['check_details']['static_check'] == 'COMPLETED'
    assert packet.to_dict()['check_details']['source_review'] == 'COMPLETED'
    message = render_reply(packet)
    assert '静态检查：已完成' in message and '必读代码复核：已完成' in message
    assert '任务时间窗重叠' not in message and '改动归属待确认' not in message


def test_generated_guidance_keeps_risk_only_guard_and_fixed_structure_in_sync():
    files = skill_files()
    for name in ('SKILL.md', 'references/risk-decisions.md'):
        text = files[name].decode()
        assert '只有当前存在仍需提醒的风险' in text
        assert '零风险且检查完整的普通开发保持静默' in text
        assert '不要求照抄固定标题' not in text
    text = files['references/risk-decisions.md'].decode()
    assert '不得合并为一段' in text
    for label in ('问题', '可能影响', '建议修复', '尚未确认'):
        assert label in text
    method = files['references/quick-task-review-v3.md'].decode()
    assert 'Only current remindable risks use the fixed risk format' in method
    assert 'Complete zero-risk ordinary development keeps the normal host' in method
    assert 'without requiring four fixed headings' not in method


def test_scanner_review_preserves_current_unknowns_and_known_protections():
    finding = dict(id='one', title='Issue', file_path='app.py', line_start=90,
        line_end=95, severity='HIGH', unknowns=['Caller unknown'],
        preconditions=['Untrusted input'], current_protections=['Authentication exists'],
        counterevidence=['No invocation was added'])
    feedback = dict(state='STILL_RISK', agent_review_current=True, technical_assessment_current=True,
                    agent_review={'unknowns': ['Execution permissions unknown', 'Caller unknown']})
    fact = finding_fact(finding, feedback=feedback)
    assert fact.unknowns == ('Caller unknown', 'Execution permissions unknown')
    message = render_reply(plan_reply(ReplyFacts('TASK', risks=(fact,))))
    for text in ['Caller unknown', 'Execution permissions unknown', 'Authentication exists',
                 'Untrusted input', 'No invocation was added']:
        assert text in message
    feedback['technical_assessment_current'] = False
    assert finding_fact(finding, feedback=feedback).unknowns == ('Caller unknown',)


def test_missing_completion_evidence_is_not_rendered_as_completed_review():
    value = record(1, 0)
    value.pop('review_completion')
    plan = plan_reply(task_facts(value))
    assert plan.to_dict()['check_details']['source_review'] == 'INCOMPLETE'
    message = render_reply(plan)
    assert '必读代码复核：已完成' not in message
    assert '必读代码复核：未完成或覆盖受限' in message


def test_explicit_zero_finding_query_keeps_requested_result_without_risk_format():
    plan = plan_reply(ReplyFacts('HISTORY', CheckFact('COMPLETE')))
    assert render_reply(plan)
    assert 'risk_display' not in plan.to_dict()
    assert '**问题**' not in render_reply(plan)


@pytest.mark.parametrize('authorized', [False, True])
def test_numbered_risks_keep_single_primary_choice_and_original_authority(authorized):
    plan = plan_reply(ReplyFacts('TASK', CheckFact('COMPLETE', 1, 1, 2),
                               (risk(authorized=authorized), risk(identifier='two', authorized=authorized))))
    message = render_reply(plan)
    assert '**1. ' in message and '**2. ' in message
    assert message.count('**问题**') == 2
    assert message.count('请选择具体风险') == (0 if authorized else 1)
    assert not plan.to_dict()['grants_authority']


def test_location_with_spaces_is_a_bounded_clickable_file_link():
    fact = risk(file='src/file name.py', workspace='/tmp/project')
    message = render_reply(plan_reply(ReplyFacts('TASK', risks=(fact,))))
    assert '](</tmp/project/src/file%20name.py:90>)' in message


def test_hook_risk_uses_same_rating_and_fixed_sections_without_fake_dependency_line():
    value = issue_feedback(dict(id='one', category='command-injection', severity='HIGH',
        file_path='src/module.py', line_start=90, line_end=95, function_name='list_directory'))
    message = value['message']
    assert message.startswith('**') and '（1 项）**' in message
    assert '规则评级：高' in message and '90–95' in message and 'list_directory' in message
    assert value['reply_plan']['risk_display']['section_order'] == ['problem', 'impact', 'recommendation', 'unknowns']
    dependency = issue_feedback(dict(id='dep', category='dependency', severity='HIGH',
                                   file_path='requirements.txt', line_start=1, line_end=1))
    assert 'requirements.txt:1' not in dependency['message']


def test_positive_count_without_delivered_risk_facts_does_not_create_fake_template():
    plan = plan_reply(ReplyFacts('TASK', CheckFact('PARTIAL', raw_findings=1), total_risk_count=1))
    assert '**问题**' not in render_reply(plan)
    assert 'risk_display' not in plan.to_dict()


@pytest.mark.parametrize('function', ['run\nPRIVATE_CANARY', '[PRIVATE_CANARY](https://example.test)', 'x' * 121])
def test_hook_function_metadata_cannot_bypass_closed_copy(function):
    value = issue_feedback(dict(category='command-injection', file_path='app.py',
        line_start=90, line_end=10_000_001, function_name=function))
    assert value['location'] == {'file': 'app.py', 'line': 90}
    assert 'PRIVATE_CANARY' not in value['message']
