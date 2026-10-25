"""Host-facing display contracts preserve evidence, language and existing scope."""
import copy
import json

import pytest

from security_runtime.hook_reply_context import (
    CONTROL_DELIMITER, render_check_gap_context, render_hook_context,
)
from security_runtime.hook_user_feedback import dependency_status_message
from security_runtime.reply_adapters import finding_fact, task_facts
from security_runtime.reply_plan import ReplyFacts, RiskFact, plan_reply
from security_runtime.reply_render import render_reply
from security_runtime.review_skill import skill_files
from security_runtime.guidance.risk_presentation import LANGUAGE_RULES, RESPONSE_STYLE_RULES
from test_task_review_results import record


@pytest.mark.parametrize('branch', ['risk', 'quiet', 'resolved', 'check_gap'])
def test_every_hook_exit_leaves_language_to_the_host_conversation(branch):
    decision = (dict(action='NONE', reason_code='SCANNER_VERIFIED_RESOLVED')
                if branch == 'resolved' else None)
    before = copy.deepcopy(decision)
    message = '' if branch == 'quiet' else '当前检查事实。'
    rendered = (render_check_gap_context(dict(status='INCONCLUSIVE'), message)
                if branch == 'check_gap' else render_hook_context({}, decision, message))
    presentation, encoded = rendered.split(CONTROL_DELIMITER, 1)
    assert LANGUAGE_RULES in presentation
    control = json.loads(encoded)
    assert decision == before
    assert not {'language', 'repair_authorized', 'grant_id'} & control.keys()
    if branch == 'quiet':
        assert '上方提示为空时无需新增安全提示' in presentation
    if branch == 'check_gap':
        assert '检查缺口不等于发现漏洞或编辑失败' in presentation
        assert 'remediation' not in control


def test_managed_core_and_risk_guidance_share_style_and_translate_all_visible_copy():
    files = skill_files()
    for name in ('SKILL.md', 'references/risk-decisions.md'):
        text = files[name].decode()
        assert RESPONSE_STYLE_RULES in text
        assert '已获明确授权的范围直接继续' in text
        assert '只有当前存在仍需提醒的风险' in text
        assert '零风险且检查完整的普通开发保持静默' in text
        assert '不要求照抄固定标题' not in text
    method = files['references/quick-task-review-v3.md'].decode()
    assert 'explicit language preference for headings, explanations and choices' in method
    assert 'Runtime\ndoes not infer conversation language' in method
    assert 'only when repair approval is still needed' in method


def test_display_policy_is_not_a_language_guess_or_a_repair_grant():
    risk = RiskFact('known', 'Issue', 'app.py', 4, 'Problem', 'Impact', 'Advice',
                    authorized=True, unknowns=('Reachability remains unknown.',))
    facts = ReplyFacts('TASK', risks=(risk,))
    before = copy.deepcopy(facts)
    plan = plan_reply(facts)
    result = plan.to_dict()
    policy = result['presentation_policy']
    assert policy['language_source'] == 'HOST_CONVERSATION'
    assert policy['explicit_language_preference_first']
    assert policy['fallback_language'] == 'zh-CN'
    assert policy['translate_headings_and_choices']
    assert policy['task_result_first'] and policy['check_gap_is_not_finding']
    assert policy['reuse_existing_authorization']
    assert not result['required_actions'] and not result['grants_authority']
    assert facts == before
    assert risk.unknowns[0] in render_reply(plan)
    assert '回复' not in render_reply(plan)


@pytest.mark.parametrize('feedback,reviewed', [
    ({}, False),
    (dict(state='STILL_RISK'), False),
    (dict(state='STILL_RISK', agent_review_current=True,
          technical_assessment_current=False), False),
    (dict(state='STILL_RISK', agent_review_current=True,
          technical_assessment_current=True), True),
])
def test_only_current_saved_code_assessment_upgrades_a_scanner_candidate(feedback, reviewed):
    finding = dict(id='candidate', title='Conditional issue', file_path='app.py', line_start=4,
                   impact='Possible effect', fix_advice='Check the input boundary.')
    fact = finding_fact(finding, feedback=feedback)
    plan = plan_reply(ReplyFacts('TASK', risks=(fact,)))
    message = render_reply(plan)
    assert fact.reviewed is reviewed
    assert ('待核实的安全提示' in message) is not reviewed
    assert ('发现 1 项安全风险' in message) is reviewed
    assert plan.to_dict()['host_assessment_before_advice'] is not reviewed
    assert not plan.to_dict()['grants_authority']


def test_existing_authorization_does_not_turn_a_candidate_into_a_confirmed_risk():
    risk = RiskFact('one', 'Candidate', 'app.py', 1, 'Problem', 'Possible effect', 'Advice',
                    authorized=True)
    plan = plan_reply(ReplyFacts('ISSUE', risks=(risk,)))
    message = render_reply(plan)
    assert '安全检查提示（待核实）' in message and '发现安全风险' not in message
    assert not plan.action_ids and '回复' not in message


def test_mixed_candidates_and_host_risks_have_a_neutral_list_title():
    scanner = RiskFact('one', 'Candidate', 'app.py', 1, 'Problem', 'Possible effect', 'Advice')
    host = RiskFact('two', 'Reviewed issue', 'app.py', 2, 'Problem', 'Conditional impact',
                    'Advice', source='HOST_REVIEW')
    mixed = render_reply(plan_reply(ReplyFacts('TASK', risks=(scanner, host))))
    assert mixed.startswith('**发现 2 项安全检查提示**')
    assert 'Candidate' in mixed and 'Reviewed issue' in mixed
    confirmed = render_reply(plan_reply(ReplyFacts('TASK', risks=(host,))))
    assert '发现 1 项安全风险' in confirmed and '待核实的安全提示' not in confirmed


def test_task_gap_reasons_are_actionable_once_without_creating_a_vulnerability():
    value = record(0, 0)
    value['static'].update(status='PARTIAL', coverage='PARTIAL',
        capability_results=dict(CODE_SAST='UNAVAILABLE', DEPENDENCY_VULN='PARTIAL'),
        scanner_runs=[
            dict(scanner='semgrep', error_code='COMPONENT_EXECUTION_IDENTITY_UNAVAILABLE',
                 error_summary='PRIVATE_CANARY_DO_NOT_DISPLAY'),
            dict(scanner='osv-scanner', error_code='OSV_DATABASE_MISSING'),
            dict(scanner='trivy-vuln', error_code='VULNERABILITY_DB_FRESHNESS_UNKNOWN')])
    value['review']['limitations'] = ['app.py 部分已脱敏内容无法核对。']
    before = copy.deepcopy(value)
    plan = plan_reply(task_facts(value))
    message = render_reply(plan)
    assert message.count('代码安全检查未启动') == 1
    assert '代码安全检查未完成' not in message
    assert message.count('依赖检查未完成') == 1
    assert '核对工具安装入口后重试' in message
    assert '补齐所需数据后重试' in message
    assert '更新时间无法确认' in message and '已经过期' not in message
    assert 'app.py 部分已脱敏内容无法核对' in message
    assert '静态检查未完成或覆盖受限' not in message
    assert 'PRIVATE_CANARY' not in message
    assert 'COMPONENT_EXECUTION_IDENTITY_UNAVAILABLE' not in message
    assert not plan.risks and not plan.action_ids
    assert not plan.to_dict()['grants_authority'] and value == before


def test_unknown_scanner_reason_keeps_a_gap_without_guessing_installation_failure():
    value = record(0, 0)
    value['static'].update(status='FAILED', coverage='UNKNOWN',
        capability_results=dict(CODE_SAST='FAILED'),
        scanner_runs=[dict(scanner='semgrep', error_code='PRIVATE_CANARY',
                           error_summary='Please reinstall everything.')])
    message = render_reply(plan_reply(task_facts(value)))
    assert '代码安全检查未完成' in message
    assert all(text not in message for text in ('PRIVATE_CANARY', 'reinstall', '安装入口'))


def test_unknown_capability_keeps_the_generic_coverage_gap():
    value = record(0, 0)
    value['static'].update(status='PARTIAL', coverage='PARTIAL',
                           capability_results=dict(UNRECOGNIZED_CAPABILITY='FAILED'))
    plan = plan_reply(task_facts(value))
    message = render_reply(plan)
    assert '静态检查未完成或覆盖受限' in message
    assert 'UNRECOGNIZED_CAPABILITY' not in message
    assert not plan.risks and not plan.action_ids


@pytest.mark.parametrize('reason,expected,absent', [
    ('ENGINE_MISSING_OFFLINE', '本地依赖检查工具尚未安装', '漏洞数据已经过期'),
    ('OSV_DATABASE_MISSING', '备用依赖检查工具已就绪', '工具尚未安装'),
    ('COMPONENT_EXECUTION_IDENTITY_UNAVAILABLE', '核对工具安装入口', '漏洞数据已经过期'),
    ('VULNERABILITY_DB_FRESHNESS_UNKNOWN', '无法确认本地漏洞数据的更新时间', '已经过期'),
])
def test_dependency_gap_distinguishes_missing_tool_data_and_unknown_age(reason, expected, absent):
    result = dict(status='PARTIAL', capabilities=dict(DEPENDENCY_VULN='PARTIAL'),
        scanner_runs=[dict(scanner='osv-scanner', error_code=reason)])
    before = copy.deepcopy(result)
    message = dependency_status_message(result)
    assert expected in message and absent not in message and reason not in message
    assert '回复' not in message and result == before
