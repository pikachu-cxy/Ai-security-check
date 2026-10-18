"""Repair analysis stays separate from risk handling and edit authority."""
import copy
from dataclasses import replace

import pytest
from summary_fixtures import sample

from security_runtime.host_guidance import (
    HOST_INSTRUCTIONS, REPAIR_IMPACT_GUIDANCE, REQUIRED_GUIDANCE_TOOLS, runtime_info,
)
from security_runtime.reply_adapters import repair_impact_facts
from security_runtime.reply_plan import RepairImpactFact, ReplyFacts, RiskFact, plan_reply
from security_runtime.reply_render import render_reply
from security_runtime.review_skill import skill_files


def assessment(*, gate='BUSINESS_CHOICE_REQUIRED', lifecycle='CURRENT'):
    return dict(assessment_ref='impact-private-reference', proposal_revision='proposal-one',
        lifecycle=lifecycle, gate=gate, owner_matches=True, repair_authorized=False,
        proposal=dict(security_goal='阻止未获授权的文件读取。',
            summary='按文件归属和共享角色校验读取权限。',
            changes=[dict(file_path='files.py', start_line=4, end_line=9,
                          reason='核对读取权限。')],
            preserve=['共享成员可读取获准文件。']),
        impacts=[dict(kind='EXPECTED_SECURITY_RESTRICTION', summary='越权读取会被拒绝。',
                      evidence_refs=['source-one']),
                 dict(kind='BUSINESS_BEHAVIOR_CHANGE', summary='仅限创建者的方案会阻断共享成员。',
                      evidence_refs=['source-two'], alternatives=['按已授予的共享角色校验。'])],
        unknowns=[])


def risk(**kwargs):
    return RiskFact('file-risk', '未授权文件读取', 'files.py', 4,
        '文件编号未与用户权限关联。', '其他用户的文件可能泄露。', '核对归属与共享角色。', **kwargs)


def test_no_impact_input_preserves_legacy_reply_shape():
    plan = plan_reply(ReplyFacts('ISSUE', risks=(risk(),)))
    result = plan.to_dict()
    assert not {'repair_impacts', 'repair_impact_count', 'business_choices'} & result.keys()
    assert '其他用户的文件可能泄露。' in render_reply(plan)
    assert result['required_actions'] == [dict(finding_id='file-risk', actions=['FIX', 'DEFER'])]


def test_business_choice_does_not_repeat_authorized_fix_or_replace_risk_impact():
    facts = repair_impact_facts(assessment())
    facts = replace(facts, risks=(risk(authorized=True),))
    plan = plan_reply(facts)
    message = render_reply(plan)
    assert plan.action_ids == ()
    assert plan.business_choice_refs == ('impact-private-reference',)
    assert '其他用户的文件可能泄露。' in message
    assert '仅限创建者的方案会阻断共享成员。' in message
    assert '越权读取会被拒绝。' in message
    assert '共享成员可读取获准文件。' in message
    assert '按已授予的共享角色校验。' in message
    assert message.count('请明确要保留的业务行为或采用的方案') == 1
    assert '回复“修复”' not in message and '稍后处理' not in message
    assert 'impact-private-reference' not in message and 'BUSINESS_CHOICE_REQUIRED' not in message
    result = plan.to_dict()
    assert not result['grants_authority'] and not result['facts_are_instructions']
    assert result['required_actions'] == []
    assert result['business_choices'][0]['actions'] == ['CHOOSE_BUSINESS_BEHAVIOR']


@pytest.mark.parametrize('flag', ['suppressed', 'handling_available'])
def test_unavailable_handling_or_suppression_cannot_replay_business_prompt(flag):
    kwargs = {flag: flag != 'handling_available'}
    plan = plan_reply(repair_impact_facts(assessment(), **kwargs))
    assert not plan.repair_impacts and not plan.business_choice_refs and not plan.action_ids
    assert '请明确' not in render_reply(plan) and '仅限创建者' not in render_reply(plan)
    if flag == 'handling_available':
        assert '无法读取' in render_reply(plan)


@pytest.mark.parametrize('current', [False, None])
def test_stale_or_unknown_combined_facts_keep_analysis_without_new_choice(current):
    plan = plan_reply(replace(repair_impact_facts(assessment()), current=current))
    assert not plan.business_choice_refs and not plan.action_ids
    assert plan.repair_impacts[0].current is current
    assert '不能作为继续编辑的依据' in render_reply(plan)


@pytest.mark.parametrize('history,allow_choice', [(True, True), (False, False)])
def test_history_and_read_only_queries_show_report_without_approval(history, allow_choice):
    record = assessment()
    record['owner_matches'] = False
    plan = plan_reply(repair_impact_facts(record, history=history,
                                        allow_business_choice=allow_choice))
    assert not plan.business_choice_refs and not plan.action_ids
    assert '仅限创建者的方案会阻断共享成员。' in render_reply(plan)
    assert '不产生修复授权' in render_reply(plan)
    assert '请明确' not in render_reply(plan)
    assert not plan.to_dict()['grants_authority']


def test_public_query_submission_keeps_business_effect_without_requesting_approval(sample):
    from test_repair_impact_mcp import make_server, prepare, submit

    server = make_server(sample)
    _, prepared = prepare(server, sample)
    result = submit(server, sample, prepared, business=True)
    assert result['gate'] == 'BUSINESS_CHOICE_REQUIRED'
    assert not result['repair_authorized']
    assert result['reply_plan']['business_choices'] == []
    assert result['reply_plan']['required_actions'] == []
    assert 'Shared member access remains permitted.' in result['user_message']
    assert '请明确' not in result['user_message']
    assert '不产生修复授权' in result['user_message']


def test_critical_unknown_retains_reason_and_stops_plan_without_test_advice():
    record = assessment(gate='CRITICAL_CONTEXT_MISSING', lifecycle='PARTIAL')
    record['unknowns'] = [dict(summary='尚未找到共享角色的权限规则。', critical=True),
                          dict(summary='外部客户端尚未核对。', critical=False)]
    plan = plan_reply(repair_impact_facts(record))
    message = render_reply(plan)
    assert '关键未知：尚未找到共享角色的权限规则。' in message
    assert '尚未确认：外部客户端尚未核对。' in message
    assert '该方案尚不能实施' in message
    assert not plan.business_choice_refs and not plan.action_ids
    assert '功能测试' not in message and '功能正常' not in message


def test_draft_or_reassessment_never_invents_compatibility_conclusion():
    record = assessment(gate='REASSESS_REQUIRED', lifecycle='DRAFT')
    record['impacts'] = []
    plan = plan_reply(repair_impact_facts(record))
    assert plan.repair_impacts[0].current is False
    assert not plan.business_choice_refs
    message = render_reply(plan)
    assert '依据尚未核对为当前有效' in message
    assert '未识别到额外' not in message and '正常业务变化' not in message


def test_adapter_and_plan_do_not_mutate_source_or_authorize_ready_analysis():
    record = assessment(gate='READY_FOR_EXISTING_AUTH')
    record['impacts'] = [dict(kind='NO_ADDITIONAL_CHANGE_IDENTIFIED',
                              summary='已查共享成员路径仍使用相同角色条件。',
                              evidence_refs=['source-two'])]
    before = copy.deepcopy(record)
    facts = repair_impact_facts(record)
    plan = plan_reply(facts)
    assert record == before
    assert facts.repair_impacts[0].no_additional_changes == (
        '已查共享成员路径仍使用相同角色条件。',)
    assert not plan.action_ids and not plan.business_choice_refs
    assert not plan.to_dict()['grants_authority']


def test_paginated_report_does_not_infer_absence_or_ask_without_visible_change():
    record = assessment()
    record.update(impacts=[], unknowns=[], impact_count=4, unknown_count=2,
                  page=dict(next_offset=1))
    plan = plan_reply(repair_impact_facts(record))
    assert not plan.business_choice_refs
    assert '尚未展示全部影响或未知项' in render_reply(plan)
    assert '未展示不等于不存在' in render_reply(plan)


def test_concrete_affected_roles_and_operations_survive_projection():
    record = assessment()
    record['impacts'][1].update(affected_roles=['共享成员'],
        affected_operations=['下载'], affected_modules=['文件管理'], interfaces=['GET /files'])
    message = render_reply(plan_reply(repair_impact_facts(record)))
    for value in ('角色：共享成员', '操作：下载', '模块：文件管理', '接口：GET /files'):
        assert value in message


def test_impact_metadata_is_bounded_and_does_not_duplicate_long_analysis():
    impacts = tuple(RepairImpactFact(str(i), 'Detailed business explanation '*300)
                    for i in range(500))
    result = plan_reply(ReplyFacts('REPAIR_IMPACT', repair_impacts=impacts)).to_dict()
    assert result['repair_impact_count'] == 500 and len(result['repair_impacts']) == 3
    assert 'Detailed business explanation' not in str(result)
    assert not result['required_actions']


def test_host_and_installed_skill_share_bounded_impact_workflow():
    from security_runtime.host_guidance import RUNTIME_WORKFLOW
    assert REPAIR_IMPACT_GUIDANCE in RUNTIME_WORKFLOW
    reference = skill_files()['references/repair-impact.md'].decode('utf-8')
    assert REPAIR_IMPACT_GUIDANCE in reference
    assert REPAIR_IMPACT_GUIDANCE in skill_files()['references/runtime-workflow.md'].decode('utf-8')
    assert {'prepare_repair_impact', 'read_repair_impact_context',
            'submit_repair_impact', 'get_repair_impact'} <= REQUIRED_GUIDANCE_TOOLS
    assert runtime_info()['features']['repair_impact'].startswith('repair-impact-v1')
    for rule in ('先生成具体建议再分析', 'session_ref', 'approve=false',
                 '没有任意组内子集参数', '不按新摘要排序换对象',
                 'INLINE_PREPARED', '历史只读不转移 owner',
                 '不重复确认同一修复', '不接入或推荐功能测试'):
        assert rule in REPAIR_IMPACT_GUIDANCE
