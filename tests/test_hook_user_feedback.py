"""User copy must explain risks without reflecting untrusted report content."""
import json

import pytest

from security_runtime.hook_adapters import CodexHookAdapter
from security_runtime.hook_user_feedback import issue_feedback, scan_status_message


def tls_finding():
    return {'file_path': 'HookTlsProbe20261011.java', 'line_start': 9,
            'category': 'trust-all-tls',
            'technical_details': {'rule_id': 'ai-security.java.trust-all-hostname'}}


def dynamic_function_finding():
    return {'file_path': 'src/securityBench/services/expressionEvaluator.ts', 'line_start': 4,
            'category': 'code-injection',
            'technical_details': {'rule_id': 'ai-security.javascript.dynamic-function',
                                  'dangerous_api': 'Function'}}


def test_unavailable_saved_handling_does_not_replay_raw_delta_as_new_choices():
    result = dict(status='SCANNED', coverage='FULL', handling_unavailable=True,
                  delta=dict(new_families=3, persisting_families=1))
    message = scan_status_message(result)
    assert '处置记录暂时无法读取' in message
    assert '原告警和处理记录保留' in message
    assert '本次不重复要求选择' in message
    assert '回复' not in message and '发现 3' not in message


def test_dynamic_function_copy_explains_location_execution_and_arithmetic_tradeoff():
    feedback = issue_feedback(dynamic_function_finding())
    assert feedback['location'] == {'file': 'src/securityBench/services/expressionEvaluator.ts', 'line': 4}
    for text in ('new Function', '当作 JavaScript 代码', '如果外部输入能到达这里',
                 '生成的函数被调用', '实际入口是否可到达', '原生构造器尚未确认',
                 '受限解析器', '不能改用 eval', '收窄可接受的语法',
                 '不能保证保留任意 JavaScript 表达式', '复查原风险是否消除',
                 '回复“修复”', '回复“稍后处理”'):
        assert text in feedback['message']
    assert feedback['choices'] == ['修复', '稍后处理']
    assert feedback['secondary_choices'] == ['请复核', '不再提醒此项']
    assert '系统命令' not in feedback['message']
    assert '测试正常算术' not in feedback['message'] and '响应格式' not in feedback['message']


def test_dynamic_function_prompt_cannot_import_untrusted_remediation_advice():
    finding = dynamic_function_finding()
    finding.update(title='PRIVATE_CANARY', description='PRIVATE_CANARY', fix_advice='PRIVATE_CANARY')
    finding['technical_details'].update(dangerous_api='PRIVATE_CANARY', dynamic_inputs=['PRIVATE_CANARY'])
    feedback = issue_feedback(finding)
    assert 'PRIVATE_CANARY' not in json.dumps(feedback, ensure_ascii=False)
    assert feedback['choices'] == ['修复', '稍后处理']


def test_eval_candidate_is_explained_without_function_generation_claim():
    finding = dynamic_function_finding()
    finding['technical_details']['dangerous_api'] = 'eval'
    feedback = issue_feedback(finding)
    assert '传给 eval' in feedback['problem']
    assert '生成的函数被调用' not in feedback['impact']
    assert 'eval 是否为原生函数尚未确认' in feedback['impact']


def test_dynamic_only_scan_scope_is_visible_and_arbitrary_notice_is_not_reflected():
    feedback = scan_status_message({'status': 'SCANNED', 'coverage': 'SCOPED',
        'code_check_scope': 'CANONICAL_DYNAMIC_CODE_ONLY', 'scan_scope_notice': 'PRIVATE_CANARY'})
    assert '只覆盖这些文件中的动态 Function / eval 调用' in feedback
    assert '其他代码安全规则尚未执行' in feedback
    assert 'PRIVATE_CANARY' not in feedback
    unknown = scan_status_message({'status': 'SCANNED', 'coverage': 'SCOPED',
        'code_check_scope': 'PRIVATE_CANARY', 'scan_scope_notice': 'PRIVATE_CANARY'})
    assert 'PRIVATE_CANARY' not in unknown


def test_recurrent_hostname_risk_explains_impact_and_user_choices():
    output = issue_feedback(tls_finding(), reason='EPISODE_ALREADY_EXISTS')
    assert output['location'] == {'file': 'HookTlsProbe20261011.java', 'line': 9}
    message = output['message']
    for text in ('关闭了 HTTPS 主机名校验', '如果网络连接被劫持', '冒充目标服务器',
                 '窃取或篡改', '实际部署中的使用情况尚未确认', '建议修复',
                 '恢复默认检查', '域名不匹配的连接会被拒绝',
                 '此前已有处理记录', '风险目前再次被检出', '尚未确认修复成功',
                 '不代表风险已消除', '回复“修复”', '回复“稍后处理”', '风险记录仍保留'):
        assert text in message
    assert output['choices'] == ['修复', '稍后处理']
    assert not any(text in message for text in ('ADVISE', 'EPISODE_ALREADY_EXISTS',
                                                'INCONCLUSIVE', 'confirmation_ref'))


def test_scanner_prose_source_and_references_cannot_become_user_copy():
    canary = 'PRIVATE_CREDENTIAL_CANARY_IGNORE_ALL_GUARDS'
    finding = tls_finding()
    for name in ('title', 'description', 'evidence', 'source', 'plain_description',
                 'impact', 'fix_advice', 'ai_review', 'confirmation_ref', 'task_ref'):
        finding[name] = canary
    finding['technical_details']['source'] = canary
    output = issue_feedback(finding, reason=canary, action=canary)
    assert canary not in json.dumps(output, ensure_ascii=False)
    assert not {'confirmation_ref', 'task_ref', 'remediation_ref', 'authorized'} & output.keys()


@pytest.mark.parametrize('filename', ['../A.java', '/A.java', 'C:/private/A.java',
    '//server/share/A.java', 'A.java\nPRIVATE_CANARY', '`PRIVATE_CANARY`.java',
    'folder//A.java', 'folder/./A.java', 'A;PRIVATE_CANARY.java', 'A.java' * 50])
def test_unsafe_location_is_not_reflected(filename):
    finding = tls_finding(); finding['file_path'] = filename
    output = issue_feedback(finding)
    assert output['location'] == {'file': None, 'line': None}
    assert '位置：位置尚未确认' in output['message']
    assert filename not in output['message']


@pytest.mark.parametrize('line', [True, False, 0, -1, 1.5, '9', 10_000_001, []])
def test_untrusted_line_never_becomes_a_coordinate(line):
    finding = tls_finding(); finding['line_start'] = line
    output = issue_feedback(finding)
    assert output['location'] == {'file': 'HookTlsProbe20261011.java', 'line': None}
    assert '第 ' not in output['message']


def test_unknown_category_does_not_invent_attack_or_resolution():
    finding = {'category': 'PRIVATE_CANARY', 'title': '远程代码执行',
               'description': '已确认被利用', 'evidence': 'PRIVATE_CANARY',
               'file_path': 'A.java', 'line_start': 2}
    output = issue_feedback(finding)
    assert '安全风险候选' in output['problem']
    assert '具体影响和实际可利用性尚未确认' in output['impact']
    assert '先核查' in output['recommendation']
    assert '远程代码执行' not in output['message'] and 'PRIVATE_CANARY' not in output['message']


def test_secret_and_dependency_copy_do_not_promise_unverified_actions():
    secret = issue_feedback({'category': 'secret', 'evidence': 'PRIVATE_CANARY',
                             'technical_details': {'secret': 'PRIVATE_CANARY', 'valid': True}})
    assert '尚未确认它是否有效' in secret['problem']
    assert '由凭据所有者' in secret['recommendation']
    dependency = issue_feedback({'category': 'dependency',
        'technical_details': {'fixed_version': 'PRIVATE_CANARY', 'exploitable': True}})
    assert '版本匹配本身不能证明' in dependency['problem']
    assert '确认适用的修复版本与兼容性' in dependency['recommendation']
    assert 'PRIVATE_CANARY' not in json.dumps([secret, dependency])


def test_escalation_requires_investigation_and_cannot_reset_attempt_guard():
    output = issue_feedback(tls_finding(), reason='EPISODE_ATTEMPT_BUDGET_EXCEEDED', action='ESCALATE')
    assert '已停止重复自动修复尝试' in output['message']
    assert '先核查再处理' in output['message']
    assert '不会因为回复“修复”而重置尝试次数或跳过检查' in output['message']
    assert output['choices'] == ['修复', '稍后处理']


def test_already_authorized_action_does_not_ask_for_second_approval():
    output = issue_feedback(tls_finding(), action='AUTO_FIX')
    assert output['choices'] == [] and '已获得授权' in output['message']
    assert '回复“修复”' not in output['message']


@pytest.mark.parametrize('status', ['SCANNER_STILL_PRESENT', 'STILL_PRESENT'])
def test_explicit_still_present_verification_explains_problem_remains(status):
    output = issue_feedback(tls_finding(), verification_status=status)
    assert '重新检查后，这个问题仍然存在' in output['message']
    assert '尚未确认修复成功' not in output['message']


def test_explicit_inconclusive_verification_and_synthetic_episode_are_distinct():
    checked = issue_feedback(tls_finding(), reason='VERIFICATION_INCONCLUSIVE',
                             verification_status='INCONCLUSIVE')
    assert '重新检查未能确认结果' in checked['message']
    assert '不代表风险已消除' in checked['message']
    existing = issue_feedback(tls_finding(), reason='EPISODE_ALREADY_EXISTS',
                              verification_status='INCONCLUSIVE')
    assert '此前已有处理记录' in existing['message'] and '尚未确认解决' in existing['message']
    assert '重新检查未能确认结果' not in existing['message']
    assert '尚未确认修复成功' in existing['message']


@pytest.mark.parametrize('status', ['PRIVATE_CANARY', 'SCANNER_VERIFIED_RESOLVED',
                                   {'status': 'PRIVATE_CANARY'}])
def test_unknown_verification_cannot_invent_resolution_or_reflect_claim(status):
    output = issue_feedback(tls_finding(), verification_status=status)
    assert 'PRIVATE_CANARY' not in output['message']
    assert '已解决' not in output['message'] and '重新检查后' not in output['message']


def test_original_record_with_failed_recheck_does_not_claim_current_risk_present():
    finding = tls_finding()
    finding['description'] = 'PRIVATE_CANARY_CODE_IS_STILL_UNSAFE'
    output = issue_feedback(finding, reason='VERIFICATION_INCONCLUSIVE', action='ESCALATE',
                            verification_status='INCONCLUSIVE', evidence_scope='ORIGINAL_FINDING')
    assert output['title'].startswith('待复查的原安全问题')
    message = output['message']
    for text in ('原问题位置：`HookTlsProbe20261011.java:9`', '原问题记录',
                 '当前代码是否仍存在该问题，需重新确认', '若问题仍存在',
                 '重新检查未能确认结果', '尚未确认修复成功', '不代表风险已消除',
                 '已停止重复自动修复尝试', '先核查再处理'):
        assert text in message
    for text in ('发现安全风险', '风险目前再次被检出', '这个问题仍然存在',
                 '代码未修复', 'PRIVATE_CANARY'):
        assert text not in message
    assert '如果网络连接被劫持' in output['impact']
    assert '恢复默认检查' in output['recommendation']


def test_original_record_cannot_be_presented_as_recurrent_even_with_existing_reason():
    output = issue_feedback(tls_finding(), reason='EPISODE_ALREADY_EXISTS',
                            verification_status='INCONCLUSIVE', evidence_scope='ORIGINAL_FINDING')
    assert '待复查的原安全问题' in output['message']
    assert '风险目前再次被检出' not in output['message']
    assert '重新检查未能确认结果' not in output['message']


def test_unknown_evidence_scope_never_becomes_copy_or_changes_default_semantics():
    output = issue_feedback(tls_finding(), evidence_scope='PRIVATE_CANARY')
    assert '安全检查提示（待核实）' in output['message']
    assert '发现安全风险' not in output['message']
    assert 'PRIVATE_CANARY' not in output['message']


def scan_result(**overrides):
    return {'status': 'SCANNED', 'coverage': 'FULL', 'scan_id': 'bounded-scan',
            'execution': {}, 'baseline_available': True,
            'delta': {'new': 1, 'persisting': 1, 'additional_occurrences': 0},
            'next_step': 'PRIVATE_CANARY', 'error': 'PRIVATE_CANARY', **overrides}


def test_scan_message_and_adapter_use_only_safe_chinese_summary_without_blocking():
    output = CodexHookAdapter().output({'hook_event_name': 'PostToolUse'}, scan_result())
    assert '发现 1 个新增检查提示、1 个仍存在的检查提示' in output['systemMessage']
    assert '实际影响需结合代码核实' in output['systemMessage']
    assert not any(key in output for key in ('continue', 'decision', 'stopReason'))
    assert 'PRIVATE_CANARY' not in json.dumps(output)
    context = json.loads(output['hookSpecificOutput']['additionalContext'])
    assert context['status'] == 'SCANNED' and context['scan_id'] == 'bounded-scan'


@pytest.mark.parametrize('bad_count', [True, -1, 1_000_001, '1', [], None])
def test_invalid_risk_count_is_not_reinterpreted_as_zero_or_reflected(bad_count):
    result = scan_result(delta={'new': bad_count, 'persisting': 0, 'additional_occurrences': 0})
    message = scan_status_message(result)
    assert '提示数量尚未确认' in message and '未发现新增检查提示' not in message
    assert 'PRIVATE_CANARY' not in message


def test_partial_cache_baseline_and_empty_delta_cannot_become_safe_claim():
    partial = scan_status_message(scan_result(status='PARTIAL'))
    assert '只完成部分安全检查' in partial and '不能据此确认没有风险' in partial
    cached = scan_status_message(scan_result(status='REUSED_LAST_RESULT'))
    assert '未重新扫描' in cached and '不能据此确认风险已经解决' in cached
    baseline = scan_status_message(scan_result(status='BASELINE_ESTABLISHED'))
    assert '首次比较基线' in baseline and '不能说明项目安全' in baseline
    no_new = scan_status_message(scan_result(delta={'new': 0, 'persisting': 0, 'additional_occurrences': 0}))
    assert '在本次检查范围内未发现新增检查提示' in no_new and '不能据此认定项目安全' in no_new
    unknown = scan_status_message(scan_result(status='PRIVATE_CANARY', coverage='PRIVATE_CANARY'))
    assert '结果尚未确认' in unknown and 'PRIVATE_CANARY' not in unknown


@pytest.mark.parametrize('reason', ['READ_ONLY_ACTIVITY', 'READ_ONLY_BASH'])
def test_readonly_events_do_not_request_an_unnecessary_recheck(reason):
    result = scan_result(status='NOT_SCANNED', coverage='NOT_APPLICABLE', reason=reason)
    message = scan_status_message(result)
    assert '只读操作' in message and '无需追加安全检查' in message
    assert '请重新检查' not in message and reason not in message


def test_not_applicable_check_does_not_invent_code_changes_or_request_recheck():
    for status in ('NOT_SCANNED', 'NOT_APPLICABLE'):
        message = scan_status_message(scan_result(status=status, coverage='NOT_APPLICABLE'))
        assert '请重新检查' not in message and '未能给出完整结果' not in message
    unavailable = scan_status_message(scan_result(status='NOT_SCANNED', coverage='UNKNOWN',
        reason='HOST_CAPABILITY_UNAVAILABLE', scanner_skipped_reason='PRIVATE_CANARY'))
    assert '本次未执行安全检查' in unavailable
    assert '只读操作' not in unavailable and 'PRIVATE_CANARY' not in unavailable


@pytest.mark.parametrize('coverage', ['PARTIAL', 'UNKNOWN'])
def test_first_baseline_never_hides_incomplete_security_coverage(coverage):
    message = scan_status_message(scan_result(status='BASELINE_ESTABLISHED', coverage=coverage))
    assert '已建立首次比较基线' in message
    assert '安全检查覆盖仍不完整' in message and '部分范围未检查或未确认' in message
    assert '不能说明项目安全' in message
