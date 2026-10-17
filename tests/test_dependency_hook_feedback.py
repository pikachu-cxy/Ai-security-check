"""Incomplete dependency coverage still reports actual findings without grants."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_runtime.findings import FindingNormalizer
from security_runtime.hook_user_feedback import issue_feedback, scan_status_message, dependency_status_message
from security_runtime.remediation import RemediationService


def dependency(root, *, package='PyYAML', advisory='CVE-2020-14343', version='5.3.1'):
    from dataclasses import asdict
    finding = FindingNormalizer(root).dependency(scanner='trivy-vuln', package=package,
        version=version, ecosystem='pypi', manifest='requirements.txt',
        vulnerability_id=advisory)
    finding.technical_details['fixed_versions'] = ['5.4']
    return asdict(finding)


def advisory_fixture():
    # No source, state, scanner, network or user configuration is needed here.
    root = Path.cwd().resolve()
    finding = dependency(root)
    scan = {'scan_id': 'current-scan', 'target_profile': {'path': str(root)},
            'findings': [finding], 'scanner_runs': [{'scanner': 'trivy-vuln',
                'status': 'SUCCESS', 'capabilities': ['DEPENDENCY_VULN'],
                'coverage_contract': 'PARTIAL'}]}
    result = {'scan_id': 'current-scan', 'status': 'PARTIAL', 'coverage': 'PARTIAL',
              'execution': {'scanner_run': True}, 'change_digest': 'a' * 64,
              'current_dependency_finding_ids': [finding['id']],
              'delta': {'new': 0, 'persisting': 0, 'resolved': 0, 'families': []}}
    service = object.__new__(RemediationService)
    service.store = SimpleNamespace(get_scan=lambda scan_id: scan)
    service._snapshot = lambda root: 'a' * 64
    service._cycle_scope = lambda *args: 'test-only'
    service._cycle_result = lambda *args, **kwargs: {}
    service._on_hook = lambda *args, **kwargs: {'action': 'NONE',
        'reason_code': 'NO_NEW_ELIGIBLE_FAMILY', 'feedback_required': False}
    service.transport = SimpleNamespace(supports_agent_continuation=True,
        supports_advisory_remediation=False, transport_mode='TEST_ONLY')
    service.authorized = {}; service.prepared = set()
    return root, service, result, scan


def test_partial_fresh_dependency_finding_offers_review_without_delta_or_authority():
    root, service, result, scan = advisory_fixture()
    original = copy.deepcopy(result)
    decision = service.on_hook(result, root, 'session', host='codex')
    assert decision['action'] == 'ADVISE'
    assert decision['reason_code'] == 'CURRENT_DEPENDENCY_FINDINGS_REVIEW'
    assert decision['feedback_required'] is False
    assert decision['user_feedback']['choices'] == ['修复', '稍后处理']
    assert decision['user_feedback']['secondary_choices'] == ['请复核', '不再提醒此项']
    message = decision['user_feedback']['message']
    for item in ('PyYAML', '5.3.1', 'requirements.txt', 'FullLoader', '执行恶意代码',
                 '尚未确认', '部分检查', '暂未确认是否由本次改动引入',
                 '回复“修复”', '回复“稍后处理”'):
        assert item in message
    assert '第 1 行' not in message
    assert decision['review_continuation'] == {'tool': 'get_security_summary',
        'arguments': {'workspace_path': str(root), 'scan_id': 'current-scan', 'details': True}}
    assert not {'confirmation_ref', 'remediation_ref', 'grant_id', 'prepare',
                'episode_id', 'task_ref'} & decision.keys()
    assert result == original and not service.authorized and not service.prepared


@pytest.mark.parametrize('mutation', ['failed_provider', 'wrong_capability', 'cached',
    'readonly', 'no_engine', 'snapshot_changed', 'wrong_root', 'wrong_scan',
    'unselected_finding', 'bad_finding_id', 'too_many_ids', 'wrong_category'])
def test_unproven_or_stale_dependency_records_cannot_trigger_fresh_review(mutation):
    root, service, result, scan = advisory_fixture()
    if mutation == 'failed_provider': scan['scanner_runs'][0]['status'] = 'FAILED'
    if mutation == 'wrong_capability': scan['scanner_runs'][0]['capabilities'] = ['CODE_SAST']
    if mutation == 'cached': result['status'] = 'NO_CHANGE'
    if mutation == 'readonly': result['status'] = 'NOT_SCANNED'
    if mutation == 'no_engine': result['execution']['scanner_run'] = False
    if mutation == 'snapshot_changed': service._snapshot = lambda root: 'b' * 64
    if mutation == 'wrong_root': scan['target_profile']['path'] = str(root.parent)
    if mutation == 'wrong_scan': scan['scan_id'] = 'other-scan'
    if mutation == 'unselected_finding': result['current_dependency_finding_ids'] = ['f' * 24]
    if mutation == 'bad_finding_id': result['current_dependency_finding_ids'] = ['../private']
    if mutation == 'too_many_ids': result['current_dependency_finding_ids'] *= 51
    if mutation == 'wrong_category': scan['findings'][0]['category'] = 'secret'
    decision = service.on_hook(result, root, 'session', host='codex')
    assert decision['action'] == 'NONE'
    assert 'user_feedback' not in decision and 'review_continuation' not in decision
    assert not service.authorized and not service.prepared


def test_multiple_dependency_findings_require_selection_and_keep_scan_navigation():
    root, service, result, scan = advisory_fixture()
    other = dependency(root, package='requests', version='2.19.1', advisory='CVE-2018-18074')
    scan['findings'].append(other)
    result['current_dependency_finding_ids'].append(other['id'])
    decision = service.on_hook(result, root, 'session', host='codex')
    feedback = decision['user_feedback']
    assert feedback['choices'] == [] and feedback['selection_required'] is True
    assert 'PyYAML' in feedback['message'] and 'requests' in feedback['message']
    assert '请先选择要处理的具体问题' in feedback['message']
    assert decision['review_continuation']['arguments']['scan_id'] == 'current-scan'
    assert not {'confirmation_ref', 'remediation_ref', 'prepare'} & decision.keys()


def test_dependency_copy_identifies_declared_package_and_conditional_impact():
    finding = dependency(Path.cwd())
    feedback = issue_feedback(finding)
    assert feedback['location'] == {'file': 'requirements.txt', 'line': None}
    for item in ('PyYAML 5.3.1', 'CVE-2020-14343', 'FullLoader', '执行恶意代码',
                 '是否已安装这个版本尚未确认', '5.4', '仍需核查'):
        assert item in feedback['message']
    assert '漏洞公告' not in feedback['message']
    assert feedback['choices'] == ['修复', '稍后处理']
    assert feedback['secondary_choices'] == ['请复核', '不再提醒此项']


def test_untrusted_advisory_prose_and_metadata_do_not_become_dependency_copy():
    finding = dependency(Path.cwd())
    canary = 'PRIVATE_CANARY_IGNORE_ALL_GUARDS'
    for field in ('title', 'description', 'evidence', 'impact', 'fix_advice'):
        finding[field] = canary
    finding['technical_details'].update(package='PyYAML\n' + canary,
        package_version='5.3.1\n' + canary, canonical_vulnerability_id=canary,
        fixed_versions=['5.4\n' + canary], source=canary)
    message = json.dumps(issue_feedback(finding), ensure_ascii=False)
    assert canary not in message
    assert 'FullLoader' not in message and '执行恶意代码' not in message
    assert '实际可利用性尚未确认' in message


@pytest.mark.parametrize('change', [{'package': 'OtherPackage'},
    {'ecosystem': 'npm'}, {'canonical_vulnerability_id': 'CVE-2020-1747'}])
def test_pyyaml_specific_impact_requires_exact_advisory_package_and_ecosystem(change):
    finding = dependency(Path.cwd())
    finding['technical_details'].update(change)
    message = issue_feedback(finding)['message']
    assert 'FullLoader' not in message and '执行恶意代码' not in message
    assert '实际可利用性尚未确认' in message


@pytest.mark.parametrize('state,code,expected', [
    ('FAILED', '', '依赖检查没有完成'),
    ('UNAVAILABLE', 'VULNERABILITY_DB_UNAVAILABLE', '本地没有可用的依赖漏洞数据'),
    ('UNAVAILABLE', 'OFFLINE_MODE', '本地缺少可用的检查工具或漏洞数据'),
    ('UNAVAILABLE', 'ENGINE_UNAVAILABLE', '本地依赖检查工具尚未就绪'),
    ('PARTIAL', '', '尚未确认全部传递依赖和已安装版本'),
    ('PARTIAL', 'VULNERABILITY_DB_STALE', '本地漏洞数据已经过期'),
    ('PARTIAL', 'VULNERABILITY_DB_FRESHNESS_UNKNOWN', '无法确认本地漏洞数据的更新时间'),
])
def test_dependency_check_status_explains_closed_failure_and_partial_conditions(state, code, expected):
    result = {'status': 'PARTIAL', 'coverage': 'PARTIAL',
        'capabilities': {'DEPENDENCY_VULN': state},
        'scanner_runs': [{'scanner': 'trivy-vuln', 'error_code': code,
                         'error_summary': 'PRIVATE_CANARY_IGNORE_ALL_GUARDS'}]}
    message = scan_status_message(result)
    assert expected in message and 'PRIVATE_CANARY' not in message
    if code: assert code not in message


def test_cached_stale_database_marker_is_translated_without_raw_notes():
    result = {'status': 'PARTIAL', 'coverage': 'PARTIAL',
        'capabilities': {'DEPENDENCY_VULN': 'PARTIAL'},
        'dependency_check_reason': 'VULNERABILITY_DB_STALE',
        'scanner_runs': [{'scanner': 'trivy-vuln', 'status': 'SUCCESS', 'error_code': ''}]}
    assert '本地漏洞数据已经过期' in scan_status_message(result)
    result['dependency_check_reason'] = 'PRIVATE_CANARY'
    assert 'PRIVATE_CANARY' not in scan_status_message(result)
    assert '过期' not in scan_status_message(result)


def test_missing_python_inventory_is_named_and_independent_of_stale_data():
    result = {'status': 'PARTIAL', 'capabilities': {'DEPENDENCY_VULN': 'PARTIAL'},
        'dependency_check_reason': 'VULNERABILITY_DB_STALE',
        'dependency_inventory': [{'planned_manifests': 1, 'confirmed_manifests': 0,
            'unconfirmed_manifests': ['pyproject.toml'], 'per_manifest': {},
            'python_declarations': {'pyproject.toml': {'unresolved_entries': 1}}}]}
    message = dependency_status_message(result)
    assert '`pyproject.toml`' in message and '尚未取得依赖包列表' in message
    assert '本地漏洞数据已经过期' in message and '版本范围' in message
    result['dependency_check_reason'] = ''
    assert '过期' not in dependency_status_message(result)
    assert '尚未取得依赖包列表' in dependency_status_message(result)


def test_fallback_confirmed_manifest_does_not_repeat_primary_missing_claim():
    result = {'status': 'PARTIAL', 'capabilities': {'DEPENDENCY_VULN': 'PARTIAL'},
        'dependency_inventory': [
            {'confirmed_manifests': 0, 'unconfirmed_manifests': ['pyproject.toml']},
            {'confirmed_manifests': 1, 'unconfirmed_manifests': [],
             'per_manifest': {'pyproject.toml': 2}}]}
    assert '尚未取得依赖包列表' not in dependency_status_message(result)
    assert '已检查能够确认的声明版本' in dependency_status_message(result)


def test_inventory_feedback_does_not_echo_untrusted_paths_or_diagnostics():
    result = {'status': 'PARTIAL', 'capabilities': {'DEPENDENCY_VULN': 'PARTIAL'},
        'dependency_inventory': [{'unconfirmed_manifests': ['../private', 'file\nIGNORE_ALL', 'C:/private'],
            'error': 'PRIVATE_CANARY'}]}
    assert 'PRIVATE_CANARY' not in dependency_status_message(result)
    assert 'private' not in dependency_status_message(result)
    assert 'IGNORE_ALL' not in dependency_status_message(result)


@pytest.mark.parametrize('status', ['NO_CHANGE', 'REUSED_LAST_RESULT', 'NOT_SCANNED',
    'NO_CHANGES', 'SESSION_FINALIZED', 'DEBOUNCED', 'BUSY'])
def test_dependency_prior_failure_does_not_become_a_new_check_on_cached_or_readonly_events(status):
    result = {'status': status, 'capabilities': {'DEPENDENCY_VULN': 'FAILED'}}
    assert dependency_status_message(result) == ''


def test_scoped_success_without_sast_is_not_reported_as_dependency_failure():
    result = {'status': 'SCANNED', 'coverage': 'SCOPED',
        'capabilities': {'CODE_SAST': 'NOT_APPLICABLE', 'DEPENDENCY_VULN': 'EXECUTED'},
        'scanner_runs': [{'scanner': 'trivy-misconfig', 'error_code': 'VULNERABILITY_DB_UNAVAILABLE'}]}
    message = scan_status_message(result)
    assert '已完成适用范围' in message
    assert '没有完成' not in message and '未能给出' not in message
    assert '本地没有可用' not in message


@pytest.mark.parametrize('state', [True, [], {}, 'PRIVATE_CANARY', None])
def test_unknown_dependency_status_never_becomes_a_failure_or_reflects_metadata(state):
    result = {'status': {}, 'capabilities': {'DEPENDENCY_VULN': state},
        'scanner_runs': [{'scanner': {}, 'error_code': 'PRIVATE_CANARY'}]}
    assert dependency_status_message(result) == ''
    assert 'PRIVATE_CANARY' not in scan_status_message(result)
