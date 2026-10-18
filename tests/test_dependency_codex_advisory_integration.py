"""Actual SDK Hook and summary navigation for advisory-only source projects."""
import asyncio
import json
import os
from types import SimpleNamespace

import pytest

from security_runtime.codex_mcp_hook import codex_hook_output
from security_runtime.hook_state import identity
from security_runtime.integration_state import WorkspaceBinding
from security_runtime.mcp_server import create_server
from security_runtime.remediation import RemediationService
from security_runtime.remediation_policy import RemediationConfig
from security_runtime.task_fix import TaskFixService
from test_codex_mcp_hook import binding as workspace_binding, claims
from test_codex_code_mode_contract import documented_posttool_effect
from test_quick_dependency_runtime import coordinator, repo, runtime, write
from hook_feedback_test_helpers import internal_context


@pytest.fixture
def source_sdk(tmp_path, monkeypatch):
    root = tmp_path / 'source-project'
    root.mkdir()
    # Keep an isolated non-Git fixture even when pytest's base is inside the
    # product repository. Git must never discover the real workspace parent.
    monkeypatch.setenv('GIT_CEILING_DIRECTORIES', str(root.parent))
    write(root, 'app.py', 'value = 1\n')
    write(root, 'requirements.txt', 'PyYAML==5.3.1\n')
    engine, dependency, _, _ = runtime(tmp_path, dependency_coverage='PARTIAL')
    base_scan = dependency.scan
    issues = [('PyYAML', '5.3.1', 'CVE-2020-14343', 'HIGH')]

    def scan(context, normalizer):
        _, run = base_scan(context, normalizer)
        found = [normalizer.dependency(scanner=dependency.name, package=package,
            version=version, ecosystem='pypi', manifest='requirements.txt',
            vulnerability_id=advisory, severity=severity)
            for package, version, advisory, severity in issues]
        run.finding_count = len(found)
        return found, run

    dependency.scan = scan
    core = coordinator(tmp_path, engine, root, non_git=True)
    binding = WorkspaceBinding(identity(os.path.normcase(str(root)))[:24],
        str(root), '', 'codex', 'PROJECT', '')
    services = []
    unauthorized_calls = []

    def forbidden(*args, **kwargs):
        unauthorized_calls.append(True)
        raise AssertionError('Advisory Hook/summary must never prepare or authorize a fix')

    monkeypatch.setattr(TaskFixService, 'prepare', forbidden)
    monkeypatch.setattr(RemediationService, '_new_episode', forbidden)

    def remediation_factory(store, **kwargs):
        service = RemediationService(store, config=RemediationConfig(tmp_path / 'policy.json'),
            directory=tmp_path / 'remediation', **kwargs)
        monkeypatch.setattr(service, 'on_hook', forbidden)
        services.append(service)
        return service

    server = create_server(engine, workspace_binding=binding, global_mode=False,
        hook_coordinator=core, hook_advisory_only=True, remediation_factory=remediation_factory)
    return root, server, engine, dependency, issues, services[0], unauthorized_calls


def invoke(server, name, arguments):
    response = asyncio.run(server.call_tool(name, arguments))
    if hasattr(response, 'isError'):
        assert not response.isError, response.content
        return response
    # Normal dict tools use the SDK's serialized text/structured tuple shape;
    # Hook tools return their explicit CallToolResult directly.
    content, structured = response if isinstance(response, tuple) else (response, None)
    if structured is None:
        structured = json.loads(content[0].text)
    return SimpleNamespace(content=content, structuredContent=structured.get('result', structured))


def hook(source_sdk, *, readonly=False):
    root, server, *_ = source_sdk
    arguments = claims(root)
    if readonly:
        arguments.update(tool_name='Bash', tool_input={'command': 'git diff'})
    response = invoke(server, 'handle_hook_event', arguments)
    data = response.structuredContent
    assert data.get('host_claim_status') != 'REJECTED', data
    wire = json.loads(response.content[0].text)
    assert wire == codex_hook_output(data)
    return data, wire


def assert_no_authority(source_sdk, data):
    root, _, _, _, _, service, unauthorized_calls = source_sdk
    decision = data.get('remediation', {})
    assert not {'confirmation_ref', 'remediation_ref', 'grant_id', 'episode_id',
                'task_ref', 'prepare', 'verify', 'agent_fix_ticket'} & decision.keys()
    assert not service.authorized and not service.prepared and not unauthorized_calls
    assert not list(service.state.directory.rglob('*.json'))
    assert (root / 'requirements.txt').read_text() == 'PyYAML==5.3.1\n'
    assert (root / 'app.py').read_text() == 'value = 1\n'


def test_partial_dependency_presence_reaches_actual_advisory_sdk_and_exact_summary_task(source_sdk):
    root, server, engine, provider, _, _, _ = source_sdk
    data, wire = hook(source_sdk)
    assert data['capabilities']['DEPENDENCY_VULN'] == 'PARTIAL'
    assert provider.offline_calls == [True] and len(provider.calls) == 1
    assert data['remediation']['action'] == 'ADVISE'
    assert data['remediation']['user_feedback']['choices'] == ['修复', '稍后处理']
    assert data['remediation']['user_feedback']['secondary_choices'] == ['请复核', '不再提醒此项']
    assert wire['continue'] is False and wire['stopReason'] == wire['systemMessage']
    assert documented_posttool_effect(wire) == {
        'nested_promise_rejected': False, 'model_feedback': wire['systemMessage']}
    for item in ('PyYAML', '5.3.1', 'requirements.txt', 'FullLoader', '执行恶意代码',
                 '尚未确认', '回复“修复”', '“稍后处理”'):
        assert item in wire['systemMessage']
    for item in ('ADVISE', 'PARTIAL', 'DEPENDENCY_RISK_REVIEW_REQUIRED', 'get_security_summary'):
        assert item not in wire['systemMessage']
    control = internal_context(wire)['remediation']
    navigation = control['review_continuation']
    assert navigation == {'tool': 'get_security_summary', 'arguments': {
        'workspace_path': str(root), 'scan_id': data['scan_id'], 'details': True}}
    current = engine.store.get_scan(data['scan_id'])['findings']
    assert control['review_finding_ids'] == [current[0]['id']]
    summary = invoke(server, navigation['tool'], navigation['arguments']).structuredContent
    tasks = [task for task in summary['tasks'] if any(
        member['finding_id'] == control['review_finding_ids'][0] for member in task['members'])]
    assert len(tasks) == 1
    assert tasks[0]['task_ref'].startswith('task-v1.') and tasks[0]['finding_count'] == 1
    assert tasks[0]['fix_handoff']['arguments']['task_ref'] == tasks[0]['task_ref']
    assert len(provider.calls) == 1 and summary['automatic_execution'] is False
    assert_no_authority(source_sdk, data)


def test_multiple_dependencies_bind_only_displayed_items_in_display_order(source_sdk):
    _, server, engine, _, issues, _, _ = source_sdk
    issues.extend([('alpha-package', '1.0', 'CVE-2099-0002', 'CRITICAL'),
                   ('beta-package', '1.0', 'CVE-2099-0003', 'HIGH'),
                   ('gamma-package', '1.0', 'CVE-2099-0004', 'MEDIUM'),
                   ('delta-package', '1.0', 'CVE-2099-0005', 'LOW')])
    data, wire = hook(source_sdk)
    feedback = data['remediation']['user_feedback']
    assert feedback['selection_required'] is True and feedback['choices'] == []
    assert len(feedback['items']) == 3 and feedback['finding_count'] == 5
    assert '**请选择具体风险，再回复「修复」或「稍后处理」。**' in wire['systemMessage']
    assert all(choice in wire['systemMessage'] for choice in ('修复', '稍后处理'))
    assert '认为误报' not in wire['systemMessage']
    assert wire['continue'] is False and documented_posttool_effect(wire)['nested_promise_rejected'] is False
    control = internal_context(wire)['remediation']
    displayed = control['review_finding_ids']
    stored = {finding['id']: finding for finding in engine.store.get_scan(data['scan_id'])['findings']}
    assert len(displayed) == len(set(displayed)) == 3 and set(displayed) < set(stored)
    for finding_id, item in zip(displayed, feedback['items']):
        details = stored[finding_id]['technical_details']
        assert details['package'] in item['title'] and details['package_version'] in item['title']
    navigation = control['review_continuation']
    summary = invoke(server, navigation['tool'], navigation['arguments']).structuredContent
    for finding_id in displayed:
        selected = [task for task in summary['tasks'] if any(
            member['finding_id'] == finding_id for member in task['members'])]
        assert len(selected) == 1 and selected[0]['task_ref'].startswith('task-v1.')
    assert_no_authority(source_sdk, data)


@pytest.mark.parametrize('readonly', [False, True])
def test_cached_or_readonly_event_does_not_reask_dependency_choice(source_sdk, readonly):
    _, _, _, provider, _, _, _ = source_sdk
    first, _ = hook(source_sdk)
    assert first['remediation']['user_feedback']['choices'] == ['修复', '稍后处理']
    data, wire = hook(source_sdk, readonly=readonly)
    assert len(provider.calls) == 1 and data['scanner_run'] is False
    assert not {'continue', 'stopReason'} & wire.keys()
    assert 'remediation' not in data
    assert '回复“修复”' not in wire.get('systemMessage', '') and '“稍后处理”' not in wire.get('systemMessage', '')
    assert_no_authority(source_sdk, data)


@pytest.mark.parametrize('freshness,expected', [
    ('STALE', '本地漏洞数据已经过期'),
    ('UNKNOWN', '无法确认本地漏洞数据的更新时间'),
])
def test_git_dependency_advisory_explains_partial_database_reason_without_authority(
        repo, tmp_path, monkeypatch, freshness, expected):
    engine, provider, _, _ = runtime(tmp_path, dependency_coverage='PARTIAL')
    base_scan = provider.scan

    def scan(context, normalizer):
        _, run = base_scan(context, normalizer)
        found = [normalizer.dependency(scanner=provider.name, package='PyYAML',
            version='5.3.1', ecosystem='pypi', manifest='requirements.txt',
            vulnerability_id='CVE-2020-14343', severity='HIGH')]
        run.finding_count = len(found)
        run.dependency_inventory['vulnerability_db_freshness'] = freshness
        return found, run

    provider.scan = scan
    core = coordinator(tmp_path, engine, repo)
    arguments = claims(repo)
    core.handle('SESSION_START', repo, 'codex', arguments['session_id'], _baseline_only=True)
    manifest = write(repo, 'requirements.txt', 'PyYAML==5.3.1\n')
    unauthorized_calls = []

    def forbidden(*args, **kwargs):
        unauthorized_calls.append(True)
        raise AssertionError('Dependency advisory must never prepare or authorize a fix')

    monkeypatch.setattr(TaskFixService, 'prepare', forbidden)
    monkeypatch.setattr(RemediationService, '_new_episode', forbidden)
    services = []

    def remediation_factory(store, **kwargs):
        service = RemediationService(store, config=RemediationConfig(tmp_path / 'policy.json'),
            directory=tmp_path / 'remediation', **kwargs)
        services.append(service)
        return service

    server = create_server(engine, workspace_binding=workspace_binding(repo), global_mode=False,
        hook_coordinator=core, hook_advisory_only=False, remediation_factory=remediation_factory)
    response = invoke(server, 'handle_hook_event', arguments)
    data = response.structuredContent
    wire = json.loads(response.content[0].text)
    decision = data['remediation']
    assert data['capabilities']['DEPENDENCY_VULN'] == 'PARTIAL'
    assert data['scanner_run'] is True and provider.offline_calls == [True]
    assert decision['action'] == 'ADVISE'
    assert decision['user_feedback']['choices'] == ['修复', '稍后处理']
    assert decision['user_feedback']['secondary_choices'] == ['请复核', '不再提醒此项']
    for item in (expected, 'PyYAML', '5.3.1', '尚未确认', '回复“修复”', '“稍后处理”'):
        assert item in wire['systemMessage']
    assert 'VULNERABILITY_DB_' not in wire['systemMessage'] and freshness not in wire['systemMessage']
    assert wire['continue'] is False and wire['stopReason'] == wire['systemMessage']
    assert documented_posttool_effect(wire)['nested_promise_rejected'] is False
    assert not {'confirmation_ref', 'remediation_ref', 'grant_id', 'episode_id',
                'task_ref', 'prepare', 'verify', 'agent_fix_ticket'} & decision.keys()
    service = services[0]
    assert not service.authorized and not service.prepared and not unauthorized_calls
    assert not list(service.state.directory.rglob('*.json'))
    assert manifest.read_text() == 'PyYAML==5.3.1\n'
