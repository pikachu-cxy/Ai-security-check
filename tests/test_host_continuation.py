"""Stop fallback authority, silence, bounded replay and owned configuration."""
import asyncio
import copy
import json
from pathlib import Path

import pytest

from test_hook_runtime import repo
from test_remediation import setup, args, prepare, FIXED, CANARY
from test_codex_mcp_hook import binding as workspace_binding
from test_codex_integration import adapter, call, config, write
from security_runtime.codex_mcp_hook import codex_hook_output
from security_runtime.codex_integration import REQUIRED_TOOLS, check_capabilities, product_hooks
from security_runtime.host_continuation import HostContinuationGuard, handle_stop_event
from security_runtime.guidance.host_guidance import runtime_info
from security_runtime.integration_lifecycle import IntegrationDiagnostic, render_integration
from security_runtime.remediation import RemediationService


def stop(setup, active=False, **claims):
    root, _, _, service, _, _ = setup
    values = dict(event='Stop', workspace_path=str(root), session_id='session', stop_hook_active=active)
    values.update(claims)
    return handle_stop_event(**values, binding=workspace_binding(root), guard=service.continuation)


def state(setup):
    service = setup[3]; path = service.state.path(setup[0], 'codex', 'session')
    key = service.state.key(setup[0]); rows = service._read(path, key)
    return service, path, key, rows, next(iter(rows.values()))


def test_original_handoff_only_no_execution_or_authority_refresh(setup):
    root, runtime, provider, service, _, grant = setup
    before = len(runtime.calls), len(provider.calls), (root / 'A.java').read_bytes()
    _, path, key, rows, record = state(setup); original = copy.deepcopy(record)
    result = stop(setup)
    assert result['status'] == 'CONTINUATION_REQUIRED' and result['decision'] == 'block'
    assert result['continuation_phase'] == 'AUTO_FIX_PREPARE_REQUIRED'
    assert result['host_continuation_attempt_count'] == 1 and not any(result['execution'].values())
    output = codex_hook_output(result)
    assert set(output) == {'decision', 'reason'}
    assert output['reason'].startswith('SECURITY_AUTO_REMEDIATION_CONTINUATION_REQUIRED.')
    retained = json.loads(output['reason'][output['reason'].index('{'):])
    assert retained == grant['remediation']['prepare'] and retained['arguments'] == args(setup)
    record = next(iter(service._read(path, key).values()))
    assert {k: v for k, v in record.items() if k != 'host_continuation'} == original
    assert before == (len(runtime.calls), len(provider.calls), (root / 'A.java').read_bytes())
    persisted = path.read_text()
    assert args(setup)['remediation_ref'] not in persisted and CANARY not in persisted
    assert str(root) not in persisted and 'setHostnameVerifier' not in persisted


@pytest.mark.parametrize('active', [False, True])
def test_max_two_independent_attempts_false_claim_does_not_reset(setup, active):
    assert stop(setup)['host_continuation_attempt_count'] == 1
    assert stop(setup, active)['host_continuation_attempt_count'] == 2
    assert stop(setup, active)['status'] == 'HOST_CONTINUATION_EXHAUSTED'
    _, path, _, _, record = state(setup)
    assert record['attempt_count'] == 1
    assert record['host_continuation']['attempt_count'] == 2
    assert record['host_continuation']['status'] == 'HOST_CONTINUATION_EXHAUSTED'
    before = path.read_bytes(), path.stat().st_mtime_ns
    for _ in range(100):
        assert codex_hook_output(stop(setup, active)) == {}
    assert before == (path.read_bytes(), path.stat().st_mtime_ns)


def test_stop_already_active_without_our_attempt_does_not_join_foreign_loop(setup):
    _, path, _, _, _ = state(setup); before = path.read_bytes()
    assert stop(setup, True)['status'] == 'STOP_ALREADY_ACTIVE'
    assert before == path.read_bytes()


def test_successful_prepare_ends_old_phase_without_edit_stage_continuation(setup):
    assert stop(setup)['decision'] == 'block'
    assert prepare(setup)['status'] == 'READY_FOR_HOST_FIX'
    assert codex_hook_output(stop(setup, True)) == {}
    assert stop(setup)['continuation_phase'] == 'NONE'


def test_existing_legitimate_retry_grant_has_its_own_bound_counter(setup):
    from test_remediation import UNSAFE
    assert stop(setup)['host_continuation_attempt_count'] == 1
    assert prepare(setup)['status'] == 'READY_FOR_HOST_FIX'
    (setup[0] / 'A.java').write_text(UNSAFE + '// attempted repair one\n')
    retry = setup[4]()
    assert retry['remediation']['attempt_count'] == 2 and retry['remediation']['action'] == 'AUTO_FIX'
    result = stop(setup)
    assert result['host_continuation_attempt_count'] == 1 and result['decision'] == 'block'
    retained = json.loads(result['reason'][result['reason'].index('{'):])
    assert retained == retry['remediation']['prepare'] and retained != setup[-1]['remediation']['prepare']


@pytest.mark.parametrize('phase,action', [('CLOSED', 'NONE'), ('ESCALATED', 'ESCALATE'), ('DECLINED', 'NONE'),
    ('EXPIRED', 'ADVISE'), ('PENDING_CONFIRMATION', 'CONFIRM_REQUIRED'), ('OFFERED', 'MANUAL_ONLY'),
    ('OFFERED', 'ADVISE'), ('OFFERED', 'NONE')])
def test_non_auto_and_terminal_states_quiet(setup, phase, action):
    service, path, key, rows, record = state(setup)
    record.update(phase=phase, last_action=action); service._save(path, rows, key)
    assert codex_hook_output(stop(setup)) == {}
    assert 'host_continuation' not in state(setup)[-1]


@pytest.mark.parametrize('setup', ['ask_before_fix', 'report_only'], indirect=True)
def test_confirmation_and_report_only_cannot_continue(setup):
    assert setup[-1]['remediation']['action'] != 'AUTO_FIX'
    assert stop(setup)['status'] == 'ALLOW_STOP'
    assert codex_hook_output(stop(setup)) == {} and not setup[3].prepared


def test_old_policy_auto_grant_excluded_even_when_action_auto(setup):
    service, path, key, rows, record = state(setup)
    record.update(authorization_kind='POLICY_AUTO', phase='OFFERED')
    service._save(path, rows, key)
    assert codex_hook_output(stop(setup)) == {}


@pytest.mark.parametrize('mutation', ['mode', 'policy-revision', 'snapshot', 'source', 'task', 'scan', 'family',
    'host', 'session', 'token', 'signature', 'key', 'expired-window', 'malformed-counter'])
def test_authority_changes_fail_closed_without_new_grant(setup, mutation):
    service, path, key, rows, record = state(setup)
    if mutation == 'mode': service.config.write('report_only')
    elif mutation == 'policy-revision': service.config.write('smart_auto')
    elif mutation == 'snapshot': (setup[0] / 'Other.java').write_text('class Other {}')
    elif mutation == 'source': (setup[0] / 'A.java').write_text(FIXED)
    elif mutation == 'signature': path.write_text(path.read_text().replace('"mac": "', '"mac": "0', 1))
    elif mutation == 'key': (path.parent / 'snapshot.key').write_bytes(b'x' * 31)
    elif mutation == 'expired-window': next(iter(service.continuation.handoffs.values()))['deadline'] = 0
    else:
        field = {'task': 'task_ref', 'scan': 'origin_scan_id', 'family': 'family_key', 'host': 'host_id',
                 'session': 'session_id', 'token': 'token_hash'}.get(mutation)
        if field: record[field] = 'changed'
        else: record['host_continuation'] = {'attempt_count': True}
        service._save(path, rows, key)
    before = path.read_bytes()
    assert codex_hook_output(stop(setup)) == {}
    assert before == path.read_bytes()


def test_connection_loss_never_recovers_or_reissues_token(setup):
    service = setup[3]
    stop(setup)
    restart = RemediationService(service.store, registry=service.registry, hooks=service.hooks)
    assert restart.continuation.handle(setup[0], 'session', False)['status'] == 'ALLOW_STOP'
    assert not restart.continuation.handoffs


def test_no_remediation_100_stops_silent_without_state_creation(repo, tmp_path):
    service = RemediationService(directory=tmp_path / 'unused')
    for _ in range(100):
        result = handle_stop_event('Stop', str(repo), 's', False,
                                  binding=workspace_binding(repo), guard=service.continuation)
        assert codex_hook_output(result) == {} and not any(result['execution'].values())
    assert not service.state.directory.exists()


@pytest.mark.parametrize('claims', [dict(event='PostToolUse'), dict(event=''), dict(workspace_path='../outside'),
    dict(workspace_path='//host/share'), dict(workspace_path='${cwd}'), dict(session_id=''),
    dict(session_id='x' * 501), dict(session_id='secret\ncanary'), dict(session_id=4),
    dict(stop_hook_active='false'), dict(stop_hook_active=0)])
def test_invalid_claims_do_not_continue_or_echo(setup, claims):
    result = stop(setup, **claims)
    assert result['status'] == 'INCONCLUSIVE' and codex_hook_output(result) == {}
    assert 'canary' not in json.dumps(result)


def test_unbound_foreign_workspace_and_foreign_session_rejected(setup, tmp_path):
    assert codex_hook_output(stop(setup, session_id='foreign-session')) == {}
    assert stop(setup, workspace_path=str(tmp_path))['status'] == 'INCONCLUSIVE'
    assert handle_stop_event('Stop', str(setup[0]), 'session', False,
        binding=None, guard=setup[3].continuation)['status'] == 'INCONCLUSIVE'


def test_symlink_workspace_claim_rejected(setup, tmp_path):
    link = setup[0] / 'link'; outside = tmp_path / 'outside'; outside.mkdir()
    from link_fixture import linked_directory
    linked_directory(link,outside)
    assert stop(setup, workspace_path=str(link))['status'] == 'INCONCLUSIVE'


def test_mcp_registration_strict_four_claims_no_echo(monkeypatch, tmp_path):
    monkeypatch.delenv('SECURITY_RUNTIME_WORKSPACE', raising=False)
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    from security_runtime.mcp_server import create_server
    server = create_server()
    tools = asyncio.run(server.list_tools()); tool = next(t for t in tools if t.name == 'handle_stop_event')
    assert tool.inputSchema['additionalProperties'] is False
    required = {'event', 'workspace_path', 'session_id', 'stop_hook_active'}
    assert set(tool.inputSchema['properties']) == required | {'turn_id', 'permission_mode'}
    assert set(tool.inputSchema['required']) == required
    assert tool.inputSchema['properties']['stop_hook_active']['type'] == 'boolean'
    valid = dict(event='Stop', workspace_path='x', session_id='s', stop_hook_active=False)
    async def check():
        for bad in [{}, {**valid, 'stop_hook_active': 'false'}, {**valid, 'action': 'AUTO_FIX'},
                    {**valid, 'remediation_ref': 'secret-canary'}, {**valid, 'source': 'secret-canary'}]:
            with pytest.raises(Exception) as error:
                await server.call_tool('handle_stop_event', bad)
            assert 'secret-canary' not in str(error.value)
        response = await server.call_tool('handle_stop_event', valid)
        assert response.content[0].text == '{}'
    asyncio.run(check())


def test_lifecycle_stop_add_repair_remove_preserves_foreign(adapter, repo):
    foreign = {'hooks': [{'type': 'command', 'command': 'keep'}]}
    write(repo, hooks={'hooks': {'Stop': [foreign]}})
    assert call(adapter, repo)['operation'] == 'CONFIGURED'
    _, path = config(repo)
    value = json.loads(path.read_bytes())
    assert value['hooks']['Stop'] == [foreign, *product_hooks()['hooks']['Stop']]
    value['hooks']['Stop'] = [foreign]; path.write_text(json.dumps(value))
    assert call(adapter, repo, 'status')['overall'] == 'DEGRADED'
    assert call(adapter, repo, 'repair')['operation'] == 'REPAIRED'
    before = path.read_bytes(), path.stat().st_mtime_ns
    assert call(adapter, repo)['operation'] == 'ALREADY_CONFIGURED'
    assert before == (path.read_bytes(), path.stat().st_mtime_ns)
    assert call(adapter, repo, 'remove')['operation'] == 'REMOVED'
    assert json.loads(path.read_bytes()) == {'hooks': {'Stop': [foreign]}}


def test_upgrade_signed_two_event_manifest_safely_adds_stop(adapter, repo, monkeypatch):
    import security_runtime.codex_integration as module
    generate = module.product_hooks
    def old():
        value = generate(); del value['hooks']['Stop']; return value
    monkeypatch.setattr(module, 'product_hooks', old)
    assert call(adapter, repo)['operation'] == 'CONFIGURED'
    assert set(adapter._manifest(repo)['records'][0]['hooks']) == {'SessionStart', 'PostToolUse'}
    monkeypatch.setattr(module, 'product_hooks', generate)
    assert call(adapter, repo)['operation'] == 'CONFIGURED'
    assert set(adapter._manifest(repo)['records'][0]['hooks']) == {'SessionStart', 'PostToolUse', 'Stop'}


@pytest.mark.parametrize('bad', [{'hooks': {'Stop': {}}}, {'hooks': {'Stop': [{'hooks': [{}]}]}},
    {'hooks': {'Stop': [{'hooks': 'not-array'}]}}])
def test_malformed_stop_config_fail_closed(adapter, repo, bad):
    write(repo, hooks=bad); before = config(repo)[1].read_bytes()
    assert call(adapter, repo)['overall'] == 'BROKEN'
    assert before == config(repo)[1].read_bytes()


def test_old_runtime_missing_stop_capability_rejected():
    with pytest.raises(IntegrationDiagnostic, match='CAPABILITY_MISMATCH'):
        check_capabilities(runtime_info(), REQUIRED_TOOLS - {'handle_stop_event'})


def test_failed_prepare_does_not_count_as_progress(setup, monkeypatch):
    from security_runtime.tasks.fix import TaskFixService
    monkeypatch.setattr(TaskFixService, 'prepare', lambda *a, **k: {'status': 'INCONCLUSIVE'})
    assert prepare(setup)['status'] == 'INCONCLUSIVE'
    assert stop(setup)['decision'] == 'block' and not setup[3].prepared


def test_retain_same_handoff_cannot_reset_signed_continuation_budget(setup):
    service, path, _, _, record = state(setup)
    stop(setup); stop(setup, True); stop(setup, True)
    service.continuation = HostContinuationGuard(service)
    service.continuation.remember(path, record, record['last_snapshot_digest'], args(setup))
    assert stop(setup)['status'] == 'HOST_CONTINUATION_EXHAUSTED'


def test_secret_in_claim_exception_not_in_result_or_hook_text(setup, monkeypatch):
    service = setup[3]
    monkeypatch.setattr(service, '_member_current', lambda *a: (_ for _ in ()).throw(ValueError(CANARY)))
    data = stop(setup)
    assert data['status'] == 'INCONCLUSIVE' and codex_hook_output(data) == {}
    assert CANARY not in json.dumps(data)


def test_cli_readiness_observation_only_does_not_recommend_repair(adapter, repo):
    call(adapter, repo)
    value = call(adapter, repo, 'status')
    assert value['readiness']['status'] == 'READINESS_NOT_OBSERVED'
    assert 'integration repair' not in render_integration(value)
    assert 'No repair or warm-up' in render_integration(value)
    _, path = config(repo); path.unlink()
    assert 'integration repair' in render_integration(call(adapter, repo, 'status'))
