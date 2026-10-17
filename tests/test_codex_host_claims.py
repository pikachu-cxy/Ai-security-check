"""Official-shaped structured claims, routing, replay and safe diagnostics."""
import asyncio
import copy
import json
import tomllib

import pytest

from security_runtime.codex_host_claims import CodexClaimGuard, diagnostics
from security_runtime.codex_integration import product_hooks
from security_runtime.global_mcp import create_global_server
from security_runtime.mcp_server import create_server
from test_codex_mcp_hook import binding
from test_global_integration import installed, projects, ready, pool_fixture, structured, complete_runtime
from test_hook_runtime import repo, dirty, coordinator


def claims(root, call='call-1', **changes):
    return dict(event='PostToolUse', workspace_path=str(root), session_id='s',
                turn_id='turn-1', tool_use_id=call, tool_name='Bash',
                permission_mode='default', tool_input={'command': 'git status'}, **changes)


def invoke(server, args):
    return structured(asyncio.run(server.call_tool('handle_hook_event', args)))


def test_global_stop_never_bootstraps_or_scans_and_rejection_is_quiet(connected, projects, monkeypatch):
    server, pool, runtimes = connected
    root = projects[0]
    monkeypatch.setattr(pool, 'bootstrap', lambda *a, **k: pytest.fail('ordinary Stop cannot bootstrap'))
    monkeypatch.setattr(runtimes[root], 'scan', lambda *a, **k: pytest.fail('ordinary Stop cannot scan'))
    for i in range(5):
        response = asyncio.run(server.call_tool('handle_stop_event', dict(event='Stop', workspace_path=str(root),
                    session_id='s', stop_hook_active=False, turn_id=f'chat-{i}')))
        assert structured(response)['status'] == 'ALLOW_STOP'
        assert json.loads(response.content[0].text) == {}
    response = asyncio.run(server.call_tool('handle_stop_event', dict(event='Stop', workspace_path='${cwd}',
                  session_id='s', stop_hook_active=False)))
    assert structured(response)['status'] == 'INCONCLUSIVE'
    assert json.loads(response.content[0].text) == {}


@pytest.fixture
def connected(installed, projects, tmp_path):
    runtimes = {}
    def factory(root, directory, bound):
        runtime = complete_runtime(); runtimes[root] = runtime
        core = coordinator(directory, runtime, cooldown_ms=0)
        return create_server(runtime, hook_coordinator=core, workspace_binding=bound,
                             global_mode=False, hook_advisory_only=True), core
    pool = pool_fixture(installed, tmp_path, factory)
    try:
        ready(pool, projects[0], 's')
        yield create_global_server(workspaces=pool), pool, runtimes
    finally:
        pool.close()


@pytest.mark.parametrize('field', ['session_id', 'workspace_path', 'turn_id', 'tool_use_id', 'tool_name'])
def test_missing_required_claims_named_before_admission(connected, projects, field):
    server, pool, runtimes = connected
    args = claims(projects[0]); del args[field]
    before = len(runtimes[projects[0]].calls)
    out = invoke(server, args)
    assert out['reason_code'] == 'INVALID_HOST_CLAIMS'
    assert out['host_claim_status'] == 'INVALID' and field in out['missing_claims']
    assert not out['scanner_run'] and len(runtimes[projects[0]].calls) == before
    assert not pool.claim_guard.invocations


@pytest.mark.parametrize('field,value', [('turn_id', '${turn_id}'), ('tool_use_id', ''),
    ('session_id', 'bad\nclaim'), ('permission_mode', 'unknown'), ('permission_mode', {}),
    ('tool_input', 'unexpanded-or-stringified-input'), ('tool_name', 'exec_command')])
def test_invalid_claims_report_fixed_field_names(connected, projects, field, value):
    server, _, _ = connected
    args = claims(projects[0]); args[field] = value
    out = invoke(server, args)
    assert out['reason_code'] == 'INVALID_HOST_CLAIMS'
    assert field in out['invalid_claims'] and out['host_claim_status'] == 'INVALID'
    assert not out['scanner_run']


def test_unexpected_claim_name_and_value_not_reflected(connected, projects):
    server, _, _ = connected
    marker = 'synthetic-private-marker'
    args = claims(projects[0]); args[marker] = marker
    out = invoke(server, args)
    assert out['invalid_claims'] == ['unexpected_fields']
    assert marker not in json.dumps(out)


def test_read_only_valid_claims_skip_scanner(connected, projects):
    server, _, runtimes = connected
    before = len(runtimes[projects[0]].calls)
    out = invoke(server, claims(projects[0]))
    assert out['host_claim_status'] == 'VALID'
    assert out['workspace_claim_match'] and out['session_claim_match']
    assert out['turn_claim_present'] and out['tool_use_claim_present']
    assert out['tool_classification'] == 'READ_ONLY' and not out['scanner_run']
    assert len(runtimes[projects[0]].calls) == before


@pytest.mark.parametrize('tool', ['Bash', 'apply_patch'])
def test_valid_mutation_reaches_existing_coordinator(connected, projects, tool):
    server, _, runtimes = connected
    root = projects[0]
    args = claims(root); args.update(tool_name=tool, tool_input={'command': 'Set-Content src/A.java fixture'})
    (root/'src/A.java').write_text('class A { int n; }\n')
    out = invoke(server, args)
    assert out['host_claim_status'] == 'VALID' and out['scanner_run'], out
    assert out['workspace_mutation_observed'] and out['changed_file_count'] == 1
    assert runtimes[root].calls[-1] == ('src/A.java',)
    assert 'remediation' not in out  # advisory-only fixture; no Deep capability used


@pytest.mark.parametrize('change', [{}, {'turn_id': 'turn-2'}, {'session_id': 's-2'}, {'tool_name': 'Write'},
    {'session_id': 's-2', 'tool_input': {'command': 'Set-Content src/A.java fixture'}}])
def test_tool_use_replay_rejected_even_under_changed_turn_or_session(connected, projects, change):
    server, pool, runtimes = connected
    args = claims(projects[0]); assert invoke(server, args)['host_claim_status'] == 'VALID'
    before = len(runtimes[projects[0]].calls)
    jobs_before = set(pool.jobs)
    out = invoke(server, {**args, **change})
    assert out['reason_code'] == 'TOOL_USE_CLAIM_REPLAYED'
    assert out['host_claim_status'] == 'REJECTED' and not out['scanner_run']
    assert len(runtimes[projects[0]].calls) == before
    assert set(pool.jobs) == jobs_before  # reject before classification/bootstrap


def test_session_workspace_mismatch_rejected_for_read_only(connected, projects):
    server, _, _ = connected
    out = invoke(server, claims(projects[1]))
    assert out['reason_code'] == 'SESSION_WORKSPACE_MISMATCH'
    assert out['session_claim_match'] is False and not out['scanner_run']


def test_invalid_workspace_rejected_before_readonly_shortcut(connected, projects):
    server, _, _ = connected
    args = claims(projects[0]); args['workspace_path'] = '.'
    out = invoke(server, args)
    assert out['workspace_claim_match'] is False and not out['scanner_run']


def test_project_readonly_foreign_claim_rejected(repo, tmp_path):
    runtime = complete_runtime()
    server = create_server(runtime, workspace_binding=binding(repo),
                           hook_coordinator=coordinator(tmp_path, runtime), global_mode=False)
    out = invoke(server, claims(tmp_path))
    assert out['reason'] == 'HOST_CLAIMS_REJECTED'
    assert out['workspace_claim_match'] is False and not runtime.calls


def test_sessionstart_stop_have_their_own_schemas(connected, projects):
    server, _, _ = connected
    args = dict(event='SessionStart', workspace_path=str(projects[0]), session_id='s', permission_mode='default')
    start = structured(asyncio.run(server.call_tool('handle_readiness_event', args)))
    assert start['status'] == 'READY' and start['host_claim_status'] == 'VALID'
    stop = structured(asyncio.run(server.call_tool('handle_stop_event', {
        **args, 'event': 'Stop', 'turn_id': 'turn-1', 'stop_hook_active': False})))
    assert stop['status'] == 'ALLOW_STOP' and stop['host_claim_status'] == 'VALID'
    assert not stop['tool_use_claim_present']
    schema = {t.name: t.inputSchema for t in asyncio.run(server.list_tools())}
    assert 'tool_use_id' not in schema['handle_readiness_event']['properties']
    assert 'tool_use_id' not in schema['handle_stop_event']['properties']
    assert {'turn_id', 'tool_use_id'} <= set(schema['handle_hook_event']['required'])


def test_claim_guard_bounded_hashes_only_and_restart():
    args = claims('/project')
    guard = CodexClaimGuard(limit=1)
    diag = diagnostics(args, 'PostToolUse')
    assert guard.accept(args, '/project', diag) is None
    assert 'call-1' not in json.dumps(guard.invocations)
    next_args = {**args, 'tool_use_id': 'call-2'}
    assert guard.accept(next_args, '/project', diag) == 'HOST_CLAIM_BUDGET_EXCEEDED'
    assert CodexClaimGuard().accept(args, '/project', diagnostics(args, 'PostToolUse')) is None


def test_temporary_home_upgrade_preserves_host_state_and_is_idempotent(installed, projects, monkeypatch, tmp_path):
    home = installed.home; home.mkdir()
    original = b'# user owned\nmodel="fixture"\n[hooks.state.fixture]\nenabled=true\ntrusted_hash="unchanged"\n[mcp_servers.node_repl]\ncommand="node"\n[custom]\nflag=true\n'
    config = home/'config.toml'; config.write_bytes(original)
    user = {'hooks': {'PostToolUse': [{'matcher': '^Other$', 'hooks': [{'type':'command', 'command':'user-fixture'}]}]}}
    hooks = home/'hooks.json'; hooks.write_text(json.dumps(user))
    import security_runtime.global_integration as module
    current = product_hooks()
    legacy = copy.deepcopy(current)
    for key in ('turn_id', 'tool_use_id', 'permission_mode'):
        legacy['hooks']['PostToolUse'][0]['hooks'][0]['input'].pop(key)
    with monkeypatch.context() as patch:
        patch.setattr(module, 'product_hooks', lambda: copy.deepcopy(legacy))
        assert installed.execute('setup')['overall'] == 'CONFIGURED'
    assert installed.execute('repair')['overall'] == 'CONFIGURED'
    after = (config.read_bytes(), hooks.read_bytes())
    generated = json.loads(after[1])
    managed = [h for g in generated['hooks']['PostToolUse'] for h in g['hooks'] if h.get('server') == 'ai_security_runtime']
    assert len(managed) == 1
    assert managed[0]['input'] == current['hooks']['PostToolUse'][0]['hooks'][0]['input']
    assert config.read_bytes().startswith(original)
    assert tomllib.loads(config.read_text())['hooks']['state']['fixture']['trusted_hash'] == 'unchanged'
    assert installed.execute('setup')['overall'] == 'CONFIGURED'
    assert installed.execute('repair')['overall'] == 'CONFIGURED'
    assert after == (config.read_bytes(), hooks.read_bytes())
    assert user['hooks']['PostToolUse'][0] in generated['hooks']['PostToolUse']
    assert installed.execute('uninstall')['overall'] == 'NOT_INSTALLED'
    assert config.read_bytes() == original
    assert json.loads(hooks.read_bytes()) == user
    (tmp_path/'generated-hooks.json').write_bytes(after[1])
