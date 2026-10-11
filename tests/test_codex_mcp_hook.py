import asyncio
import json
import os
import sys
import tempfile
import itertools
from pathlib import Path

import pytest

from security_runtime.codex_mcp_hook import codex_hook_output, codex_mcp_hook_config, handle_codex_hook
from security_runtime.hook_adapters import run_host_event
from security_runtime.integration_state import WorkspaceBinding
from security_runtime.mcp_server import create_server
from test_hook_runtime import FakeRuntime, coordinator, dirty, repo, row
from hook_feedback_test_helpers import internal_context


_tool_calls = itertools.count()

def claims(root):
    return dict(event='PostToolUse', workspace_path=str(root), session_id='poc-session',
                tool_name='apply_patch', turn_id='fixture-turn', tool_use_id=f'fixture-call-{next(_tool_calls)}')


def binding(root):
    return WorkspaceBinding.create(root, 'generic-mcp')


def test_poc_config_only_posttooluse_and_metadata(capsys):
    from security_runtime.cli import main
    assert main(['hooks', 'generate-mcp-poc', 'codex', '--json']) == 0
    config = json.loads(capsys.readouterr().out)
    assert config == codex_mcp_hook_config()
    assert set(config['hooks']) == {'PostToolUse'}
    group = config['hooks']['PostToolUse'][0]
    assert group['matcher'] == '^(Bash|apply_patch|Edit|Write)$'
    handler = group['hooks'][0]
    assert handler == dict(type='mcp_tool', server='ai_security_runtime', tool='handle_hook_event',
        input=dict(event='${hook_event_name}', workspace_path='${cwd}',
                   session_id='${session_id}', tool_name='${tool_name}',
                   turn_id='${turn_id}', tool_use_id='${tool_use_id}', permission_mode='${permission_mode}',
                   tool_input='${tool_input}'),
        timeout=120, statusMessage='AI Security Runtime [mcp-hook-poc]')
    assert 'command' not in handler


@pytest.mark.parametrize('argv', [['hooks', 'generate-mcp-poc', 'cursor'],
    ['hooks', 'generate-mcp-poc', 'codex', '--path', '.']])
def test_generator_rejects_other_hosts_or_install_path(argv, capsys):
    from security_runtime.cli import main
    assert main(argv) == 2


def test_mcp_registration_schema_and_output(repo, tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', str(repo))
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    runtime = FakeRuntime()
    dirty(repo)
    server = create_server(runtime)
    async def run():
        tools = {tool.name: tool for tool in await server.list_tools()}
        tool = tools['handle_hook_event']
        from security_runtime.host_guidance import REQUIRED_GUIDANCE_TOOLS
        assert REQUIRED_GUIDANCE_TOOLS <= set(tools)
        assert set(tool.inputSchema['required']) == set(claims(repo))
        assert set(tool.inputSchema['properties']) == set(claims(repo)) | {'tool_input', 'permission_mode'}
        assert tool.inputSchema['additionalProperties'] is False
        assert all(value['type'] == 'string' for key, value in tool.inputSchema['properties'].items()
                   if key not in {'tool_input', 'permission_mode'})
        assert not tool.annotations.readOnlyHint and not tool.annotations.openWorldHint
        response = await server.call_tool('handle_hook_event', claims(repo))
        data = response.structuredContent
        assert data['scanner_run'] and data['status'] == 'BASELINE_ESTABLISHED'
        assert data['new_families'] == 0 and len(runtime.calls) == 1
        output = json.loads(response.content[0].text)
        assert output == codex_hook_output(data)
        assert set(output) == {'systemMessage', 'hookSpecificOutput'}
        assert output['hookSpecificOutput']['hookEventName'] == 'PostToolUse'
        context = internal_context(output)
        assert context['status'] == data['status'] and 'duration_ms' not in context
        assert data['duration_ms'] >= 0  # complete diagnostics stay structured
    asyncio.run(run())


@pytest.mark.parametrize('change', [dict(event='Stop'), dict(event='FILE_CHANGED'),
    dict(session_id=''), dict(session_id='${session_id}'), dict(session_id='x'*501),
    dict(session_id='bad\nclaim'), dict(tool_name='Other'), dict(workspace_path='.'),
    dict(workspace_path='${cwd}')])
def test_invalid_claims_inconclusive_without_scanning(repo, tmp_path, change):
    runtime = FakeRuntime()
    result = handle_codex_hook(**(claims(repo) | change), binding=binding(repo),
                               coordinator=coordinator(tmp_path, runtime))
    assert result['status'] == 'INCONCLUSIVE' and not result['scanner_run']
    assert result['coverage'] == 'UNKNOWN' and not runtime.calls


def test_missing_binding_cannot_scan(repo, tmp_path):
    runtime = FakeRuntime()
    result = handle_codex_hook(**claims(repo), binding=None, coordinator=coordinator(tmp_path, runtime))
    assert result['reason'] == 'WORKSPACE_BINDING_REQUIRED' and not runtime.calls


@pytest.mark.parametrize('command', ['git status', 'Get-Content src/A.java', 'rg danger src'])
def test_bash_read_only_skips_scanner(repo, tmp_path, command):
    runtime = FakeRuntime()
    result = handle_codex_hook(**(claims(repo) | {'tool_name': 'Bash', 'tool_input': {'command': command}}),
                               binding=binding(repo), coordinator=coordinator(tmp_path, runtime))
    assert result['status'] == 'NOT_SCANNED'
    assert result['tool_classification'] == 'READ_ONLY'
    assert not result['scanner_run'] and not runtime.calls


def test_bash_mutation_and_unknown_are_scanned(repo, tmp_path):
    for tool_input, classification in ({'command': 'Set-Content x.java value'}, 'POSSIBLE_WORKSPACE_MUTATION'), ({'command': 'make'}, 'UNKNOWN'):
        runtime = FakeRuntime()
        state_root = tmp_path / classification
        state_root.mkdir()
        dirty(repo, 'bash-change\n')
        result = handle_codex_hook(**(claims(repo) | {'tool_name': 'Bash', 'tool_input': tool_input}),
                                   binding=binding(repo), coordinator=coordinator(state_root, runtime))
        assert result['tool_classification'] == classification
        assert len(runtime.calls) == 1, result


@pytest.mark.parametrize('foreign', ['parent', 'unc'])
def test_foreign_claim_is_rejected_before_filesystem_or_git_probe(repo, tmp_path, monkeypatch, foreign):
    root_binding = binding(repo)
    from security_runtime.workspace import WorkspaceResolver
    def no_probe(*args, **kwargs):
        pytest.fail('Foreign host claim must not be resolved/probed')
    monkeypatch.setattr(WorkspaceResolver, 'resolve', no_probe)
    value = str(repo/'..'/'outside') if foreign == 'parent' else '//untrusted-server.invalid/share/project'
    runtime = FakeRuntime()
    result = handle_codex_hook(**(claims(repo) | dict(workspace_path=value)),
        binding=root_binding, coordinator=coordinator(tmp_path, runtime))
    assert result['status'] == 'INCONCLUSIVE' and not runtime.calls


def test_foreign_workspace_and_subdirectory_binding(repo, tmp_path):
    runtime = FakeRuntime()
    c = coordinator(tmp_path, runtime)
    root_binding = binding(repo)
    rejected = handle_codex_hook(**(claims(repo) | dict(workspace_path=str(tmp_path))),
                                 binding=root_binding, coordinator=c)
    assert rejected['status'] == 'INCONCLUSIVE' and not runtime.calls
    subdir = repo/'src'; subdir.mkdir()
    accepted = handle_codex_hook(**(claims(repo) | dict(workspace_path=str(subdir))),
                                 binding=root_binding, coordinator=c)
    assert accepted['status'] != 'INCONCLUSIVE'


def test_symlink_workspace_rejected(repo, tmp_path):
    alias = tmp_path/'alias'
    try:
        alias.symlink_to(repo, target_is_directory=True)
    except OSError:
        pytest.skip('Creating directory symlinks is unavailable')
    runtime = FakeRuntime()
    rejected = handle_codex_hook(**(claims(repo) | dict(workspace_path=str(alias))),
                                 binding=binding(repo), coordinator=coordinator(tmp_path, runtime))
    assert rejected['status'] == 'INCONCLUSIVE' and not runtime.calls


def test_transport_reuses_core_multiset_cooldown_and_command_state(repo, tmp_path):
    runtime = FakeRuntime()
    now = [1000]
    c = coordinator(tmp_path, runtime, clock=lambda: now[0])
    def call():
        return handle_codex_hook(**claims(repo), binding=binding(repo), coordinator=c)
    dirty(repo)
    assert call()['status'] == 'BASELINE_ESTABLISHED'
    runtime.findings = [row(repo, 100)]
    dirty(repo, 'danger\n')
    assert call()['debounced'] and len(runtime.calls) == 1
    now[0] += 2
    assert call()['new_families'] == 1
    runtime.findings = [row(repo, 110)]
    dirty(repo, '\n'*10+'danger\n'); now[0] += 2
    moved = call()
    assert moved['persisting_families'] == 1 and moved['new_families'] == moved['resolved_families'] == 0
    runtime.findings.append(row(repo, 300))
    dirty(repo, 'two\n'); now[0] += 2
    assert call()['additional_occurrences'] == 1
    runtime.findings = runtime.findings[:1]
    dirty(repo, 'one\n'); now[0] += 2
    removed = call()
    assert removed['removed_occurrences'] == 1 and removed['resolved_families'] == 0
    runtime.findings = []
    dirty(repo, 'safe\n'); now[0] += 2
    assert call()['resolved_families'] == 1
    count = len(runtime.calls)
    command = run_host_event(dict(hook_event_name='PostToolUse', cwd=str(repo),
        session_id='poc-session', tool_name='apply_patch'), repo, 'codex', c)
    reused = call()
    assert reused['reused'] and not reused['scanner_run'] and len(runtime.calls) == count
    assert json.loads(command['hookSpecificOutput']['additionalContext'])['status'] == reused['status']


def test_secret_and_claims_do_not_enter_mcp_output_or_state(repo, tmp_path):
    secret = 'synthetic_private_credential_do_not_echo'
    dirty(repo, secret)
    runtime = FakeRuntime([row(repo, category='secret', evidence=secret)])
    c = coordinator(tmp_path, runtime)
    data = handle_codex_hook(**(claims(repo) | dict(session_id=secret)), binding=binding(repo), coordinator=c)
    assert secret not in json.dumps(data)
    assert 'families' not in data and 'findings' not in data
    for path in (tmp_path/'state').rglob('*'):
        if path.is_file():
            assert secret.encode() not in path.read_bytes()
    c.handle = lambda *args: (_ for _ in ()).throw(ValueError(secret))
    failed = handle_codex_hook(**claims(repo), binding=binding(repo), coordinator=c)
    assert secret not in json.dumps(failed) and failed['status'] == 'INCONCLUSIVE'


@pytest.mark.parametrize('arguments', [{}, dict(event=123, workspace_path='secret123', session_id='s', tool_name='apply_patch'),
    dict(event='PostToolUse', workspace_path='not-a-path', session_id='s', tool_name='apply_patch', source_code='secret123'),
    dict(event='PostToolUse', workspace_path='not-a-path', session_id={'secret': 'secret123'}, tool_name='apply_patch')])
def test_sdk_rejects_missing_wrong_type_or_extra_input_without_echo(arguments, monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_WORKSPACE', raising=False)
    server = create_server(FakeRuntime())
    async def run():
        with pytest.raises(Exception) as error:
            await server.call_tool('handle_hook_event', arguments)
        assert 'secret123' not in str(error.value)
    asyncio.run(run())


def test_real_stdio_mcp_transport_redacted_and_no_change(repo, tmp_path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    secret = 'syntheticSecretNeverInHookTransport123'
    dirty(repo, '// '+secret+'\nclass A {}\n')
    env = dict(os.environ, SECURITY_RUNTIME_WORKSPACE=str(repo),
        SECURITY_RUNTIME_STATE_DIR=str(tmp_path/'stdio-state'), SECURITY_RUNTIME_OFFLINE='1',
        SECURITY_RUNTIME_MCP_SELF_TEST='1', PYTHONUTF8='1')
    async def run():
        params = StdioServerParameters(command=sys.executable, args=['-m', 'security_runtime.cli', 'mcp'],
                                       cwd=repo, env=env)
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as stderr:
            async with stdio_client(params, errlog=stderr) as (read, write):
                async with ClientSession(read, write) as client:
                    await asyncio.wait_for(client.initialize(), 20)
                    assert 'handle_hook_event' in {t.name for t in (await client.list_tools()).tools}
                    first = await client.call_tool('handle_hook_event', claims(repo))
                    assert not first.isError and first.structuredContent['status'] == 'BASELINE_ESTABLISHED'
                    repeat = await client.call_tool('handle_hook_event', claims(repo))
                    assert not repeat.isError and repeat.structuredContent['reused']
                    assert not repeat.structuredContent['scanner_run']
                    bad = await client.call_tool('handle_hook_event', claims(repo) | dict(tool_response=secret))
                    assert bad.isError
                    missing = await client.call_tool('handle_hook_event', {})
                    assert missing.isError
                    assert secret not in json.dumps([r.model_dump() for r in (first, repeat, bad, missing)])
            stderr.seek(0)
            assert secret not in stderr.read()
    asyncio.run(run())
