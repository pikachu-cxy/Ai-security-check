"""WorkBuddy native events reuse checks, session ownership and Stop budgets."""
import json
from pathlib import Path
from types import SimpleNamespace
import pytest

from test_development_check import check
from security_runtime.workbuddy_hook import handle
from security_runtime.workbuddy_integration import WorkBuddyConnectorInstallation, hook_command, workbuddy_config_dir
from security_runtime.tasks.ownership import verify_session_ref, session_owner
from security_runtime.development_check import DevelopmentCheckService
from security_runtime.hook_runtime import HookCoordinator


def event(root, name, **fields):
    return dict(dict(cwd=str(root), session_id='wb-chat', generation_id='turn-one', hook_event_name=name), **fields)


@pytest.mark.parametrize('directories,wb_env,cb_env,explicit,expected', [
    ([], '', '', None, '.workbuddy'),
    (['.workbuddy'], '', '', None, '.workbuddy'),
    (['.workbuddy-ai'], '', '', None, '.workbuddy-ai'),
    (['.workbuddy', '.workbuddy-ai'], '', '', None, '.workbuddy-ai'),
    (['.workbuddy-ai'], 'custom-wb', 'custom-cb', None, 'custom-wb'),
    (['.workbuddy-ai'], '   ', 'custom-cb', None, 'custom-cb'),
    (['.workbuddy-ai'], 'custom-wb', 'custom-cb', 'explicit', 'explicit'),
])
def test_config_dir_selection(tmp_path, monkeypatch, directories, wb_env, cb_env, explicit, expected):
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: tmp_path))
    monkeypatch.setenv('WORKBUDDY_CONFIG_DIR', str(tmp_path/wb_env) if wb_env.strip() else wb_env)
    monkeypatch.setenv('CODEBUDDY_CONFIG_DIR', str(tmp_path/cb_env) if cb_env else '')
    for name in directories:
        (tmp_path/name).mkdir()
    assert workbuddy_config_dir(tmp_path/explicit if explicit else None) == tmp_path/expected


def test_edit_records_without_scan_and_stop_does_not_cross_turn(check, monkeypatch):
    root, original, runtime, state = check
    core = HookCoordinator(runtime, original.hooks, task_audit_mode=True)
    output = handle(event(root, 'SessionStart'), root=root, core=core)
    context = output['hookSpecificOutput']['additionalContext']
    token = context.split('"session_ref": "')[1].split('"')[0]
    owner = verify_session_ref(core.store, root, token)
    assert owner == session_owner('workbuddy', 'wb-chat')
    service = DevelopmentCheckService(runtime, core.store, owner=owner, scan_path_provider=runtime.store.path,
                                      launcher=lambda *a: None)
    ref = service.begin(root, 'wb-task')['check_ref']
    handle(event(root, 'PostToolUse', tool_name='write_to_file', tool_use_id='write-1',
                 tool_input={'path': str(root/'app.ts')}), root=root, core=core)
    saved = service.get(root, ref)
    assert saved['scope']['paths'] == ['app.ts'] and not saved['finish_requested']
    assert state['calls'] == 0
    # A different chat does not acquire the old task. A read-only turn does not stop.
    assert handle(event(root, 'Stop', generation_id='turn-two'), root=root, core=core) == {}
    assert handle(event(root, 'Stop', session_id='other-chat'), root=root, core=core) == {}
    monkeypatch.setattr(DevelopmentCheckService, '_wake', lambda *a: None)
    assert handle(event(root, 'Stop'), root=root, core=core)['decision'] == 'block'
    assert service.get(root, ref)['finish_requested']
    assert state['calls'] == 0


def test_pre_read_does_not_open_check(check):
    root, service, runtime, _ = check
    core = HookCoordinator(runtime, service.hooks, task_audit_mode=True)
    handle(event(root, 'PreToolUse', tool_name='execute_command', tool_input={'command':'pwd'}), root=root, core=core)
    assert not service.store(root).rows()
    with pytest.raises(ValueError):
        handle(event(root, 'Stop', cwd=str(root.parent)), root=root, core=core)


def test_global_setup_preserves_settings_and_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: tmp_path))
    monkeypatch.delenv('WORKBUDDY_CONFIG_DIR', raising=False)
    monkeypatch.delenv('CODEBUDDY_CONFIG_DIR', raising=False)
    legacy = tmp_path/'.workbuddy'
    legacy.mkdir()
    (legacy/'mcp.json').write_text('{}')
    home = tmp_path/'.workbuddy-ai'
    home.mkdir()
    user = {'hooks': [{'type':'command','command':'echo user'}]}
    (home/'settings.json').write_text(json.dumps({'theme':'dark','hooks':{'Stop':[user]}}))
    adapter = WorkBuddyConnectorInstallation(directory=tmp_path/'private',
        discover=lambda:dict(command='/short/security-check',prefix=[],kind='FROZEN'))
    assert adapter.setup()['overall'] == 'CONFIGURED'
    first = (home/'settings.json').read_bytes()
    assert adapter.setup()['overall'] == 'CONFIGURED'
    assert (home/'settings.json').read_bytes() == first
    settings = json.loads(first)
    assert settings['theme'] == 'dark' and settings['hooks']['Stop'][0] == user
    mcp = json.loads((home/'mcp.json').read_text())['mcpServers']['ai-security-runtime']
    assert mcp['env']['SECURITY_RUNTIME_HOST'] == 'workbuddy'
    assert (home/'skills/ai-security-review/SKILL.md').is_file()
    assert (legacy/'mcp.json').read_text() == '{}'
    assert not (legacy/'settings.json').exists()
    assert not (legacy/'skills').exists()


def test_windows_command_quotes_spaces_and_long_path():
    path = 'C:\\Users\\中文 User\\' + 'deep folder\\'*25 + 'security-check.exe'
    command = hook_command(dict(command=path, prefix=[]), windows=True)
    assert command == '"'+path+'" "workbuddy-hook"'
    assert '--path' not in command  # Project path travels over stdin, not cmd.exe.
    with pytest.raises(ValueError):
        hook_command(dict(command='C:\\%USER%\\security-check.exe',prefix=[]), windows=True)


def test_global_mcp_routes_workbuddy_session(tmp_path, monkeypatch):
    import asyncio
    from security_runtime.global_mcp import GlobalWorkspaces, create_global_server
    from security_runtime.tasks.ownership import issue_session_ref
    from test_global_integration import structured
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    home = tmp_path/'wb'
    adapter = WorkBuddyConnectorInstallation(home=home, directory=tmp_path/'private',
        discover=lambda:dict(command='/short/security-check',prefix=[],kind='FROZEN'))
    adapter.setup()
    root = tmp_path/'project'; root.mkdir()
    (root/'app.py').write_text('value = 1\n')
    pool = GlobalWorkspaces(base=tmp_path/'workspaces', integration=adapter, host='workbuddy')
    _, core = pool.admit(root)
    token = issue_session_ref(core.store, root, 'workbuddy', 'wb', compact=True)
    server = create_global_server(workspaces=pool)
    tools = asyncio.run(server.list_tools())
    assert len(tools) <= 20
    args = dict(workspace_path=str(root), session_ref=token, task_key='acceptance')
    result = structured(asyncio.run(server.call_tool('development_check',
        dict(operation='begin_development_check', arguments=args))))
    assert result['status'] == 'OPEN', result
    pool.executor.shutdown(wait=True)


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Requires real Windows long-path IO')
def test_windows_deep_workbuddy_home(tmp_path, monkeypatch):
    from security_runtime.hook_state import native_io_path
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    home = tmp_path / ('a'*80) / ('b'*80) / ('c'*80) / '.workbuddy'
    assert len(str(home)) > 260
    native_io_path(home).mkdir(parents=True)
    adapter = WorkBuddyConnectorInstallation(home=home, directory=tmp_path/'private',
        discover=lambda:dict(command='C:\\ASR\\security-check.exe',prefix=[],kind='FROZEN'))
    assert adapter.setup()['overall'] == 'CONFIGURED'
    assert adapter.setup()['overall'] == 'CONFIGURED'
