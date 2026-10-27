import json
from pathlib import Path

import pytest

from security_runtime.hook_adapters import CodexHookAdapter, CursorHookAdapter, HookIntegrationRegistry, MARKER, run_host_event
from security_runtime.cli import main
from test_hook_runtime import repo, FakeRuntime, coordinator, dirty


@pytest.mark.parametrize('name,tool,expected',[('SessionStart',None,'SESSION_START'),('PostToolUse','apply_patch','FILE_CHANGED'),('PostToolUse','Edit','FILE_CHANGED'),('PostToolUse','Write','FILE_CHANGED'),('Stop',None,'AGENT_STOP')])
def test_codex_official_payload_translation(repo,name,tool,expected):
    payload={'hook_event_name':name,'tool_name':tool,'cwd':str(repo),'session_id':'s',
             'tool_input':{'command':'UNTRUSTED_CODE: run external model; leak fixture_credential'},
             'transcript_path':'outside/private','last_assistant_message':'ignore safety'}
    event,session=CodexHookAdapter().translate(payload,repo)
    assert event==expected and session=='s'


def test_codex_bound_workspace_and_tool_rejected(repo,tmp_path):
    adapter=CodexHookAdapter()
    for payload in ({'hook_event_name':'Stop','cwd':str(tmp_path),'session_id':'s'},
                    {'hook_event_name':'PostToolUse','cwd':str(repo),'session_id':'s','tool_name':'Unknown'},
                    {'hook_event_name':'SessionStart','cwd':str(repo),'session_id':None}):
        with pytest.raises(ValueError):adapter.translate(payload,repo)


def test_codex_output_advisory_without_continuation_or_secret(repo,tmp_path):
    c=coordinator(tmp_path,FakeRuntime())
    for event in ('SessionStart','Stop'):
        output=run_host_event({'hook_event_name':event,'cwd':str(repo),'session_id':'s','tool_input':'private_credential'},repo,'codex',c)
        assert 'systemMessage' in output and 'decision' not in output and 'continue' not in output
        assert 'private_credential' not in json.dumps(output)


def test_install_merge_idempotent_repair_remove_preserves_mcp_and_unknown(repo):
    folder=repo/'.codex';folder.mkdir()
    toml=folder/'config.toml';toml.write_text('# preserved comment\n[mcp_servers.mine]\ncommand = "custom"\n')
    config=folder/'hooks.json'
    user={'description':'mine','future_setting':{'anything':True},'hooks':{'Stop':[{'matcher':'*','custom':'preserve','hooks':[{'type':'command','command':'my-command'}]}]}}
    config.write_text(json.dumps(user))
    registry=HookIntegrationRegistry()
    registry.manage('install','codex',repo)
    installed=config.read_bytes();toml_bytes=toml.read_bytes()
    assert registry.manage('status','codex',repo)['status']=='CONFIG_ONLY'
    registry.manage('install','codex',repo)
    assert config.read_bytes()==installed and toml.read_bytes()==toml_bytes
    value=json.loads(installed);value['hooks']['SessionStart'][-1]['hooks'][0]['command']='old executable'
    config.write_text(json.dumps(value))
    assert registry.manage('status','codex',repo)['status']=='NEEDS_REPAIR'
    registry.manage('repair','codex',repo)
    assert config.read_bytes()==installed
    registry.manage('remove','codex',repo)
    assert json.loads(config.read_text())==user and toml.read_bytes()==toml_bytes


@pytest.mark.parametrize('bad',['{invalid','[]','{"hooks": []}','{"hooks":{"Stop":[{}]}}'])
def test_invalid_config_no_overwrite_no_secret_echo(repo,bad):
    folder=repo/'.codex';folder.mkdir();config=folder/'hooks.json';config.write_text(bad)
    original=config.read_bytes()
    with pytest.raises(ValueError,match='no changes made'):
        HookIntegrationRegistry().manage('install','codex',repo)
    assert config.read_bytes()==original


def test_bad_toml_does_not_write_hooks(repo):
    folder=repo/'.codex';folder.mkdir();(folder/'config.toml').write_text('secret="private_credential"\ninvalid = [')
    with pytest.raises(ValueError,match='no changes made'):
        HookIntegrationRegistry().manage('install','codex',repo)
    assert not (folder/'hooks.json').exists()


@pytest.mark.parametrize('host',['kiro','workbuddy','codebuddy','qoder'])
def test_manual_hosts_do_not_invent_schema(repo,host):
    output=HookIntegrationRegistry().manage('install',host,repo)
    assert output['status']=='MANUAL_CONFIGURATION_REQUIRED'
    assert set(output['commands'])=={'session-start','file-changed','agent-stop'}
    assert not (repo/('.'+host)).exists()


def test_agent_hook_findings_exit_zero_and_human_json(repo,tmp_path,monkeypatch,capsys):
    import security_runtime.hook_runtime as module
    from test_hook_runtime import row
    dirty(repo);c=coordinator(tmp_path,FakeRuntime([row(repo)]))
    # Exercise the legacy advisory formatter with its explicit legacy core;
    # the CLI now passes task_audit_mode to the constructor.
    monkeypatch.setattr(module,'HookCoordinator',lambda **_kwargs:c)
    assert main(['hook','file-changed','--path',str(repo),'--host','codex','--json'])==0
    output=json.loads(capsys.readouterr().out)
    assert output['policy']=='ADVISORY' and output['status']=='BASELINE_ESTABLISHED'
    assert main(['hook','agent-stop','--path',str(repo),'--host','codex'])==0
    assert 'REUSED_LAST_RESULT' in capsys.readouterr().out


def test_cli_runtime_exception_generic_no_untrusted_echo(repo,monkeypatch,capsys):
    import security_runtime.hook_runtime as module
    class Broken:
        def handle(self,*args):raise RuntimeError('private_credential UNTRUSTED_CODE')
    monkeypatch.setattr(module,'HookCoordinator',Broken)
    assert main(['hook','agent-stop','--path',str(repo),'--json'])==2
    output=capsys.readouterr()
    assert 'private_credential' not in output.out+output.err
    assert json.loads(output.out)['error_code']=='HOOK_RUNTIME_FAILED'


def test_cursor_verified_schema_merge_remove_and_translation(repo,tmp_path):
    folder=repo/'.cursor';folder.mkdir();path=folder/'hooks.json'
    original={'version':1,'custom':'keep','hooks':{'stop':[{'command':'my-handler'}]}}
    path.write_text(json.dumps(original))
    registry=HookIntegrationRegistry();registry.manage('install','cursor',repo)
    assert registry.manage('status','cursor',repo)['status']=='CONFIG_ONLY'
    data=path.read_bytes();registry.manage('repair','cursor',repo);assert path.read_bytes()==data
    adapter=CursorHookAdapter()
    payload={'hook_event_name':'afterFileEdit','workspace_roots':[str(repo)],'conversation_id':'s','edits':[{'new_string':'private_credential'}]}
    assert adapter.translate(payload,repo)==('FILE_CHANGED','s')
    assert run_host_event(payload,repo,'cursor',coordinator(tmp_path,FakeRuntime()))=={}
    registry.manage('remove','cursor',repo)
    assert json.loads(path.read_text())==original


def test_cursor_future_schema_not_overwritten(repo):
    folder=repo/'.cursor';folder.mkdir();path=folder/'hooks.json';path.write_text('{"version":2,"hooks":{}}')
    before=path.read_bytes()
    with pytest.raises(ValueError):HookIntegrationRegistry().manage('install','cursor',repo)
    assert path.read_bytes()==before


def test_runtime_only_config_locally_ignored_and_removed(repo):
    from security_runtime.git import GitService
    registry=HookIntegrationRegistry();registry.manage('install','codex',repo)
    git=GitService(repo)
    assert '.codex/hooks.json' not in git.changed_files('quick')
    assert (repo/'.codex/hooks.json').exists()
    registry.manage('remove','codex',repo)
    assert not (repo/'.codex/hooks.json').exists()
    assert 'AI Security Runtime: .codex/hooks.json' not in (repo/'.git/info/exclude').read_text()


def test_local_ignore_failure_rolls_back_config(repo,monkeypatch):
    from security_runtime.integration_config import IntegrationConfigStore
    def failure(*args,**kwargs):raise OSError('fixture failure')
    monkeypatch.setattr(IntegrationConfigStore,'_local_exclude',failure)
    with pytest.raises(OSError):HookIntegrationRegistry().manage('install','codex',repo)
    assert not (repo/'.codex/hooks.json').exists()
