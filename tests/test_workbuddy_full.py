import json
from unittest.mock import patch

import pytest

from security_runtime.workbuddy_connector import WorkBuddyConnectorInstallation
from security_runtime.workbuddy_hook import WorkBuddyBindings, handle_workbuddy_event
from security_runtime.review_skill import ReviewSkillManager
from security_runtime.recent_hooks import RecentHookStore
from security_runtime.tasks.ownership import verify_session_ref
from test_hook_runtime import repo, coordinator, FakeRuntime
from test_development_check import check


@pytest.fixture
def integration(tmp_path):
    return WorkBuddyConnectorInstallation(home=tmp_path/'workbuddy', directory=tmp_path/'owned',
        discover=lambda: dict(kind='INSTALLED', command='/test/runtime', prefix=[]),
        skill=ReviewSkillManager(tmp_path/'skills', tmp_path/'skill-state'))


def test_install_preserves_settings_and_other_mcp_and_removes_owned_skill(integration):
    home = integration.home
    home.mkdir()
    original = dict(theme='dark', hooks={'Stop':[dict(hooks=[dict(type='command', command='user-hook')])]})
    (home/'settings.json').write_text(json.dumps(original))
    mcp = dict(mcpServers={'other':dict(command='other')})
    (home/'mcp.json').write_text(json.dumps(mcp))
    assert integration.execute('setup')['overall'] == 'CONFIGURED'
    assert integration.execute('repair')['overall'] == 'CONFIGURED'
    config = json.loads((home/'settings.json').read_text())
    assert config['theme'] == 'dark'
    assert len(config['hooks']['Stop']) == 2
    assert 'workbuddy-hook' in config['hooks']['PostToolUse'][0]['hooks'][0]['command']
    assert integration.execute('remove')['overall'] == 'REMOVED'
    assert json.loads((home/'settings.json').read_text()) == original
    assert json.loads((home/'mcp.json').read_text()) == mcp
    assert not (integration.skill.root/'SKILL.md').exists()


def test_unowned_hook_and_modified_mcp_preserved(integration):
    home=integration.home
    home.mkdir()
    value=dict(hooks={'Stop':[dict(hooks=[dict(type='command', command='unknown workbuddy-hook')])]})
    path=home/'settings.json'
    path.write_text(json.dumps(value))
    before=path.read_bytes()
    with pytest.raises(ValueError): integration.execute('setup')
    assert path.read_bytes() == before


def test_remove_leaves_no_empty_hook_container_in_user_settings(integration):
    integration.home.mkdir()
    path=integration.home/'settings.json'
    path.write_text(json.dumps(dict(theme='dark')))
    integration.execute('setup')
    assert integration.mcp().desired['disabled'] is False
    integration.execute('remove')
    assert json.loads(path.read_text()) == dict(theme='dark')


def packet(root, event='PostToolUse', **extra):
    return dict(hook_event_name=event, session_id='wb-session', generation_id='turn-one',
        cwd=str(root), tool_name='Write', tool_use_id='call-one',
        tool_input=dict(file_path=str(root/'A.java')), stop_hook_active=False, **extra)


def harness(tmp_path):
    core=coordinator(tmp_path, FakeRuntime(), task_audit_mode=True)
    return dict(core=core, bindings=WorkBuddyBindings(tmp_path/'bindings'), store=RecentHookStore(tmp_path/'recent'))


def test_missing_start_cwd_defers_without_any_workspace_guess(tmp_path):
    kw=harness(tmp_path)
    out,result=handle_workbuddy_event(dict(hook_event_name='SessionStart',session_id='s'), **kw)
    assert out == {} and result['reason'] == 'WORKSPACE_BINDING_REQUIRED'
    assert not kw['bindings'].base.exists()


def test_pre_post_records_only_observed_file_and_delivers_session(repo,tmp_path):
    kw=harness(tmp_path)
    with patch('security_runtime.development_file_watch.start_window'):
        handle_workbuddy_event(packet(repo,'PreToolUse'), **kw)
    (repo/'A.java').write_text('edited\n')
    out,result=handle_workbuddy_event(packet(repo), **kw)
    assert result.get('development_check_ref'), result
    assert out['hookSpecificOutput']['hookEventName']=='PostToolUse'
    assert 'session_ref' in out['hookSpecificOutput']['additionalContext']
    assert kw['core'].runtime.calls == []
    again,same=handle_workbuddy_event(packet(repo), **kw)
    assert same['development_check_ref'] == result['development_check_ref']
    assert same['dirty_seq']==result['dirty_seq']


def test_readonly_mcp_no_check_and_post_requires_matching_pre(repo,tmp_path):
    kw=harness(tmp_path)
    out,result=handle_workbuddy_event(packet(repo), **kw)
    assert out=={} and not result.get('development_check_ref')
    p=packet(repo,'PreToolUse');p['tool_name']='mcp__ai-security-runtime__get_runtime_info'
    handle_workbuddy_event(p,**kw)
    p['hook_event_name']='PostToolUse'
    out,result=handle_workbuddy_event(p,**kw)
    assert not result.get('development_check_ref')
    assert result['scanner_skipped_reason']=='READ_ONLY_ACTIVITY'


def test_cross_workspace_session_and_wrong_generation_rejected(repo,tmp_path):
    kw=harness(tmp_path)
    p=packet(repo,'PreToolUse');p['tool_name']='Read'
    handle_workbuddy_event(p,**kw)
    p['hook_event_name']='PostToolUse';p['generation_id']='wrong'
    out,result=handle_workbuddy_event(p,**kw)
    assert out=={}
    other=tmp_path/'other';other.mkdir();(other/'pyproject.toml').write_text('')
    p=packet(other,'PreToolUse')
    out,result=handle_workbuddy_event(p,**kw)
    assert out=={} and result['status']=='INCONCLUSIVE'


def test_stop_translates_shared_decision_and_keeps_guard(repo,tmp_path):
    kw=harness(tmp_path)
    p=packet(repo,'Stop');p['stop_hook_active']=True
    with patch('security_runtime.development_stop.fallback', return_value=dict(decision='block',reason='continue original')) as fallback:
        out,result=handle_workbuddy_event(p,**kw)
    assert out['decision']=='block' and 'continue original' in out['reason']
    assert fallback.call_args.kwargs['stop_hook_active'] is True
    assert fallback.call_args.args[2]['host']=='workbuddy'


def test_workbuddy_real_stop_budget_does_not_resubmit(check):
    from security_runtime.development_stop import fallback
    root, service, _, _ = check
    owner = dict(host='workbuddy', session='a'*64)
    service.owner = owner
    calls=[]
    service.launcher=lambda *args: calls.append(args)
    ref=service.begin(root,'workbuddy')['check_ref']
    service.record(root,ref,['app.ts'])
    assert fallback(service.hooks,root,owner,service=service)['decision']=='block'
    assert fallback(service.hooks,root,owner,service=service,stop_hook_active=True)['decision']=='block'
    exhausted=fallback(service.hooks,root,owner,service=service,stop_hook_active=True)
    assert exhausted['status']=='STOP_FALLBACK_INCOMPLETE' and 'decision' not in exhausted
    assert len(calls)==1


def test_global_workbuddy_mcp_hides_native_hook_tools():
    import asyncio
    from types import SimpleNamespace
    from security_runtime.global_mcp import create_global_server, HOOKS
    server=create_global_server(workspaces=SimpleNamespace(host='workbuddy'))
    names={t.name for t in asyncio.run(server.list_tools())}
    assert 'finish_development_check' in names and 'get_runtime_info' in names
    assert not names.intersection(HOOKS)


def test_global_install_probe_does_not_build_capability_report_twice(tmp_path,monkeypatch,capsys):
    from security_runtime.cli import main
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR',str(tmp_path/'state'))
    monkeypatch.setenv('SECURITY_RUNTIME_GLOBAL','1')
    calls=[]
    monkeypatch.setattr('security_runtime.guidance.host_guidance.runtime_info',lambda: calls.append('plain') or {})
    monkeypatch.setattr('security_runtime.global_mcp.global_runtime_info',lambda: calls.append('global') or dict(version='test'))
    assert main(['runtime-info','--json'])==0
    assert calls==['global']
    assert json.loads(capsys.readouterr().out)==dict(version='test')


def test_workbuddy_delivery_keeps_complete_probe_with_bounded_cold_start(tmp_path):
    import os
    from security_runtime.workbuddy_connector import probe_delivery
    with patch('security_runtime.codex_integration.probe_runtime', return_value={'status':'READY'}) as probe:
        assert probe_delivery(tmp_path)=={'status':'READY'}
    runtime, root, env = probe.call_args.args
    assert runtime['command']==str(tmp_path/('security-check.exe' if os.name=='nt' else 'security-check'))
    assert root.name=='codex-home'
    assert env['SECURITY_RUNTIME_GLOBAL']=='1'
    assert probe.call_args.kwargs==dict(timeout=120,mcp_timeout=90)
