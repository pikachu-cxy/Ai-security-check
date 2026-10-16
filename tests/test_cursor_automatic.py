"""Automatic Cursor transport uses real task state; scanner results are fixtures."""
import asyncio
import json

import pytest

from security_runtime.cursor_connector import CursorConnectorInstallation, setup_personal_cursor
from security_runtime.cursor_hook import CursorBindings, handle_cursor_event
from security_runtime.cursor_tasks import CursorTaskBridge
from security_runtime.cursor_event_adapter import CursorHostEventAdapter
from security_runtime.global_mcp import GlobalWorkspaces, create_global_server
from security_runtime.recent_hooks import RecentHookStore
from security_runtime.review_skill import ReviewSkillManager
from test_cursor_host_adapter import payload
from test_hook_runtime import repo, coordinator, FakeRuntime
from test_task_security import LedgerRuntime
from test_global_integration import structured


@pytest.fixture
def integration(tmp_path):
    skill = ReviewSkillManager(tmp_path/'skills', tmp_path/'skill-state')
    return CursorConnectorInstallation(home=tmp_path/'cursor home', directory=tmp_path/'owned',
        discover=lambda: dict(kind='INSTALLED', command='runtime with spaces.exe', prefix=[]), skill=skill)


def test_install_preserves_user_data_idempotent_remove_keeps_shared_skill(integration):
    home = integration.home
    home.mkdir()
    user = dict(version=1, hooks={'stop':[{'command':'user-hook'}]}, custom={'preserve':True})
    (home/'hooks.json').write_text(json.dumps(user))
    mcp = {'mcpServers':{'other':{'command':'user-mcp'}}, 'unknown':True}
    (home/'mcp.json').write_text(json.dumps(mcp))
    data = setup_personal_cursor(integration)
    assert data['installation']['local_files_ready'] and not data['installation']['scan_ready']
    hooks = json.loads((home/'hooks.json').read_bytes())
    assert len(hooks['hooks']) == 6
    assert '--automatic' in hooks['hooks']['preToolUse'][0]['command']
    assert hooks['hooks']['stop'][0] == user['hooks']['stop'][0]
    config = json.loads((home/'mcp.json').read_bytes())
    assert config['mcpServers']['other'] == mcp['mcpServers']['other']
    entry = config['mcpServers']['ai-security-runtime']
    assert entry['env'] == {'SECURITY_RUNTIME_HOST':'cursor','SECURITY_RUNTIME_GLOBAL':'1'}
    before = [(home/n).read_bytes() for n in ('hooks.json','mcp.json')]
    assert integration.execute('repair')['overall'] == 'CONFIGURED'
    assert before == [(home/n).read_bytes() for n in ('hooks.json','mcp.json')]
    assert integration.execute('remove')['overall'] == 'REMOVED'
    assert json.loads((home/'hooks.json').read_bytes()) == user
    assert json.loads((home/'mcp.json').read_bytes()) == mcp
    assert integration.skill.status()['status'] == 'INSTALLED'


@pytest.mark.parametrize('kind', ['same-name', 'alias', 'hook', 'skill'])
def test_unknown_configuration_not_adopted(integration, kind):
    home = integration.home
    home.mkdir()
    if kind in {'same-name','alias'}:
        value = {'mcpServers':{'ai-security-runtime' if kind=='same-name' else 'renamed':
                 {'command':'user-server' if kind=='same-name' else 'security-check.exe', 'args':['mcp']}}}
        target = home/'mcp.json'
        target.write_text(json.dumps(value))
    elif kind == 'hook':
        target = home/'hooks.json'
        target.write_text(json.dumps(dict(version=1,hooks={'stop':[{'command':'unknown cursor-hook'}]})))
    else:
        integration.skill.root.mkdir(parents=True)
        target = integration.skill.root/'SKILL.md'
        target.write_text('User content')
    before = target.read_bytes()
    with pytest.raises(ValueError):
        integration.execute('setup')
    assert target.read_bytes() == before


def test_install_failure_rolls_back_own_hooks_and_skill(integration, monkeypatch):
    from security_runtime.owned_json import OwnedJsonServer
    def fail(*a):
        raise OSError('fixture')
    monkeypatch.setattr(OwnedJsonServer, 'execute', fail)
    with pytest.raises(OSError):
        integration.execute('setup')
    assert not (integration.home/'hooks.json').exists()
    assert not (integration.home/'mcp.json').exists()
    assert integration.skill.status()['status'] == 'NOT_INSTALLED'


def test_project_runtime_conflict_preserved(integration, repo):
    config = repo/'.cursor'
    config.mkdir()
    (config/'mcp.json').write_text('{"mcpServers":{"ai-security-runtime":{"command":"old"}}}')
    with pytest.raises(ValueError, match='LEGACY_PROJECT'):
        integration.execute('setup', repo)
    assert not (integration.home/'hooks.json').exists()


def test_duplicate_host_skill_is_preserved(integration):
    other = integration.home/'skills/ai-security-review'
    other.mkdir(parents=True)
    (other/'SKILL.md').write_text('User host guidance')
    with pytest.raises(ValueError, match='DUPLICATE_REVIEW_SKILL'):
        integration.execute('setup')
    assert (other/'SKILL.md').read_text() == 'User host guidance'
    assert not (integration.home/'hooks.json').exists()


def test_concurrent_editor_preserved_during_rollback(integration, monkeypatch):
    from security_runtime.owned_json import OwnedJsonServer
    def fail(*a):
        (integration.home/'hooks.json').write_text('{"external":"user edit"}')
        raise OSError('fixture')
    monkeypatch.setattr(OwnedJsonServer, 'execute', fail)
    with pytest.raises(ValueError, match='RECOVERY_REQUIRED'):
        integration.execute('setup')
    assert json.loads((integration.home/'hooks.json').read_bytes()) == {'external':'user edit'}


def ingress(repo, tmp_path, core, event, **fields):
    return handle_cursor_event(payload(repo,event,**fields), automatic=True, core=core,
        bindings=CursorBindings(tmp_path/'bindings'), project_dir=str(repo),
        store=RecentHookStore(tmp_path/'recent.db'))


def tool(repo,tmp_path,core,name='Write',generation='private-generation', **fields):
    return ingress(repo,tmp_path,core,'preToolUse',tool_name=name,tool_use_id='opaque',
        generation_id=generation, tool_input=fields)


def test_pre_edit_dirty_baseline_post_context_and_no_double_scan(repo,tmp_path):
    runtime=FakeRuntime();core=coordinator(tmp_path,runtime)
    (repo/'A.java').write_text('pre-existing user bytes')
    output,before=tool(repo,tmp_path,core)
    assert output == {'permission':'allow'} and before['status']=='BASELINE_CAPTURED'
    bridge=CursorTaskBridge(core,repo,'private-cursor-conversation','private-generation')
    record=bridge.current()
    assert record['baseline']['texts']['A.java'] and not runtime.calls
    (repo/'A.java').write_text('task bytes')
    _,result=ingress(repo,tmp_path,core,'afterFileEdit')
    assert result['scanner_run'] and result['hook_check_recording']=='RECORDED'
    output,post=ingress(repo,tmp_path,core,'postToolUse',tool_name='Write',tool_use_id='opaque')
    assert before['task_ref'] in output['additional_context']
    assert 'finish_security_task' in output['additional_context']
    assert 'prepare_task_security_review' in output['additional_context']
    assert len(runtime.calls)==1 and not post['scanner_run']
    assert bridge.current()['hook_checks']


@pytest.mark.parametrize('shape', ['missing', 'null', 'empty'])
def test_unavailable_tool_id_keeps_pre_edit_baseline_and_context(repo,tmp_path,shape):
    core=coordinator(tmp_path,FakeRuntime())
    fields={} if shape=='missing' else {'tool_use_id':None if shape=='null' else ''}
    raw=payload(repo,'preToolUse',tool_name='Write',tool_input={},**fields)
    before_text=(repo/'A.java').read_text()
    output,result=handle_cursor_event(raw,automatic=True,core=core,
        bindings=CursorBindings(tmp_path/'bindings'),project_dir=str(repo),
        store=RecentHookStore(tmp_path/'recent.db'))
    assert output=={'permission':'allow'} and result['status']=='BASELINE_CAPTURED'
    assert result['tool_use_id_state']=={'missing':'MISSING','null':'NULL','empty':'EMPTY'}[shape]
    bridge=CursorTaskBridge(core,repo,raw['conversation_id'],raw['generation_id'])
    record=bridge.current()
    assert record['baseline']['hashes']['A.java'] != ''
    (repo/'A.java').write_text(before_text+'task edit\n')
    ingress(repo,tmp_path,core,'afterFileEdit')
    context=ingress(repo,tmp_path,core,'postToolUse',tool_name='Write',**fields)[0]
    assert record['task_ref'] in context['additional_context']
    rows=RecentHookStore(tmp_path/'recent.db').recent(repo)['records']
    pre=next(r for r in rows if r['event']=='preToolUse')
    assert pre['handler_status']=='BASELINE_CAPTURED' and pre['tool_use_id_state']==result['tool_use_id_state']
    assert not pre['scanner_run'] and len(core.runtime.calls)==1


@pytest.mark.parametrize('value', [123, True, [], {}, ' ', 'x'*501, 'private\x00value', '\ud800'])
def test_diagnostic_only_id_does_not_block_or_leak_into_task(repo,tmp_path,value):
    raw=payload(repo,'preToolUse',tool_name='Write',tool_use_id=value)
    core=coordinator(tmp_path,FakeRuntime())
    output,result=handle_cursor_event(raw,automatic=True,core=core,
        bindings=CursorBindings(tmp_path/'bindings'),project_dir=str(repo),
        store=RecentHookStore(tmp_path/'recent.db'))
    assert result['status']=='BASELINE_CAPTURED' and result['tool_use_id_state']=='INVALID'
    assert result['invalid_claims']==[] and not core.runtime.calls
    record=CursorTaskBridge(core,repo,raw['conversation_id'],raw['generation_id']).current()
    assert record['connector_owner']['host']=='cursor'
    assert 'tool_use_id' not in record


@pytest.mark.parametrize('field,value', [('conversation_id',123), ('generation_id',''),
    ('workspace_roots',['different-root','second-root']), ('tool_name',{})])
def test_ignoring_diagnostic_id_never_weakens_binding_claims(repo,tmp_path,field,value):
    raw=payload(repo,'preToolUse',tool_name='Write',tool_use_id={})
    raw[field]=value
    result=handle_cursor_event(raw,automatic=True,core=coordinator(tmp_path,FakeRuntime()),
        bindings=CursorBindings(tmp_path/'bindings'),project_dir=str(repo),
        store=RecentHookStore(tmp_path/'recent.db'))[1]
    assert result['reason']=='INVALID_HOST_CLAIMS' and not result['scanner_run']


@pytest.mark.parametrize('name', ['MCP:begin_security_task',
    'MCP:ai-security-runtime:begin_security_task',
    'MCP:mcp_ai_security_runtime_begin_security_task'])
def test_mcp_begin_prepares_same_key_before_call_and_edit(repo,tmp_path,name):
    core=coordinator(tmp_path,FakeRuntime())
    bridge=CursorTaskBridge(core,repo,'private-cursor-conversation','private-generation')
    key='host-generated-unique-key'
    from security_runtime.task_ownership import issue_session_ref
    token=issue_session_ref(core.store,repo,'cursor','private-cursor-conversation')
    before=tool(repo,tmp_path,core,name,workspace_path=str(repo),task_key=key,session_ref=token)[1]
    assert before['status']=='BASELINE_CAPTURED' and not core.runtime.calls
    manual=bridge.tasks.begin(str(repo),key)
    assert manual['status']=='ACTIVE' and manual['task_ref']==before['task_ref']
    assert bridge.current()['connector_owner']==bridge.owner
    assert before['task_ref'] in ingress(repo,tmp_path,core,'postToolUse',
        tool_name=name,tool_use_id={})[0]['additional_context']
    assert tool(repo,tmp_path,core)[1]['task_ref']==before['task_ref']
    (repo/'A.java').write_text('task edit')
    result=ingress(repo,tmp_path,core,'afterFileEdit')[1]
    assert result['scanner_run'] and result['hook_check_recording']=='RECORDED'
    assert len(core.runtime.calls)==1 and bridge.current()['hook_checks']


@pytest.mark.parametrize('bad', ['other-workspace','relative','missing-key','oversize-key'])
def test_mcp_begin_rejects_unbound_preparation(repo,tmp_path,bad):
    core=coordinator(tmp_path,FakeRuntime())
    other=tmp_path/'other';other.mkdir(exist_ok=True)
    fields=dict(workspace_path=str(repo),task_key='key')
    if bad=='other-workspace': fields['workspace_path']=str(other)
    if bad=='relative': fields['workspace_path']='.'
    if bad=='missing-key': fields.pop('task_key')
    if bad=='oversize-key': fields['task_key']='x'*201
    result=tool(repo,tmp_path,core,'MCP:begin_security_task',**fields)[1]
    assert result['status']=='BASELINE_UNAVAILABLE'
    assert CursorTaskBridge(core,repo,'private-cursor-conversation','private-generation').current() is None
    assert not core.runtime.calls


def test_mcp_preparation_never_adopts_existing_manual_or_other_server(repo,tmp_path):
    core=coordinator(tmp_path,FakeRuntime())
    bridge=CursorTaskBridge(core,repo,'private-cursor-conversation','private-generation')
    assert tool(repo,tmp_path,core,'MCP:other:begin_security_task',
        workspace_path=str(repo),task_key='key')[1]['status']=='READ_ONLY_OR_UNSUPPORTED'
    from security_runtime.task_security import TaskSecurityService
    ref=TaskSecurityService(core.runtime,core.store).begin(str(repo),'key')['task_ref']
    result=tool(repo,tmp_path,core,'MCP:begin_security_task',workspace_path=str(repo),task_key='key')[1]
    assert result['status']=='MCP_PREPARATION_DELEGATED'
    assert 'connector_owner' not in TaskSecurityService(core.runtime,core.store).load(repo,ref)
    assert not core.runtime.calls


def test_legacy_mode_still_requires_tool_id(repo):
    raw=payload(repo,'postToolUse',tool_name='Write',tool_use_id='')
    assert CursorHostEventAdapter().validate_claims(raw,'postToolUse')['host_claim_status']=='INVALID'


def test_read_only_chat_cancel_and_missing_pre_never_invent_task(repo,tmp_path):
    runtime=FakeRuntime();core=coordinator(tmp_path,runtime)
    assert tool(repo,tmp_path,core,'Read')[1]['status']=='READ_ONLY_OR_UNSUPPORTED'
    assert tool(repo,tmp_path,core,'Shell',command='git status')[1]['status']=='READ_ONLY_OR_UNSUPPORTED'
    assert ingress(repo,tmp_path,core,'stop')[0]=={}
    (repo/'A.java').write_text('edited without pre')
    output,_=ingress(repo,tmp_path,core,'postToolUse',tool_name='Write',tool_use_id='opaque')
    assert '未完成' in output['additional_context']
    assert CursorTaskBridge(core,repo,'private-cursor-conversation','private-generation').current() is None
    assert not runtime.calls


def test_stop_once_persists_reuses_ref_across_generation_and_next_task_works(repo,tmp_path):
    runtime=FakeRuntime();core=coordinator(tmp_path,runtime)
    first=tool(repo,tmp_path,core)[1]['task_ref']
    (repo/'A.java').write_text('task edit')
    msg=ingress(repo,tmp_path,core,'stop')[0]['followup_message']
    assert first in msg and not runtime.calls
    assert ingress(repo,tmp_path,core,'stop')[0]=={}
    assert ingress(repo,tmp_path,core,'stop',loop_count=1)[0]=={}
    assert ingress(repo,tmp_path,core,'stop',status='aborted')[0]=={}
    tool(repo,tmp_path,core,'Read',generation='automatic-followup')
    context=ingress(repo,tmp_path,core,'postToolUse',tool_name='Read',tool_use_id='read',
                    generation_id='automatic-followup')[0]['additional_context']
    assert first in context
    bridge=CursorTaskBridge(core,repo,'private-cursor-conversation','automatic-followup')
    record=bridge.current();record['phase']='COMPLETE';bridge.tasks.store(repo).save(record)
    second=tool(repo,tmp_path,core,generation='second-real-task')[1]['task_ref']
    assert second != first and second in ingress(repo,tmp_path,core,'stop',generation_id='second-real-task')[0]['followup_message']


def test_other_session_and_manual_task_not_joined(repo,tmp_path):
    core=coordinator(tmp_path,FakeRuntime())
    first=tool(repo,tmp_path,core)[1]['task_ref']
    result=ingress(repo,tmp_path,core,'preToolUse',tool_name='Write',tool_use_id='x',
                   conversation_id='other-conversation')[1]
    assert result['status']=='BASELINE_CAPTURED' and core.runtime.calls==[]
    assert result['task_ref']!=first
    assert first == CursorTaskBridge(core,repo,'private-cursor-conversation','private-generation').current()['task_ref']


def test_cursor_router_hides_codex_hook_tools_and_routes_to_shared_workspace(integration,repo,tmp_path):
    integration.execute('setup')
    pool=GlobalWorkspaces(host='cursor',base=tmp_path/'cursor-workspaces',integration=integration)
    server=create_global_server(workspaces=pool,host='cursor')
    async def exercise():
        tools={t.name:t for t in await server.list_tools()}
        assert not {'handle_readiness_event','handle_hook_event','handle_stop_event'} & tools.keys()
        assert 'begin_security_task' in tools and 'prepare_functional_verification' not in tools
        approved=integration.configuration_status()['routine_tool_approval']['routine_tools']
        assert set(approved) <= tools.keys()
        missing=await server.call_tool('begin_security_task',{'task_key':'test'})
        assert missing.structuredContent['reason_code']=='WORKSPACE_CLAIM_REQUIRED'
        info=await server.call_tool('get_runtime_info',{})
        assert info.structuredContent['host_connector']=='cursor'
        result=await server.call_tool('begin_security_task',{'task_key':'test','workspace_path':str(repo)})
        assert structured(result)['status']=='ACTIVE'
        unknown=await server.call_tool('handle_stop_event',{})
        assert unknown.structuredContent['reason_code']=='INVALID_HOST_CLAIMS'
    try:
        asyncio.run(exercise())
    finally:
        pool.close()
