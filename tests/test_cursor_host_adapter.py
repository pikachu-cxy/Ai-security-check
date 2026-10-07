import json
import os
from pathlib import Path

import pytest

from security_runtime.cursor_event_adapter import CursorHostEventAdapter
from security_runtime.cursor_hook import CursorBindings, handle_cursor_event
from security_runtime.cursor_integration import GlobalCursorIntegration, launcher
from security_runtime.recent_hooks import RecentHookStore
from test_hook_runtime import repo, coordinator, FakeRuntime
from test_host_event_normalization import other_repo


def payload(root, event='afterFileEdit', **fields):
    value = dict(conversation_id='private-cursor-conversation', generation_id='private-generation',
        hook_event_name=event, workspace_roots=[str(root)], cursor_version='fixture')
    if event == 'sessionStart':
        value.update(session_id=value['conversation_id'], is_background_agent=False, composer_mode='agent')
    elif event == 'afterFileEdit':
        value.update(file_path=str(root/'A.java'), edits=[dict(old_string='secret-old', new_string='secret-new')])
    elif event == 'afterShellExecution':
        value.update(command='git status', output='secret-output', duration=15, sandbox=False)
    else:
        value.update(status='completed', loop_count=0)
    value.update(fields)
    return value


@pytest.mark.parametrize('event,command,kind,operation',[
    ('sessionStart',None,'SESSION_START','UNKNOWN'),
    ('afterFileEdit',None,'WORKSPACE_ACTIVITY','DIRECT_FILE_MUTATION'),
    ('afterShellExecution','git status','WORKSPACE_ACTIVITY','READ_ONLY'),
    ('afterShellExecution','Set-Content A.java value','WORKSPACE_ACTIVITY','POSSIBLE_WORKSPACE_MUTATION'),
    ('afterShellExecution','formatter','WORKSPACE_ACTIVITY','UNKNOWN'),
    ('stop',None,'SESSION_STOP','UNKNOWN'),
])
def test_mapping(repo,event,command,kind,operation):
    adapter=CursorHostEventAdapter();raw=payload(repo,event)
    if command is not None:raw['command']=command
    diag=adapter.validate_claims(raw,event)
    assert diag['host_claim_status']=='VALID'
    assert adapter.resolve(raw,project_dir=str(repo))==repo
    out=adapter.normalize(raw,repo,binding_diagnostics=dict(workspace_claim_match=True,session_claim_match=True))
    assert out.kind==kind and out.operation==operation
    assert out.context.invocation_binding is None and not out.context.capabilities.supports_invocation_id
    assert 'private-cursor' not in repr(out) and 'Set-Content' not in repr(out)


@pytest.mark.parametrize('key,value',[('conversation_id',''),('generation_id',None),
    ('workspace_roots',[None]),('workspace_roots',['a','b']),('file_path',None),('session_id','wrong')])
def test_invalid_claims(repo,tmp_path,key,value):
    raw=payload(repo);raw[key]=value
    output,result=handle_cursor_event(raw,core=coordinator(tmp_path,FakeRuntime()),
        bindings=CursorBindings(tmp_path/'bindings'),store=RecentHookStore(tmp_path/'recent.db'))
    assert result['reason']=='INVALID_HOST_CLAIMS' and not result['scanner_run'] and output=={}
    row=RecentHookStore(tmp_path/'recent.db').recent(unbound=True)['records'][0]
    assert row['last_stage']=='CLAIMS_REJECTED' and row['invalid_claims']


def test_binding_rejects_cross_workspace_after_reload(repo,tmp_path):
    bindings=CursorBindings(tmp_path/'bindings');bindings.accept(repo,'conversation')
    other=other_repo(tmp_path/'other')
    with pytest.raises(ValueError,match='SESSION_WORKSPACE_MISMATCH'):
        CursorBindings(tmp_path/'bindings').accept(other,'conversation')
    CursorBindings(tmp_path/'bindings').accept(other,'other-conversation')
    raw=(tmp_path/'bindings'/'bindings.json').read_text()
    assert 'conversation' not in raw and str(repo) not in raw


@pytest.mark.parametrize('flavor',['root','subdir','slashes','case','trailing'])
def test_canonical_roots(repo,flavor):
    sub=repo/'src';sub.mkdir(exist_ok=True)
    root={'root':str(repo),'subdir':str(sub),'slashes':str(repo).replace('\\','/'),
          'case':str(repo).upper() if os.name=='nt' else str(repo),'trailing':str(repo)+os.sep}[flavor]
    assert CursorHostEventAdapter().resolve(payload(repo,workspace_roots=[root]),project_dir=str(repo))==repo


def test_file_boundary_and_nested_repo(repo,tmp_path):
    other=other_repo(repo/'nested')
    adapter=CursorHostEventAdapter()
    with pytest.raises(ValueError):adapter.resolve(payload(repo,file_path=str(other/'A.java')),project_dir=str(repo))
    with pytest.raises(ValueError):adapter.resolve(payload(repo),project_dir=str(tmp_path))
    with pytest.raises(ValueError):adapter.resolve(payload(repo,file_path='../A.java'),project_dir=str(repo))


@pytest.mark.parametrize('event',['afterFileEdit','afterShellExecution'])
def test_real_delta_same_revert_and_readonly(repo,tmp_path,event):
    runtime=FakeRuntime();core=coordinator(tmp_path,runtime,cooldown_ms=0)
    store=RecentHookStore(tmp_path/'recent.db');bindings=CursorBindings(tmp_path/'bindings')
    def run(raw):return handle_cursor_event(raw,core=core,bindings=bindings,store=store,project_dir=str(repo))[1]
    assert run(payload(repo,'sessionStart'))['host_claim_status']=='VALID'
    before=(repo/'A.java').read_bytes();runtime.calls.clear()
    raw=payload(repo,event)
    if event=='afterShellExecution':raw['command']='Set-Content A.java value'
    assert run(raw)['status']=='NO_CHANGE' and not runtime.calls
    (repo/'A.java').write_bytes(b'class A { int timeout=2400; }\r\n')
    result=run(raw)
    assert result['workspace_mutation_observed'] is True and result['changed_file_count']==1
    assert result['scanner_run'] and runtime.calls==[('A.java',)]
    runtime.calls.clear()
    assert run(raw)['status']=='NO_CHANGE' and not runtime.calls
    assert run(payload(repo,'afterShellExecution'))['scanner_skipped_reason']=='READ_ONLY_ACTIVITY'
    (repo/'A.java').write_bytes(b'temporary');(repo/'A.java').write_bytes(b'class A { int timeout=2400; }\r\n')
    assert run(raw)['status']=='NO_CHANGE'
    row=store.recent(repo)['records'][0]
    assert row['host']=='cursor' and row['event_schema']=='cursor-'+event+'-v1'
    all_bytes=(tmp_path/'recent.db').read_bytes()
    for secret in (b'private-cursor-conversation',b'private-generation',b'secret-new',b'git status',b'secret-output'):
        assert secret not in all_bytes


def test_lazy_no_snapshot_remote_and_handler_error(repo,tmp_path):
    runtime=FakeRuntime();core=coordinator(tmp_path,runtime,cooldown_ms=0)
    store=RecentHookStore(tmp_path/'recent.db');bindings=CursorBindings(tmp_path/'bindings')
    out,result=handle_cursor_event(payload(repo),core=core,bindings=bindings,store=store,project_dir=str(repo))
    assert result['snapshot_available'] is False and result['workspace_mutation_observed'] is None
    assert result['delta']['new']==0
    _,result=handle_cursor_event(payload(repo),core=core,bindings=bindings,store=store,remote=True,project_dir=str(repo))
    assert result['reason']=='CURSOR_REMOTE_NOT_SUPPORTED'
    class Broken:
        runtime=None
        def handle(self,*args):raise RuntimeError('secret-error')
    _,result=handle_cursor_event(payload(repo),core=Broken(),bindings=bindings,store=store,project_dir=str(repo))
    assert result['reason']=='HANDLER_EXCEPTION'
    assert store.recent(repo)['records'][0]['last_stage']=='HANDLER_ERROR'


def integration(tmp_path):
    runtime=dict(command=str(Path(os.sys.executable)),prefix=['-I','-m','security_runtime.cli'],kind='SYSTEM_PYTHON')
    return GlobalCursorIntegration(home=tmp_path/'cursor home',directory=tmp_path/'ownership',discover=lambda:runtime)


def test_global_lifecycle_preserves_config_and_idempotence(tmp_path):
    item=integration(tmp_path);item.home.mkdir()
    user={'version':1,'unknown':{'preserve':True},'hooks':{'afterFileEdit':[{'command':'user-custom'}],
        'preToolUse':[{'type':'prompt','prompt':'custom'}]}}
    (item.home/'hooks.json').write_text(json.dumps(user));(item.home/'mcp.json').write_bytes(b'user mcp bytes')
    assert item.execute('setup')['overall']=='CONFIGURED'
    installed=(item.home/'hooks.json').read_bytes()
    assert item.execute('setup')['changed'] is False and item.execute('repair')['changed'] is False
    assert (item.home/'hooks.json').read_bytes()==installed
    assert item.execute('status')['overall']=='CONFIGURED'
    assert item.execute('remove')['overall']=='REMOVED'
    assert json.loads((item.home/'hooks.json').read_bytes())==user
    assert (item.home/'mcp.json').read_bytes()==b'user mcp bytes'
    assert item.execute('remove')['changed'] is False


def test_fresh_install_missing_owned_repair_and_unowned_rejection(tmp_path):
    item=integration(tmp_path)
    assert item.execute('setup')['overall']=='CONFIGURED'
    doc=json.loads((item.home/'hooks.json').read_bytes());doc['hooks'].pop('afterFileEdit')
    (item.home/'hooks.json').write_text(json.dumps(doc))
    assert item.execute('repair')['overall']=='CONFIGURED'
    doc=json.loads((item.home/'hooks.json').read_bytes());doc['hooks']['afterFileEdit'][0]['command']+=' --tampered'
    (item.home/'hooks.json').write_text(json.dumps(doc));before=(item.home/'hooks.json').read_bytes()
    with pytest.raises(ValueError,match='UNOWNED_RUNTIME_HOOK'):item.execute('repair')
    assert (item.home/'hooks.json').read_bytes()==before


def test_launcher_quoting(tmp_path):
    runtime=dict(command=str(tmp_path/'Python Space'/'python.exe'),prefix=['-I','-m','security_runtime.cli'])
    assert 'cursor-hook' in launcher(runtime) and 'Python Space' in launcher(runtime)
    if os.name=='nt':
        with pytest.raises(ValueError):launcher(dict(runtime,command='C:\\bad%PATH%\\python.exe'))


def test_workspace_isolation_and_multifile_bom(repo,tmp_path):
    runtime=FakeRuntime();core=coordinator(tmp_path,runtime,cooldown_ms=0)
    store=RecentHookStore(tmp_path/'recent.db');bindings=CursorBindings(tmp_path/'bindings')
    other=other_repo(tmp_path/'other')
    def run(root,event='afterFileEdit',**kwargs):
        raw=payload(root,event,conversation_id='session-a' if root==repo else 'session-b',**kwargs)
        if event=='sessionStart':raw['session_id']=raw['conversation_id']
        return handle_cursor_event(raw,core=core,store=store,bindings=bindings,project_dir=str(root))[1]
    run(repo,'sessionStart');run(other,'sessionStart');runtime.calls.clear()
    (repo/'A.java').write_bytes(b'\xef\xbb\xbfclass A {}\r\n');(repo/'B.java').write_bytes(b'class B {}\r\n')
    result=run(repo)
    assert result['changed_file_count']==2 and result['scanner_run']
    runtime.calls.clear()
    assert run(other)['status']=='NO_CHANGE' and not runtime.calls
    assert all(r['session_hash']!=store.recent(repo)['records'][0]['session_hash'] for r in store.recent(other)['records'])


def test_missing_claims_and_schema_event_specific(repo,tmp_path):
    adapter=CursorHostEventAdapter()
    raw=payload(repo);raw.pop('generation_id')
    assert adapter.validate_claims(raw,'afterFileEdit')['missing_claims']==['generation_id']
    assert adapter.validate_claims(payload(repo,'sessionStart'),'sessionStart')['host_claim_status']=='VALID'
    assert adapter.validate_claims(payload(repo,'stop'),'stop')['host_claim_status']=='VALID'
    assert not adapter.transport_capabilities.supports_live_remediation_continuation
    assert not adapter.transport_capabilities.supports_stop_followup


def test_binding_corruption_and_budget_fail_closed(repo,tmp_path):
    bindings=CursorBindings(tmp_path/'bindings')
    for index in range(64):bindings.accept(repo,'session-'+str(index))
    with pytest.raises(ValueError,match='SESSION_CONNECTION_BUDGET_EXCEEDED'):bindings.accept(repo,'overflow')
    path=bindings.base/'bindings.json';value=json.loads(path.read_bytes());value['sequence']+=1
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='WORKSPACE_REFERENCE_STALE'):bindings.accept(repo,'session-0')


def test_malformed_and_duplicate_owned_config_fail_closed(tmp_path):
    item=integration(tmp_path);item.execute('setup')
    path=item.home/'hooks.json';doc=json.loads(path.read_bytes())
    doc['hooks']['afterFileEdit'].append(doc['hooks']['afterFileEdit'][0].copy());path.write_text(json.dumps(doc))
    with pytest.raises(ValueError,match='POTENTIAL_DUPLICATE_HOOK'):item.execute('repair')
    doc['hooks']['afterFileEdit']=[{'command':42}];path.write_text(json.dumps(doc))
    with pytest.raises(ValueError,match='CONFIG_INVALID'):item.execute('repair')


def test_stop_same_snapshot_converges_without_followup(repo,tmp_path):
    runtime=FakeRuntime();core=coordinator(tmp_path,runtime,cooldown_ms=0)
    store=RecentHookStore(tmp_path/'recent.db');bindings=CursorBindings(tmp_path/'bindings')
    handle_cursor_event(payload(repo,'sessionStart'),core=core,store=store,bindings=bindings,project_dir=str(repo))
    runtime.calls.clear()
    for index in range(3):
        output,result=handle_cursor_event(payload(repo,'stop',loop_count=index),core=core,store=store,bindings=bindings,project_dir=str(repo))
        assert output=={} and result['status']=='SESSION_FINALIZED' and not result['scanner_run']
    assert not runtime.calls


@pytest.mark.parametrize('raw',[None,[],{'hook_event_name':[]},{'hook_event_name':'unsupported'}])
def test_malformed_ingress_still_observed(tmp_path,raw):
    store=RecentHookStore(tmp_path/'recent.db')
    _,result=handle_cursor_event(raw,store=store)
    assert result['reason']=='INVALID_HOST_CLAIMS'
    assert store.recent(unbound=True)['records'][0]['last_stage']=='CLAIMS_REJECTED'
