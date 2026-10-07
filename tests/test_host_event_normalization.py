"""Host-neutral dispatch uses real filesystem deltas and existing scanner fixtures."""
import asyncio
import ast
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from security_runtime.codex_event_adapter import CodexEventAdapter
from security_runtime.codex_host_claims import CodexClaimGuard
from security_runtime.host_events import (EventKind, HostCapabilities, NormalizedHostEvent,
    OperationClass, VerifiedHostContext)
from security_runtime.host_event_runtime import handle_normalized_event
from security_runtime.hook_state import identity
from security_runtime.integration_state import WorkspaceBinding
from security_runtime.recent_hooks import Observation, RecentHookStore, CURRENT
from test_hook_runtime import repo, coordinator, FakeRuntime
from test_codex_host_claims import connected, claims, invoke
from test_global_integration import installed, projects


def git(root, *arguments):
    return subprocess.run(['git','-C',str(root),*arguments],check=True,capture_output=True)


def other_repo(root):
    root.mkdir()
    git(root,'init','-q');git(root,'config','user.email','fixture@example.invalid');git(root,'config','user.name','Fixture')
    (root/'A.java').write_bytes(b'class A {}');git(root,'add','.');git(root,'commit','-qm','fixture')
    return root


def args(root, event='PostToolUse', tool='Write', command=None, invocation='i'):
    data=dict(event=event, workspace_path=str(root), session_id='private-session-fixture')
    if event=='PostToolUse':
        data.update(tool_name=tool,turn_id='private-turn-fixture',tool_use_id=invocation)
        if command is not None: data['tool_input']={'command':command}
    if event=='Stop': data['stop_hook_active']=False
    return data


def bound(root, data, guard=None):
    binding=WorkspaceBinding('fixture',str(root),str(root),'codex','PROJECT','')
    return CodexEventAdapter().bind_project(data,binding=binding,guard=guard or CodexClaimGuard())


@pytest.mark.parametrize('event,tool,command,kind,operation',[
    ('SessionStart',None,None,EventKind.SESSION_START,OperationClass.UNKNOWN),
    ('PostToolUse','apply_patch',None,EventKind.WORKSPACE_ACTIVITY,OperationClass.DIRECT_FILE_MUTATION),
    ('PostToolUse','Edit',None,EventKind.WORKSPACE_ACTIVITY,OperationClass.DIRECT_FILE_MUTATION),
    ('PostToolUse','Write',None,EventKind.WORKSPACE_ACTIVITY,OperationClass.DIRECT_FILE_MUTATION),
    ('PostToolUse','Bash','git status',EventKind.WORKSPACE_ACTIVITY,OperationClass.READ_ONLY),
    ('PostToolUse','Bash','Set-Content A.java value',EventKind.WORKSPACE_ACTIVITY,OperationClass.POSSIBLE_WORKSPACE_MUTATION),
    ('PostToolUse','Bash','opaque-executable',EventKind.WORKSPACE_ACTIVITY,OperationClass.UNKNOWN),
    ('Stop',None,None,EventKind.SESSION_STOP,OperationClass.UNKNOWN),
])
def test_adapter_event_shapes(repo,event,tool,command,kind,operation):
    normalized,diag,reason=bound(repo,args(repo,event,tool,command))
    assert reason is None and diag['host_claim_status']=='VALID'
    assert normalized.kind==kind and normalized.operation==operation
    assert normalized.context.session_binding==identity('private-session-fixture')
    assert normalized.context.validation_status=='BINDING_CONSISTENT'
    serialized=repr(normalized)+json.dumps(normalized.diagnostics())
    for raw in ('private-session-fixture','private-turn-fixture','Set-Content'):
        assert raw not in serialized
    assert not hasattr(normalized, 'tool_input')


@pytest.mark.parametrize('field,value',[('turn_id',None),('tool_use_id',None),
    ('session_id',''),('permission_mode','unknown'),('turn_id','${turn_id}'),('tool_name','not-a-tool')])
def test_adapter_claims_fail_closed(repo,field,value):
    data=args(repo);data[field]=value
    normalized,diag,reason=bound(repo,data)
    assert normalized is None and reason=='INVALID_HOST_CLAIMS'
    assert diag['host_claim_status']=='INVALID'


def test_replay_and_workspace_session_consistency(repo,tmp_path):
    guard=CodexClaimGuard();first=args(repo)
    assert bound(repo,first,guard)[2] is None
    assert bound(repo,first,guard)[2]=='TOOL_USE_CLAIM_REPLAYED'
    wrong=dict(first,workspace_path=str(tmp_path),tool_use_id='other')
    assert bound(repo,wrong,guard)[2]=='HOST_CLAIMS_REJECTED'
    other=other_repo(tmp_path/'other')
    assert bound(other,args(other,invocation='another'),guard)[2]=='SESSION_WORKSPACE_MISMATCH'


def generic_event(root,kind,operation=OperationClass.UNKNOWN,session='neutral-session'):
    context=VerifiedHostContext('generic',root,identity(os.path.normcase(str(root))),
        identity(session),None,HostCapabilities(supports_session_start=True),session)
    return NormalizedHostEvent(kind,context,operation,
        stop_guard_active=False if kind==EventKind.SESSION_STOP else None)


def test_core_session_activity_stop_without_raw_host_fields(repo,tmp_path):
    runtime=FakeRuntime();core=coordinator(tmp_path,runtime,cooldown_ms=0)
    start,_=handle_normalized_event(generic_event(repo,EventKind.SESSION_START),coordinator=core)
    assert start['normalized_event_kind']=='SESSION_START'
    runtime.calls.clear()
    (repo/'A.java').write_bytes(b'class A { int timeout=2400; }\r\n')
    activity=generic_event(repo,EventKind.WORKSPACE_ACTIVITY,OperationClass.DIRECT_FILE_MUTATION)
    out,_=handle_normalized_event(activity,coordinator=core)
    assert out['execution']['scanner_run'] and out['changed_file_count']==1
    assert out['normalized_scanner_trigger_reason']=='WORKSPACE_CONTENT_DELTA'
    assert runtime.calls==[('A.java',)]
    runtime.calls.clear()
    out,_=handle_normalized_event(activity,coordinator=core)
    assert out['status']=='NO_CHANGE' and not runtime.calls
    stop=replace(generic_event(repo,EventKind.SESSION_STOP),stop_guard_active=False)
    out,_=handle_normalized_event(stop,coordinator=core)
    assert out['status']=='REUSED_LAST_RESULT' and not runtime.calls


def test_core_readonly_hint_and_unattributed(repo,tmp_path):
    core=coordinator(tmp_path,FakeRuntime(),cooldown_ms=0)
    out,_=handle_normalized_event(generic_event(repo,EventKind.WORKSPACE_ACTIVITY,
        OperationClass.READ_ONLY),coordinator=core)
    assert out['status']=='NOT_SCANNED' and not core.runtime.calls
    direct=replace(generic_event(repo,EventKind.WORKSPACE_ACTIVITY,
        OperationClass.DIRECT_FILE_MUTATION),mutation_hint=True)
    out,_=handle_normalized_event(direct,coordinator=core)
    assert out['snapshot_available'] is False and out['delta']['new']==0
    assert out['workspace_mutation_observed'] is None
    core.runtime.calls.clear()
    out,_=handle_normalized_event(direct,coordinator=core)
    assert out['status']=='NO_CHANGE' and not core.runtime.calls


def test_core_cannot_receive_raw_payload_or_inconsistent_context(repo,tmp_path):
    core=coordinator(tmp_path,FakeRuntime())
    with pytest.raises(ValueError):handle_normalized_event({'tool_name':'Write'},coordinator=core)
    event=generic_event(repo,EventKind.SESSION_START)
    with pytest.raises(ValueError):replace(event.context,workspace_identity='0'*64)
    with pytest.raises(ValueError):replace(event,kind='PostToolUse')
    with pytest.raises(ValueError):replace(event,clock_scope='0'*32)
    assert not core.runtime.calls


def test_neutral_workspace_isolation(repo,tmp_path):
    runtime=FakeRuntime();core=coordinator(tmp_path,runtime,cooldown_ms=0)
    handle_normalized_event(generic_event(repo,EventKind.SESSION_START),coordinator=core)
    other=other_repo(tmp_path/'other')
    handle_normalized_event(generic_event(other,EventKind.SESSION_START),coordinator=core)
    (repo/'A.java').write_bytes(b'changed')
    runtime.calls.clear()
    out,_=handle_normalized_event(generic_event(other,EventKind.WORKSPACE_ACTIVITY),coordinator=core)
    assert out['status']=='NO_CHANGE' and not runtime.calls


def test_persistent_normalized_diagnostics_and_privacy(repo,tmp_path):
    core=coordinator(tmp_path,FakeRuntime(),cooldown_ms=0)
    normalized,diag,reason=bound(repo,args(repo,tool='Bash',command='git status'))
    store=RecentHookStore(tmp_path/'diagnostics.db')
    observer=Observation('handle_hook_event',args(repo),store)
    observer.bind(repo);token=CURRENT.set(observer)
    try:
        out,_=handle_normalized_event(normalized,coordinator=core)
        observer.finish(out)
    finally:CURRENT.reset(token)
    row=RecentHookStore(store.path).recent(repo)['records'][0]
    assert row['normalized_event_kind']=='WORKSPACE_ACTIVITY'
    assert row['normalized_operation_class']=='READ_ONLY'
    assert row['workspace_binding_status']=='BINDING_CONSISTENT'
    assert row['scanner_run'] is False
    encoded=json.dumps(row)
    for raw in ('private-session-fixture','private-turn-fixture','git status'):
        assert raw not in encoded
    assert 'tool_input' not in row and row['host_capabilities']['supports_tool_input'] is True


def test_mcp_legacy_and_normalized_diagnostics_together(connected,projects):
    server,_,_=connected
    out=invoke(server,claims(projects[0]))
    assert out['tool_classification']=='READ_ONLY'
    assert out['normalized_operation_class']=='READ_ONLY'
    assert out['reason']=='READ_ONLY_BASH' and out['scanner_run'] is False


def test_capabilities_and_host_neutral_control_flow():
    adapter=CodexEventAdapter()
    assert adapter.capabilities.supports_stop and adapter.capabilities.supports_invocation_id
    assert adapter.capabilities.supports_global_install and not adapter.capabilities.supports_workspace_open
    from security_runtime import host_event_runtime
    tree=ast.parse(Path(host_event_runtime.__file__).read_text(encoding='utf-8'))
    prohibited={'Bash','apply_patch','Edit','Write','PostToolUse','SessionStart','Stop','codex'}
    assert not {n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)} & prohibited
    assert not any(isinstance(n,ast.ImportFrom) and n.module and 'codex' in n.module for n in ast.walk(tree))


def test_adapter_cannot_normalize_before_binding_validation(repo):
    with pytest.raises(ValueError,match='Validated Codex binding required'):
        CodexEventAdapter().normalize(args(repo),repo)


def test_direct_mutation_hint_is_not_filesystem_proof(repo,tmp_path):
    runtime=FakeRuntime();core=coordinator(tmp_path,runtime,cooldown_ms=0)
    handle_normalized_event(generic_event(repo,EventKind.SESSION_START),coordinator=core)
    runtime.calls.clear()
    event=replace(generic_event(repo,EventKind.WORKSPACE_ACTIVITY,
        OperationClass.DIRECT_FILE_MUTATION),mutation_hint=True)
    out,_=handle_normalized_event(event,coordinator=core)
    assert out['status']=='NO_CHANGE' and out['workspace_mutation_observed'] is False
    assert not runtime.calls


def test_normalized_stop_guard_receives_same_host_namespace(repo,tmp_path):
    core=coordinator(tmp_path,FakeRuntime())
    seen=[]
    class Guard:
        def handle(self,root,session,active,*,host):
            seen.append((root,session,active,host))
            return {'status':'ALLOW_STOP'}
    event=generic_event(repo,EventKind.SESSION_STOP)
    out,decision=handle_normalized_event(event,coordinator=core,continuation=Guard())
    assert seen==[(repo,'neutral-session',False,'generic')]
    assert out['status']=='ALLOW_STOP' and decision is None and not core.runtime.calls
