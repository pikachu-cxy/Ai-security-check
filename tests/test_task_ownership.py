"""Independent owners, reference fencing, orphan recovery and shared-checkout gaps."""
import asyncio
import json

import pytest

from security_runtime import task_ownership as own
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.mcp_server import create_server
from security_runtime.task_security import TaskSecurityService
from security_runtime.task_hook_activity import _record_task_hook
from test_task_security import service, LedgerRuntime


def scoped(sample, label, clock=None):
    legacy,root,runtime=sample
    return TaskSecurityService(runtime,legacy.hooks,owner=own.session_owner('codex',label),
        **({'now':clock} if clock else {}))


def test_parallel_sessions_same_key_have_independent_baselines(service):
    _,root,_=service;a,b=scoped(service,'a'),scoped(service,'b')
    first=a.begin(root,'development');second=b.begin(root,'development')
    assert first['status']==second['status']=='ACTIVE' and first['task_ref']!=second['task_ref']
    assert a.begin(root,'development')['task_ref']==first['task_ref']
    assert b.begin(root,'development')['task_ref']==second['task_ref']
    assert a.store(root).get(active=True) is None
    assert a.store(root).get(active=True,owner=a._owner())['task_ref']==first['task_ref']


def test_other_session_cannot_close_or_prepare_a_task(service):
    _,root,_=service;a,b=scoped(service,'a'),scoped(service,'b')
    ref=a.begin(root,'first')['task_ref']
    for action in [lambda:b.finish(root,ref),lambda:b.skip(root,ref,'incorrect owner'),lambda:b.prepare(root,ref)]:
        with pytest.raises(ValueError,match='another session'):action()
    assert a.load(root,ref)['phase']=='ACTIVE'


def test_signed_historical_read_does_not_adopt_or_extend_task(service):
    _,root,runtime=service;a,b=scoped(service,'a'),scoped(service,'b')
    ref=a.begin(root,'first')['task_ref'];before=a.store(root).path.read_bytes()
    assert b.get(root,ref)['status']=='ACTIVE'
    assert a.store(root).path.read_bytes()==before and not runtime.calls
    with pytest.raises(ValueError):b.skip(root,ref,'read is not adoption')


def test_same_session_can_create_distinct_tasks_without_guessing_latest(service):
    _,root,_=service;a=scoped(service,'a')
    one=a.begin(root,'one')['task_ref'];two=a.begin(root,'two')['task_ref']
    assert one!=two and a.store(root).get(active=True,owner=a._owner()) is None
    assert a.store(root).for_hook('codex',a._owner()['session']) is None


def test_old_unowned_task_is_retained_and_does_not_block_scoped_begin(service):
    old,root,_=service;legacy=old.begin(root,'old')['task_ref']
    a=scoped(service,'a');new=a.begin(root,'new')['task_ref']
    assert legacy!=new and old.load(root,legacy)['phase']=='ACTIVE'
    with pytest.raises(ValueError):a.skip(root,legacy,'do not retire an unknown owner')


def test_hook_updates_only_its_exact_session_and_ref(service):
    _,root,_=service;a,b=scoped(service,'a'),scoped(service,'b')
    ar=a.begin(root,'a')['task_ref'];br=b.begin(root,'b')['task_ref']
    event=dict(host='codex',session_id=a._owner()['session'],status='DEFERRED',
        workspace_mutation_observed=True,execution={'scanner_run':False},delta={},hook_scope_files=['routes.py'])
    task,state=_record_task_hook(a.hooks,root,event,None)
    assert state=='RECORDED' and task['task_ref']==ar
    assert not b.load(root,br).get('hook_checks')
    assert _record_task_hook(a.hooks,root,event,None,expected_task_ref=br)[1]=='TASK_OWNER_MISMATCH'
    assert not b.load(root,br).get('hook_checks')


@pytest.mark.parametrize('observed',[None,'unchanged'])
def test_lease_expiry_does_not_end_an_unknown_or_live_process(service,monkeypatch,observed):
    _,root,_=service;clock=[1000.0];a=scoped(service,'a',lambda:clock[0])
    ref=a.begin(root,'one')['task_ref'];record=a.load(root,ref)
    monkeypatch.setattr(own,'process_stamp',lambda pid:record['writer']['stamp'] if observed=='unchanged' else None)
    clock[0]+=own.LEASE_SECONDS+1
    a.begin(root,'two')
    assert a.load(root,ref)['phase']=='ACTIVE'


def test_dead_historical_writer_stays_read_only_without_blocking_new_v3_key(service,monkeypatch):
    _,root,_=service;clock=[1000.0];a=scoped(service,'a',lambda:clock[0])
    ref=a.begin(root,'one')['task_ref'];record=a.load(root,ref)
    record['static']={'findings':[{'id':'retained-risk','category':'authorization'}]}
    record['review_protocol']=2  # A signed record issued by an older Runtime.
    historical=a.store(root).save(record)
    clock[0]+=own.LEASE_SECONDS+1
    monkeypatch.setattr(own,'process_stamp',lambda pid:False)
    fresh=a.begin(root,'two')
    assert fresh['status']=='ACTIVE' and fresh['task_ref']!=ref
    old=a.load(root,ref)
    assert old==historical and old['static']['findings'][0]['id']=='retained-risk'
    assert a.load(root,fresh['task_ref'])['review_protocol']==3


def test_overlapping_checkout_never_reports_a_full_review(service):
    _,root,_=service;a,b=scoped(service,'a'),scoped(service,'b')
    ar=a.begin(root,'a')['task_ref'];br=b.begin(root,'b')['task_ref']
    (root/'routes.py').write_text('def route(): return 1\n')
    result=a.finish(root,ar)
    assert any(v['reason']=='CONCURRENT_TASK_ATTRIBUTION_UNAVAILABLE' for v in result['limitations'])
    packet=a.prepare(root,ar,protocol_version=3)
    submitted=a.submit(root,ar,packet['review_session'],[],'REVIEWED',[])
    assert submitted['result_saved'] and not submitted['scanner_run']
    assert a.get(root,ar)['host_review']['coverage']=='PARTIAL'
    assert b.load(root,br)['phase']=='ACTIVE'


def call(server,name,**args):
    result=asyncio.run(server._tool_manager.call_tool(name,args,convert_result=True))
    return result.structuredContent if hasattr(result,'structuredContent') else json.loads(result[0].text)


def test_separate_mcp_connections_do_not_adopt_or_block_each_other(service):
    legacy,root,runtime=service;core=HookCoordinator(runtime,legacy.hooks)
    a=create_server(runtime,hook_coordinator=core,global_mode=False)
    b=create_server(runtime,hook_coordinator=core,global_mode=False)
    ar=call(a,'begin_security_task',workspace_path=str(root),task_key='same')['task_ref']
    br=call(b,'begin_security_task',workspace_path=str(root),task_key='same')['task_ref']
    assert ar!=br
    with pytest.raises(Exception,match='another session'):
        call(b,'finish_security_task',workspace_path=str(root),task_ref=ar,skip_review_reason='foreign')
    assert call(a,'finish_security_task',workspace_path=str(root),task_ref=ar,skip_review_reason='Own task stopped')['status']=='INCOMPLETE'
    assert call(b,'get_task_security_review',workspace_path=str(root),task_ref=br)['status']=='ACTIVE'


def test_verified_session_can_resume_after_reconnect_but_not_as_other_chat(service):
    legacy,root,runtime=service;core=HookCoordinator(runtime,legacy.hooks)
    a=create_server(runtime,hook_coordinator=core,global_mode=False)
    with own.owner_scope(own.session_owner('codex','same-chat')):
        ref=call(a,'begin_security_task',workspace_path=str(root),task_key='one')['task_ref']
    b=create_server(runtime,hook_coordinator=core,global_mode=False)
    with own.owner_scope(own.session_owner('codex','other-chat')):
        with pytest.raises(Exception,match='another session'):
            call(b,'finish_security_task',workspace_path=str(root),task_ref=ref,skip_review_reason='foreign')
    with own.owner_scope(own.session_owner('codex','same-chat')):
        result=call(b,'finish_security_task',workspace_path=str(root),task_ref=ref,skip_review_reason='Own interrupted task')
    assert result['status']=='INCOMPLETE'


def test_process_identity_is_read_only_and_validates_input():
    import os
    assert own.process_stamp(0) is None and own.process_stamp('123') is None
    assert own.process_stamp(os.getpid()) is None or isinstance(own.process_stamp(os.getpid()),str)
    assert not own.writer_gone({'pid':os.getpid(),'stamp':own.process_stamp(os.getpid())})


def test_signed_session_ref_rejects_tampering_expiry_and_other_workspace(service,tmp_path):
    legacy,root,_=service
    token=own.issue_session_ref(legacy.hooks,root,'codex','private-session',now=1000)
    assert 'private-session' not in token
    assert own.verify_session_ref(legacy.hooks,root,token,now=1001)==own.session_owner('codex','private-session')
    other=tmp_path/'other';other.mkdir()
    before=set(legacy.hooks.directory.rglob('*'))
    for invalid,workspace,instant in [(token[:-1]+('0' if token[-1]!='0' else '1'),root,1001),
            (token,root,999),(token,root,1000+own.SESSION_TTL),(token,other,1001),('x'*2000,root,1001)]:
        with pytest.raises(ValueError,match='invalid, expired'):
            own.verify_session_ref(legacy.hooks,workspace,invalid,now=instant)
    assert set(legacy.hooks.directory.rglob('*'))==before


def test_signed_session_survives_mcp_reconnect_without_new_baseline(service):
    legacy,root,runtime=service;core=HookCoordinator(runtime,legacy.hooks)
    token=own.issue_session_ref(core.store,root,'codex','same-chat')
    a=create_server(runtime,hook_coordinator=core,global_mode=False)
    ref=call(a,'begin_security_task',workspace_path=str(root),task_key='one',session_ref=token)['task_ref']
    baseline=legacy.store(root).get(ref)['baseline']
    (root/'routes.py').write_text('value = 1\n')
    b=create_server(runtime,hook_coordinator=core,global_mode=False)
    wrong=own.issue_session_ref(core.store,root,'codex','other-chat')
    with pytest.raises(Exception,match='another session'):
        call(b,'finish_security_task',workspace_path=str(root),task_ref=ref,session_ref=wrong)
    result=call(b,'finish_security_task',workspace_path=str(root),task_ref=ref,session_ref=token)
    assert result['status']=='READY' and legacy.store(root).get(ref)['baseline']['hashes']==baseline['hashes']
    assert len(legacy.store(root).records())==1 and len(runtime.calls)==1
    assert call(b,'prepare_task_security_review',workspace_path=str(root),task_ref=ref,protocol_version=3)['review_session']


def test_cursor_pre_edit_task_finishes_through_actual_mcp_connection(service):
    from security_runtime.cursor_tasks import CursorTaskBridge
    legacy,root,runtime=service;core=HookCoordinator(runtime,legacy.hooks)
    bridge=CursorTaskBridge(core,root,'cursor-session','generation')
    before=bridge.before(dict(tool_name='Edit',tool_input={},conversation_id='cursor-session'))
    context=bridge.context();args=json.loads(context.splitlines()[1])
    baseline=legacy.store(root).get(before['task_ref'])['baseline']
    (root/'routes.py').write_text('value = 2\n')
    server=create_server(runtime,hook_coordinator=core,global_mode=False)
    result=call(server,'finish_security_task',**args)
    assert result['status']=='READY' and result['task_ref']==before['task_ref']
    assert legacy.store(root).get(before['task_ref'])['baseline']['hashes']==baseline['hashes']
    assert len(legacy.store(root).records())==1


def test_late_hook_never_writes_a_closed_task(service):
    _,root,_=service;a=scoped(service,'a');ref=a.begin(root,'a')['task_ref']
    a.skip(root,ref,'Stopped before review')
    before=a.load(root,ref)
    event=dict(host='codex',session_id=a._owner()['session'],workspace_mutation_observed=True)
    assert _record_task_hook(a.hooks,root,event,None,expected_task_ref=ref)[1]=='TASK_CLOSED'
    assert a.load(root,ref)==before


def test_ephemeral_hook_exit_does_not_prove_conversation_ended(service,monkeypatch):
    legacy,root,runtime=service;clock=[1000.0]
    owner=own.session_owner('cursor','chat')
    tasks=TaskSecurityService(runtime,legacy.hooks,now=lambda:clock[0],owner=owner)
    ref=tasks.begin(root,'automatic',_owner=owner)['task_ref']
    assert tasks.load(root,ref)['writer'] is None
    monkeypatch.setattr(own,'process_stamp',lambda pid:False)
    clock[0]+=own.LEASE_SECONDS+1
    tasks.begin(root,'new-task')
    assert tasks.load(root,ref)['phase']=='ACTIVE'
