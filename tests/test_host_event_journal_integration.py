"""Real coordinator/task paths keep durable claims outside scan authority."""
import json

import pytest

from security_runtime.host_event_journal import HostEventJournal, JournalError
from security_runtime.host_event_runtime import handle_normalized_event
from security_runtime.hook_state import identity
from security_runtime.tasks.hook_activity import _record_task_hook
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.security_state import TaskSecurityStore
from test_host_event_journal import event,owner
from test_hook_runtime import repo,coordinator,FakeRuntime,dirty


@pytest.fixture
def active(repo,tmp_path):
    core=coordinator(tmp_path,FakeRuntime(),cooldown_ms=0)
    core.handle('SESSION_START',repo,'codex','private-session')
    value=event(repo)
    tasks=TaskSecurityService(core.runtime,core.store,owner=owner(value))
    ref=tasks.begin(repo,'original')['task_ref']
    dirty(repo,'class Changed {}\n')
    return core,tasks,ref,value


def run(active):
    core,_,_,value=active
    return handle_normalized_event(value,coordinator=core)[0]


def record(active,result):
    return _record_task_hook(active[0].store,active[3].context.workspace,result,None,
                             expected_task_ref=active[2])


def test_real_call_runs_once_and_duplicate_reuses_original_task_row(active):
    core,tasks,ref,value=active;root=value.context.workspace
    first=run(active)
    assert first['execution']['scanner_run'] and first['event_processing']['state']=='COMPLETED'
    saved,recording=record(active,first)
    assert recording=='RECORDED' and len(saved['hook_checks'])==1
    assert saved['hook_checks'][0]['event_ref']==first['event_processing']['event_ref']
    baseline=saved['baseline'];count=len(core.runtime.calls)
    assert core.store.pending_activity(root,'codex','private-session') is None
    duplicate=run(active)
    again,recording=record(active,duplicate)
    assert duplicate['event_processing']['state']=='ALREADY_COMPLETED'
    assert not duplicate['execution']['scanner_run'] and len(core.runtime.calls)==count
    assert recording=='ALREADY_RECORDED' and again==saved and again['baseline']==baseline
    assert core.store.pending_activity(root,'codex','private-session') is None


def test_ack_failure_keeps_committed_row_then_only_reconciles_link(active,monkeypatch):
    core,_,_,value=active;root=value.context.workspace
    first=run(active);ack=HostEventJournal.ack_task
    monkeypatch.setattr(HostEventJournal,'ack_task',lambda *a,**k: (_ for _ in ()).throw(JournalError('unavailable')))
    saved,recording=record(active,first)
    assert recording=='RECORDED' and first['event_processing']['task_linkage']=='PENDING'
    journal=HostEventJournal(core.store,root);reference=first['event_processing']['event_ref']
    assert journal.get(reference,owner(value))['task_link'] is None
    count=len(core.runtime.calls)
    monkeypatch.setattr(HostEventJournal,'ack_task',ack)
    duplicate=run(active);again,recording=record(active,duplicate)
    assert recording=='ALREADY_RECORDED' and again==saved and len(core.runtime.calls)==count
    assert journal.get(reference,owner(value))['task_link']['recording']=='RECORDED'


def test_execution_crash_is_uncertain_and_records_gap_without_rescan(active,monkeypatch):
    core,tasks,ref,value=active;original=core.handle
    def crashed(*args,**kwargs):
        original(*args,**kwargs)
        raise RuntimeError('private executor failure')
    monkeypatch.setattr(core,'handle',crashed)
    with pytest.raises(RuntimeError):run(active)
    count=len(core.runtime.calls)
    monkeypatch.setattr(core,'handle',original)
    replay=run(active)
    assert replay['event_processing']['state']=='EXECUTION_UNCONFIRMED'
    assert not replay['execution']['scanner_run'] and len(core.runtime.calls)==count
    saved,recording=record(active,replay)
    assert recording=='FAILURE_MARKER_RECORDED' and not saved.get('hook_checks')
    store=TaskSecurityStore(core.store,value.context.workspace)
    marker=store.get_hook_failure(ref)
    assert marker['failure_count']==1 and marker['scope_files']==[]
    saved2,recording=record(active,run(active))
    assert recording=='ALREADY_RECORDED' and store.get_hook_failure(ref)==marker
    assert saved2==saved and len(core.runtime.calls)==count


def test_late_replay_does_not_attach_to_new_active_task(active):
    core,tasks,ref,value=active;root=value.context.workspace
    original=run(active);count=len(core.runtime.calls)
    tasks.skip(root,ref,'Explicitly switch to later work.')
    fresh=tasks.begin(root,'later')['task_ref']
    current=tasks.load(root,fresh)
    replay=run(active)
    assert replay['security_task_ref']==ref and replay['event_processing']['task_ref']==ref
    assert _record_task_hook(core.store,root,replay,None)==(None,'TASK_CLOSED')
    assert tasks.load(root,fresh)==current and len(core.runtime.calls)==count


@pytest.mark.parametrize('original_bound',[True,False])
def test_journal_claim_cannot_adopt_task_created_before_core_claim(active,monkeypatch,original_bound):
    from task_review_helpers import review_all
    core,tasks,ref,value=active;root=value.context.workspace
    if not original_bound:
        tasks.skip(root,ref,'Explicitly close earlier work before an unbound event.')
    original_start=HostEventJournal.start
    later={}
    def switch_after_claim(journal,claim):
        assert claim.task_ref==(ref if original_bound else None)
        started=original_start(journal,claim)
        assert started
        if original_bound:
            tasks.finish(root,ref)
            packet=tasks.prepare(root,ref)
            tasks.review_method(root,ref,packet['review_session'])
            review_all(tasks,root,ref,packet)
            tasks.submit(root,ref,packet['review_session'],[],'REVIEWED',[])
            assert tasks.load(root,ref)['phase']=='COMPLETE'
        fresh=tasks.begin(root,'explicit-later-work')['task_ref']
        later.update(ref=fresh,record=tasks.load(root,fresh),calls=len(core.runtime.calls))
        return started
    monkeypatch.setattr(HostEventJournal,'start',switch_after_claim)
    result=run(active)
    assert result['reason']=='EVENT_TASK_BINDING_CHANGED'
    assert result['event_processing']['task_ref']==(ref if original_bound else None)
    assert not result['execution']['scanner_run'] and len(core.runtime.calls)==later['calls']
    assert result.get('security_task_ref')!=(later['ref'])
    assert tasks.load(root,later['ref'])==later['record']
    assert not later['record'].get('hook_checks')
    assert core.store.pending_activity(root,'codex','private-session') is not None
    _,recording=_record_task_hook(core.store,root,result,None)
    assert recording==('TASK_CLOSED' if original_bound else 'NOT_APPLICABLE')
    assert tasks.load(root,later['ref'])==later['record']


def test_completed_effect_without_task_row_preserves_original_scan_gap(active):
    core,_,ref,value=active;first=run(active);count=len(core.runtime.calls)
    # Simulate process termination after event completion and before task row.
    replay=run(active);_,recording=record(active,replay)
    assert recording=='FAILURE_MARKER_RECORDED'
    marker=TaskSecurityStore(core.store,value.context.workspace).get_hook_failure(ref)
    assert marker['scan_ids']==[first['scan_id']] and len(core.runtime.calls)==count


def test_completion_ack_failure_keeps_result_and_original_row(active,monkeypatch):
    core,_,_,value=active
    monkeypatch.setattr(HostEventJournal,'complete',lambda *a,**k: False)
    result=run(active)
    assert result['execution']['scanner_run'] and result['event_processing']['state']=='COMPLETION_PENDING'
    saved,recording=record(active,result)
    assert recording=='RECORDED' and saved['hook_checks'][0]['scan_id']==result['scan_id']
    assert result['event_processing']['task_linkage']=='PENDING'
    count=len(core.runtime.calls)
    replay=run(active);again,recording=record(active,replay)
    assert replay['event_processing']['state']=='IN_PROGRESS'
    assert recording=='ALREADY_RECORDED' and again==saved and len(core.runtime.calls)==count


def test_journal_failure_never_dispatches_or_grants_authority(active,monkeypatch):
    core,_,_,value=active;count=len(core.runtime.calls)
    monkeypatch.setattr(HostEventJournal,'claim',lambda *a,**k: (_ for _ in ()).throw(JournalError('private error')))
    result=run(active)
    assert result['reason']=='JOURNAL_UNAVAILABLE' and not result['execution']['scanner_run']
    assert len(core.runtime.calls)==count and 'private error' not in json.dumps(result)
    assert not result['event_processing']['exact_call_deduplication']


def test_codex_fresh_connection_guard_replay_uses_durable_claim_and_keeps_pending_clear(active):
    from security_runtime.codex_mcp_hook import handle_codex_hook
    from security_runtime.codex_host_claims import CodexClaimGuard
    from test_codex_mcp_hook import binding
    from test_hook_runtime import row
    core,_,ref,value=active;root=value.context.workspace
    core.runtime.findings = [row(root)]
    def hook():
        return handle_codex_hook('PostToolUse',str(root),'private-session','Write',
            binding=binding(root),coordinator=core,turn_id='private-turn',tool_use_id='actual-call',
            permission_mode='default',claim_guard=CodexClaimGuard())
    first=hook();count=len(core.runtime.calls)
    assert first['scanner_run'] and first['event_processing']['state']=='COMPLETED'
    assert first['task_delivery']['delivery_receipt']['response_prepared']
    assert not first['task_delivery']['delivery_receipt']['transport_written']
    row=TaskSecurityStore(core.store,root).get(ref)
    assert row['hook_checks'][0]['event_ref']==first['event_processing']['event_ref']
    assert core.store.pending_activity(root,'codex','private-session') is None
    replay=hook()
    assert replay['event_processing']['state']=='ALREADY_COMPLETED' and not replay['scanner_run']
    assert replay['hook_check_recording']=='ALREADY_RECORDED' and len(core.runtime.calls)==count
    assert TaskSecurityStore(core.store,root).get(ref)==row
    assert core.store.pending_activity(root,'codex','private-session') is None
