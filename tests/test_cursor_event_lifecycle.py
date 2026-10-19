import json
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

from security_runtime.cursor_hook import CursorBindings, handle_cursor_event
from security_runtime.hook_runtime import capture_snapshot
from security_runtime.hook_state import HookStateStore
from security_runtime.recent_hooks import RecentHookStore, safe_fields
from test_hook_runtime import repo, coordinator, FakeRuntime, row
from test_cursor_host_adapter import payload


def ingress(repo, tmp_path, core, *, event='afterFileEdit', **fields):
    return handle_cursor_event(payload(repo,event,**fields), core=core,
        bindings=CursorBindings(tmp_path/'bindings'), project_dir=str(repo),
        store=RecentHookStore(tmp_path/'recent.db'))[1]


def test_session_snapshot_only_duplicate_retains_pre_edit(repo,tmp_path):
    runtime=FakeRuntime(); core=coordinator(tmp_path,runtime)
    result=ingress(repo,tmp_path,core,event='sessionStart',generation_id='')
    assert result['status']=='BASELINE_ESTABLISHED' and result['host_claim_status']=='VALID'
    assert result['event_dispatch_route']=='SESSION_BASELINE'
    assert result['baseline_state_before']=='MISSING' and result['baseline_state_after']=='AVAILABLE'
    assert result['baseline_publish_status']=='PUBLISHED' and result['scanner_invocation_count']==0
    assert not result['scanner_run'] and not runtime.calls and result['coverage']=='UNKNOWN'
    state=core.store.path(repo,'cursor','private-cursor-conversation'); before=state.read_bytes()
    (repo/'A.java').write_text('class A { int timeout=2400; }')
    duplicate=ingress(repo,tmp_path,core,event='sessionStart')
    assert duplicate['baseline_publish_status']=='RETAINED' and state.read_bytes()==before
    record=RecentHookStore(tmp_path/'recent.db').recent(repo)['records'][-1]
    assert record['scanner_trigger_reason'] is None and 'BASELINE_PUBLISHED' in {p['stage'] for p in record['stages']}


@pytest.mark.parametrize('event',['afterFileEdit','afterShellExecution'])
def test_digest_delta_once_same_bytes_revert_and_no_cooldown_loss(repo,tmp_path,event):
    runtime=FakeRuntime(); core=coordinator(tmp_path,runtime)
    (repo/'A.java').write_bytes(b'class A { int timeout=2300; }\r\n')
    ingress(repo,tmp_path,core,event='sessionStart')
    (repo/'A.java').write_bytes(b'class A { int timeout=2400; }\r\n')
    fields={'command':'Set-Content A.java private-command'} if event=='afterShellExecution' else {}
    result=ingress(repo,tmp_path,core,event=event,**fields)
    assert result['event_dispatch_route']=='WORKSPACE_RECONCILIATION'
    assert result['snapshot_source']=='SESSION_BASELINE' and result['changed_file_count']==1
    assert result['workspace_mutation_observed'] and result['scanner_run']
    assert result['scanner_invocation_count']==1 and runtime.calls==[('A.java',)]
    assert not result['pending_mutation'] and not result['mutation_event_dropped']
    assert ingress(repo,tmp_path,core,event=event,**fields)['status']=='NO_CHANGE'
    (repo/'A.java').write_bytes(b'\xef\xbb\xbfclass A { int timeout=2500; }\r\n')
    next_edit=ingress(repo,tmp_path,core,event=event,**fields)
    assert next_edit['scanner_run'] and len(runtime.calls)==2  # No Stop scanner to drain a debounce.
    (repo/'A.java').write_bytes(b'temporary')
    (repo/'A.java').write_bytes(b'\xef\xbb\xbfclass A { int timeout=2500; }\r\n')
    assert ingress(repo,tmp_path,core,event=event,**fields)['status']=='NO_CHANGE'


@pytest.mark.parametrize('baseline',[True,False])
def test_stop_never_scans_or_creates_baseline_even_changed(repo,tmp_path,baseline):
    runtime=FakeRuntime(); core=coordinator(tmp_path,runtime)
    if baseline: ingress(repo,tmp_path,core,event='sessionStart')
    state=core.store.path(repo,'cursor','private-cursor-conversation')
    before=state.read_bytes() if state.exists() else None
    (repo/'A.java').write_text('changed')
    result=ingress(repo,tmp_path,core,event='stop')
    assert result['event_dispatch_route']=='SESSION_FINALIZATION' and not result['scanner_run']
    assert result['status']==('SESSION_FINALIZED' if baseline else 'INCONCLUSIVE')
    assert result['reason']==(None if baseline else 'SESSION_STOP_WITHOUT_BASELINE')
    assert (state.read_bytes() if state.exists() else None)==before and not runtime.calls


def test_readonly_never_enters_reconciliation_or_scanner(repo,tmp_path):
    runtime=FakeRuntime(); core=coordinator(tmp_path,runtime)
    ingress(repo,tmp_path,core,event='sessionStart')
    (repo/'A.java').write_text('mutation by another tool')
    result=ingress(repo,tmp_path,core,event='afterShellExecution',command='git status')
    assert result['scanner_skipped_reason']=='READ_ONLY_ACTIVITY' and not runtime.calls
    assert ingress(repo,tmp_path,core)['scanner_run']


def test_failed_session_capture_lazy_activity_does_not_fake_attribution(repo,tmp_path):
    runtime=FakeRuntime([row(repo)]); core=coordinator(tmp_path,runtime)
    core.snapshot_capture=lambda *a: (_ for _ in ()).throw(ValueError('private-source-error'))
    result=ingress(repo,tmp_path,core,event='sessionStart')
    assert result['reason']=='BASELINE_CAPTURE_FAILED' and result['baseline_publish_status']=='FAILED'
    assert result['baseline_state_after']=='MISSING' and not runtime.calls
    assert result['scan_attempt']['publication']=='NOT_PUBLISHED'
    from security_runtime.scan_attempt import ScanAttemptStore
    assert ScanAttemptStore(core.store,repo).read()['lane']['state']=='FAILED'
    core.snapshot_capture=capture_snapshot
    (repo/'A.java').write_text('changed')
    result=ingress(repo,tmp_path,core)
    assert result['snapshot_available'] is False and result['workspace_mutation_observed'] is None
    assert result['reason']=='FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT' and result['delta']['new']==0
    assert result['scanner_run'] and len(runtime.calls)==1


def test_comparison_baseline_is_not_empty_security_proof(repo,tmp_path):
    runtime=FakeRuntime([row(repo)]); core=coordinator(tmp_path,runtime)
    ingress(repo,tmp_path,core,event='sessionStart')
    (repo/'A.java').write_text('changed')
    result=ingress(repo,tmp_path,core)
    assert result['workspace_mutation_observed'] and result['scanner_run']
    assert result['delta']['new']==0 and result['reason']=='FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT'
    # A fake/incomplete detector is not equivalent pre-edit proof. Keep the
    # comparison baseline instead of promoting current risk to trusted history.
    state=core.store.load(core.store.path(repo,'cursor','private-cursor-conversation'))[0]
    assert not state['families'] and state['last_result']['status']=='COMPARISON_BASELINE'


def test_multifile_scope_excludes_unchanged_pre_existing_dirty_file(repo,tmp_path):
    runtime=FakeRuntime(); core=coordinator(tmp_path,runtime)
    (repo/'preexisting.java').write_text('class Preexisting {}')
    ingress(repo,tmp_path,core,event='sessionStart')
    (repo/'A.java').write_text('class A {}')
    (repo/'B.java').write_text('class B {}')
    result=ingress(repo,tmp_path,core)
    assert result['changed_file_count']==2 and runtime.calls==[('A.java','B.java')]


def test_failed_scan_keeps_pending_and_previous_snapshot_for_retry(repo,tmp_path):
    runtime=FakeRuntime(status='FAILED'); core=coordinator(tmp_path,runtime)
    ingress(repo,tmp_path,core,event='sessionStart')
    path=core.store.path(repo,'cursor','private-cursor-conversation'); before=path.read_bytes()
    (repo/'A.java').write_text('changed')
    result=ingress(repo,tmp_path,core)
    assert result['status']=='FAILED' and result['pending_mutation'] and path.read_bytes()==before
    runtime.status='SUCCESS'
    assert ingress(repo,tmp_path,core)['scanner_run'] and len(runtime.calls)==2
    assert core.store.pending_activity(repo,'cursor','private-cursor-conversation') is None


def child(repo,tmp_path,mode):
    return subprocess.Popen([sys.executable,str(Path(__file__).parent/'fixtures/cursor_lifecycle_process.py'),
        str(repo),str(tmp_path),mode],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        text=True,encoding='utf-8',env={**os.environ,'PYTHONUTF8':'1'})


def release(proc):
    proc.stdin.write('release\n'); proc.stdin.flush()


def result(proc):
    out,err=proc.communicate(timeout=20)
    assert proc.returncode==0,err
    return json.loads(out.splitlines()[-1])


@pytest.mark.parametrize('mode',['publish','capture'])
def test_independent_process_session_activity_overlap(repo,tmp_path,mode):
    (repo/'A.java').write_text('class A { int timeout=2300; }')
    start=child(repo,tmp_path,mode); edit=None
    try:
        assert start.stdout.readline().strip()==('SNAPSHOT_READY' if mode=='publish' else 'CAPTURE_PENDING')
        (repo/'A.java').write_text('class A { int timeout=2400; }')
        edit=child(repo,tmp_path,'activity')
        assert edit.stdout.readline().strip()=='ACTIVITY_MARKED'
        release(start)
        began=result(start); changed=result(edit)
        assert not began['result']['scanner_run'] and not began['scopes']
        assert not changed['result']['mutation_event_dropped']
        if mode=='publish':
            assert changed['result']['scanner_run'] and changed['scopes']==[['A.java']]
            assert not changed['result']['pending_mutation']
            assert began['result']['baseline_publish_status']=='PUBLISHED'
            assert changed['result']['workspace_mutation_observed'] and changed['result']['changed_file_count']==1
            assert changed['result']['activity_waited_for_baseline']
        else:
            # Capture is now outside the OS state lock. A competing mutation
            # sees the durable lane BUSY and keeps intent instead of waiting
            # inside a long source transaction or executing a second scan.
            assert changed['result']['reason']=='WORKSPACE_SCAN_ATTEMPT_BUSY'
            assert not changed['result']['scanner_run'] and not changed['scopes']
            assert changed['result']['pending_mutation']
            assert began['result']['reason']=='BASELINE_ATTRIBUTION_UNAVAILABLE'
            retried=result(child(repo,tmp_path,'activity'))
            assert retried['result']['scanner_run'] and retried['scopes']==[['A.java']]
            assert retried['result']['workspace_mutation_observed'] is None
            assert retried['result']['delta']['new']==0 and not retried['result']['pending_mutation']
        duplicate=result(child(repo,tmp_path,'activity'))
        assert duplicate['result']['status']=='NO_CHANGE' and not duplicate['scopes']
    finally:
        for proc in (start,edit):
            if proc is not None and proc.poll() is None:
                proc.kill(); proc.communicate(timeout=10)


def test_lock_timeout_is_persistent_pending_then_retry_not_lost(repo,tmp_path):
    runtime=FakeRuntime(); core=coordinator(tmp_path,runtime)
    core.store.directory=tmp_path/'hooks'
    ingress(repo,tmp_path,core,event='sessionStart')
    # Worker shares exactly the same Core state directory, different OS process.
    original=core.store.lock
    worker=child(repo,tmp_path,'hold')
    try:
        assert worker.stdout.readline().strip()=='LOCKED'
        @contextmanager
        def bounded(root, **kwargs):
            with original(root,wait_seconds=.03) as acquired: yield acquired
        core.store.lock=bounded
        (repo/'A.java').write_text('changed')
        result_=ingress(repo,tmp_path,core)
        assert result_['reason']=='WORKSPACE_SINGLE_FLIGHT_TIMEOUT' and result_['pending_mutation']
        assert not result_['mutation_event_dropped'] and not runtime.calls
        assert HookStateStore(tmp_path/'hooks').pending_activity(repo,'cursor','private-cursor-conversation')
        release(worker); worker.communicate(timeout=10)
        core.store.lock=original
        result_=ingress(repo,tmp_path,core)
        assert result_['scanner_run'] and result_['changed_file_count']==1 and len(runtime.calls)==1
        assert not result_['pending_mutation']
    finally:
        if worker.poll() is None:worker.kill(); worker.communicate(timeout=10)


def test_pending_conditional_completion_never_erases_new_arrival(repo,tmp_path):
    store=HookStateStore(tmp_path/'state')
    one=store.pending_activity(repo,'cursor','session',mark=True)
    two=store.pending_activity(repo,'cursor','session',mark=True)
    assert one!=two and store.pending_activity(repo,'cursor','session',completed=one)==two
    assert store.pending_activity(repo,'cursor','session',completed=two) is None
    three=store.pending_activity(repo,'cursor','session',mark=True)
    assert three!=one and store.pending_activity(repo,'cursor','session',completed=one)==three


def test_lifecycle_diagnostics_are_closed_safe_fields():
    source=dict(event_dispatch_route='SESSION_BASELINE',baseline_state_before='MISSING',baseline_state_after='AVAILABLE',
        baseline_publish_status='PUBLISHED',activity_waited_for_baseline=True,activity_wait_ms=25.5,busy_reason=None,
        mutation_event_dropped=False,scanner_invocation_count=0,pending_mutation=True,
        source='private-source',command='private-command',session_id='private-session')
    safe=safe_fields(source)
    assert 'private-' not in json.dumps(safe) and safe['activity_wait_ms']==25.5
    assert safe_fields(dict(event_dispatch_route='private-command'))['event_dispatch_route']=='UNKNOWN'
