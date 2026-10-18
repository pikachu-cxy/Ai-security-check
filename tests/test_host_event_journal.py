"""Durable claims bound to real calls; elapsed leases never prove no execution."""
import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import replace

import pytest

from security_runtime.hook_state import HookStateStore, identity
from security_runtime.host_events import EventKind, NormalizedHostEvent, OperationClass, VerifiedHostContext
from security_runtime.host_lifecycle import HostCapabilities
from security_runtime.host_event_journal import HostEventJournal, JournalError


def event(root, invocation='real-call', session='private-session'):
    context = VerifiedHostContext('codex', root, identity(os.path.normcase(str(root))),
        identity(session), identity(invocation), HostCapabilities(supports_invocation_id=True), session)
    return NormalizedHostEvent(EventKind.WORKSPACE_ACTIVITY, context, OperationClass.DIRECT_FILE_MUTATION)


@pytest.fixture
def journal(tmp_path):
    root=tmp_path/'workspace';root.mkdir()
    return HostEventJournal(HookStateStore(tmp_path/'state'), root)


def owner(value):
    return dict(host=value.context.host, session=value.context.session_binding)


def test_recreated_instance_deduplicates_and_never_exposes_claim_capability(journal):
    value=event(journal.root);claim=journal.claim(value)
    assert claim.state=='CLAIMED' and journal.start(claim)
    assert journal.complete(claim, {'scan_id':'scan-1','execution':{'scanner_run':True},'source':'private-source'})
    other=HostEventJournal(journal.hooks,journal.root)
    assert other.claim(value).state=='ALREADY_COMPLETED'
    assert not other.start(claim) and not other.complete(claim, {})
    view=other.get(claim.event_ref,owner(value))
    assert view['outcome']==dict(scan_id='scan-1',scanner_run=True)
    assert view['task_link'] is None
    encoded=json.dumps(view)+json.dumps(claim.facts())+repr(claim)
    assert claim.token not in encoded
    with sqlite3.connect(journal.path) as db:
        raw=db.execute('SELECT data FROM host_events').fetchone()[0]
    assert 'private-source' not in raw and 'private-session' not in raw and 'real-call' not in raw
    assert claim.token not in raw


def test_fencing_only_reclaims_before_dispatch_and_expired_execution_stays_uncertain(journal):
    now=[100.];journal.now=lambda:now[0]
    value=event(journal.root);old=journal.claim(value,lease_seconds=1)
    assert journal.claim(value).state=='IN_PROGRESS'
    now[0]+=2
    fresh=journal.claim(value,lease_seconds=1)
    assert fresh.fence==old.fence+1 and not journal.start(old)
    assert not journal.renew(old) and journal.start(fresh)
    now[0]+=2
    assert journal.claim(value).state=='EXECUTION_UNCONFIRMED'
    assert not journal.complete(fresh, {}) and not journal.start(fresh)
    assert journal.get(fresh.event_ref,owner(value))['state']=='UNCERTAIN'
    now[0]+=100000
    assert journal.claim(value).state=='EXECUTION_UNCONFIRMED'


def test_live_owner_renews_and_atomic_task_ack_is_bound(journal):
    now=[100.];journal.now=lambda:now[0]
    value=event(journal.root);claim=journal.claim(value,lease_seconds=1)
    assert journal.start(claim)
    now[0]+=.5
    assert journal.renew(claim,lease_seconds=2)
    now[0]+=1
    assert journal.complete(claim, {})
    task='ts1-'+'a'*32
    assert journal.ack_task(claim.event_ref,owner(value),task)
    assert not journal.ack_task(claim.event_ref,owner(value),task)
    with pytest.raises(JournalError,match='changed'):
        journal.ack_task(claim.event_ref,owner(value),'ts1-'+'b'*32)
    with pytest.raises(JournalError,match='owner'):
        journal.get(claim.event_ref,dict(host='codex',session='0'*64))
    with pytest.raises(JournalError,match='owner'):
        journal.ack_task(claim.event_ref,dict(host='codex',session='0'*64),task)


@pytest.mark.parametrize('mode',['no-id','unsupported-id','read-only','start','stop'])
def test_nonapplicable_events_create_no_journal(journal,mode):
    value=event(journal.root)
    if mode=='no-id':value=replace(value,context=replace(value.context,invocation_binding=None))
    elif mode=='unsupported-id':value=replace(value,context=replace(value.context,capabilities=HostCapabilities()))
    elif mode=='read-only':value=replace(value,operation=OperationClass.READ_ONLY)
    elif mode=='start':value=replace(value,kind=EventKind.SESSION_START,operation=OperationClass.UNKNOWN)
    else:value=replace(value,kind=EventKind.SESSION_STOP,operation=OperationClass.UNKNOWN,stop_guard_active=False)
    claim=journal.claim(value)
    assert claim.state=='CONTENT_RECONCILIATION_ONLY' and not claim.facts()['exact_call_deduplication']
    assert not journal.start(claim) and not journal.complete(claim,{}) and not journal.uncertain(claim)
    assert not journal.path.exists() and not journal.path.parent.exists()


def test_binding_conflict_tampering_and_pending_capacity_fail_closed(journal):
    journal.max_rows=1
    value=event(journal.root);claim=journal.claim(value)
    assert journal.claim(replace(value,operation=OperationClass.UNKNOWN)).state=='BINDING_CONFLICT'
    with pytest.raises(JournalError,match='capacity'):
        journal.claim(event(journal.root,'second'))
    assert journal.start(claim) and journal.uncertain(claim)
    journal.now=lambda:10**12
    with pytest.raises(JournalError,match='capacity'):
        journal.claim(event(journal.root,'second'))
    with sqlite3.connect(journal.path) as db:
        db.execute('UPDATE host_events SET data=?',('{"source":"must-not-echo"}',))
    with pytest.raises(JournalError,match='verified') as caught:
        journal.claim(value)
    assert 'must-not-echo' not in str(caught.value)


def test_only_verified_terminal_rows_expire(journal):
    journal.max_rows=1;journal.retention_seconds=10;now=[100.];journal.now=lambda:now[0]
    value=event(journal.root);claim=journal.claim(value)
    assert journal.start(claim) and journal.complete(claim,{})
    now[0]+=11
    assert journal.claim(event(journal.root,'second')).state=='CLAIMED'
    assert journal.get(claim.event_ref,owner(value)) is None


def test_completed_execution_with_unacknowledged_task_link_never_expires(journal):
    journal.max_rows=1;journal.retention_seconds=1;now=[100.];journal.now=lambda:now[0]
    value=event(journal.root);claim=journal.claim(value,task_ref='ts1-'+'a'*32)
    assert journal.start(claim) and journal.complete(claim,{})
    now[0]+=10
    with pytest.raises(JournalError,match='capacity'):
        journal.claim(event(journal.root,'second'))
    assert journal.ack_task(claim.event_ref,owner(value),'ts1-'+'a'*32)
    now[0]+=10
    assert journal.claim(event(journal.root,'second')).state=='CLAIMED'


@pytest.mark.parametrize('tamper',['copied-ref','unicode-mac','invalid-json'])
def test_journal_row_binding_and_corrupt_signatures_fail_closed(journal,tamper):
    value=event(journal.root);claim=journal.claim(value)
    with sqlite3.connect(journal.path) as db:
        if tamper=='copied-ref':
            db.execute('UPDATE host_events SET ref=?',('hev1-'+'0'*64,))
        elif tamper=='unicode-mac':
            db.execute('UPDATE host_events SET mac=?',('坏',))
        else:db.execute('UPDATE host_events SET data=?',('private not json',))
    reference='hev1-'+'0'*64 if tamper=='copied-ref' else claim.event_ref
    with pytest.raises(JournalError,match='verified'):
        journal.get(reference,owner(value))


def test_independent_processes_admit_one_real_call(journal):
    # The journal's BEGIN IMMEDIATE, rather than process-local locks, decides.
    code = '''from pathlib import Path
import os,sys
from security_runtime.hook_state import HookStateStore,identity
from security_runtime.host_events import EventKind,NormalizedHostEvent,OperationClass,VerifiedHostContext
from security_runtime.host_lifecycle import HostCapabilities
from security_runtime.host_event_journal import HostEventJournal
root=Path(sys.argv[2]);session='process-session'
context=VerifiedHostContext('codex',root,identity(os.path.normcase(str(root))),identity(session),identity('call'),HostCapabilities(supports_invocation_id=True),session)
event=NormalizedHostEvent(EventKind.WORKSPACE_ACTIVITY,context,OperationClass.DIRECT_FILE_MUTATION)
print(HostEventJournal(HookStateStore(Path(sys.argv[1])),root).claim(event).state,flush=True)
'''
    children=[subprocess.Popen([sys.executable,'-c',code,str(journal.hooks.directory),str(journal.root)],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(2)]
    results=[]
    try:
        for child in children:
            out,err=child.communicate(timeout=15)
            assert child.returncode==0,err
            results.append(out.strip())
    finally:
        for child in children:
            if child.poll() is None:child.kill();child.wait()
    assert sorted(results)==['CLAIMED','IN_PROGRESS']
