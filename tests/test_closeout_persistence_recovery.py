"""Real child-process exits around durable facts; detector output is simulated."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from security_runtime.closeout import CloseoutService
from security_runtime.closeout_state import CloseoutStateStore
from security_runtime.hook_state import HookStateStore
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import GitleaksAdapter, ScannerRegistry
from security_runtime.storage import SQLiteStore
from test_secret_recheck_coverage import secret_engine  # noqa: F401
from test_closeout_regression import closeout_fixture


CHILD = r'''
import json, os, sys
from pathlib import Path
import pytest
from test_secret_recheck_coverage import secret_engine
from test_closeout_regression import closeout_fixture
from security_runtime.closeout_state import CloseoutStateStore
base=Path(sys.argv[1]); phase=sys.argv[2]
mp=pytest.MonkeyPatch()
engine=secret_engine.__wrapped__(base,mp)
service,_,_=closeout_fixture(engine,base)
root=engine[0]
service.hooks.pending_activity(root,'codex','session',mark=True)
job=service.prepare(root,['fixture.ts'],host='codex',session='session')
(base/'navigation.json').write_text(json.dumps({'ref':job['closeout_ref']}))
if phase=='source':
    original=CloseoutStateStore.finish
    def stopped(self,*args,**kwargs):
        result=original(self,*args,**kwargs)
        if kwargs.get('persistence') is not None and result[1]: os._exit(71)
        return result
    mp.setattr(CloseoutStateStore,'finish',stopped)
else:
    original=service.closures.record
    def stopped(*args,**kwargs):
        result=original(*args,**kwargs)
        if kwargs.get('effect_id') and result['status']=='SAVED': os._exit(72)
        return result
    mp.setattr(service.closures,'record',stopped)
service.run(job['closeout_ref'],root)
raise AssertionError('The requested hard-exit boundary was not reached')
'''


def snapshot(directory):
    return {str(p): p.read_bytes() for p in directory.rglob('*') if p.is_file()}


def recovered_service(base):
    runtime = SecurityRuntime(ScannerRegistry([GitleaksAdapter()]), SQLiteStore(base/'state'/'runtime.db'))
    def unexpected(*args, **kwargs):
        raise AssertionError('Recovery must not execute another scanner')
    runtime.scan = unexpected
    return CloseoutService(runtime, HookStateStore(base/'hooks'))


@pytest.mark.parametrize('phase,exit_code', [('source',71), ('target',72)])
def test_hard_exit_recovers_same_source_without_scanning_and_get_is_readonly(tmp_path, phase, exit_code):
    env = dict(os.environ)
    env['PYTHONPATH'] = os.pathsep.join([str(Path(__file__).parent), str(Path(__file__).parents[1]/'src')])
    child = subprocess.run([sys.executable,'-B','-c',CHILD,str(tmp_path),phase],
        env=env,capture_output=True,text=True,timeout=90)
    assert child.returncode == exit_code, child.stdout + child.stderr
    ref = json.loads((tmp_path/'navigation.json').read_text())['ref']
    root = tmp_path/'project'
    service = recovered_service(tmp_path)
    original_scans = service.runtime.store.latest_scan(root)
    before = snapshot(tmp_path)
    pending = service.get(ref,root)
    assert pending['status'] == 'NEEDS_RETRY' and pending['current_version'] is False
    assert pending['receipt']['persistence_sync']['state'] == 'PENDING'
    assert all(pending['receipt'][key] is False for key in
        ('current_version','check_completed','credential_closure_complete','risk_fix_complete'))
    assert snapshot(tmp_path) == before
    assert len(service._store(root).pending_effects(ref, service._workspace(root))) == 1
    completed = service.run(ref,root)
    assert completed['status'] == 'COMPLETED' and completed['recovered'] and not completed['scanner_run']
    assert completed['execution_accepted'] and completed['receipt']['risk_fix_complete']
    assert completed['receipt']['persistence_sync']['state'] == 'APPLIED'
    assert not service.hooks.pending_activity(root,'codex','session')
    assert len(service.closures._read(root)) == 2
    assert service.runtime.store.latest_scan(root) == original_scans
    assert service._store(root).pending_effects(ref, service._workspace(root)) == []


def prepared(secret_engine,tmp_path):
    service,_,_=closeout_fixture(secret_engine,tmp_path)
    root=secret_engine[0]
    service.hooks.pending_activity(root,'codex','session',mark=True)
    return service,root,service.prepare(root,['fixture.ts'],host='codex',session='session')


def test_source_ack_failure_recovers_after_its_own_pending_completion(secret_engine,tmp_path,monkeypatch):
    service,root,job=prepared(secret_engine,tmp_path)
    original=CloseoutStateStore.acknowledge_effect
    def failed(*args,**kwargs):raise OSError('injected source ACK failure')
    monkeypatch.setattr(CloseoutStateStore,'acknowledge_effect',failed)
    result=service.run(job['closeout_ref'],root)
    assert result['status']=='NEEDS_RETRY' and not result['receipt']['risk_fix_complete']
    assert result['source_result_saved'] is True
    assert '原检查结果已保存' in result['user_feedback']['message']
    assert not service.hooks.pending_activity(root,'codex','session')
    calls=secret_engine[3]['calls']
    monkeypatch.setattr(CloseoutStateStore,'acknowledge_effect',original)
    resumed=service.run(job['closeout_ref'],root)
    assert resumed['status']=='COMPLETED' and resumed['receipt']['risk_fix_complete']
    assert secret_engine[3]['calls']==calls


@pytest.mark.parametrize('change',['source','event','new-owner'])
def test_pending_source_never_overwrites_new_source_event_or_same_generation_owner(
        secret_engine,tmp_path,monkeypatch,change):
    service,root,job=prepared(secret_engine,tmp_path)
    original=service.closures.record
    monkeypatch.setattr(service.closures,'record',lambda *a,**k: (_ for _ in ()).throw(OSError('target unavailable')))
    service.run(job['closeout_ref'],root)
    store=service._store(root);before=store.get(job['closeout_ref'],service._workspace(root))
    assert before['receipt']['persistence_sync']['state']=='PENDING'
    monkeypatch.setattr(service.closures,'record',original)
    if change=='source':
        (root/'fixture.ts').write_text('export const NEW_PUBLIC_FIXTURE="fixture-canary";\n')
    elif change=='event':
        service.hooks.pending_activity(root,'codex','session',mark=True)
    else:
        claimed,owner=store.claim(job['closeout_ref'],service._workspace(root),
            before['prepared_revision'],before['plan_fingerprint'],recover=True)
        assert claimed['generation']==before['generation'] and owner
        receipt=dict(before['receipt'],marker='new-owner',current_version=False)
        newest,accepted=store.finish(job['closeout_ref'],service._workspace(root),claimed['generation'],owner,
            status='NEEDS_RETRY',coverage='UNKNOWN',receipt=receipt)
        assert accepted
    calls=secret_engine[3]['calls']
    result=service.run(job['closeout_ref'],root)
    assert result['recovered'] and not result['execution_accepted']
    assert not result['receipt']['risk_fix_complete']
    assert not service.closures._read(root) and secret_engine[3]['calls']==calls
    if change=='new-owner':assert store.get(job['closeout_ref'],service._workspace(root))==newest


def test_new_target_authority_version_supersedes_old_closeout_without_overwrite(secret_engine,tmp_path,monkeypatch):
    service,root,job=prepared(secret_engine,tmp_path)
    original=service.closures.record
    monkeypatch.setattr(service.closures,'record',lambda *a,**k: (_ for _ in ()).throw(OSError('target unavailable')))
    service.run(job['closeout_ref'],root)
    monkeypatch.setattr(service.closures,'record',original)
    with service.hooks.lock(root) as acquired:
        assert acquired
        service.closures.record(root,[],[],source='newer-independent-fact',effect_id='newer-target',locked=True)
    target=service.closures._authority(root).read()
    calls=secret_engine[3]['calls']
    result=service.run(job['closeout_ref'],root)
    assert result['recovered'] and not result['execution_accepted']
    assert not result['receipt']['risk_fix_complete']
    assert service.closures._authority(root).read()==target
    assert secret_engine[3]['calls']==calls


def test_source_ack_cannot_change_same_generation_new_owner_after_target_commit(secret_engine,tmp_path,monkeypatch):
    service,root,job=prepared(secret_engine,tmp_path)
    original=CloseoutStateStore.acknowledge_effect
    retained={}
    def newer(self,effect,**kwargs):
        current=self.get(effect['closeout_ref'],effect['workspace_id'])
        latest,owner=self.claim(effect['closeout_ref'],effect['workspace_id'],
            current['prepared_revision'],current['plan_fingerprint'],recover=True)
        assert owner and latest['generation']==effect['generation']
        receipt=dict(current['receipt'],marker='new-owner-after-target')
        saved,accepted=self.finish(effect['closeout_ref'],effect['workspace_id'],latest['generation'],owner,
            status='NEEDS_RETRY',coverage='UNKNOWN',receipt=receipt)
        assert accepted
        service.hooks.pending_activity(root,'codex','session',mark=True)
        retained.update(saved)
        return original(self,effect,**kwargs)
    monkeypatch.setattr(CloseoutStateStore,'acknowledge_effect',newer)
    result=service.run(job['closeout_ref'],root)
    assert not result['execution_accepted'] and not result['receipt']['risk_fix_complete']
    assert service._store(root).get(job['closeout_ref'],service._workspace(root))==retained
    assert service.hooks.pending_activity(root,'codex','session')


def test_corrupt_outbox_is_not_an_empty_queue_and_readonly_get_keeps_pending(secret_engine,tmp_path,monkeypatch):
    import sqlite3
    service,root,job=prepared(secret_engine,tmp_path)
    monkeypatch.setattr(service.closures,'record',lambda *a,**k: (_ for _ in ()).throw(OSError('target unavailable')))
    service.run(job['closeout_ref'],root)
    store=service._store(root)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE closeout_effect_outbox SET data='{invalid' WHERE state='PENDING'")
    before=snapshot(tmp_path)
    result=service.get(job['closeout_ref'],root)
    assert not result['receipt']['risk_fix_complete'] and not result['current_version']
    assert snapshot(tmp_path)==before
    calls=secret_engine[3]['calls']
    with pytest.raises(ValueError):service.run(job['closeout_ref'],root)
    assert snapshot(tmp_path)==before and secret_engine[3]['calls']==calls


def test_interrupted_target_migration_is_resumed_only_by_run(secret_engine,tmp_path,monkeypatch):
    from security_runtime.private_authority import PrivateAuthority
    service,root,job=prepared(secret_engine,tmp_path)
    original=PrivateAuthority._backup
    def interrupted(self,transition):
        if self.old.name=='closures.state':raise OSError('interrupted target migration')
        return original(self,transition)
    monkeypatch.setattr(PrivateAuthority,'_backup',interrupted)
    result=service.run(job['closeout_ref'],root)
    assert result['receipt']['persistence_sync']['state']=='PENDING'
    assert service.closures._authority(root).journal.exists()
    calls=secret_engine[3]['calls']
    before=snapshot(tmp_path)
    assert not service.get(job['closeout_ref'],root)['receipt']['risk_fix_complete']
    assert snapshot(tmp_path)==before
    monkeypatch.setattr(PrivateAuthority,'_backup',original)
    resumed=service.run(job['closeout_ref'],root)
    assert resumed['receipt']['risk_fix_complete'] and resumed['recovered']
    assert secret_engine[3]['calls']==calls


def test_historical_target_inbox_cannot_confirm_newer_same_risk_facts(secret_engine,tmp_path,monkeypatch):
    service,root,job=prepared(secret_engine,tmp_path)
    original=CloseoutStateStore.acknowledge_effect
    monkeypatch.setattr(CloseoutStateStore,'acknowledge_effect',
        lambda *a,**k: (_ for _ in ()).throw(OSError('source ACK unavailable')))
    service.run(job['closeout_ref'],root)
    store=service._store(root)
    effect=store.pending_effects(job['closeout_ref'],service._workspace(root))[0]
    assert service.closures.effect_current(root,effect['event_id'])
    with service.hooks.lock(root) as acquired:
        assert acquired
        service.closures.record(root,effect['details']['members'],effect['receipt']['risk_verification'],
            source='NEWER_INDEPENDENT_RECHECK',generation=100,locked=True)
    target=service.closures._authority(root).read()
    assert not service.closures.effect_current(root,effect['event_id'])
    calls=secret_engine[3]['calls']
    monkeypatch.setattr(CloseoutStateStore,'acknowledge_effect',original)
    result=service.run(job['closeout_ref'],root)
    assert result['persistence_recovery']['state']=='SUPERSEDED'
    assert not result['execution_accepted'] and not result['receipt']['risk_fix_complete']
    assert service.closures._authority(root).read()==target and secret_engine[3]['calls']==calls


def test_new_event_during_final_presentation_cannot_report_current_risk_closed(secret_engine,tmp_path,monkeypatch):
    service,root,job=prepared(secret_engine,tmp_path)
    original=service._present
    def arrived(*args,**kwargs):
        service.hooks.pending_activity(root,'codex','session',mark=True)
        return original(*args,**kwargs)
    monkeypatch.setattr(service,'_present',arrived)
    result=service.run(job['closeout_ref'],root)
    assert not result['current_version'] and result['risk_status']=='UNCONFIRMED_OR_PRESENT'
