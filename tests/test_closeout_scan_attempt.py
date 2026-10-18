"""Real fixed-input execution and publication fences in explicit closeouts."""
from dataclasses import asdict

import pytest

from test_secret_recheck_coverage import secret_engine, original
from test_closeout_regression import closeout_fixture
from security_runtime.scan_attempt import AttemptLease, ScanAttemptStore
from security_runtime.progress import ScanCancelled
from security_runtime.verification import VerificationService


def test_closeout_primary_and_origin_recheck_share_input_with_workspace_lock_released(secret_engine,tmp_path,monkeypatch):
    service,_,_=closeout_fixture(secret_engine,tmp_path)
    root,_,adapter,_,_=secret_engine
    job=service.prepare(root,['fixture.ts'],host='codex',session='session')
    invoke=adapter.scan;seen=[]
    def observed(context,normalizer):
        with service.hooks.lock(root,wait_seconds=0) as acquired:
            assert acquired, 'Provider executed while workspace lock was held'
        assert context.input_view is not None
        seen.append(context.input_view.input_id)
        return invoke(context,normalizer)
    monkeypatch.setattr(adapter,'scan',observed)
    result=service.run(job['closeout_ref'],root)
    assert result['status']=='COMPLETED' and result['execution_accepted']
    assert len(seen)==2 and len(set(seen))==1
    assert result['receipt']['scan_attempt']['input_id']==seen[0]
    assert result['receipt']['scan_attempt']['publication']=='ACCEPTED'
    attempts=ScanAttemptStore(service.hooks,root).read()
    assert attempts['lane']['state']=='COMPLETED' and attempts['directories']==[]
    scan=service.runtime.store.get_scan(result['receipt']['scan_id'])
    assert scan['scan_context']['execution_attempt']['publication']=='PENDING'
    from security_runtime.scan_freshness import summary
    historical=summary(scan,service.runtime.store,root)
    assert historical['task_publication']=='NOT_DERIVED_FROM_SCAN_HISTORY'
    assert historical['execution_attempt']['current_check_proof'] is False
    assert not historical['full_project_reusable']


def test_claimed_source_a_cannot_accept_captured_b_after_source_returns_to_a(secret_engine,tmp_path,monkeypatch):
    service,_,_=closeout_fixture(secret_engine,tmp_path)
    root,path,_,state,_=secret_engine
    job=service.prepare(root,['fixture.ts'],host='codex',session='session')
    before=path.read_bytes();invoke=service.runtime.scan;count=state['calls']
    def substitute(*args,**kwargs):
        path.write_text('export const PUBLIC_FAKE_FIXTURE="fixture-canary";\n')
        try:return invoke(*args,**kwargs)
        finally:path.write_bytes(before)
    monkeypatch.setattr(service.runtime,'scan',substitute)
    result=service.run(job['closeout_ref'],root)
    assert result['status']=='NEEDS_RETRY' and not result['execution_accepted']
    assert state['calls']==count and path.read_bytes()==before
    assert not service.closures._read(root)
    assert ScanAttemptStore(service.hooks,root).read()['directories']==[]


def test_live_edit_during_origin_recheck_does_not_change_captured_bytes_or_close_risk(secret_engine,tmp_path,monkeypatch):
    service,_,_=closeout_fixture(secret_engine,tmp_path)
    root,path,adapter,_,_=secret_engine
    service.hooks.pending_activity(root,'codex','session',mark=True)
    job=service.prepare(root,['fixture.ts'],host='codex',session='session')
    invoke=VerificationService.verify_many
    def edited(self,workspace,members,scan,**kwargs):
        view=kwargs['input_view'];before=(view.execution_root/'fixture.ts').read_bytes()
        path.write_text('export const NEW_PUBLIC_FIXTURE="fixture-canary";\n')
        service.hooks.pending_activity(root,'codex','session',mark=True)
        result=invoke(self,workspace,members,scan,**kwargs)
        assert (view.execution_root/'fixture.ts').read_bytes()==before
        assert all(row['verification_status']=='SCANNER_VERIFIED_RESOLVED' for row in result)
        return result
    monkeypatch.setattr(VerificationService,'verify_many',edited)
    result=service.run(job['closeout_ref'],root)
    assert result['status']=='NEEDS_RETRY' and result['risk_status']=='UNCONFIRMED_OR_PRESENT'
    assert result['receipt']['current_version'] is False
    assert service.hooks.pending_activity(root,'codex','session')
    assert not service.closures._read(root)


def test_cancelled_attempt_keeps_baseline_original_risk_and_pending_activity(secret_engine,tmp_path,monkeypatch):
    service,_,_=closeout_fixture(secret_engine,tmp_path)
    root,_,adapter,_,_=secret_engine
    service.hooks.pending_activity(root,'codex','session',mark=True)
    before,_=service.hooks.load(service.hooks.path(root,'codex','session'))
    job=service.prepare(root,['fixture.ts'],host='codex',session='session')
    invoke=adapter.scan
    def cancel(context,normalizer):
        attempts=ScanAttemptStore(service.hooks,root)
        row=attempts.read()['lane']
        lease=AttemptLease(**{key:row[key] for key in ('attempt_id','generation','lease_owner','cancel_generation')})
        with service.hooks.lock(root) as acquired:
            assert acquired and attempts.cancel(lease)
        raise ScanCancelled()
    monkeypatch.setattr(adapter,'scan',cancel)
    result=service.run(job['closeout_ref'],root)
    assert result['status']=='NEEDS_RETRY' and not result['execution_accepted']
    assert result['reason']=='SCAN_ATTEMPT_CANCELLED'
    after,_=service.hooks.load(service.hooks.path(root,'codex','session'))
    assert after==before and not service.closures._read(root)
    assert service.hooks.pending_activity(root,'codex','session')


def test_origin_verification_does_not_swallow_cooperative_cancellation(secret_engine,monkeypatch):
    findings,run=original(secret_engine)
    root,_,adapter,_,_=secret_engine
    def cancel(*args):raise ScanCancelled()
    monkeypatch.setattr(adapter,'scan',cancel)
    from security_runtime.scanners import ScannerRegistry
    with pytest.raises(ScanCancelled):
        VerificationService(ScannerRegistry([adapter])).verify_many(root,[asdict(f) for f in findings],
            {'target_profile':{'files':['fixture.ts']},'scanner_runs':[asdict(run)]})


def test_closure_failure_after_partial_scan_clears_only_its_saved_proof_flags(secret_engine,tmp_path,monkeypatch):
    service,_,_=closeout_fixture(secret_engine,tmp_path)
    root,_,adapter,_,_=secret_engine
    job=service.prepare(root,['fixture.ts'],host='codex',session='session')
    invoke=adapter.scan
    def partial(context,normalizer):
        findings,run=invoke(context,normalizer)
        if context.mode=='quick':run.status='FAILED'
        return findings,run
    monkeypatch.setattr(adapter,'scan',partial)
    def failed(*args,**kwargs):raise OSError('injected persistence failure')
    monkeypatch.setattr(service.closures,'record',failed)
    result=service.run(job['closeout_ref'],root)
    assert result['status']=='NEEDS_RETRY' and not result['execution_accepted']
    saved=service._store(root).get(job['closeout_ref'],service._workspace(root))
    assert saved['receipt']['persistence_status']=='INCOMPLETE'
    for key in ('current_version','check_completed','risk_fix_complete','credential_closure_complete'):
        assert saved['receipt'][key] is False


def test_late_exception_cannot_invalidate_same_generation_new_owner_receipt(secret_engine,tmp_path,monkeypatch):
    service,_,_=closeout_fixture(secret_engine,tmp_path)
    root=secret_engine[0]
    job=service.prepare(root,['fixture.ts'],host='codex',session='session')
    store=service._store(root);invoke=service.runtime.scan;retained={}
    def newer_owner(*args,**kwargs):
        scan=invoke(*args,**kwargs)
        old=store.get(job['closeout_ref'],service._workspace(root))
        newer,owner=store.claim(job['closeout_ref'],service._workspace(root),
            old['prepared_revision'],old['plan_fingerprint'],recover=True)
        assert owner is not None and newer['generation']==old['generation']
        receipt={'generation':newer['generation'],'current_version':True,'check_completed':True,
            'risk_fix_complete':True,'credential_closure_complete':True,'marker':'other-owner'}
        saved,accepted=store.finish(job['closeout_ref'],service._workspace(root),newer['generation'],owner,
            status='COMPLETED',coverage='FULL',receipt=receipt,scan_id=scan.scan_id)
        assert accepted
        retained.update(saved)
        raise OSError('late old runner failure')
    monkeypatch.setattr(service.runtime,'scan',newer_owner)
    result=service.run(job['closeout_ref'],root)
    assert not result['execution_accepted']
    assert store.get(job['closeout_ref'],service._workspace(root))==retained
    assert retained['receipt']['marker']=='other-owner' and retained['status']=='COMPLETED'
