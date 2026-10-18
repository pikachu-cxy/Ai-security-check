"""Regression guards for first closeout, bounded source reads and per-risk outcomes."""
from dataclasses import asdict
import json
import pytest
from test_task_security import service, begin, candidate, prepared
from task_review_helpers import evidence_id,read_plan,read_window,review_all
from security_runtime.task_risk_ledger import TaskRiskLedger
from security_runtime.verification import declared_dependency_proof
from security_runtime.models import ScannerRun

def test_prepare_performs_missing_first_closeout_once(service):
    s, root, runtime = service
    ref = begin(service)
    (root/'routes.py').write_text('def changed():\n    return 1\n')
    packet = s.prepare(root, ref)
    assert packet['status'] == 'REVIEW_REQUIRED' and len(runtime.calls) == 1
    assert s.prepare(root, ref)['review_session'] == packet['review_session']
    assert len(runtime.calls) == 1
    (root/'routes.py').write_text('def changed():\n    return 2\n')
    assert s.prepare(root, ref)['status'] == 'STALE' and len(runtime.calls) == 1

def test_early_prepare_no_changes_is_quiet_and_running_is_busy(service):
    s, root, runtime = service
    ref = begin(service)
    assert s.prepare(root, ref)['status'] == 'NO_CHANGES' and not runtime.calls
    second = s.begin(root, 'second')['task_ref']
    record = s.load(root, second)
    record['phase'] = 'STATIC_RUNNING'
    s.store(root).save(record)
    assert s.prepare(root,second)['status']=='STALE'  # A bare old phase is no lease.
    from security_runtime.scan_attempt import ScanAttemptStore,source_binding
    with s.hooks.lock(root):
        lease=ScanAttemptStore(s.hooks,root,now=s.now).claim('TASK',second,source_binding({'task':second}))
        record=s.load(root,second)
        record['static_execution']=lease.receipt
        s.store(root).save(record)
    assert s.prepare(root, second)['status'] == 'BUSY' and not runtime.calls

def test_long_test_source_is_read_once_in_same_budget(service):
    s, root, runtime = service
    (root/'tests').mkdir()
    (root/'tests/test_long.py').write_text('old = 1\n')
    ref = begin(service)
    (root/'tests/test_long.py').write_text(''.join(f'item_{i} = {i}\n' for i in range(206)))
    packet = s.prepare(root, ref)
    units,_=read_plan(s,root,ref,packet)
    assert any(window['path']=='tests/test_long.py' for unit in units for window in unit['required_windows'])
    session=packet['review_session']
    pages=read_window(s,root,ref,session,dict(path='tests/test_long.py',start_line=1,end_line=206,
                                           location_version='CURRENT_TASK_END'))
    assert sum(len(page.get('lines',[])) for page in pages)==206
    assert all(len(page.get('lines',[]))<=80 for page in pages)
    before=s.read(root,ref,session,'tests/test_long.py',1,1,'BEFORE_TASK')
    assert s.load(root,ref)['evidence'][evidence_id(before)]['location_version']=='BEFORE_TASK'
    assert 'old = ' in before['lines'][0]
    s.read(root,ref,session,'auth.py',1,2)
    review_all(s,root,ref,packet)
    charged=s.load(root,ref)['review_ledger']
    source_bytes,reads=charged['source_bytes'],charged['reads']
    duplicate=s.read(root,ref,session,'tests/test_long.py',1,80)
    assert duplicate['status']=='ALREADY_DELIVERED'
    assert s.load(root,ref)['review_ledger']['source_bytes']==source_bytes
    assert s.load(root,ref)['review_ledger']['reads']==reads
    saved=s.submit(root,ref,session,[],'REVIEWED',[])
    assert saved['result_saved']
    out=s.get(root,ref)
    assert out['context_read_coverage']['unread_range_count']==0
    assert out['context_read_coverage']['plan_gap_count']==0
    assert out['context_read_coverage']['used_bytes'] <= out['context_read_coverage']['max_bytes']

def register_host(sample):
    s,root,runtime=sample
    ref,session,packet=prepared(sample)
    entry=s.read(root,ref,session,'routes.py',1,2)
    auth=s.read(root,ref,session,'auth.py',1,2)
    review_all(s,root,ref,packet)
    receipt=s.submit(root,ref,session,[candidate(evidence_id(entry),evidence_id(auth))],'REVIEWED',[])
    assert receipt['result_saved']
    out=s.get(root,ref)
    finding=next(row for row in out['findings'] if row['source']=='HOST_TASK_REVIEW')
    return ref,finding['detail']['id']

def test_host_closure_links_original_id_and_becomes_stale_after_edit(service):
    s,root,runtime=service
    original,fid=register_host(service)
    assert s.risk_ledger(root,original)['counts']=={'OPEN':1}
    ref=s.begin(root,'fix-approved')['task_ref']
    (root/'routes.py').write_text('def get_order(order_id, user):\n    return load_owned_order(order_id, user)\n')
    p=s.prepare(root,ref); session=p['review_session']
    entry=s.read(root,ref,session,'routes.py',1,2)
    auth=s.read(root,ref,session,'auth.py',1,2)
    review_all(s,root,ref,p)
    resolution=dict(original_task_ref=original,finding_id=fid,
        evidence_refs=[evidence_id(entry),evidence_id(auth)],outcome='CODE_REVIEWED_RESOLVED',
        rationale='Ownership checked before repository operation.',tests='Host ran targeted ownership test.')
    s.submit(root,ref,session,[],'REVIEWED',[],[resolution])
    ledger=s.risk_ledger(root,original)
    assert ledger['counts']=={'CODE_REVIEWED_RESOLVED':1}
    assert not ledger['repair_authorized'] and not ledger['production_safety_verified']
    assert ledger['items'][0]['evidence_type']=='HOST_CODE_REVIEW_NOT_SCANNER_PROOF'
    (root/'routes.py').write_text('unsafe again\n')
    assert s.risk_ledger(root,original)['counts']=={'NEEDS_RECHECK':1}

def test_host_cannot_close_without_original_paths_or_forge_native_proof(service):
    s,root,_=service
    original,fid=register_host(service)
    ref=s.begin(root,'fix')['task_ref']; (root/'routes.py').write_text('fixed\n')
    p=s.prepare(root,ref); e=s.read(root,ref,p['review_session'],'routes.py',1,1)
    row=dict(original_task_ref=original,finding_id=fid,evidence_refs=[evidence_id(e)],
        outcome='CODE_REVIEWED_RESOLVED',rationale='fixed',tests='test')
    with pytest.raises(ValueError,match='call/control'):
        s.submit(root,ref,p['review_session'],[],'REVIEWED',[],[row])
    row['outcome']='SCANNER_VERIFIED_RESOLVED'
    with pytest.raises(ValueError,match='outcome'):
        s.submit(root,ref,p['review_session'],[],'REVIEWED',[],[row])
    assert s.risk_ledger(root,original)['counts']=={'NEEDS_RECHECK':1}

def test_ledger_tamper_rejected(service):
    s,root,_=service; original,_=register_host(service)
    ledger=TaskRiskLedger(s.hooks,root)
    index=ledger.authority.read()['partitions'][original]
    shard=ledger.partitions.directory/index['file']
    data=json.loads(shard.read_bytes())
    next(iter(data['content']['rows'].values()))['status']='SCANNER_VERIFIED_RESOLVED'
    shard.write_text(json.dumps(data))
    with pytest.raises(ValueError,match='partition content changed'):
        s.risk_ledger(root,original)

def proof_fixture():
    row=dict(category='dependency',technical_details=dict(ecosystem='npm',package='lodash',vulnerability_id='CVE-fixture'))
    run=ScannerRun('trivy-vuln','0.74.0','SUCCESS',1,coverage_contract='PARTIAL',
        coverage_notes=['Offline Trivy extraction does not attest a complete resolved dependency graph.'],
        dependency_inventory=dict(vulnerability_db_freshness='FRESH', inventory_truncated=False,
            per_manifest={'package-lock.json':1},package_coordinates=[dict(manifest='package-lock.json',ecosystem='npm',package='lodash',version='4.18.0')]))
    return row,run

def test_scoped_dependency_proof_keeps_graph_and_install_unknown():
    row,run=proof_fixture()
    proof=declared_dependency_proof(row,run,'package-lock.json',True)
    assert proof['scope']=='DECLARED_PACKAGE_ADVISORY' and proof['versions']==['4.18.0']
    assert not proof['complete_dependency_graph_verified'] and not proof['installed_package_verified']
    assert run.coverage_contract=='PARTIAL'

@pytest.mark.parametrize('gap',['STALE','UNKNOWN','MISSING','package','manifest','truncated','warning','process'])
def test_scoped_dependency_absence_needs_all_proof(gap):
    row,run=proof_fixture(); observed=True
    if gap in {'STALE','UNKNOWN','MISSING'}: run.dependency_inventory['vulnerability_db_freshness']=gap
    elif gap=='package': run.dependency_inventory['package_coordinates'][0]['package']='other'
    elif gap=='manifest': run.dependency_inventory['per_manifest']={}
    elif gap=='truncated': run.dependency_inventory['inventory_truncated']=True
    elif gap=='warning': run.coverage_notes.append('Dependency extraction/resolution warnings prevent confirmation.')
    else: observed=False
    assert declared_dependency_proof(row,run,'package-lock.json',observed) is None


def test_legacy_ledger_read_is_derived_without_creating_state(service,tmp_path):
    s,root,_=service
    original,fid=register_host(service)
    from security_runtime.hook_state import HookStateStore
    historical=HookStateStore(tmp_path/'uninitialized-legacy-ledger')
    ledger=TaskRiskLedger(historical,root)
    view=ledger.view(original,origin_record=s.load(root,original))
    assert view['total']==1 and view['items'][0]['finding_id']==fid
    assert not historical.directory.exists()
