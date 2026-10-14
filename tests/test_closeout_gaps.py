"""Regression guards for first closeout, bounded source reads and per-risk outcomes."""
from dataclasses import asdict
import json
import pytest
from test_task_security import service, begin, candidate, prepared
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
    assert s.prepare(root, second)['status'] == 'BUSY' and not runtime.calls

def test_long_test_source_is_read_once_in_same_budget(service):
    s, root, runtime = service
    (root/'tests').mkdir()
    (root/'tests/test_long.py').write_text('old = 1\n')
    ref = begin(service)
    (root/'tests/test_long.py').write_text(''.join(f'item_{i} = {i}\n' for i in range(206)))
    packet = s.prepare(root, ref)
    assert next(d for d in packet['diffs'] if d['path']=='tests/test_long.py')['availability']=='ON_DEMAND'
    session=packet['review_session']
    request=dict(path='tests/test_long.py', start_line=1, end_line=206)
    while True:
        page=s.read(root,ref,session,**request)
        assert len(page['numbered_lines']) <= 80
        if not page['has_more']: break
        request=dict(path=page['next_read']['file_path'],start_line=page['next_read']['start_line'],end_line=page['next_read']['end_line'])
    before=s.read(root,ref,session,'tests/test_long.py',1,1,'BEFORE_TASK')
    assert before['location_version']=='BEFORE_TASK' and 'old = ' in before['numbered_lines'][0]
    s.read(root,ref,session,'auth.py',1,2)
    out=s.submit(root,ref,session,[],'REVIEWED',[])
    assert not out['context_read_coverage']['unread_ranges']
    assert out['context_read_coverage']['used_bytes'] <= 64000

def register_host(sample):
    s,root,runtime=sample
    ref,session,_=prepared(sample)
    entry=s.read(root,ref,session,'routes.py',1,2)
    auth=s.read(root,ref,session,'auth.py',1,2)
    out=s.submit(root,ref,session,[candidate(entry['evidence_id'],auth['evidence_id'])],'REVIEWED',[])
    return ref,out['host_review']['findings'][0]['id']

def test_host_closure_links_original_id_and_becomes_stale_after_edit(service):
    s,root,runtime=service
    original,fid=register_host(service)
    assert s.risk_ledger(root,original)['counts']=={'OPEN':1}
    ref=s.begin(root,'fix-approved')['task_ref']
    (root/'routes.py').write_text('def get_order(order_id, user):\n    return load_owned_order(order_id, user)\n')
    p=s.prepare(root,ref); session=p['review_session']
    entry=s.read(root,ref,session,'routes.py',1,2)
    auth=s.read(root,ref,session,'auth.py',1,2)
    resolution=dict(original_task_ref=original,finding_id=fid,
        evidence_refs=[entry['evidence_id'],auth['evidence_id']],outcome='CODE_REVIEWED_RESOLVED',
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
    row=dict(original_task_ref=original,finding_id=fid,evidence_refs=[e['evidence_id']],
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
    data=json.loads(ledger.path.read_bytes())
    next(iter(data['rows'].values()))['status']='SCANNER_VERIFIED_RESOLVED'
    ledger.path.write_text(json.dumps(data))
    with pytest.raises(ValueError,match='cannot be verified'):
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


def test_legacy_ledger_read_is_derived_without_creating_state(service):
    s,root,_=service
    original,fid=register_host(service)
    ledger=TaskRiskLedger(s.hooks,root)
    ledger.path.unlink()
    view=s.risk_ledger(root,original)
    assert view['total']==1 and view['items'][0]['finding_id']==fid
    assert not ledger.path.exists()
