"""Synthetic review labels never modify scanner evidence or enforce policy."""
import copy
import json
import sqlite3
from dataclasses import asdict

import pytest

from security_runtime.findings import FindingNormalizer, deduplicate
from security_runtime.finding_quality import FindingQualityService, quality_finding, metrics, STATUSES
from security_runtime.models import ScanResult, TargetProfile
from security_runtime.storage import SQLiteStore, ReadOnlySQLiteStore


def finding(root, **overrides):
    args = dict(scanner='semgrep', category='sql-injection', title='Synthetic SQL risk',
        description='Synthetic scanner message', severity='HIGH', confidence='MEDIUM',
        file_path='src/App.java', line=4, rule_id='fixture.sqli', evidence='executeQuery(input)')
    args.update(overrides)
    return FindingNormalizer(root).make(**args)


def save(store, root, findings, scan='s1', coverage='FULL'):
    result = ScanResult(scan, 'release', TargetProfile(str(root)), 'COMPLETED', findings, [],
                        'Synthetic', 'REVIEW', 1, coverage=coverage)
    store.save(result)
    return store.get_scan(scan)


def decision(row, status='TRUE_POSITIVE', source='HUMAN'):
    return dict(finding_id=row['finding_id'], observation_hash=row['observation_hash'],
        triage_status=status, triage_reason='Synthetic reviewed evidence', triage_source=source)


def test_portable_identity_and_legacy_workspace_safety(tmp_path):
    first = finding(tmp_path/'checkout-one')
    second = finding(tmp_path/'checkout-two')
    assert first.id != second.id  # Existing authorization/DB references unchanged.
    a, b = quality_finding(asdict(first)), quality_finding(asdict(second))
    assert a['finding_id'] == b['finding_id'] and a['observation_hash'] == b['observation_hash']
    decorated = asdict(first)
    decorated.update(scan_id='different-scan', timestamp='different-time', ordering=99)
    assert quality_finding(decorated)['finding_id']==a['finding_id']
    assert a['finding_id'] != quality_finding(asdict(finding(tmp_path, line=5)))['finding_id']
    reordered = deduplicate([finding(tmp_path, scanner='trivy'), finding(tmp_path)])
    original = deduplicate([finding(tmp_path), finding(tmp_path, scanner='trivy')])
    assert quality_finding(asdict(original[0]))['finding_id'] == quality_finding(asdict(reordered[0]))['finding_id']


def test_dependency_identity_ignores_provider_alias_and_manifest_line(tmp_path):
    def dep(root, scanner, advisory, aliases):
        return FindingNormalizer(root).dependency(scanner=scanner, package='fixture', version='1',
            ecosystem='pypi', manifest='requirements.txt', vulnerability_id=advisory, aliases=aliases)
    a=dep(tmp_path/'one', 'trivy-vuln', 'CVE-2026-1234', ['GHSA-fixture'])
    b=dep(tmp_path/'two', 'osv-scanner', 'GHSA-fixture', ['CVE-2026-1234'])
    b.line_start=b.line_end=20
    assert quality_finding(asdict(a))['finding_id'] == quality_finding(asdict(b))['finding_id']


@pytest.mark.parametrize('status', STATUSES)
def test_all_review_states_persist_separately(tmp_path, status):
    store=SQLiteStore(tmp_path/'state.db'); before=save(store,tmp_path,[finding(tmp_path)],coverage='PARTIAL')
    service=FindingQualityService(store); row=service.view('s1')['findings'][0]
    service.review('s1',[decision(row,status)])
    row=FindingQualityService(ReadOnlySQLiteStore(store.path)).view('s1')['findings'][0]
    assert row['triage_status']==status and row['triage_source']=='HUMAN' and row['triaged_at']
    assert store.get_scan('s1')==before and store.triage_records('s1')=={}
    assert service.view('s1')['scan_coverage']=='PARTIAL'


def test_review_batch_atomic_observation_bound_and_workspace_isolated(tmp_path):
    store=SQLiteStore(tmp_path/'state.db'); save(store,tmp_path,[finding(tmp_path),finding(tmp_path,line=9)])
    service=FindingQualityService(store); rows=service.view('s1')['findings']
    bad=decision(rows[1]); bad['observation_hash']='changed'
    with pytest.raises(ValueError): service.review('s1',[decision(rows[0]),bad])
    assert service.view('s1')['metrics']['overall']['reviewed']==0
    service.review('s1',[decision(rows[0])])
    # A new scan retains ID but needs review; surrounding source may have changed.
    save(store,tmp_path,[finding(tmp_path)],scan='s2')
    assert service.view('s2')['findings'][0]['finding_id']==rows[0]['finding_id']
    assert service.view('s2')['metrics']['overall']['reviewed']==0
    save(store,tmp_path/'other',[finding(tmp_path/'other')],scan='s3')
    assert service.view('s3')['metrics']['overall']['reviewed']==0
    altered=finding(tmp_path,confidence='LOW'); save(store,tmp_path,[altered])
    assert service.view('s1')['metrics']['overall']['reviewed']==0


def test_old_database_export_is_read_only(tmp_path):
    path=tmp_path/'old.db'; store=SQLiteStore(path); save(store,tmp_path,[finding(tmp_path)])
    with sqlite3.connect(path) as db: db.execute('DROP TABLE finding_reviews')
    before=path.read_bytes()
    view=FindingQualityService(ReadOnlySQLiteStore(path)).view('s1')
    assert view['metrics']['overall']['precision_on_reviewed'] is None
    assert view['metrics']['rankings']=={'FP':[], 'TP':[], 'NEEDS_CONTEXT':[]}
    assert path.read_bytes()==before


def test_metrics_denominator_and_source_separation(tmp_path):
    rows=[quality_finding(asdict(finding(tmp_path,line=i+1))) for i in range(7)]
    for row,status,source in zip(rows, [*STATUSES,'TRUE_POSITIVE'], ['HUMAN']*6+['AI']):
        row.update(triage_status=status,triage_source=source)
    result=metrics(rows)
    assert result['overall']['total']==7 and result['overall']['reviewed']==6
    assert result['overall']['TP']==2 and result['overall']['FP']==1
    assert result['overall']['precision_on_reviewed']==2/3
    assert result['by_source']['HUMAN']['precision_on_reviewed']==1/2
    assert result['by_source']['AI']['precision_on_reviewed']==1
    assert result['recall'] is None and result['rankings']['FP'][0]['FP']==1


@pytest.mark.parametrize('category,level', [('code','DIRECT_MATCH'),('secret','SECRET_MATCH'),
    ('dependency','DEPENDENCY_MATCH'),('configuration','CONFIG_MATCH')])
def test_evidence_never_invents_flow_or_secret(tmp_path,category,level):
    raw=asdict(finding(tmp_path,category=category,evidence='synthetic private match'))
    row=quality_finding(raw)
    assert row['evidence']['evidence_level']==level
    assert row['evidence']['source'] is None and row['evidence']['sink'] is None
    assert row['evidence']['trace']==[] and not row['evidence']['dataflow_available']
    if category=='secret': assert 'synthetic private match' not in json.dumps(row)


def test_mcp_preserves_legacy_id_and_triage_with_quality_view(tmp_path):
    from security_runtime.mcp_server import _agent_finding
    raw=asdict(finding(tmp_path)); before=copy.deepcopy(raw)
    raw.update(triage_status='VALID',verdict='LIKELY')
    view=_agent_finding(raw)
    assert view['id']==before['id'] and view['triage_status']=='VALID'
    assert view['quality']['triage_status']=='UNREVIEWED'
    assert view['quality']['evidence']['scanner_evidence']==before['evidence']


def test_unrepresentable_quality_location_never_drops_scanner_result(tmp_path):
    from security_runtime.mcp_server import _agent_finding
    raw=asdict(finding(tmp_path)); raw['file_path']='../outside'
    view=_agent_finding(raw)
    assert view['id']==raw['id'] and view['quality'] is None
    assert view['quality_diagnostic']=='INVALID_REVIEW_LOCATION'


def test_semgrep_login_placeholder_is_not_matched_source_code(tmp_path):
    raw=asdict(finding(tmp_path,evidence='requires login'))
    row=quality_finding(raw)
    assert row['evidence']['scanner_evidence']=='requires login'
    assert row['evidence']['matched_code'] is None
    assert row['evidence']['matched_code_status']=='UNAVAILABLE_SCANNER_PLACEHOLDER'
    assert row['triage_status']=='UNREVIEWED' and raw['evidence']=='requires login'


def test_local_export_and_explicit_review(tmp_path,capsys):
    from scripts.finding_quality import main
    store=SQLiteStore(tmp_path/'state.db'); before=save(store,tmp_path,[finding(tmp_path)])
    args=['--workspace',str(tmp_path),'--database',str(store.path),'--scan','s1']
    main(['export',*args]); output=tmp_path/'.security-runtime/finding-quality'
    exported=json.loads((output/'baseline.json').read_text())
    reviews=tmp_path/'decisions.json'; reviews.write_text(json.dumps([decision(exported['findings'][0])]))
    main(['review',*args,'--decisions',str(reviews)])
    assert json.loads((output/'baseline.json').read_text())['metrics']['overall']['TP']==1
    assert store.get_scan('s1')==before
    with pytest.raises(SystemExit): main(['export',*args[:-1],'not-this-scan'])
    assert 'executeQuery' not in capsys.readouterr().out


@pytest.mark.parametrize('source', ['HUMAN', 'AI', 'POLICY'])
def test_explicit_sources_are_audit_labels_not_actions(tmp_path,source):
    from security_runtime.risk import RiskEngine
    raw=finding(tmp_path); store=SQLiteStore(tmp_path/'state.db'); save(store,tmp_path,[raw])
    before_risk = RiskEngine().assess([raw])
    service=FindingQualityService(store); row=service.view('s1')['findings'][0]
    service.review('s1',[decision(row,'FALSE_POSITIVE',source)])
    assert service.view('s1')['findings'][0]['triage_source']==source
    assert RiskEngine().assess([raw])==before_risk and raw.status=='OPEN'


@pytest.mark.parametrize('damage', ['status','source','reason','timestamp','action','duplicate','id'])
def test_invalid_review_does_not_publish_any_decision(tmp_path,damage):
    store=SQLiteStore(tmp_path/'state.db'); before=save(store,tmp_path,[finding(tmp_path)])
    service=FindingQualityService(store); item=decision(service.view('s1')['findings'][0])
    items=[item]
    if damage=='status': item['triage_status']='LIKELY'
    elif damage=='source': item['triage_source']='AUTOMATIC'
    elif damage=='reason': item['triage_reason']=''
    elif damage=='timestamp': item['triaged_at']='injected'
    elif damage=='action': item['action']='SUPPRESS'
    elif damage=='duplicate': items.append(copy.deepcopy(item))
    else: item['finding_id']=[]
    with pytest.raises(ValueError): service.review('s1',items)
    assert service.view('s1')['metrics']['overall']['reviewed']==0 and store.get_scan('s1')==before


def test_default_export_reuses_existing_global_workspace_db(tmp_path,monkeypatch,capsys):
    from scripts.finding_quality import main
    from security_runtime.global_workspace import workspace_state
    root=tmp_path/'project'; root.mkdir()
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR',str(tmp_path/'global-state'))
    store=SQLiteStore(workspace_state(root)/'scans.db'); save(store,root,[finding(root)])
    main(['export','--workspace',str(root),'--scan','s1'])
    assert json.loads(capsys.readouterr().out)['metrics']['total']==1


def test_export_refuses_linked_output_without_any_writes(tmp_path,monkeypatch):
    from scripts.finding_quality import main
    import security_runtime.hook_state as module
    store=SQLiteStore(tmp_path/'state.db'); save(store,tmp_path,[finding(tmp_path)])
    before=store.path.read_bytes()
    def reject(path): raise ValueError('linked output fixture')
    monkeypatch.setattr(module,'no_links',reject)
    with pytest.raises(ValueError):
        main(['export','--workspace',str(tmp_path),'--database',str(store.path),'--scan','s1'])
    assert store.path.read_bytes()==before and not (tmp_path/'.security-runtime').exists()
