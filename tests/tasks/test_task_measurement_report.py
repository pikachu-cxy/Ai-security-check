"""Malformed or non-improving measurements cannot produce a passing verdict."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('measurement_report', Path(__file__).parents[2]/'tools/summarize_task_measurements.py')
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


@pytest.fixture
def measured():
    def data(factor):
        rows = []
        for sample,size in (('component',10),('full',20)):
            for n in range(3):
                static = dict(status='COMPLETED',coverage='FULL',scope_files=['a.py'],actual_files=['a.py'],
                    findings=[], capability_results={'CODE_SAST':'EXECUTED'},
                    scanner_runs=[dict(scanner='engine',version='1',status='SUCCESS',coverage_contract='FULL',scanner_diagnostics={'cache':{}})])
                result = dict(status='COMPLETE',current_version=True,baseline_file_count=size,
                    unverified_file_count=0,limitations=[],host_review={'coverage':'PARTIAL'})
                rows.append(dict(project=dict(sample=sample,files=size,limitations=[],inventory_files=size,languages=['Python'],sample_commit='fixed'),
                    iteration=n,static_record=static,result=result,finish={'status':'READY'},retry={'status':'READY'},
                    hook=dict(status='BASELINE_ESTABLISHED',coverage='FULL',execution_state='EXECUTED'),
                    cache_state='process_warm_new_task_state',
                    final_file_hashes={'a.py':'same'},pages=[{'start_line':v} for v in (1,81,161)],
                    stages=[dict(stage=s,wall_ms=(size*10+n+j)*factor,calls={'read':size,'safe_source':1,'hash':size},read_bytes=size*100) for s in report.STAGES for j in range(3 if s=='context_page' else 1)]))
        return dict(environment={k:'same' for k in ('machine','archive_sha256','rules_identity','dependencies','dependency_database','offline')},rows=rows)
    before,after = data(1),data(.6)
    side = {f"{r['project']['sample']}:{r['iteration']}":dict(baseline_complete=True,end_complete=True,
        baseline_limits=[],end_limits=[],bytes=r['result']['baseline_file_count']*100,limitations=[],baseline_files=r['result']['baseline_file_count'],end_files=r['result']['baseline_file_count']) for r in before['rows']}
    return before,after,dict(status='PASS',sides={'b':copy.deepcopy(side),'a':copy.deepcopy(side)})


def verdict(measured):
    return report.assess(*measured,'b','a')


def test_pass_and_percentage_are_derived(measured):
    result = verdict(measured)
    assert result['passed']
    assert all(v['percent'] == pytest.approx(40) for v in result['benefits'].values())


@pytest.mark.parametrize('factor',[1,1.2])
def test_equal_or_slower_cannot_pass(measured,factor):
    for b,a in zip(measured[0]['rows'],measured[1]['rows']):
        for bs,as_ in zip(b['stages'],a['stages']): as_['wall_ms'] = bs['wall_ms']*factor
    assert not verdict(measured)['passed']


def test_median_gain_with_overlapping_ranges_is_not_passed(measured):
    for r in measured[1]['rows']:
        next(s for s in r['stages'] if s['stage']=='context_page')['wall_ms'] *= 2
    assert not verdict(measured)['passed']


def test_same_extra_manifest_context_preserves_requested_coverage(measured):
    for data in measured[:2]:
        for r in data['rows']: r['static_record']['actual_files'].append('pyproject.toml')
    assert verdict(measured)['passed']


def test_rejected_cli_replaces_old_pass_report(measured,tmp_path,monkeypatch):
    before,after,snap=measured
    after['environment']['rules_identity']='changed'
    paths=[tmp_path/n for n in ('b','a','snap.json')]
    for p,data in zip(paths,(before,after,snap)): p.write_text(json.dumps(data))
    output=tmp_path/'report.md'; output.write_text('previous passing report')
    monkeypatch.setattr('sys.argv',['report',str(paths[0]),str(paths[1]),'--snapshots',str(paths[2]),'--output',str(output)])
    assert report.main()==2
    assert output.read_text(encoding='utf-8').startswith('验收未通过')


def test_cli_printed_benefit_is_not_hardcoded(measured,tmp_path,monkeypatch):
    paths=[tmp_path/n for n in ('b','a','snap.json')]
    for path,data in zip(paths,measured): path.write_text(json.dumps(data))
    output=tmp_path/'report.md'
    monkeypatch.setattr('sys.argv',['report',str(paths[0]),str(paths[1]),'--snapshots',str(paths[2]),'--output',str(output)])
    assert report.main()==0
    text=output.read_text(encoding='utf-8')
    assert 'component 分页中位耗时变化 +40.0%' in text
    assert 'full 分页中位耗时变化 +40.0%' in text
    assert '下降约 28%' not in text and '下降约 30%' not in text


@pytest.mark.parametrize('change', ['few','duplicate','failed','hook','provider','coverage','scope','stale','identity','snapshot','nan','missing_page'])
def test_invalid_or_unsuccessful_evidence_rejected(measured,change):
    b,a,snap = measured
    if change=='few':
        b['rows']=[r for r in b['rows'] if r['iteration']<2]
        a['rows']=[r for r in a['rows'] if r['iteration']<2]
    elif change=='duplicate': b['rows'][1]['iteration']=0; a['rows'][1]['iteration']=0
    elif change=='identity': a['environment']['rules_identity']='different'
    elif change=='snapshot': snap['sides']['a']['full:0']['end_complete']=False
    else:
        for d in (b,a):
            r=d['rows'][0]
            if change=='failed': r['static_record']['status']='FAILED'
            elif change=='hook': r['hook']['execution_state']='FAILED'
            elif change=='provider': r['static_record']['scanner_runs'][0]['status']='TIMEOUT'
            elif change=='coverage': r['static_record']['coverage']='UNKNOWN'
            elif change=='scope': r['static_record']['actual_files']=[]
            elif change=='stale': r['result']['current_version']=False
            elif change=='nan': r['stages'][0]['wall_ms']=float('nan')
            elif change=='missing_page': r['pages'].pop()
    with pytest.raises(ValueError): verdict(measured)
