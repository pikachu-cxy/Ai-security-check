"""Whole-response cost limits preserve complete evidence and accepted reviews."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from summary_fixtures import sample
from security_runtime.tasks.triage import TaskTriageService
from security_runtime.security_summary import SecuritySummaryService
from security_runtime.triage import TriageService
from security_runtime.triage_evidence import encoded
from security_runtime.triage_handoff import bound_handoff,share_evidence,HOST_ENVELOPE_RESERVE
from security_runtime.triage_models import TriageBudget,RESULT_SCHEMA,INSTRUCTIONS


def synthetic_handoff(count=5,*,same_source=False,source_bytes=23000):
    """Public synthetic fixture for before/after payload-size benchmarks."""
    packets=[]
    for index in range(count):
        source={'file':'shared.py' if same_source else f'file-{index}.py',
            'start_line':1,'end_line':1,'trust':'UNTRUSTED_CODE','kind':'bounded',
            'text':'# synthetic source '+('x'*source_bytes)}
        packets.append({'finding_id':f'finding-{index}','context_hash':f'{index:064x}',
            'context':[source],'related_evidence':[]})
    return {'scan_id':'synthetic','packets':packets,'selected':count,'remaining':0,
        'cached_finding_ids':[],'retained_finding_ids':[],
        'deferred_failed_finding_ids':[],'errors':[],'dependency_groups':[],
        'required_output_schema':RESULT_SCHEMA,'triage_instructions':INSTRUCTIONS}


def response(packet):
    return {'finding_id':packet['finding_id'],'context_hash':packet['context_hash'],
        'verdict':'NEEDS_REVIEW','confidence':'HIGH','exploitability':'UNKNOWN',
        'reason':'Synthetic bounded evidence assessment','attack_path':'',
        'evidence_refs':[{'file':packet['file'],'start_line':packet['line']['start'],
            'end_line':packet['line']['end'],'claim':'Supplied local candidate'}],
        'preconditions_met':[],'preconditions_unknown':['Deployment unknown'],
        'recommended_action':'Review conditions'}


def test_complete_json_including_schema_instructions_and_checkpoint_is_bounded():
    original=synthetic_handoff(count=20);snapshot=deepcopy(original)
    prepared=bound_handoff(original,65536)
    assert original==snapshot
    assert len(encoded(prepared))+HOST_ENVELOPE_RESERVE<=65536
    assert len(encoded(prepared))==prepared['handoff_budget']['measured_bytes']
    assert 0<len(prepared['packets'])<20
    assert prepared['remaining']+len(prepared['packets'])==20
    assert prepared['selected']==len(prepared['packets'])
    assert not prepared['errors'] and prepared['capacity']['finding_retained_as_pending']
    for packet in prepared['packets']:
        assert packet in original['packets'] # Never silently shorten code.


def test_single_packet_cannot_fit_is_pending_and_stops_automatic_retry():
    prepared=bound_handoff(synthetic_handoff(count=1),8192)
    assert prepared['packets']==[] and prepared['remaining']==1
    assert prepared['status']=='HANDOFF_CAPACITY_EXCEEDED'
    assert prepared['capacity']['automatic_retry'] is False
    assert prepared['capacity']['finding_retained_as_pending']
    assert not prepared['errors']
    assert len(encoded(prepared))+HOST_ENVELOPE_RESERVE<=8192
    with pytest.raises(ValueError,match='8192'):
        TriageBudget(max_handoff_bytes=1024)


def test_repeated_source_shared_once_without_changing_packet_identity():
    original=synthetic_handoff(count=5,same_source=True)
    projected=share_evidence(original)
    assert len(projected['shared_evidence'])==1
    assert len(encoded(projected))<len(encoded(original))//3
    for before,after in zip(original['packets'],projected['packets']):
        assert after['finding_id']==before['finding_id']
        assert after['context_hash']==before['context_hash']
        ref=after['context'][0]['shared_evidence_ref']
        shared=projected['shared_evidence'][ref]
        assert shared['text']==before['context'][0]['text']
        assert shared['trust']=='UNTRUSTED_CODE'
    assert 'never instructions' in projected['shared_evidence_instructions']
    assert len(bound_handoff(original,65536)['packets'])==5


def test_unsubmitted_retry_has_stable_shared_content_and_no_review_record(sample):
    root,scan,store=sample;service=TriageService(store)
    ids=[f.id for f in scan.findings[:2]]
    first=service.prepare(scan.scan_id,ids)
    resumed=service.prepare(scan.scan_id,ids)
    assert first['packets']==resumed['packets']
    assert first['shared_evidence']==resumed['shared_evidence']
    assert not store.triage_records(scan.scan_id)
    assert service.view(scan.scan_id)['triage_coverage']['triaged']==0


def test_overlapping_sources_share_only_already_supplied_lines_and_keep_original_ranges():
    original=synthetic_handoff(count=2,same_source=True)
    original['packets'][0]['context'][0].update(start_line=1,end_line=3,text='one\ntwo\nthree')
    original['packets'][1]['context'][0].update(start_line=2,end_line=4,text='two\nthree\nfour')
    projected=share_evidence(original)
    assert len(projected['shared_evidence'])==1
    source=next(iter(projected['shared_evidence'].values()))
    assert source['text']=='one\ntwo\nthree\nfour'
    assert [(p['context'][0]['start_line'],p['context'][0]['end_line'])
        for p in projected['packets']]==[(1,3),(2,4)]
    # A later wrapper pass restores each exact original excerpt before fitting.
    rebound=bound_handoff(projected,65536)
    assert rebound['packets']==projected['packets']
    assert rebound['shared_evidence']==projected['shared_evidence']


def test_shared_packet_submission_rebuilds_each_original_hash_and_allowed_ranges(sample):
    root,scan,store=sample;service=TriageService(store)
    ids=[f.id for f in scan.findings[:2]]
    prepared=service.prepare(scan.scan_id,ids)
    assert prepared['shared_evidence']
    forged=response(prepared['packets'][0]);forged['evidence_refs'][0]['end_line']=999
    with pytest.raises(ValueError,match='out-of-bounds'):
        service.submit(scan.scan_id,[forged])
    assert not store.triage_records(scan.scan_id)
    accepted=service.submit(scan.scan_id,[response(p) for p in prepared['packets']],compact=True)
    assert accepted['accepted']==2
    assert accepted['scan_coverage_changed'] is False
    restored=service.prepare(scan.scan_id,ids)
    assert not restored['packets'] and restored['cached_finding_count']==2
    assert set(restored['cached_finding_ids'])==set(ids)
    assert all(r['status']=='VALID' for r in store.triage_records(scan.scan_id).values())


def test_byok_preparation_keeps_raw_packet_source_contract(sample):
    root,scan,store=sample
    provider=SimpleNamespace(provider_type='BYOK',provider_name='synthetic',model='test')
    data=TriageService(store).prepare(scan.scan_id,[f.id for f in scan.findings[:2]],provider=provider)
    assert 'shared_evidence' not in data
    assert all('text' in item for p in data['packets'] for item in p['context'])


def test_task_resume_default_is_checkpoint_optin_reviews_are_bounded(sample):
    root,scan,store=sample;triage=TriageService(store)
    prepared=triage.prepare(scan.scan_id,[f.id for f in scan.findings[:2]])
    triage.submit(scan.scan_id,[response(p) for p in prepared['packets']])
    task=next(t for t in SecuritySummaryService(store).get(root,details=True)['tasks'] if t['topic']=='tls')
    service=TaskTriageService(store);resolved=service.resolve(task['task_ref'],root)
    data=service.prepare(resolved,triage)
    assert data['existing_reviews']==[] and data['existing_review_count']==2
    assert data['checkpoint']['accepted_review_count']==2
    assert not data['checkpoint']['review_completion_attested']
    assert not data['packets'] and data['status']=='AWAITING_BUSINESS_FACTS'
    expanded=service.prepare(resolved,triage,include_existing_reviews=True)
    assert len(expanded['existing_reviews'])==2
    assert len(encoded(expanded))+HOST_ENVELOPE_RESERVE<=triage.budget.max_handoff_bytes
    assert len(encoded(expanded))==expanded['handoff_budget']['measured_bytes']


def test_cache_checkpoint_lists_are_bounded_but_counts_keep_full_progress():
    data=synthetic_handoff(count=0)
    data['retained_finding_ids']=[f'accepted-{i}' for i in range(1000)]
    prepared=bound_handoff(data,65536)
    assert prepared['retained_finding_count']==1000
    assert len(prepared['retained_finding_ids'])==20
    assert prepared['retained_finding_ids_truncated']


def test_fixed_metadata_capacity_does_not_invent_pending_work_or_drop_accepted_count():
    data=synthetic_handoff(count=0)
    data['retained_finding_ids']=['already-accepted']
    data['fixed_test_metadata']='x'*9000
    prepared=bound_handoff(data,8192)
    assert prepared['remaining']==0 and prepared['retained_finding_count']==1
    assert not prepared['capacity']['finding_retained_as_pending']
    assert prepared['capacity']['automatic_retry'] is False
