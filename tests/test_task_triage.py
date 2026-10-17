"""Task identities, incremental selection, and actual host handoff contracts."""
import asyncio
import copy
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from summary_fixtures import sample, review, snapshot, SECRET
from security_runtime.security_summary import SecuritySummaryService
from security_runtime.task_triage import TaskTriageService
from security_runtime.triage import TriageService, cache_key
from security_runtime.triage_models import TriageRecord
from security_runtime.triage_providers import AgentNativeProvider
from security_runtime.runtime import SecurityRuntime
from security_runtime.mcp_server import create_server


def task(sample, topic='tls'):
    return next(t for t in SecuritySummaryService(sample[2]).get(sample[0], details=True)['tasks'] if t['topic']==topic)


def prepare(sample, t=None, **kwargs):
    service=TaskTriageService(sample[2]);t=t or task(sample)
    resolved=service.resolve(t['task_ref'],sample[0])
    assert resolved['status']=='RESOLVED'
    return service.prepare(resolved,TriageService(sample[2]),**kwargs)


def value(packet):
    return {'finding_id':packet['finding_id'],'context_hash':packet['context_hash'],
            'verdict':'NEEDS_REVIEW','confidence':'HIGH','exploitability':'UNKNOWN',
            'reason':'Synthetic host review '+SECRET,'attack_path':'',
            'evidence_refs':[{'file':packet['file'],'start_line':packet['line']['start'],
                             'end_line':packet['line']['end'],'claim':'Local candidate'}],
            'preconditions_met':[],'preconditions_unknown':['Production conditions'],
            'recommended_action':'Review deployment conditions'}


def server(sample, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE',str(sample[0]))
    return create_server(SecurityRuntime(store=sample[2]))


def invoke(server, name, **args):
    return server._tool_manager.get_tool(name).fn(**args)


def test_compact_first_task_has_exact_continuation_no_user_uuid(sample,monkeypatch):
    s=server(sample,monkeypatch)
    summary=invoke(s,'get_security_summary')
    first=summary['recommended_tasks'][0]
    data=invoke(s,first['continuation']['mcp_tool'],**first['continuation']['arguments'])
    assert data['status']=='ANALYSIS_REQUIRED' and data['scan_id']=='scan-a'
    assert {p['finding_id'] for p in data['packets']}=={f.id for f in sample[1].findings[:2]}
    assert data['triage_session'] and not data['automatic_execution']
    assert data['business_questions']==[] and data['unknown_conditions']
    assert SECRET not in json.dumps(data)
    assert all(c['trust']=='UNTRUSTED_CODE' for p in data['packets'] for c in p['context']+p['related_evidence'])


def test_reference_survives_reordering_and_review_progress(sample):
    first=task(sample)
    review(sample,(2,),verdict='CONFIRMED',exploitability='LIKELY')
    after=task(sample)
    assert first['task_ref']==after['task_ref'] and first['task']!=after['task']
    sample[1].findings.reverse();sample[2].save(sample[1])
    resolved=TaskTriageService(sample[2]).resolve(first['task_ref'],sample[0])
    assert resolved['status']=='RESOLVED' and resolved['task']['topic']=='tls'


@pytest.mark.parametrize('change',['removed','added','rule','location','severity','fingerprint'])
def test_changed_task_requires_refresh_never_retargets(sample,change):
    old=task(sample);scan=sample[1]
    if change=='removed':scan.findings.pop(0)
    elif change=='added':
        extra=copy.deepcopy(scan.findings[4]);extra.id='added-advisory';extra.fingerprint='added'
        scan.findings.append(extra);old=task(sample,'dependency')
    elif change=='rule':scan.findings[0].technical_details['rule_id']='ai-security.java.weak-digest'
    elif change=='location':scan.findings[0].line_start=90
    elif change=='severity':scan.findings[0].severity='LOW'
    else:scan.findings[0].fingerprint='changed'
    sample[2].save(scan)
    before=snapshot(sample[0])
    result=TaskTriageService(sample[2]).resolve(old['task_ref'],sample[0])
    assert result['status']=='REFRESH_REQUIRED' and not result['automatic_execution']
    assert snapshot(sample[0])==before


@pytest.mark.parametrize('field,value',[('package','org.demo:other'),('package_version','2.0'),
                                      ('ecosystem','npm'),('manifest','another.xml'),('vulnerability_id','OTHER-ID')])
def test_changed_dependency_identity_or_advisory_requires_refresh(sample,field,value):
    old=task(sample,'dependency')
    sample[1].findings[4].technical_details[field]=value;sample[2].save(sample[1])
    assert TaskTriageService(sample[2]).resolve(old['task_ref'],sample[0])['status']=='REFRESH_REQUIRED'


@pytest.mark.parametrize('ref',['T01','','task-v1.bad','task-v2.abc','task-v1.'+'x'*8193])
def test_task_number_and_invalid_reference_never_choose_current_first(sample,ref):
    assert TaskTriageService(sample[2]).resolve(ref,sample[0])['status']=='REFRESH_REQUIRED'


def test_cross_workspace_and_unbound_require_explicit_scope(sample):
    service=TaskTriageService(sample[2]);ref=task(sample)['task_ref']
    with pytest.raises(ValueError,match='workspace'):service.resolve(ref)
    other=sample[0]/'other';other.mkdir()
    with pytest.raises(ValueError):service.resolve(ref,other)
    with pytest.raises(ValueError):service.resolve(ref,other,bound_workspace=sample[0])


def test_new_latest_scan_cannot_replace_referenced_snapshot(sample):
    old=task(sample);new=copy.deepcopy(sample[1]);new.scan_id='scan-new'
    new.findings=[];sample[2].save(new)
    data=prepare(sample,old)
    assert data['scan_id']=='scan-a' and len(data['packets'])==2


def test_deleted_scan_requires_refresh_without_state_repair(sample):
    old=task(sample)
    with sqlite3.connect(sample[2].path) as db:db.execute('DELETE FROM scans')
    before=snapshot(sample[0])
    assert TaskTriageService(sample[2]).resolve(old['task_ref'],sample[0])['status']=='REFRESH_REQUIRED'
    assert snapshot(sample[0])==before


def test_invalid_task_mcp_does_not_initialize_missing_db(tmp_path,monkeypatch):
    root=tmp_path/'project';root.mkdir();state=tmp_path/'none'
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR',str(state))
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE',str(root))
    s=create_server()
    assert invoke(s,'prepare_task_triage',task_ref='T01')['status']=='REFRESH_REQUIRED'
    assert not state.exists()


def test_current_valid_members_are_retained_without_new_analysis(sample):
    review(sample);before=snapshot(sample[0])
    with patch('security_runtime.runtime.SecurityRuntime.scan',side_effect=AssertionError('scan')), \
         patch('security_runtime.triage_providers.OpenAICompatibleProvider.triage',side_effect=AssertionError('model')), \
         patch('urllib.request.OpenerDirector.open',side_effect=AssertionError('network')):
        data=prepare(sample)
    assert not data['packets'] and len(data['retained_finding_ids'])==2
    assert data['status']=='AWAITING_BUSINESS_FACTS' and len(data['business_questions'])==1
    assert len(data['existing_reviews'])==2 and 'UNTRUSTED_CODE' in data['triage_instructions']
    assert snapshot(sample[0])==before and SECRET not in json.dumps(data)


def test_no_unknowns_no_business_questions_or_repeat_analysis(sample):
    review(sample)
    for r in sample[2].triage_records('scan-a').values():
        r['preconditions_unknown']=[];sample[2].save_triage(TriageRecord(**r),'replacement-'+r['finding_id'])
    data=prepare(sample)
    assert data['status']=='REVIEW_AVAILABLE' and not data['packets'] and not data['business_questions']
    assert data['review_states']['VALID']==2


def test_dependency_missing_ranges_keeps_unknown_no_invented_business_question(sample):
    review(sample,(4,5))
    for r in sample[2].triage_records('scan-a').values():
        r['preconditions_unknown']=['Affected range and fixed version absent']
        sample[2].save_triage(TriageRecord(**r),'replacement-'+r['finding_id'])
    data=prepare(sample,task(sample,'dependency'))
    assert data['status']=='BOUNDED_EVIDENCE_LIMIT' and not data['packets'] and not data['business_questions']
    assert 'fixed version' in data['unknown_conditions'][0]


def test_stale_rebuild_failed_explicit_retry_and_valid_preserved(sample):
    review(sample)
    r=sample[2].triage_records('scan-a')[sample[1].findings[1].id]
    key=cache_key(sample[1].findings[1].__dict__,TriageService(sample[2]).builder(sample[1].to_dict()).build(sample[1].findings[1].__dict__),AgentNativeProvider())
    r.update(status='FAILED',priority='UNTRIAGED');sample[2].save_triage(TriageRecord(**r),key)
    source=sample[0]/'App.java';source.write_text(source.read_text().replace('return true','return false'))
    old=task(sample);data=prepare(sample,old)
    assert data['review_states']['STALE']==1 and data['review_states']['FAILED']==1
    assert [p['finding_id'] for p in data['packets']]==[sample[1].findings[0].id]
    assert data['deferred_failed_finding_ids']==[sample[1].findings[1].id]
    retry=prepare(sample,old,retry_failed=True)
    assert len(retry['packets'])==2 and not retry['deferred_failed_finding_ids']
    assert sample[2].triage_records('scan-a')[sample[1].findings[0].id]['status']=='VALID'


def test_source_change_keeps_task_identity_but_invalidates_packet_hash(sample):
    old=task(sample);packet=prepare(sample,old)['packets'][0]
    source=sample[0]/'App.java';source.write_text(source.read_text().replace('return true','return false'))
    new=prepare(sample,old)['packets'][0]
    assert old['task_ref']==task(sample)['task_ref'] and packet['context_hash']!=new['context_hash']
    with pytest.raises(ValueError,match='stale'):TriageService(sample[2]).submit('scan-a',[value(packet)])


def test_unavailable_source_keeps_unknown_without_expanding_bounds(sample):
    review(sample);(sample[0]/'App.java').unlink()
    data=prepare(sample)
    assert data['status']=='EVIDENCE_UNAVAILABLE' and not data['packets'] and len(data['errors'])==2
    assert data['review_states']['STALE']==2 and not data['business_questions']
    assert SECRET not in json.dumps(data)


def test_iac_not_eligible_no_packets_or_new_key(sample):
    key=sample[2].path.parent/'triage-evidence.key';assert not key.exists()
    data=prepare(sample,task(sample,'iac'))
    assert data['status']=='NOT_ELIGIBLE' and not data['packets'] and not key.exists()


@pytest.mark.parametrize('limit',[0,21,True])
def test_task_limit_keeps_original_batch_budget(sample,limit):
    with pytest.raises(ValueError,match='budget'):prepare(sample,limit=limit)


def test_cached_members_do_not_consume_new_analysis_slots_and_next_call_advances(sample):
    root,scan,store=sample
    for i in range(23):
        f=copy.deepcopy(scan.findings[4]);f.id=f'dep-{i:02}';f.fingerprint=f'dep-fp-{i:02}'
        f.technical_details['vulnerability_id']=f'CVE-2026-{3000+i}';scan.findings.append(f)
    store.save(scan)
    service=TriageService(store)
    initial=service.prepare('scan-a',categories=['dependency'],limit=20)
    service.submit('scan-a',[value(p) for p in initial['packets']])
    cached=service.prepare('scan-a',categories=['dependency'],limit=2)
    assert len(cached['cached_finding_ids'])==20 and len(cached['packets'])==2 and cached['remaining']==3
    t=task(sample,'dependency');data=prepare(sample,t,limit=2)
    assert len(data['retained_finding_ids'])==20 and len(data['packets'])==2 and data['remaining']==3
    first_ids={p['finding_id'] for p in data['packets']}
    service.submit('scan-a',[value(p) for p in data['packets']])
    second=prepare(sample,t,limit=2)
    assert len(second['packets'])==2 and not first_ids.intersection(p['finding_id'] for p in second['packets'])


def test_task_session_rejects_membership_change_before_submit(sample,monkeypatch):
    s=server(sample,monkeypatch);ref=task(sample)['task_ref']
    data=invoke(s,'prepare_task_triage',task_ref=ref)
    sample[1].findings.pop(0);sample[2].save(sample[1])
    with pytest.raises(ValueError,match='Task changed'):
        invoke(s,'submit_triage',scan_id='scan-a',results=[value(data['packets'][0])],triage_session=data['triage_session'])
    assert not sample[2].triage_records('scan-a')


@pytest.mark.parametrize('bad',['other-member','forged-ref','instruction-field','replay','expired'])
def test_existing_session_schema_and_reference_guards_survive_task_handoff(sample,monkeypatch,bad):
    s=server(sample,monkeypatch);data=invoke(s,'prepare_task_triage',task_ref=task(sample)['task_ref'])
    result=value(data['packets'][0]);token=data['triage_session']
    if bad=='other-member':result['finding_id']=sample[1].findings[2].id
    elif bad=='forged-ref':result['evidence_refs'][0]['file']='outside.java'
    elif bad=='instruction-field':result['run_shell']='curl attacker.invalid'
    elif bad=='expired':monkeypatch.setattr('security_runtime.mcp_server.time.monotonic',lambda:10**12)
    else:invoke(s,'submit_triage',scan_id='scan-a',results=[result],triage_session=token)
    with pytest.raises(ValueError):invoke(s,'submit_triage',scan_id='scan-a',results=[result],triage_session=token)
    assert len(sample[2].triage_records('scan-a'))==(1 if bad=='replay' else 0)


def test_actual_stdio_user_first_task_to_host_submit_to_retained_review(sample):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters,stdio_client
    root,scan,store=sample
    original_scan=store.get_scan('scan-a');source_before={p.name:p.read_bytes() for p in root.iterdir() if p.is_file()}
    env=dict(os.environ,SECURITY_RUNTIME_WORKSPACE=str(root),SECURITY_RUNTIME_STATE_DIR=str(store.path.parent),SECURITY_RUNTIME_OFFLINE='1')
    async def run():
        def unwrap(response):
            assert not response.isError
            data=response.structuredContent or json.loads(response.content[0].text)
            return data.get('result',data)
        params=StdioServerParameters(command=sys.executable,args=['-m','security_runtime.cli','mcp'],cwd=root,env=env)
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as stderr:
            async with stdio_client(params,errlog=stderr) as (read,write):
                async with ClientSession(read,write) as client:
                    initialized=await asyncio.wait_for(client.initialize(),20)
                    assert 'Do not ask users for Finding UUIDs' in initialized.instructions
                    listed=(await client.list_tools()).tools
                    assert {'get_security_summary','prepare_task_triage','get_runtime_info'} <= {t.name for t in listed}
                    metadata={t.name:t for t in listed}
                    assert metadata['get_security_summary'].annotations.readOnlyHint
                    assert not metadata['prepare_task_triage'].annotations.readOnlyHint
                    info=unwrap(await client.call_tool('get_runtime_info',{}))
                    assert set(info['required_guidance_tools']) <= set(metadata)
                    assert info['capability_contract']=='developer-guidance-v0.3'
                    summary=unwrap(await client.call_tool('get_security_summary',{}))
                    first=summary['recommended_tasks'][0]['continuation']
                    data=unwrap(await client.call_tool(first['mcp_tool'],first['arguments']))
                    submitted=unwrap(await client.call_tool('submit_triage',{'scan_id':data['scan_id'],
                        'results':[value(p) for p in data['packets']],'triage_session':data['triage_session']}))
                    assert submitted['accepted']==2 and submitted['view']['scan_coverage']=='PARTIAL'
                    next_data=unwrap(await client.call_tool(first['mcp_tool'],first['arguments']))
                    assert next_data['status']=='AWAITING_BUSINESS_FACTS' and not next_data['packets']
                    assert len(next_data['existing_reviews'])==2 and 'triage_session' not in next_data
                    assert SECRET not in json.dumps(next_data)
            stderr.seek(0);assert not stderr.read()
    asyncio.run(run())
    assert store.get_scan('scan-a')==original_scan
    assert source_before=={p.name:p.read_bytes() for p in root.iterdir() if p.is_file()}


def test_existing_review_context_has_explicit_count_and_size_caps(sample):
    root,scan,store=sample
    for i in range(23):
        f=copy.deepcopy(scan.findings[4]);f.id=f'large-{i:02}';f.fingerprint=f'large-fp-{i:02}'
        f.technical_details['vulnerability_id']=f'CVE-2026-{5000+i}';scan.findings.append(f)
    store.save(scan);service=TriageService(store)
    ids=[f.id for f in scan.findings if f.category=='dependency']
    for fid in ids:
        packet=service.prepare('scan-a',finding_ids=[fid])['packets'][0]
        result=value(packet)
        result['reason']=('Bounded synthetic explanation. '*80)[:2000]
        result['attack_path']=('Unknown conditional local behavior. '*70)[:2000]
        result['preconditions_unknown']=[(f'Production unknown {fid} condition {i}. '*10)[:300] for i in range(20)]
        service.submit('scan-a',[result])
    before=snapshot(root);data=prepare(sample,task(sample,'dependency'))
    assert data['existing_review_count']==25 and data['existing_reviews_truncated']
    assert len(data['existing_reviews'])<=20 and len(json.dumps(data['existing_reviews'],ensure_ascii=False,separators=(',',':')).encode())<=65536
    assert len(data['unknown_conditions'])==20 and data['unknown_conditions_truncated']
    assert not data['packets'] and len(data['retained_finding_ids'])==25
    assert snapshot(root)==before and data['existing_review_access']['arguments']['details']


def test_failed_only_requires_explicit_retry_not_new_priority(sample):
    review(sample,(2,));fid=sample[1].findings[2].id
    r=sample[2].triage_records('scan-a')[fid];r.update(status='FAILED',priority='UNTRIAGED')
    packet=TriageService(sample[2]).builder(sample[1].to_dict()).build(sample[1].findings[2].__dict__)
    sample[2].save_triage(TriageRecord(**r),cache_key(sample[1].findings[2].__dict__,packet,AgentNativeProvider()))
    old=task(sample,'code');data=prepare(sample,old)
    assert data['status']=='FAILED_RETRY_REQUIRED' and not data['packets'] and not data['business_questions']
    assert data['deferred_failed_finding_ids']==[fid]
    retry=prepare(sample,old,retry_failed=True)
    assert len(retry['packets'])==1 and sample[2].triage_records('scan-a')[fid]['status']=='FAILED'


def test_untriaged_is_prepared_before_stale_in_same_task(sample):
    review(sample,(4,));old=task(sample,'dependency')
    (sample[0]/'pom.xml').write_text('<project>\n <name>changed</name>\n</project>\n')
    data=prepare(sample,old,limit=1)
    assert data['packets'][0]['finding_id']==sample[1].findings[5].id
    assert data['review_states']['STALE']==1 and data['remaining']==1


def test_runtime_info_cli_is_readonly_and_recovery_uses_same_environment(tmp_path,monkeypatch,capsys):
    from security_runtime.cli import main
    state=tmp_path/'not-created';monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR',str(state))
    assert main(['runtime-info','--json'])==0
    output=capsys.readouterr();info=json.loads(output.out)
    assert not output.err and not state.exists()
    assert info['same_environment_check']['executable']==sys.executable
    assert info['same_environment_check']['arguments']==['-m','security_runtime.cli','runtime-info','--json']
    assert info['tool_check']=='REQUIRED_SUBSET_NOT_EXACT_COUNT'
    assert not any(info['execution'].values()) and '自动' not in str(info['features']['task_triage'])
    checked=__import__('subprocess').run([info['same_environment_check']['executable'],*info['same_environment_check']['arguments']],
        capture_output=True,text=True,encoding='utf-8',check=True,timeout=30)
    assert json.loads(checked.stdout)['capability_contract']==info['capability_contract'] and not checked.stderr


def test_runtime_info_mcp_does_not_initialize_state_and_accepts_extra_tools(tmp_path,monkeypatch):
    from security_runtime.host_guidance import REQUIRED_GUIDANCE_TOOLS
    root=tmp_path/'project';root.mkdir();state=tmp_path/'no-state'
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR',str(state));monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE',str(root))
    s=create_server()
    @s.tool()
    def future_extra_tool()->dict:return {'future':True}
    info=invoke(s,'get_runtime_info')
    assert REQUIRED_GUIDANCE_TOOLS <= {t.name for t in s._tool_manager.list_tools()}
    assert info['features']['automatic_patch_workflow']=='NOT_IMPLEMENTED' and not state.exists()
