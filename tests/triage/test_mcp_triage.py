import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters,stdio_client


def unpack(response):
    data=response.structuredContent or json.loads(response.content[0].text)
    return data.get('result',data) if isinstance(data,dict) else data


def assert_unverified_secret_context(local, secret):
    assert local['evidence_status']=='UNAVAILABLE'
    assert local['reason']=='SNAPSHOT_FINGERPRINT_MISSING'
    assert local['original_evidence'] is None
    assert local['current_context']['relative_path']=='config.properties'
    assert local['current_context']['matched_code']==f'api_key="{secret}"'
    assert local['redaction']=='NONE' and local['source_representation_version']==3


def test_real_stdio_host_agent_mock_model(tmp_path):
    project=tmp_path/'project';project.mkdir()
    (project/'App.java').write_text('class App {\n void method() {\n  boolean verify() { return true; }\n }\n}\n')
    secret='syntheticHostAgentCredential999'
    (project/'config.properties').write_text(f'api_key="{secret}"\n')
    env=dict(os.environ,SECURITY_RUNTIME_WORKSPACE=str(project),SECURITY_RUNTIME_STATE_DIR=str(tmp_path/'state'),
        SECURITY_RUNTIME_INTEGRATION='generic-mcp',SECURITY_RUNTIME_OFFLINE='1')
    driver=Path(__file__).with_name('mcp_fixture_server.py')
    async def run():
        params=StdioServerParameters(command=sys.executable,args=[str(driver)],cwd=project,env=env)
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as stderr:
            async with stdio_client(params,errlog=stderr) as (read,write):
                async with ClientSession(read,write) as client:
                    await asyncio.wait_for(client.initialize(),20)
                    scan=unpack(await client.call_tool('scan_project',{}));sid=scan['scan_id']
                    prepare=await client.call_tool('prepare_triage',{'scan_id':sid})
                    assert not prepare.isError;data=unpack(prepare)
                    assert len(data['packets'])==2
                    secret_packet=next(p for p in data['packets'] if p['category']=='secret')
                    assert secret_packet['source_presentation']=='RAW_V3'
                    assert any(row['file']=='config.properties' and row['text']==f'api_key="{secret}"'
                               for row in secret_packet['context'])
                    assert secret_packet['local_evidence']['redaction']=='NONE'
                    assert secret_packet['local_evidence']['evidence_status']=='UNAVAILABLE'
                    assert secret_packet['local_evidence']['reason']=='SNAPSHOT_FINGERPRINT_MISSING'
                    assert secret_packet['local_evidence']['original_match_verified'] is False
                    assert secret_packet['sanitized_scanner_evidence']=='[REDACTED_SECRET]'
                    packet=next(p for p in data['packets'] if p['category']=='code')
                    value=dict(finding_id=packet['finding_id'],context_hash=packet['context_hash'],verdict='LIKELY',confidence='HIGH',exploitability='UNKNOWN',reason='Mock model; local signal only',attack_path='',
                        evidence_refs=[{'file':packet['file'],'start_line':3,'end_line':3,'claim':'local signal'}],preconditions_met=[],preconditions_unknown=['Reachability unknown'],recommended_action='Review')
                    bad=json.loads(json.dumps(value));bad['evidence_refs'][0]['file']='../outside'
                    rejected=await client.call_tool('submit_triage',{'scan_id':sid,'results':[bad],'triage_session':data['triage_session']})
                    assert rejected.isError
                    rejected=await client.call_tool('submit_triage',{'scan_id':sid,'results':[value],'triage_session':'fabricated'})
                    assert rejected.isError
                    accepted=await client.call_tool('submit_triage',{'scan_id':sid,'results':[value],'triage_session':data['triage_session']})
                    assert not accepted.isError
                    rejected=await client.call_tool('submit_triage',{'scan_id':sid,'results':[value],'triage_session':data['triage_session']})
                    assert rejected.isError
                    found=unpack(await client.call_tool('get_findings',{'scan_id':sid,'view':'full'}))
                    # This scanner fixture explicitly supplies a marker as its
                    # evidence. Raw source reads do not rewrite that old input.
                    assert len(found)==2 and secret not in json.dumps(found)
                    assert {f['triage_status'] for f in found}=={'VALID','UNTRIAGED'}
                    assert all(f['quality']['finding_id'].startswith('fq1-') for f in found)
                    assert {f['quality']['triage_status'] for f in found}=={'UNREVIEWED'}
                    assert {f['quality']['evidence']['evidence_level'] for f in found}=={'DIRECT_MATCH','SECRET_MATCH'}
                    assert all(f['quality']['evidence']['trace']==[] for f in found)
                    detailed=unpack(await client.call_tool('get_findings',{'scan_id':sid,'include_evidence':True,'view':'full'}))
                    assert len(detailed)==2
                    local=next(f for f in detailed if f['category']!='secret')['local_evidence']
                    assert local['reason']=='SNAPSHOT_FINGERPRINT_MISSING'
                    assert 'verify()' in local['current_context']['matched_code']
                    assert local['original_evidence'] is None
                    assert_unverified_secret_context(
                        next(f for f in detailed if f['category']=='secret')['local_evidence'], secret)
                    one=unpack(await client.call_tool('get_findings',{'scan_id':sid,'include_evidence':True,'finding_id':detailed[0]['id'],'context_lines':0,'view':'full'}))
                    assert len(one)==1 and one[0]['id']==detailed[0]['id']
                    rejected=await client.call_tool('get_findings',{'scan_id':sid,'finding_id':'not-in-scan'})
                    assert rejected.isError
                    # Explicit local synthetic review becomes visible through
                    # the existing MCP tool without rewriting AI validation.
                    from security_runtime.finding_quality import FindingQualityService
                    from security_runtime.storage import SQLiteStore
                    review_store=SQLiteStore(tmp_path/'state/scans.db')
                    row=next(f['quality'] for f in found if f['category']!='secret')
                    FindingQualityService(review_store).review(sid,[dict(
                        finding_id=row['finding_id'],observation_hash=row['observation_hash'],
                        triage_status='TRUE_POSITIVE',triage_reason='Synthetic human review',triage_source='HUMAN')])
                    refreshed=unpack(await client.call_tool('get_findings',{'scan_id':sid,'view':'full'}))
                    reviewed=next(f for f in refreshed if f['category']!='secret')
                    assert reviewed['quality']['triage_status']=='TRUE_POSITIVE'
                    assert reviewed['quality']['triage_source']=='HUMAN' and reviewed['verdict']=='LIKELY'
                    view=unpack(await client.call_tool('get_triage',{'scan_id':sid}))
                    assert view['triage_coverage']['triaged']==1 and view['scan_coverage']==scan['coverage']
                    # Host workspace binding applies to all added operations.
                    rejected=await client.call_tool('prepare_triage',{'scan_id':'other-workspace'})
                    assert rejected.isError
            stderr.seek(0);text=stderr.read()
            assert secret not in text and '正在' not in text
    asyncio.run(run())


def test_real_stdio_local_evidence_freshness(tmp_path):
    project=tmp_path/'project';project.mkdir()
    source=project/'App.java'
    source.write_text('class App {\n void method() {\n boolean verify() { return true; }\n }\n}\n')
    secret='syntheticLocalEvidenceCredentialOnly'
    (project/'config.properties').write_text(f'api_key="{secret}"\n')
    env=dict(os.environ,SECURITY_RUNTIME_WORKSPACE=str(project),
        SECURITY_RUNTIME_STATE_DIR=str(tmp_path/'state'),SECURITY_RUNTIME_INTEGRATION='generic-mcp',
        SECURITY_RUNTIME_OFFLINE='1',SECURITY_RUNTIME_TEST_CAPTURE_EVIDENCE='1')
    driver=Path(__file__).with_name('mcp_fixture_server.py')
    async def run():
        params=StdioServerParameters(command=sys.executable,args=[str(driver)],cwd=project,env=env)
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as stderr:
            async with stdio_client(params,errlog=stderr) as (read,write):
                async with ClientSession(read,write) as client:
                    await asyncio.wait_for(client.initialize(),20)
                    scan=unpack(await client.call_tool('scan_project',{}))
                    args={'scan_id':scan['scan_id'],'include_evidence':True,'view':'full'}
                    found=unpack(await client.call_tool('get_findings',args))
                    code=next(row for row in found if row['category']!='secret')
                    local=code['local_evidence']
                    assert local['evidence_status']=='EXACT' and local['current_context'] is None
                    assert 'verify()' in local['original_evidence']['matched_code']
                    # Only App.java has a captured fingerprint in this fixture;
                    # secret source is current context, not verified scan evidence.
                    assert_unverified_secret_context(
                        next(row for row in found if row['category']=='secret')['local_evidence'], secret)
                    source.write_text(source.read_text()+'// changed\n')
                    changed=unpack(await client.call_tool('get_findings',dict(args,finding_id=code['id'])))
                    assert changed[0]['id']==code['id'] and changed[0]['quality']['finding_id']==code['quality']['finding_id']
                    assert changed[0]['quality']['triage_status']=='UNREVIEWED'
                    local=changed[0]['local_evidence']
                    assert local['evidence_status']=='STALE' and local['original_evidence'] is None
                    assert 'verify()' in local['current_context']['matched_code']
                    assert scan['coverage']!='UNKNOWN'
            stderr.seek(0)
            assert secret not in stderr.read()
    asyncio.run(run())
