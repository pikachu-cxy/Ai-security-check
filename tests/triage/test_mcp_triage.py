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


def test_real_stdio_host_agent_mock_model(tmp_path):
    (tmp_path/'App.java').write_text('class App {\n void method() {\n  boolean verify() { return true; }\n }\n}\n')
    secret='syntheticHostAgentCredential999'
    (tmp_path/'config.properties').write_text(f'api_key="{secret}"\n')
    env=dict(os.environ,SECURITY_RUNTIME_WORKSPACE=str(tmp_path),SECURITY_RUNTIME_STATE_DIR=str(tmp_path/'state'),
        SECURITY_RUNTIME_INTEGRATION='generic-mcp',SECURITY_RUNTIME_OFFLINE='1')
    driver=Path(__file__).with_name('mcp_fixture_server.py')
    async def run():
        params=StdioServerParameters(command=sys.executable,args=[str(driver)],cwd=tmp_path,env=env)
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as stderr:
            async with stdio_client(params,errlog=stderr) as (read,write):
                async with ClientSession(read,write) as client:
                    await asyncio.wait_for(client.initialize(),20)
                    scan=unpack(await client.call_tool('scan_project',{}));sid=scan['scan_id']
                    prepare=await client.call_tool('prepare_triage',{'scan_id':sid})
                    assert not prepare.isError;data=unpack(prepare)
                    assert secret not in json.dumps(data) and len(data['packets'])==2
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
                    found=unpack(await client.call_tool('get_findings',{'scan_id':sid}))
                    assert len(found)==2 and secret not in json.dumps(found)
                    assert {f['triage_status'] for f in found}=={'VALID','UNTRIAGED'}
                    view=unpack(await client.call_tool('get_triage',{'scan_id':sid}))
                    assert view['triage_coverage']['triaged']==1 and view['scan_coverage']==scan['coverage']
                    # Host workspace binding applies to all added operations.
                    rejected=await client.call_tool('prepare_triage',{'scan_id':'other-workspace'})
                    assert rejected.isError
            stderr.seek(0);text=stderr.read()
            assert secret not in text and '正在' not in text
    asyncio.run(run())
