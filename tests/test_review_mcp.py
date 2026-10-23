"""Actual official SDK stdio; synthetic scanner/host claims, no Hook or LLM."""
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters,stdio_client

from security_runtime.guidance.host_guidance import RUNTIME_WORKFLOW
from security_runtime.guidance.mcp_guidance import MCP_INSTRUCTIONS
from security_runtime.review_skill import ReviewSkillManager
from security_runtime.mcp_views import page_bounds


def unpack(response):
    assert not response.isError
    data=response.structuredContent or json.loads(response.content[0].text)
    return data.get('result',data) if isinstance(data,dict) else data


@pytest.mark.parametrize('arguments',[('page',-1,5),('page',0,51),('page',0,0),
    ('page',True,5),('full',1,None),('summary',0,6,True)])
def test_pagination_boundaries(arguments):
    with pytest.raises(ValueError):
        page_bounds(*arguments[:3],evidence=arguments[3] if len(arguments)>3 else False)


def test_official_sdk_no_hook_task_review_and_output_volume(tmp_path):
    project=tmp_path/'project';project.mkdir()
    source=project/'App.java'
    source.write_text('import javax.net.ssl.*;\nclass App {\n'+
        ''.join(f' HostnameVerifier v{i} = (host, session) -> true;\n' for i in range(114))+'}\n')
    installed=ReviewSkillManager(tmp_path/'home/.agents/skills',tmp_path/'skill-state')
    installed.execute('install')
    assert RUNTIME_WORKFLOW in (installed.root/'references/runtime-workflow.md').read_text(encoding='utf-8')
    assert not (project/'.codex/hooks.json').exists()
    env=dict(os.environ,SECURITY_RUNTIME_WORKSPACE=str(project),
        SECURITY_RUNTIME_STATE_DIR=str(tmp_path/'state'),SECURITY_RUNTIME_OFFLINE='1',
        SECURITY_RUNTIME_INTEGRATION='generic-mcp',SECURITY_RUNTIME_MCP_SELF_TEST='1')
    driver=Path(__file__).with_name('review_fixture_server.py')
    async def run():
        params=StdioServerParameters(command=sys.executable,args=[str(driver)],cwd=project,env=env)
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as stderr:
            async with stdio_client(params,errlog=stderr) as (read,write):
                async with ClientSession(read,write) as client:
                    async def call(name,arguments):
                        return await asyncio.wait_for(client.call_tool(name,arguments),30)
                    initialized=await asyncio.wait_for(client.initialize(),20)
                    assert initialized.instructions==MCP_INSTRUCTIONS
                    before=unpack(await call('get_security_summary',{}))
                    assert before.get('scan_id') is None
                    scan=unpack(await call('scan_project',{'summary':True}))
                    sid=scan['scan_id']
                    assert scan['finding_count']==114 and 'findings' not in scan
                    legacy=await call('get_findings',{'scan_id':sid,'view':'full'})
                    full=unpack(legacy);assert len(full)==114
                    page_response=await call('get_findings',{'scan_id':sid,'view':'summary','limit':5})
                    page=unpack(page_response)
                    assert page['total']==114 and len(page['items'])==5
                    assert page['items'][0]['file_path']=='App.java'
                    assert page['items'][0]['scanner_sources']==['semgrep']
                    ids=[r['id'] for r in page['items']]
                    continuation=page['continuation']
                    while continuation:
                        page=unpack(await call(continuation['tool'],continuation['arguments']))
                        ids.extend(r['id'] for r in page['items']);continuation=page['continuation']
                    assert ids==[row['id'] for row in full]
                    details=unpack(await call('get_findings',{'scan_id':sid,'finding_id':ids[0],
                        'view':'page','limit':1,'include_evidence':True}))
                    assert details['items'][0]['local_evidence']['evidence_status']=='EXACT'
                    rejected=await call('get_findings',{'scan_id':sid,'view':'page','limit':6,'include_evidence':True})
                    assert rejected.isError
                    summary=unpack(await call('get_security_summary',{'scan_id':sid}))
                    reference=summary['recommended_tasks'][0]['continuation']['arguments']['task_ref']
                    prepare_args={'task_ref':reference,'limit':5,'include_existing_reviews':False}
                    prepared=unpack(await call('prepare_task_triage',prepare_args))
                    assert len(prepared['packets'])==1 and prepared['existing_reviews']==[]
                    assert prepared['existing_review_count']==0
                    def claim(packet):
                        return dict(finding_id=packet['finding_id'],context_hash=packet['context_hash'],
                            verdict='NEEDS_REVIEW',confidence='LOW',exploitability='UNKNOWN',
                            reason='Synthetic host protocol claim; deployment unknown',attack_path='',
                            evidence_refs=[],preconditions_met=[],preconditions_unknown=['Deployment'],
                            recommended_action='Review')
                    packets=prepared['packets']
                    generic=unpack(await call('prepare_triage',{'scan_id':sid,'limit':5}))
                    other=next(p for p in generic['packets'] if p['finding_id']!=packets[0]['finding_id'])
                    submit_args={'scan_id':sid,'triage_session':prepared['triage_session']}
                    verbose_ack=await call('submit_triage',{'scan_id':sid,
                        'triage_session':generic['triage_session'],'results':[claim(other)],'compact':False})
                    assert unpack(verbose_ack)['accepted']==1
                    compact_ack=await call('submit_triage',submit_args|{'results':[claim(packets[0])],'compact':True})
                    ack=unpack(compact_ack)
                    assert ack['accepted']==1 and 'view' not in ack
                    assert ack['continuation']['arguments']['task_ref']==reference
                    resumed=unpack(await call('prepare_task_triage',ack['continuation']['arguments']))
                    assert not resumed['packets']
                    view=unpack(await call('get_triage',{'scan_id':sid,'view':'summary','limit':5}))
                    assert view['triage_coverage']['triaged']==2 and view['scan_coverage']==scan['coverage']
                    # Measure complete protocol payload, not just application text.
                    sizes={key:len(value.model_dump_json().encode('utf-8')) for key,value in {
                        'legacy_findings':legacy,'summary_page_5':page_response,
                        'legacy_submit':verbose_ack,'compact_submit':compact_ack}.items()}
                    assert sizes['summary_page_5']<sizes['legacy_findings']/10
                    assert sizes['compact_submit']<sizes['legacy_submit']/10
                    (tmp_path/'output-volume.json').write_text(json.dumps(sizes))
                    subset=[ids[-1]]
                    bounded=unpack(await call('prepare_triage',{'scan_id':sid,'finding_ids':subset,'limit':1}))
                    receipt=unpack(await call('submit_triage',{'scan_id':sid,
                        'triage_session':bounded['triage_session'],'results':[claim(bounded['packets'][0])],'compact':True}))
                    assert receipt['continuation']['arguments']['finding_ids']==subset
                    changed=source.read_text().replace('v0 =','changed =')
                    source.write_text(changed)
                    stale=unpack(await call('get_triage',{'scan_id':sid,'view':'summary','limit':5}))
                    assert stale['triage_coverage']['stale']==3
                    assert not (project/'.codex/hooks.json').exists()
    asyncio.run(run())
