"""Replay bounded Codex host analysis of a real saved scan through actual MCP.

No public model/API requests. No scanner mocks are used for the saved native
scan. The analysis below is a review artifact from this coding-agent session,
not an accuracy label, human ground truth, or automated reachability proof.
Only structured records, hashes and size metrics are persisted.
"""
import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from statistics import mean

from security_runtime.models import ScanResult,TargetProfile,Finding,ScannerRun
from security_runtime.storage import SQLiteStore
from security_runtime.triage_models import category
from security_runtime.triage_evidence import encoded
from security_runtime.human import render_scan,render_triage


def unpack(response):
    if response.isError: raise ValueError('MCP request failed')
    data=response.structuredContent or json.loads(response.content[0].text)
    return data.get('result',data) if isinstance(data,dict) else data


def host_analysis(packet):
    line=packet['line'];refs=[{'file':packet['file'],'start_line':line['start'],'end_line':line['end'],'claim':'Scanner location confirmed within bounded source context'}]
    verdict='NEEDS_REVIEW';confidence='MEDIUM';exploitability='UNKNOWN'
    unknown=['Deployment and runtime preconditions are not established.'];attack=''
    reason='Evidence remains insufficient for a stronger conclusion.'
    if packet['category']=='code':
        if packet['rule_id'].endswith(('trust-all-hostname','trust-all-certificates')):
            use=next((c for c in packet['context'] if c['kind']=='same_file_related_use' and 'setSSLSocketFactory' in c['text']),None)
            if use is None: raise ValueError('Benchmark installation evidence is absent')
            refs.append({'file':use['file'],'start_line':use['start_line'],'end_line':use['end_line'],'claim':'Local HTTPS client installs custom verifier and SSL context'})
            verdict='CONFIRMED';confidence='HIGH';exploitability='LIKELY'
            reason='Trust bypass is instantiated and installed in the same-file HTTPS client. The finding is locally confirmed; public exploitability is not proven.'
            attack='HTTPS client setup installs unconditional hostname verifier and trust manager without server-certificate validation.'
            unknown=['Actual production call reachability and attacker network position remain unknown.']
        else:
            reason='MD5 helper is used in key-appended payment signing in the local context. Protocol requirements, authentication impact and an exploitable collision/forgery path require further review; this is not confirmed HIGH merely because MD5 appears.'
            exploitability='CONDITIONAL';unknown=['Protocol compatibility and concrete signature-forgery preconditions.']
    elif packet['category']=='secret':
        kind=packet['enrichment']['file_kind']
        if kind=='DOC':
            verdict='UNLIKELY';confidence='MEDIUM'
            reason='Bounded context is a payment-signature documentation example. That lowers review priority but does not prove the credential is fake; no suppression is permitted.'
        elif kind=='SOURCE':
            verdict='LIKELY';confidence='MEDIUM';exploitability='CONDITIONAL'
            reason='The redacted Java constant is referenced by local AES encode/decode helpers. It is a credible hardcoded-key candidate, but live usage and credential validity remain unproven.'
        else:
            reason='A redacted secret-like value occurs in production-shaped configuration. Example/default status and live credential validity cannot be inferred from location or redacted contents.'
        unknown=['Credential validity and deployment use.'];attack=''
    else:
        reason='Native OSV establishes an affected package/version candidate in this Maven inventory. The partial graph and bounded manifest evidence do not establish use of the affected API or vulnerability-specific runtime conditions.'
        exploitability='CONDITIONAL';unknown=['Affected API reachability, advisory-specific runtime conditions, and complete Maven graph.']
    return dict(finding_id=packet['finding_id'],context_hash=packet['context_hash'],verdict=verdict,
        confidence=confidence,exploitability=exploitability,reason=reason,attack_path=attack,evidence_refs=refs,
        preconditions_met=['Scanner candidate and current local evidence exist.'],preconditions_unknown=unknown,
        recommended_action='Prioritize confirmed TLS bypass. Review configuration secrets and upgrade/advisory preconditions without assuming reachability.')


async def benchmark(scan,store_path,output,executable=None):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters,stdio_client
    project=Path(scan['target_profile']['path'])
    env=dict(os.environ,SECURITY_RUNTIME_STATE_DIR=str(store_path.parent),SECURITY_RUNTIME_WORKSPACE=str(project),
        SECURITY_RUNTIME_INTEGRATION='generic-mcp',SECURITY_RUNTIME_OFFLINE='1')
    command=[str(executable.resolve())] if executable else [sys.executable,'-m','security_runtime.cli']
    params=StdioServerParameters(command=command[0],args=[*command[1:],'mcp'],cwd=project,env=env)
    dep=[f for f in scan['findings'] if category(f)=='dependency']
    critical=[f['id'] for f in dep if f['severity']=='CRITICAL']
    high=[f['id'] for f in dep if f['severity']=='HIGH'][:10]
    selections=[{'categories':['code']},{'categories':['secret']},{'finding_ids':critical+high}]
    sizes=[];submitted=[];packets_metadata=[];cache_hits=0
    with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as stderr:
        async with stdio_client(params,errlog=stderr) as (read,write):
            async with ClientSession(read,write) as client:
                await asyncio.wait_for(client.initialize(),30)
                before=unpack(await client.call_tool('get_findings',{'scan_id':scan['scan_id']}))
                for selection in selections:
                    prepared=unpack(await client.call_tool('prepare_triage',{'scan_id':scan['scan_id'],**selection}))
                    if prepared['errors']: raise ValueError('Benchmark evidence errors')
                    cache_hits+=len(prepared['cached_finding_ids'])
                    packets=prepared['packets']
                    for packet in packets:
                        size=len(encoded(packet));sizes.append(size)
                        packets_metadata.append({'finding_id':packet['finding_id'],'category':packet['category'],
                            'context_hash':packet['context_hash'],'context_bytes':size,
                            'references':[{'file':c['file'],'start_line':c['start_line'],'end_line':c['end_line'],'kind':c['kind']} for c in packet['context']+packet['related_evidence']]})
                    if packets:
                        values=[host_analysis(packet) for packet in packets]
                        accepted=unpack(await client.call_tool('submit_triage',{'scan_id':scan['scan_id'],'results':values,'triage_session':prepared['triage_session']}))
                        submitted+=accepted['records']
                view=unpack(await client.call_tool('get_triage',{'scan_id':scan['scan_id']}))
                after=unpack(await client.call_tool('get_findings',{'scan_id':scan['scan_id']}))
        stderr.seek(0);mcp_stderr=stderr.read()
        if mcp_stderr: raise ValueError('Unexpected MCP benchmark stderr')
    assert len(before)==len(after)==len(scan['findings'])
    original=SQLiteStore(store_path).get_scan(scan['scan_id'])
    assert original==scan,'Triage changed raw scan'
    record={'scenario':'Saved native online Jeepay scan; actual stdio MCP; bounded coding-agent analysis from this session; no public LLM call',
        'scan_id':scan['scan_id'],'analysis_provider':'AGENT_NATIVE / host-agent / host-managed (Codex session)',
        'metrics':{'raw_findings':len(before),'triaged_findings':view['triage_coverage']['triaged'],
            'verdicts':dict(Counter(row['triage']['verdict'] for row in view['findings'] if row['triage_status']=='VALID')),
            'triage_coverage':view['triage_coverage'],'invalid_output_rate':0,'evidence_validation_failures':0,
            'average_context_bytes':round(mean(sizes)) if sizes else None,'maximum_context_bytes':max(sizes,default=0),
            'cache_hits':cache_hits,'dependency_groups':len(view['dependency_groups']),
            'dependency_sample':{'critical':len(critical),'high':len(high)}},
        'packet_metadata':packets_metadata,'records':submitted,'view':view,
        'mcp_stderr':'','raw_findings_preserved':True,'scan_coverage_unchanged':True,
        'native_capability_details':scan['capability_details'],'accuracy_claim':None,
        'human_ground_truth':'UNREVIEWED; stored independently and editable by human reviewers'}
    output.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    output.with_suffix('.human.txt').write_text(render_triage(view)+'\n',encoding='utf-8')
    model=ScanResult(**(scan|{'target_profile':TargetProfile(**scan['target_profile']),
        'findings':[Finding(**f) for f in scan['findings']], 'scanner_runs':[ScannerRun(**r) for r in scan['scanner_runs']]}))
    output.with_name('jeepay-candidate-human.txt').write_text(render_scan(model)+'\n',encoding='utf-8')
    annotations={'scan_id':scan['scan_id'],'allowed_labels':['LIKELY_TRUE_POSITIVE','LIKELY_FALSE_POSITIVE','NEEDS_REVIEW'],
        'records':[{'finding_id':row['finding_id'],'human_label':None,'reviewer':None,'status':'UNREVIEWED'} for row in view['findings'] if row['triage_status']=='VALID']}
    ground_truth=output.with_name('jeepay-human-ground-truth.json')
    if not ground_truth.exists():
        ground_truth.write_text(json.dumps(annotations,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(record['metrics'],ensure_ascii=False,indent=2))


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    parser=argparse.ArgumentParser();parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--state',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--executable',type=Path);args=parser.parse_args()
    scan=json.loads(args.input.read_text(encoding='utf-8'))['result']
    store=SQLiteStore(args.state.resolve()/'scans.db')
    model=ScanResult(**(scan|{'target_profile':TargetProfile(**scan['target_profile']),
        'findings':[Finding(**f) for f in scan['findings']], 'scanner_runs':[ScannerRun(**r) for r in scan['scanner_runs']]}))
    store.save(model)
    asyncio.run(benchmark(scan,store.path,args.output,args.executable))


if __name__=='__main__': main()
