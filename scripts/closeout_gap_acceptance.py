"""Replay mixed/control closeouts through MCP; host analyses are fixed fixtures.
No original project/config changes, no network or target dependency installation.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from security_runtime.hook_state import no_links
from task_review_v3_acceptance import V3Review, require_v3

SOURCES = ['dashboard.py','settings.py','package.json','package-lock.json','component-profile.json',
           *['modules/'+n+'.py' for n in ('command','file','page','record','request','sql')],
           *['orders/'+n+'.py' for n in ('api','presentation','repository','service')],
           'tests/test_baseline.py','tests/test_workbench.py','tests/test_security_fixes.py']
CONTEXT = ['dashboard.py','settings.py','package.json','package-lock.json',
           *['modules/'+n+'.py' for n in ('command','file','page','record','request','sql')],
           *['orders/'+n+'.py' for n in ('api','presentation','repository','service')],
           'tests/test_baseline.py','tests/test_workbench.py','tests/test_security_fixes.py']

def baseline(source, root):
    names=subprocess.check_output(['git','-C',str(source),'ls-tree','-r','--name-only','HEAD']).decode().splitlines()
    for name in names:
        if name not in SOURCES+['README.md','.gitignore','modules/__init__.py','orders/__init__.py']:
            raise ValueError('Unexpected fixture source')
        target=root/name; target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(subprocess.check_output(['git','-C',str(source),'show','HEAD:'+name]))
    subprocess.run(['git','-c','init.templateDir=','init','-q',str(root)],check=True)

def copy_files(source, root, names=SOURCES):
    for name in names:
        path=source/name; no_links(path)
        if path.is_file():
            target=root/name; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(path.read_bytes())

async def run(args):
    output=args.output.absolute(); no_links(output)
    if output.exists(): raise ValueError('Use a fresh output')
    output.mkdir(parents=True)
    receipts=[]
    for index,source in enumerate((args.mixed,args.control),1):
        source=source.resolve(strict=True); no_links(source)
        root=output/f'project-{index}'; root.mkdir(); baseline(source,root)
        env={k:os.environ[k] for k in ('SystemRoot','PATH','LOCALAPPDATA','APPDATA','TEMP','TMP','USERPROFILE') if k in os.environ}
        env.update(SECURITY_RUNTIME_STATE_DIR=str(output/f'state-{index}'),
            SECURITY_RUNTIME_DATA_DIR=str(args.engine_root.resolve()), SECURITY_RUNTIME_WORKSPACE=str(root.resolve()),
            SECURITY_RUNTIME_OFFLINE='1', SECURITY_RUNTIME_MCP_SELF_TEST='1', PYTHONUTF8='1')
        params=StdioServerParameters(command=str(args.executable.resolve()),args=['mcp'],cwd=root,env=env)
        with (output/f'stderr-{index}.txt').open('w',encoding='utf-8') as stderr:
            async with stdio_client(params,errlog=stderr) as (read,write):
                async with ClientSession(read,write) as client:
                    await client.initialize()
                    async def call(name,**kw):
                        r=await client.call_tool(name,kw)
                        if r.isError: raise AssertionError((name,r.content))
                        data=r.structuredContent or json.loads(r.content[0].text)
                        return data.get('result',data)
                    async def windows(review,names=CONTEXT,overrides=None):
                        evidence={}
                        for name in names:
                            if not (root/name).is_file(): continue
                            low, high = (overrides or {}).get(name, (1,None))
                            evidence[name]=await review.read(name,low,high)
                        return evidence
                    info=await call('get_runtime_info')
                    require_v3(info,{tool.name for tool in (await client.list_tools()).tools})
                    original=(await call('begin_security_task',task_key='normal-development',workspace_path=str(root)))['task_ref']
                    copy_files(source,root)
                    # Intentionally omit finish: reproduce the observed early prepare.
                    packet=await call('prepare_task_security_review',task_ref=original,workspace_path=str(root),protocol_version=3)
                    assert packet['status']=='REVIEW_REQUIRED'
                    review=V3Review(call,original,packet['review_session'],root)
                    await review.plan()
                    evidence=await windows(review)
                    findings=[]
                    if index==1:
                        for path,category in [('orders/repository.py','authorization'),('modules/sql.py','sql-injection'),
                                              ('modules/file.py','path-traversal'),('modules/request.py','ssrf'),
                                              ('modules/record.py','deserialization'),('modules/page.py','xss')]:
                            refs=[evidence['dashboard.py'][0],evidence[path][0]]
                            if category=='authorization':
                                refs += [evidence['orders/api.py'][0],evidence['orders/service.py'][0]]
                            item=dict(title='Fixture '+category,category=category,severity='MEDIUM',
                                primary_evidence=evidence[path][0],evidence_refs=refs,impact='Untrusted input reaches the original unchecked operation.',
                                preconditions=['Caller controls input'],unknowns=['External deployment and reachability not verified'],
                                counterevidence=['No actual external operation executed'],fix_advice='Use the corresponding checked implementation.')
                            if category=='authorization':
                                item.update(risk_scope='RELATED_EXISTING',task_evidence=evidence['orders/api.py'][0],
                                            current_protections=['Login and output field filter; owner check absent'])
                            findings.append(item)
                    initial_receipt,initial_pages=await review.save_partial(findings,
                        ['Fixed host fixture; no independent AI reasoning or complete before/current review.'])
                    initial=initial_pages[0]
                    ledger=await call('get_task_risk_ledger',task_ref=original,workspace_path=str(root))
                    assert ledger['total']==(13 if index==1 else 0), ledger
                    assert initial['host_review']['coverage']=='PARTIAL', initial
                    assert initial['host_review']['finding_count']==len(findings)
                    verification=[]
                    if index==1:
                        summary=await call('get_security_summary',scan_id=initial['static']['scan_id'],details=True,workspace_path=str(root))
                        tasks=summary['tasks']; assert len(tasks)==3
                        for task in tasks:
                            await call('prepare_task_fix',task_ref=task['task_ref'],workspace_path=str(root))
                        copy_files(args.repaired,root,['modules/command.py','settings.py','component-profile.json','package.json','package-lock.json'])
                        for task in tasks:
                            result=await call('verify_task_fix',task_ref=task['task_ref'],workspace_path=str(root))
                            verification.append(result)
                            assert result['status']=='SCANNER_VERIFIED_RESOLVED', result
                        ref=(await call('begin_security_task',task_key='approved-context-repair',workspace_path=str(root)))['task_ref']
                        copy_files(args.repaired,root)
                        p=await call('prepare_task_security_review',task_ref=ref,workspace_path=str(root),protocol_version=3)
                        repair_review=V3Review(call,ref,p['review_session'],root)
                        await repair_review.plan()
                        needed=['dashboard.py',*['modules/'+n+'.py' for n in ('file','page','record','request','sql')],
                            'orders/api.py','orders/service.py','orders/repository.py',
                            'modules/command.py','settings.py','tests/test_workbench.py','tests/test_security_fixes.py']
                        e=await windows(repair_review,needed,{'tests/test_workbench.py':(46,89)})
                        resolutions=[]
                        for item in ledger['items']:
                            if item['source']!='HOST_TASK_REVIEW': continue
                            resolutions.append(dict(original_task_ref=original,finding_id=item['finding_id'],
                                evidence_refs=[e[path][0] for path in item['required_source_paths']],outcome='INCONCLUSIVE',
                                rationale='Selected repaired source was read in a fixed fixture; partial host coverage cannot establish resolution.',
                                tests='Host ran the mock regression suite in this isolated copy.'))
                        test=subprocess.run([str(args.python.resolve()),'-B','-m','unittest','discover','-s','tests','-v'],cwd=root,capture_output=True,text=True)
                        (output/'tests.txt').write_text(test.stdout+test.stderr,encoding='utf-8')
                        assert test.returncode==0
                        final_receipt,final_pages=await repair_review.save_partial([],
                            ['Fixed host fixture; incomplete before/current obligations and no independent model validation.'],
                            risk_resolutions=resolutions)
                        final=final_pages[0]
                        ledger=await call('get_task_risk_ledger',task_ref=original,workspace_path=str(root))
                        assert ledger['counts']=={'SCANNER_VERIFIED_RESOLVED':7,'INCONCLUSIVE':6}, ledger
                        assert final['host_review']['coverage']=='PARTIAL'
                        assert not final['repair_authorized']
                    else:
                        final=initial
                        final_receipt,final_pages=initial_receipt,initial_pages
                        assert not initial['risk_choices'] and not initial['static']['finding_count']
                    receipts.append(dict(case=index,build_identity=info['build_identity'],original_task_ref=original,
                        initial=initial,initial_receipt=initial_receipt,initial_history_pages=initial_pages,
                        final=final,final_receipt=final_receipt,final_history_pages=final_pages,risk_ledger=ledger,verification=verification,
                        host_review_is_fixture=True,desktop_dispatch_observed=False,original_projects_modified=False))
    (output/'receipt.json').write_text(json.dumps(receipts,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(status='PASS',receipt=str(output/'receipt.json'),
        ledger_counts=[r['risk_ledger']['counts'] for r in receipts]),ensure_ascii=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('executable','python','engine-root','output','mixed','control','repaired'):
        p.add_argument('--'+name,type=Path,required=True)
    asyncio.run(run(p.parse_args()))
