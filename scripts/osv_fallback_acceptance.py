"""Actual CLI/MCP fallback using a synthetic lockfile and local test OSV DB.

No production project data, remote vulnerability queries or target builds.
The prepared native OSV/Gitleaks engines must already exist.
"""
import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from security_runtime.toolchain import ToolManager, ToolStatus


def assert_offline_fallback(payload):
    assert payload['capability_results']['DEPENDENCY_VULN'] == 'PARTIAL', 'Offline test data must retain partial coverage'
    details = payload['capability_details']['DEPENDENCY_VULN']
    assert details['active_provider'] == 'osv-scanner' and details['provider_role'] == 'FALLBACK'
    assert details['coverage'] == 'PARTIAL'
    runs = {run['scanner']: run for run in payload['scanner_runs']}
    assert runs['trivy-vuln']['status'] == 'UNAVAILABLE', 'Primary engine must be explicitly unavailable'
    fallback = runs['osv-scanner']
    assert fallback['status'] == 'SUCCESS' and fallback['coverage_contract'] == 'PARTIAL'
    inventory = fallback['dependency_inventory']
    assert inventory['vulnerability_db_freshness'] == 'UNKNOWN', 'A local test archive is not freshness proof'
    assert inventory['complete_dependency_graph_attested'] is False
    assert inventory['planned_manifests'] == inventory['confirmed_manifests'] == 1
    assert inventory['confirmed_package_occurrences'] >= 1, 'Missing extraction is not a passed fallback'
    assert any('freshness is unconfirmed' in note for note in fallback['coverage_notes'])


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--executable',type=Path)
    parser.add_argument('--output',type=Path,default=Path('docs/osv-cli-mcp-evidence.json'))
    args=parser.parse_args()
    manager=ToolManager()
    osv,gitleaks=manager.resolve('osv-scanner'),manager.resolve('gitleaks')
    if osv.status!=ToolStatus.READY or gitleaks.status!=ToolStatus.READY:
        raise SystemExit('Prepare native OSV and Gitleaks explicitly before this acceptance.')
    command=[str(args.executable.resolve())] if args.executable else [sys.executable,'-m','security_runtime.cli']
    with tempfile.TemporaryDirectory(prefix='osv-fallback-acceptance-') as temporary:
        root=Path(temporary);project=root/'project';project.mkdir()
        lock={'name':'synthetic-offline-acceptance','lockfileVersion':3,'packages':{
            '':{'name':'synthetic-offline-acceptance','version':'1.0.0'},
            'node_modules/synthetic-package':{'version':'1.0.0'}}}
        (project/'package-lock.json').write_text(json.dumps(lock),encoding='utf-8')
        db=root/'managed/data/osv/osv-scalibr/npm/all.zip';db.parent.mkdir(parents=True)
        with zipfile.ZipFile(db,'w') as package:
            package.writestr('TEST-LOCAL.json',json.dumps({'schema_version':'1.6.0','id':'TEST-LOCAL',
                'modified':'2026-01-01T00:00:00Z','affected':[{'package':{'ecosystem':'npm','name':'other-package'},'versions':['1.0.0']}]}))
        environment=dict(os.environ,SECURITY_RUNTIME_DATA_DIR=str(root/'managed'),
            SECURITY_RUNTIME_STATE_DIR=str(root/'state'),SECURITY_RUNTIME_OFFLINE='1',
            SECURITY_RUNTIME_TRIVY_PATH=str(root/'missing-trivy.exe'),
            SECURITY_RUNTIME_OSV_SCANNER_PATH=osv.path,SECURITY_RUNTIME_GITLEAKS_PATH=gitleaks.path,
            SECURITY_RUNTIME_WORKSPACE=str(project),SECURITY_RUNTIME_INTEGRATION='generic-mcp',
            HTTP_PROXY='http://127.0.0.1:9',HTTPS_PROXY='http://127.0.0.1:9',NO_PROXY='')
        for name in ('SECURITY_RUNTIME_CONFIG','SECURITY_RUNTIME_PLUGIN_DIR'):
            environment.pop(name,None)
        captured=[]
        for progress in (True,False):
            scan=subprocess.run([*command,'scan','--mode','release','--path',str(project),'--json',*([] if progress else ['--no-progress'])],
                cwd=project,env=environment,capture_output=True,text=True,encoding='utf-8',timeout=60)
            assert scan.returncode==0,scan.stderr
            payload=json.loads(scan.stdout)
            assert_offline_fallback(payload)
            if progress and scan.stderr:
                assert '已选择依赖回退' in scan.stderr and '依赖回退完成' in scan.stderr,scan.stderr
            elif not progress:
                assert not scan.stderr,scan.stderr
            # The existing delayed renderer intentionally stays silent when the
            # actual scan completes before 0.5s, notably on fast arm64 runners.
            captured.append({'progress':progress,'progress_visible':bool(scan.stderr),'result':payload,'stderr':scan.stderr})

        async def check_mcp():
            from mcp import ClientSession
            from mcp.client.stdio import StdioServerParameters,stdio_client
            params=StdioServerParameters(command=command[0],args=[*command[1:],'mcp'],cwd=project,env=environment)
            with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as stderr:
                async with stdio_client(params,errlog=stderr) as (read,write):
                    async with ClientSession(read,write) as client:
                        await asyncio.wait_for(client.initialize(),30)
                        response=await asyncio.wait_for(client.call_tool('scan_project',{}),60)
                        assert not response.isError
                        data=response.structuredContent or json.loads(response.content[0].text)
                        data=data.get('result',data)
                        assert_offline_fallback(data)
                stderr.seek(0)
                assert not stderr.read(),'MCP emitted unexpected stderr'
                return data
        mcp=asyncio.run(check_mcp())
        record={'scenario':'synthetic lockfile; explicit missing Trivy; native OSV 2.6.0; locally authored test DB; offline; loopback proxy',
            'executable':str(args.executable) if args.executable else 'installed Python CLI','cli':captured,'mcp':mcp}
        args.output.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print('Actual CLI JSON, stderr progress, --no-progress and SDK MCP fallback acceptance passed.')


if __name__=='__main__':
    main()
