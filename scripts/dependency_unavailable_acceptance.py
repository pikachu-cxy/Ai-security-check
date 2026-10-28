"""Native CLI/MCP dependency failure contract; synthetic inputs, no fallback.

The healthy Trivy path is verified separately by verify_artifact --full.
This gate isolates the unavailable-primary path without downloading any engine.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def assert_dependency_gap(payload):
    assert payload['capability_results']['DEPENDENCY_VULN'] == 'UNAVAILABLE', payload['capability_results']
    details = payload['capability_details']['DEPENDENCY_VULN']
    assert details['active_provider'] is None and details['coverage'] == 'NONE', details
    assert details['primary_provider'] == 'trivy', details
    runs = {run['scanner']: run for run in payload['scanner_runs']}
    assert runs['trivy-vuln']['status'] == 'UNAVAILABLE', runs['trivy-vuln']
    assert runs['trivy-vuln']['error_code'], 'Missing explicit failure diagnostic'
    assert 'osv-scanner' not in runs, 'Default workflow must not invoke OSV'
    assert payload['status'] != 'COMPLETED', 'Missing dependencies cannot be reported as complete'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    executable = str(args.executable.resolve())
    with tempfile.TemporaryDirectory(prefix='dependency-gap-acceptance-') as temporary:
        root = Path(temporary)
        project = root / 'project'
        project.mkdir()
        (project / 'package-lock.json').write_text(json.dumps({
            'name': 'synthetic-dependency-gap', 'lockfileVersion': 3,
            'packages': {'': {'name': 'synthetic-dependency-gap', 'version': '1.0.0'},
                         'node_modules/synthetic-package': {'version': '1.0.0'}}}), encoding='utf-8')
        data = root / 'managed'
        environment = dict(os.environ, SECURITY_RUNTIME_DATA_DIR=str(data),
            SECURITY_RUNTIME_STATE_DIR=str(root / 'state'), SECURITY_RUNTIME_OFFLINE='1',
            SECURITY_RUNTIME_TRIVY_PATH=str(root / 'missing-trivy'),
            SECURITY_RUNTIME_WORKSPACE=str(project), SECURITY_RUNTIME_INTEGRATION='generic-mcp',
            HTTP_PROXY='http://127.0.0.1:9', HTTPS_PROXY='http://127.0.0.1:9', NO_PROXY='')
        for name in ('SECURITY_RUNTIME_CONFIG', 'SECURITY_RUNTIME_PLUGIN_DIR'):
            environment.pop(name, None)
        captured = []
        for progress in (True, False):
            result = subprocess.run([executable, 'scan', '--mode', 'release', '--path', str(project),
                '--json', *([] if progress else ['--no-progress'])], cwd=project, env=environment,
                capture_output=True, text=True, encoding='utf-8', timeout=180)
            assert result.returncode == 0, result.stderr
            payload = json.loads(result.stdout)
            assert_dependency_gap(payload)
            if not progress:
                assert not result.stderr, result.stderr
            captured.append({'progress': progress, 'result': payload, 'stderr': result.stderr})

        async def check_mcp():
            from mcp import ClientSession
            from mcp.client.stdio import StdioServerParameters, stdio_client
            params = StdioServerParameters(command=executable, args=['mcp'], cwd=project, env=environment)
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as client:
                    await asyncio.wait_for(client.initialize(), 30)
                    response = await asyncio.wait_for(client.call_tool('scan_project', {}), 180)
                    assert not response.isError, response
                    payload = response.structuredContent or json.loads(response.content[0].text)
                    payload = payload.get('result', payload)
                    assert_dependency_gap(payload)
                    return payload

        mcp = asyncio.run(check_mcp())
        assert not (data / 'tools' / 'osv-scanner').exists(), 'Unexpected OSV installation'
        args.output.write_text(json.dumps({'scenario': 'Unavailable Trivy; no automatic fallback',
            'executable': executable, 'cli': captured, 'mcp': mcp}, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
        print('Native CLI and MCP report unavailable Trivy without invoking or installing OSV.')


if __name__ == '__main__':
    main()
