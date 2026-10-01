"""Real CLI/SDK acceptance plus explicitly mocked Maven/network failures.

All projects and state are isolated. No target build command is executed.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch
from urllib.error import URLError

from security_runtime.cli import main, render
from security_runtime.diagnostics import DiagnosticError, classify_network_error
from security_runtime.mcp_server import _agent_result, create_server
from security_runtime.processes import ProcessResult, run_process
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry
from security_runtime.toolchain import ResolvedTool, ToolManager, ToolStatus


MAVEN_STDERR = ('FATAL Error remote Maven repository returned 429 Too Many Requests\n'
                'https://repo.maven.apache.org/maven2/example/test.pom\nRetry-After: 1299.\n'
                'Authorization: Bearer DIAGNOSTIC_PRIVATE_AUTH\npassword=DIAGNOSTIC_PRIVATE_PASSWORD')


def mock_registry():
    manager = ToolManager()
    manager.ensure = lambda tool: ResolvedTool(tool, 'mock', tool, None, ToolStatus.READY)
    manager.prepare_trivy_database = lambda binary: ToolStatus.READY
    return ScannerRegistry(tool_manager=manager)


def mock_execute(args, cwd, timeout):
    if Path(args[0]).name == 'semgrep':
        return ProcessResult(0, '{"results": []}', '', 1)
    if args[0] == 'gitleaks':
        Path(args[args.index('--report-path') + 1]).write_text(json.dumps([
            {'Description': 'Synthetic acceptance secret', 'File': 'application.yml', 'StartLine': 1, 'RuleID': 'synthetic-test'}]))
        return ProcessResult(0, '', '', 1)
    assert args[0] == 'trivy'
    return ProcessResult(1, '', MAVEN_STDERR, 1)


def capture(args):
    output = io.StringIO()
    with redirect_stdout(output):
        try:
            code = main(args)
        except SystemExit as exc:
            code = exc.code
    return {'exit_code': code, 'stdout': output.getvalue()}


async def mcp_failure(root):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    env = dict(os.environ, SECURITY_RUNTIME_WORKSPACE=str(root), SECURITY_RUNTIME_INTEGRATION='generic-mcp')
    params = StdioServerParameters(command=sys.executable, args=[str(Path(__file__).resolve()), '--mcp-mock-server'], cwd=root, env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as client:
            await client.initialize()
            response = await client.call_tool('scan_project', {})
            assert not response.isError
            result = response.structuredContent or json.loads(response.content[0].text)
            return result.get('result', result)


def run():
    evidence = {'notes': ['Git/non-Git scans use actual installed engines.',
                           'Maven HTTP 429 and first-download timeouts are explicit mocks, not a real Jeepay scan.',
                           'No Maven/Gradle/npm/pip/go target build or installation command is run.']}
    with tempfile.TemporaryDirectory(prefix='runtime-diagnostics-') as temporary:
        base = Path(temporary)
        old_environment = dict(os.environ)
        try:
            os.environ['SECURITY_RUNTIME_STATE_DIR'] = str(base / 'state')
            os.environ['SECURITY_RUNTIME_OFFLINE'] = '1'
            evidence['real_cli'] = {}
            for name, is_git in [('git-project', True), ('source-directory', False)]:
                root = base / name
                root.mkdir()
                (root / 'app.py').write_text('import os\nos.system(input())\n')
                (root / 'requirements.txt').write_text('requests==2.31.0\n')
                if is_git:
                    subprocess.run(['git', 'init', '-q', str(root)], check=True)
                commands = [['--version'], ['doctor'], ['doctor', '--verbose'], ['tools', 'status'],
                            ['scan', '--mode', 'release', '--json'], ['scan', '--mode', 'release']]
                records = []
                for args in commands:
                    result = run_process([sys.executable, '-m', 'security_runtime.cli', *args], cwd=root, env=dict(os.environ), timeout=180)
                    assert result.return_code in (0, 1), result.stderr
                    records.append({'command': 'security-check ' + ' '.join(args), 'exit_code': result.return_code, 'stdout': result.stdout})
                    if '--json' in args:
                        payload = json.loads(result.stdout)
                        assert all(run['status'] == 'SUCCESS' for run in payload['scanner_runs']), payload['scanner_runs']
                evidence['real_cli'][name] = records
            root = base / 'mock-maven-project'
            root.mkdir()
            (root / 'pom.xml').write_text('<project><modelVersion>4.0.0</modelVersion></project>')
            (root / 'application.yml').write_text('password: SYNTHETIC_ONLY\n')
            (root / 'App.java').write_text('class App {}\n')
            original_cwd = Path.cwd()
            try:
                os.chdir(root)
                with patch('security_runtime.cli.ScannerRegistry', side_effect=lambda **kwargs: mock_registry()), patch('security_runtime.scanners._execute', side_effect=mock_execute):
                    evidence['mock_maven_cli'] = [capture(args) for args in [['--version'], ['doctor'], ['doctor', '--verbose'], ['tools', 'status'], ['scan', '--mode', 'release'], ['scan', '--mode', 'release', '--json']]]
            finally:
                os.chdir(original_cwd)
            payload = json.loads(evidence['mock_maven_cli'][-1]['stdout'])
            assert payload['capability_results']['SECRET_SCAN'] == 'PARTIAL'
            assert payload['capability_results']['DEPENDENCY_VULN'] == 'FAILED'
            assert len(payload['findings']) == 1 and payload['coverage'] == 'PARTIAL'
            evidence['mock_maven_mcp_sdk'] = asyncio.run(mcp_failure(root))
            assert evidence['mock_maven_mcp_sdk']['scanner_runs'][-1]['error_code'] == 'MAVEN_RATE_LIMITED'
            evidence['download_timeout'] = {}
            os.environ['SECURITY_RUNTIME_OFFLINE'] = '0'
            for configured in (False, True):
                for key in ('HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy'):
                    os.environ.pop(key, None)
                if configured:
                    os.environ['HTTPS_PROXY'] = 'http://user:DIAGNOSTIC_PRIVATE_PROXY@proxy.invalid:8080/?token=DIAGNOSTIC_PRIVATE_QUERY'
                manager = ToolManager(root=base / ('mock-download-' + str(configured)))
                manager.resolve = lambda tool: ResolvedTool(tool, '', '', None, ToolStatus.MISSING)
                with patch('urllib.request.urlopen', side_effect=URLError(TimeoutError())), patch('security_runtime.cli.ToolManager', return_value=manager):
                    record = capture(['tools', 'install', 'gitleaks'])
                assert record['exit_code'] == 2 and 'NETWORK_TIMEOUT' in record['stdout']
                evidence['download_timeout']['proxy_configured' if configured else 'proxy_not_configured'] = record
            assert 'DIAGNOSTIC_PRIVATE_' not in json.dumps(evidence)
        finally:
            os.environ.clear()
            os.environ.update(old_environment)
    return evidence


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path)
    parser.add_argument('--mcp-mock-server', action='store_true')
    args = parser.parse_args()
    if args.mcp_mock_server:
        with patch('security_runtime.scanners._execute', side_effect=mock_execute):
            create_server(SecurityRuntime(registry=mock_registry())).run(transport='stdio')
    else:
        assert args.output is not None
        evidence = run()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print('Diagnostics acceptance passed: ' + str(args.output))
