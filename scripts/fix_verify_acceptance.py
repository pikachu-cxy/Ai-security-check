"""Actual local Semgrep acceptance on disposable synthetic Java, never Jeepay."""
import argparse
import asyncio
import json
import os
import tempfile
from pathlib import Path

from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode, ScanResult
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry, SemgrepAdapter
from security_runtime.storage import SQLiteStore
from security_runtime.target import TargetDetector
from security_runtime.verification_policy import local_recheck
from security_runtime.security_summary import SecuritySummaryService
from security_runtime.task_fix import TaskFixService
from security_runtime.sast import SemgrepEngineProvider


def source(line=100, vulnerable=True):
    header = 'import javax.net.ssl.*;\nclass Fixture {\n'
    body = ('HostnameVerifier verifier = (host, session) -> true;' if vulnerable else
            'HostnameVerifier verifier = HttpsURLConnection.getDefaultHostnameVerifier();')
    return header + '\n' * (line - 3) + body + '\n}\n'


def group_source(hostname=True, certificate=True):
    host = ('(host, session) -> true' if hostname else 'HttpsURLConnection.getDefaultHostnameVerifier()')
    check = '' if certificate else 'throw new java.security.cert.CertificateException();'
    return ('import javax.net.ssl.*;\nimport java.security.cert.*;\nclass Fixture {\n' + '\n' * 96 +
        f'HostnameVerifier verifier = {host};\n' +
        'X509TrustManager trust = new X509TrustManager() {\n' +
        f'public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {{ {check} }}\n' +
        'public void checkClientTrusted(X509Certificate[] chain, String auth) {}\n' +
        'public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }\n};\n}\n')


class FailingFixtureEngine(SemgrepEngineProvider):
    # A real Semgrep subprocess deliberately rejects this invalid flag.
    verification_offline = verification_scope_complete = True

    def command(self, executable, request):
        return [str(executable), 'scan', '--runtime-fixture-invalid-flag']


async def native_sdk_acceptance(executable):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    with tempfile.TemporaryDirectory(prefix='runtime-native-fix-') as temporary:
        root = Path(temporary).resolve()
        file = root / 'Tls.java'
        file.write_text(group_source(), encoding='utf-8')
        adapter = SemgrepAdapter()
        with local_recheck():
            found, run = adapter.scan(ScanContext(str(root), ScanMode.FEATURE, ('Tls.java',)), FindingNormalizer(root))
        assert run.status == 'SUCCESS' and len(found) == 2, run
        store = SQLiteStore(root / 'state/scans.db')
        scan = ScanResult('synthetic-native-task-fix', ScanMode.FEATURE, TargetDetector().detect(root, ['Tls.java']),
            'COMPLETED', found, [run], 'Synthetic fixture', 'REVIEW', run.duration_ms)
        store.save(scan)
        before = store.path.read_bytes()
        env = dict(os.environ, SECURITY_RUNTIME_STATE_DIR=str(store.path.parent),
            SECURITY_RUNTIME_WORKSPACE=str(root), SECURITY_RUNTIME_OFFLINE='1', PYTHONUTF8='1')
        params = StdioServerParameters(command=str(Path(executable).resolve()), args=['mcp'], cwd=root, env=env)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as client:
                initialized = await client.initialize()
                assert 'Agent fixes. Runtime verifies.' in initialized.instructions
                names = {t.name for t in (await client.list_tools()).tools}
                assert {'prepare_task_fix','verify_task_fix','get_runtime_info'} <= names
                async def call(name, args):
                    response = await client.call_tool(name, args)
                    assert not response.isError, response
                    data = response.structuredContent or json.loads(response.content[0].text)
                    return data.get('result', data)
                info = await call('get_runtime_info', {})
                assert info['features']['task_fix_verify'] == 'v0.1'
                summary = await call('get_security_summary', {})
                chosen = summary['recommended_tasks'][0]
                fix = await call('prepare_task_fix', chosen['fix_handoff']['arguments'])
                assert fix['status'] == 'READY_FOR_HOST_FIX' and not any(fix['execution'].values())
                args = fix['verification_plan']['arguments']
                unchanged = await call('verify_task_fix', args)
                assert unchanged['status'] == 'STILL_PRESENT', unchanged
                file.write_text(group_source(False, True), encoding='utf-8')
                partial = await call('verify_task_fix', args)
                assert partial['status'] == 'PARTIALLY_RESOLVED', partial
                file.write_text(group_source(False, False), encoding='utf-8')
                complete = await call('verify_task_fix', dict(args, host_reported_execution={'patch_applied':True,'tests_run':True}))
                assert complete['status'] == 'SCANNER_VERIFIED_RESOLVED', complete
                assert complete['host_reported_execution']['trust'] == 'UNTRUSTED_HOST_REPORT'
                assert not complete['runtime_observed_execution']['tests_run']
                assert (await call('verify_task_fix', {'task_ref':'T01'}))['status'] == 'REFRESH_REQUIRED'
        assert store.path.read_bytes() == before
        return {'transport': 'ACTUAL_SDK_STDIO', 'runtime_executable': str(Path(executable).resolve()),
            'runtime_version': info['version'], 'capability_contract': info['capability_contract'],
            'tools': sorted(names), 'unchanged': unchanged, 'one_remaining': partial, 'all_fixed': complete,
            'state_unchanged': True, 'host_natural_language_ux': 'PENDING', 'model_invocation': False}


def run_acceptance():
    with tempfile.TemporaryDirectory(prefix='runtime-fix-verification-') as temporary:
        root = Path(temporary).resolve()
        file = root / 'Tls.java'
        file.write_text(source(), encoding='utf-8')
        adapter = SemgrepAdapter()
        profile = TargetDetector().detect(root, ['Tls.java'])
        with local_recheck():
            found, run = adapter.scan(ScanContext(str(root), ScanMode.FEATURE, ('Tls.java',)), FindingNormalizer(root))
        assert run.status == 'SUCCESS', run
        old = next(f for f in found if f.technical_details['rule_id'] == 'ai-security.java.trust-all-hostname')
        assert old.line_start == 100, old.line_start
        store = SQLiteStore(root / 'state.db')
        scan = ScanResult('synthetic-fix-a', ScanMode.FEATURE, profile, 'COMPLETED', found, [run],
                          'Synthetic local scanner evidence', 'REVIEW', run.duration_ms)
        store.save(scan)
        runtime = SecurityRuntime(ScannerRegistry([adapter]), store)
        exact = runtime.verify(old.id, root)
        file.write_text(source(110), encoding='utf-8')
        moved = runtime.verify(old.id, root)
        assert moved['verification_status'] == 'STILL_PRESENT' and moved['matched_by'] == 'equivalence_key', moved
        assert moved['current_evidence'][0]['line_start'] == 110
        file.write_text(source(110, False), encoding='utf-8')
        fixed = runtime.verify(old.id, root)
        assert fixed['verification_status'] == 'SCANNER_VERIFIED_RESOLVED', fixed
        assert store.get_scan(scan.scan_id)['findings'][0]['line_start'] == 100
        record = {'fixture': 'DISPOSABLE_SYNTHETIC_JAVA', 'semgrep_version': run.version,
                'original': exact, 'line_100_to_110': moved, 'minimal_fix': fixed,
                'target_build': False, 'ground_truth': 'NOT_INDEPENDENT_HUMAN_REVIEW',
                'target_edits': 'SYNTHETIC_HARNESS_ONLY', 'jeepay_modified': False}
        file.write_text(group_source(), encoding='utf-8')
        with local_recheck():
            grouped, grouped_run = adapter.scan(ScanContext(str(root), ScanMode.FEATURE, ('Tls.java',)), FindingNormalizer(root))
        assert len(grouped) == 2, [(f.technical_details, f.line_start) for f in grouped]
        scan.scan_id, scan.findings, scan.scanner_runs = 'synthetic-fix-b', grouped, [grouped_run]
        store.save(scan)
        task = next(t for t in SecuritySummaryService(store).get(root, scan.scan_id, details=True)['tasks'] if t['topic'] == 'tls')
        assert task['finding_count'] == 2
        service = TaskFixService(store, runtime.registry)
        handoff = service.prepare(task['task_ref'], root)
        assert not any(handoff['execution'].values())
        file.write_text(group_source(False, True), encoding='utf-8')
        partial = service.verify(task['task_ref'], root)
        assert partial['status'] == 'PARTIALLY_RESOLVED', partial
        file.write_text(group_source(False, False), encoding='utf-8')
        complete = service.verify(task['task_ref'], root)
        assert complete['status'] == 'SCANNER_VERIFIED_RESOLVED', complete
        broken = SemgrepAdapter(engine_provider=FailingFixtureEngine())
        failure = TaskFixService(store, ScannerRegistry([broken])).verify(task['task_ref'], root)
        assert failure['status'] == 'INCONCLUSIVE', failure
        assert all(m['scanner_runs'][0]['status'] == 'FAILED' for m in failure['members'])
        record.update(grouped_one_remaining=partial, grouped_all_fixed=complete, real_scanner_failure=failure)
        return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--executable', type=Path, help='Additionally verify actual installed/native MCP SDK with real Semgrep')
    args = parser.parse_args()
    record = run_acceptance()
    if args.executable:
        record['installed_native_sdk'] = asyncio.run(native_sdk_acceptance(args.executable))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Actual local Semgrep: occurrence, line movement, minimal fix, grouped partial/all fix and process failure passed.')
