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
from security_runtime.tasks.fix import TaskFixService
from security_runtime.sast import SemgrepEngineProvider
from security_runtime.guidance.mcp_guidance import MCP_INSTRUCTIONS
if __package__:
    from .tls_impact_fixture import assess_tls_fixture
else:
    from tls_impact_fixture import assess_tls_fixture


def acceptance_workspace(temporary):
    base = Path(temporary).resolve()
    root = base / 'project'
    root.mkdir()
    return root, SQLiteStore(base / 'state/scans.db')


TLS_RULE_ID = 'java.lang.security.audit.crypto.ssl.insecure-hostname-verifier.insecure-hostname-verifier'


def source(line=100, vulnerable=True):
    header = 'import javax.net.ssl.*;\nclass Fixture {\n'
    body = ('class InsecureVerifier implements HostnameVerifier { public boolean verify(String host, SSLSession session) { return true; } }' if vulnerable else
            'HostnameVerifier verifier = HttpsURLConnection.getDefaultHostnameVerifier();')
    return header + '\n' * (line - 3) + body + '\n}\n'


def write_task_sources(root, hostname=True, secondary=True):
    # Independent paths have independent equivalence identities. Both fixtures
    # use the pinned upstream hostname verifier rule.
    (root / 'Tls.java').write_text(source(vulnerable=hostname), encoding='utf-8')
    (root / 'OtherTls.java').write_text(source(vulnerable=secondary).replace('class Fixture', 'class OtherFixture'), encoding='utf-8')


class FailingFixtureEngine(SemgrepEngineProvider):
    # A real Semgrep subprocess deliberately rejects this invalid flag.
    verification_offline = verification_scope_complete = True

    def command(self, executable, request):
        return [str(executable), 'scan', '--runtime-fixture-invalid-flag']


async def native_sdk_acceptance(executable):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    with tempfile.TemporaryDirectory(prefix='runtime-native-fix-') as temporary:
        root, store = acceptance_workspace(temporary)
        file = root / 'Tls.java'
        write_task_sources(root)
        adapter = SemgrepAdapter()
        with local_recheck():
            found, run = adapter.scan(ScanContext(str(root), ScanMode.FEATURE, ('Tls.java', 'OtherTls.java')), FindingNormalizer(root))
        assert run.status == 'SUCCESS' and len(found) == 2, run
        scan = ScanResult('synthetic-native-task-fix', ScanMode.FEATURE, TargetDetector().detect(root, ['Tls.java', 'OtherTls.java']),
            'COMPLETED', found, [run], 'Synthetic fixture', 'REVIEW', run.duration_ms)
        store.save(scan)
        before = store.path.read_bytes()
        env = dict(os.environ, SECURITY_RUNTIME_STATE_DIR=str(store.path.parent),
            SECURITY_RUNTIME_WORKSPACE=str(root), SECURITY_RUNTIME_OFFLINE='1', PYTHONUTF8='1')
        params = StdioServerParameters(command=str(Path(executable).resolve()), args=['mcp'], cwd=root, env=env)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as client:
                initialized = await client.initialize()
                assert initialized.instructions == MCP_INSTRUCTIONS
                names = {t.name for t in (await client.list_tools()).tools}
                assert {'prepare_task_fix','verify_task_fix','get_runtime_info'} <= names
                async def call(name, args):
                    response = await client.call_tool(name, args)
                    assert not response.isError, response
                    data = response.structuredContent or json.loads(response.content[0].text)
                    return data.get('result', data)
                info = await call('get_runtime_info', {})
                assert info['features']['task_fix_verify'] == 'v0.1'
                from security_runtime.guidance.guidance_catalog import get_runtime_guidance
                guidance = await call('get_runtime_guidance', {'topic': 'repair-impact'})
                expected = get_runtime_guidance('repair-impact')
                assert guidance['status'] == 'READY' and guidance['content'] == expected['content']
                assert guidance['sha256'] == info['guidance_catalog']['topics']['repair-impact']['sha256']
                assert not guidance['authority']['repair_authorized']
                summary = await call('get_security_summary', {})
                chosen = summary['recommended_tasks']
                assert len(chosen) == 2 and all(t['finding_count'] == 1 for t in chosen)
                fixes = []
                for task in chosen:
                    arguments = task['fix_handoff']['arguments']
                    waiting = await call('prepare_task_fix', arguments)
                    assert waiting['status'] == 'IMPACT_REQUIRED', waiting
                    ref = await assess_tls_fixture(call, waiting, root, {
                        'Tls.java': source(), 'OtherTls.java': source().replace('class Fixture', 'class OtherFixture')})
                    fixes.append(await call('prepare_task_fix', dict(arguments, impact_ref=ref)))
                assert all(f['status'] == 'READY_FOR_HOST_FIX' and not any(f['execution'].values()) for f in fixes)
                arguments = [f['verification_plan']['arguments'] for f in fixes]
                unchanged = [await call('verify_task_fix', args) for args in arguments]
                assert all(r['status'] == 'STILL_PRESENT' for r in unchanged), unchanged
                write_task_sources(root, False, True)
                partial = [await call('verify_task_fix', args) for args in arguments]
                assert {r['status'] for r in partial} == {'SCANNER_VERIFIED_RESOLVED', 'STILL_PRESENT'}, partial
                write_task_sources(root, False, False)
                complete = [await call('verify_task_fix', dict(args, host_reported_execution={'patch_applied':True,'tests_run':True})) for args in arguments]
                assert all(r['status'] == 'SCANNER_VERIFIED_RESOLVED' for r in complete), complete
                assert all(r['host_reported_execution']['trust'] == 'UNTRUSTED_HOST_REPORT' for r in complete)
                assert not any(r['runtime_observed_execution']['tests_run'] for r in complete)
                assert (await call('verify_task_fix', {'task_ref':'T01'}))['status'] == 'REFRESH_REQUIRED'
        assert store.path.read_bytes() == before
        return {'transport': 'ACTUAL_SDK_STDIO', 'runtime_executable': str(Path(executable).resolve()),
            'runtime_version': info['version'], 'capability_contract': info['capability_contract'],
            'tools': sorted(names), 'unchanged': unchanged, 'one_remaining': partial, 'all_fixed': complete,
            'state_unchanged': True, 'host_natural_language_ux': 'PENDING', 'model_invocation': False,
            'impact_reasoning': 'SIMULATED_HOST_KNOWN_TLS_FIXTURE_ONLY'}


def run_acceptance():
    with tempfile.TemporaryDirectory(prefix='runtime-fix-verification-') as temporary:
        root, store = acceptance_workspace(temporary)
        file = root / 'Tls.java'
        file.write_text(source(), encoding='utf-8')
        adapter = SemgrepAdapter()
        profile = TargetDetector().detect(root, ['Tls.java'])
        with local_recheck():
            found, run = adapter.scan(ScanContext(str(root), ScanMode.FEATURE, ('Tls.java',)), FindingNormalizer(root))
        assert run.status == 'SUCCESS', run
        old = next(f for f in found if f.technical_details['rule_id'] == TLS_RULE_ID)
        assert old.line_start == 100, old.line_start
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
        write_task_sources(root)
        with local_recheck():
            grouped, grouped_run = adapter.scan(ScanContext(str(root), ScanMode.FEATURE, ('Tls.java', 'OtherTls.java')), FindingNormalizer(root))
        assert len(grouped) == 2, [(f.technical_details, f.line_start) for f in grouped]
        scan.target_profile = TargetDetector().detect(root, ['Tls.java', 'OtherTls.java'])
        scan.scan_id, scan.findings, scan.scanner_runs = 'synthetic-fix-b', grouped, [grouped_run]
        store.save(scan)
        tasks = SecuritySummaryService(store).get(root, scan.scan_id, details=True)['tasks']
        assert len(tasks) == 2 and all(t['finding_count'] == 1 for t in tasks), tasks
        service = TaskFixService(store, runtime.registry)
        handoffs = [service.prepare(task['task_ref'], root) for task in tasks]
        assert not any(any(h['execution'].values()) for h in handoffs)
        write_task_sources(root, False, True)
        partial = [service.verify(task['task_ref'], root) for task in tasks]
        assert {r['status'] for r in partial} == {'SCANNER_VERIFIED_RESOLVED', 'STILL_PRESENT'}, partial
        write_task_sources(root, False, False)
        complete = [service.verify(task['task_ref'], root) for task in tasks]
        assert all(r['status'] == 'SCANNER_VERIFIED_RESOLVED' for r in complete), complete
        broken = SemgrepAdapter(engine_provider=FailingFixtureEngine())
        failure = [TaskFixService(store, ScannerRegistry([broken])).verify(task['task_ref'], root) for task in tasks]
        assert all(r['status'] == 'INCONCLUSIVE' for r in failure), failure
        assert all(m['scanner_runs'][0]['status'] == 'FAILED' for r in failure for m in r['members'])
        record.update(separate_tasks_one_remaining=partial, separate_tasks_all_fixed=complete, real_scanner_failure=failure)
        return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--executable', type=Path, help='Additionally verify actual installed/native MCP SDK with real Semgrep')
    args = parser.parse_args()
    print('Fix verification stage: local synthetic scanner cases', flush=True)
    record = run_acceptance()
    if args.executable:
        print('Fix verification stage: native MCP synthetic cases', flush=True)
        record['installed_native_sdk'] = asyncio.run(native_sdk_acceptance(args.executable))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Actual local OpenGrep: occurrence, line movement, minimal fix, two upstream-rule tasks, partial/all fix and process failure passed.')
