"""Real managed cold/warm/rebuilt preparation and five-target Secret benchmark."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from remediation_episode_acceptance import SAFE, UNSAFE


def run():
    from security_runtime.runtime import SecurityRuntime
    from security_runtime.scan_input import scoped_request
    from security_runtime.scanners import SemgrepAdapter, GitleaksAdapter, ScannerRegistry
    from security_runtime.storage import SQLiteStore
    from security_runtime.toolchain import ToolManager, ToolSource
    from security_runtime.verification import VerificationService
    import security_runtime.scanners as scanners
    calls = []
    original = scanners._execute
    def execute(argv, *args):
        start = time.perf_counter()
        result = original(argv, *args)
        row = {'type': 'SAST_SCAN' if 'scan' in argv else 'SECRET_SCAN',
               'wall_ms': round((time.perf_counter()-start)*1000, 3)}
        if row['type'] == 'SAST_SCAN':
            data = json.loads(result.stdout)
            row.update(rules=len(data.get('time', {}).get('rules', [])),
                       files=len(data.get('paths', {}).get('scanned', [])))
        calls.append(row)
        return result
    scanners._execute = execute
    try:
        with tempfile.TemporaryDirectory(prefix='asr-cache-lifetime-') as temporary:
            parent = Path(temporary); root = parent/'project'; root.mkdir()
            subprocess.run(['git', 'init', str(root)], check=True, capture_output=True)
            target = 'src/main/java/demo/CodeModeTlsService.java'
            path = root/target; path.parent.mkdir(parents=True)
            def create():
                manager = ToolManager()
                for engine in ('semgrep', 'gitleaks'):
                    tool = manager.ensure(engine, offline=True)
                    assert tool.source == ToolSource.MANAGED and tool.status == 'READY'
                return SecurityRuntime(ScannerRegistry([SemgrepAdapter(manager), GitleaksAdapter(manager)],
                    tool_manager=manager, fallback_adapters=[]), SQLiteStore(parent/'scan.db'))
            runtime = create(); samples = []
            def scan(label, files, source):
                path.write_text(source, encoding='utf-8'); calls.clear(); start = time.perf_counter()
                result = runtime.scan(root, 'quick', request=scoped_request(root, tuple(files)))
                assert result.capability_results['CODE_SAST'] == 'EXECUTED'
                assert result.capability_results['SECRET_SCAN'] == 'EXECUTED'
                samples.append(dict(label=label, wall_ms=round((time.perf_counter()-start)*1000, 3),
                    invocations=list(calls), diagnostics=result.scanner_diagnostics))
                return result
            for index in range(3):
                scan(('cold_safe', 'warm_safe_2', 'warm_safe_3')[index], [target], SAFE+f'\n// edit {index}\n')
            runtime = create()
            scan('rebuilt_registry_safe', [target], SAFE+'\n// rebuilt registry\n')
            extra = ('notes/one.txt', 'notes/two.txt', 'README.md', 'settings.properties')
            for name in extra:
                file = root/name; file.parent.mkdir(parents=True, exist_ok=True); file.write_text('ordinary fixture content\n')
            scan('five_file_safe', [target, *extra], SAFE+'\n// five-file scope\n')
            risk = scan('five_file_risk', [target, *extra], UNSAFE)
            finding = next(row for row in risk.to_dict()['findings']
                           if row['technical_details'].get('rule_id') == 'ai-security.java.trust-all-hostname')
            path.write_text(SAFE, encoding='utf-8'); calls.clear(); start = time.perf_counter()
            checked = VerificationService(runtime.registry).verify_many(root, [finding], risk.to_dict())[0]
            assert checked['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
            assert checked['runtime_observed_execution']['engine_process_observed']
            samples.append(dict(label='targeted_security_rescan', wall_ms=round((time.perf_counter()-start)*1000, 3),
                                invocations=list(calls), scanner_runs=checked['scanner_runs']))
            return dict(status='PASS', kind='ACTUAL_MANAGED_SCANNER', samples=samples, network=False,
                        model=False, source_persisted=False, daemon=False, fake_process=False, sleep=False)
    finally:
        scanners._execute = original


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); os.environ['SECURITY_RUNTIME_OFFLINE'] = '1'
    data = run(); args.output.write_text(json.dumps(data, indent=2), encoding='utf-8')
    print(json.dumps([{'label': row['label'], 'wall_ms': row['wall_ms'],
                      'scan_invocations': len(row['invocations'])} for row in data['samples']]))
