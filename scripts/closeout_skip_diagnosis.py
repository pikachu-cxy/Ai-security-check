"""Read only the saved explicit r9 scope; retain fixed skip counts, never trace/source."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
from security_runtime.scanners import GitleaksAdapter
from security_runtime.toolchain import ToolManager
from security_runtime.models import ScanContext, ScanMode
from security_runtime.findings import FindingNormalizer
from security_runtime.verification_policy import local_recheck


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--engine-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    saved = json.loads(args.evidence.read_text(encoding='utf-8-sig'))
    root = Path(saved['workspace'])
    old = saved['scans'][0]
    batch = next(r for r in old['scanner_runs'] if r['scanner'] == 'gitleaks')
    files = batch['scanner_diagnostics']['scope']['relative_targets']
    assert len(files) == 17 and not any(Path(p).name.startswith('.env') for p in files)
    adapter = GitleaksAdapter(ToolManager(root=args.engine_root))
    checks = []
    for label, scope in [('SAVED_BATCH_READ_ONLY_DIAGNOSIS', files),
                          ('ORIGINAL_FILE_READ_ONLY_DIAGNOSIS', ['security-hook-test/secret-fixture-r9-20261012.ts'])]:
        with local_recheck():
            findings, run = adapter.scan(ScanContext(str(root), ScanMode.QUICK, tuple(scope)), FindingNormalizer(root))
        checks.append({'source': label, 'scope': scope, 'status': run.status, 'duration_ms': run.duration_ms,
                       'candidate_count': len(findings), 'receipt': run.scanner_diagnostics.get('secret_coverage', {})})
    result = {'source': 'READ_ONLY_REAL_R9_ENGINE_DIAGNOSIS', 'checks': checks,
              'old_proof_rewritten': False, 'live_closure_state_written': False,
              'manual_hook_handlers_called': False, 'desktop_auto_acceptance': '尚未通过'}
    from security_runtime.secret_coverage import covers
    original_checks = []
    for snapshot in saved['snapshots']:
        for family in snapshot['families']:
            if (family['file_path'] == 'security-hook-test/secret-fixture-r9-20261012.ts' and
                    family['rule_id'] in {'github-pat', 'generic-api-key'}):
                original = dict(family['proof'], rule_id=family['rule_id'])
                original_checks.append({'rule_id': family['rule_id'], 'original_identity': original,
                    'covered_now': covers(run, original, family['file_path'], root=root)})
    result['original_rule_checks'] = list({json.dumps(r, sort_keys=True): r for r in original_checks}.values())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps([{'source': c['source'], 'status': c['status'], 'proof': c['receipt'].get('status'),
                      'summary': c['receipt'].get('execution_summary')} for c in checks], ensure_ascii=False))


if __name__ == '__main__': main()
