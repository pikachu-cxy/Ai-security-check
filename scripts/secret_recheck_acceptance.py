"""Real offline Gitleaks acceptance with public fake data; no host Hook dispatch."""
import argparse
import json
import tempfile
from dataclasses import asdict
from pathlib import Path

from security_runtime.findings import FindingNormalizer
from security_runtime.hook_runtime import covered, family_delta, family_multiset
from security_runtime.hook_user_feedback import secret_verification_feedback
from security_runtime.models import ScanContext, ScanMode
from security_runtime.scanners import GitleaksAdapter, ScannerRegistry
from security_runtime.toolchain import ToolManager
from security_runtime.verification import VerificationService
from security_runtime.verification_policy import local_recheck


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    adapter = GitleaksAdapter(ToolManager(args.engine_root))
    with tempfile.TemporaryDirectory(prefix='ai-security-public-secret-') as temporary:
        root = Path(temporary)
        path = root / 'security-hook-test' / 'secret-fixture.ts'
        path.parent.mkdir()
        name = path.relative_to(root).as_posix()
        # Public synthetic string, generated here and never issued by a provider.
        fake = 'ghp_' + '0123456789abcdefghijklmnopqrstuvXYZabc'
        path.write_text('// Public fake fixture only.\n// Never issued.\nexport const demoToken = "' + fake + '";\n', encoding='utf-8')
        context = ScanContext(str(root), ScanMode.QUICK, (name,))
        with local_recheck():
            findings, before_run = adapter.scan(context, FindingNormalizer(root))
        assert before_run.status == 'SUCCESS', (before_run.error_code, before_run.error_summary)
        assert {'github-pat', 'generic-api-key'}.issubset({f.technical_details['rule_id'] for f in findings})
        previous = family_multiset(findings, [before_run], {})
        scan = {'target_profile': {'files': [name]}, 'scanner_runs': [asdict(before_run)]}
        service = VerificationService(ScannerRegistry([adapter]))
        unchanged = service.verify_many(root, [asdict(f) for f in findings], scan)
        assert all(r['verification_status'] == 'STILL_PRESENT' for r in unchanged)
        path.write_text('// Public fake fixture only.\n// Never issued.\nexport const demoToken = "' + fake + '"; // gitleaks:allow\n', encoding='utf-8')
        suppressed = service.verify_many(root, [asdict(f) for f in findings], scan)
        assert all(r['verification_status'] == 'INCONCLUSIVE' for r in suppressed)
        path.write_text('// Public fake fixture only.\n// Fixture value removed; explanation retained.\n', encoding='utf-8')
        rechecked = service.verify_many(root, [asdict(f) for f in findings], scan)
        if not all(r['verification_status'] == 'SCANNER_VERIFIED_RESOLVED' for r in rechecked):
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps({'status': 'FAILED', 'before_receipt': before_run.scanner_diagnostics.get('secret_coverage'),
                'rechecked': [{'status': r['status'], 'reason': r.get('reason'),
                    'scanner_runs': r['scanner_runs']} for r in rechecked]}, indent=2), encoding='utf-8')
        assert all(r['verification_status'] == 'SCANNER_VERIFIED_RESOLVED' for r in rechecked), [r.get('reason') for r in rechecked]
        with local_recheck():
            after, after_run = adapter.scan(context, FindingNormalizer(root))
        retained, delta = family_delta(previous, family_multiset(after, [after_run], {}), lambda f: covered(f, [after_run], {}))
        assert delta['resolved'] == len(previous) and not retained
        result = {'source': 'REAL_OFFLINE_ENGINE_AND_VERIFICATION_SERVICE', 'host_hook_acceptance': '尚未通过；待用户安装后重新测试',
            'manual_hook_handlers_called': False, 'public_fake_fixture_only': True,
            'engine_version': before_run.version, 'detected_rules': sorted({f.technical_details['rule_id'] for f in findings}),
            'unchanged_statuses': sorted({r['verification_status'] for r in unchanged}),
            'inline_suppression_statuses': sorted({r['verification_status'] for r in suppressed}),
            'cleaned_statuses': sorted({r['verification_status'] for r in rechecked}),
            'discovery_ms': before_run.duration_ms, 'post_edit_scan_ms': after_run.duration_ms,
            'independent_recheck_ms': [run['duration_ms'] for run in rechecked[0]['scanner_runs']],
            'receipt': after_run.scanner_diagnostics.get('secret_coverage'),
            'simulated_delta_using_real_engine_runs': delta,
            'user_feedback': secret_verification_feedback(rechecked)}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({k: result[k] for k in ('engine_version', 'detected_rules', 'cleaned_statuses',
            'discovery_ms', 'post_edit_scan_ms', 'independent_recheck_ms', 'host_hook_acceptance')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
