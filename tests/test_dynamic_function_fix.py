"""Real local detector evidence through the task-bound fix and retest workflow."""
from dataclasses import replace
from pathlib import Path

import pytest

from security_runtime.dynamic_function import NativeFunctionScanner, RULE_ID
from security_runtime.findings import FindingNormalizer
from security_runtime.hook_user_feedback import issue_feedback
from security_runtime.models import ScanContext, ScanMode, ScanResult
from security_runtime.scanners import ScannerRegistry
from security_runtime.security_summary import SecuritySummaryService
from security_runtime.storage import SQLiteStore
from security_runtime.target import TargetDetector
from security_runtime.task_fix import TaskFixService
from security_runtime.triage_models import category


UNSAFE = '''export function calculate(expression: string): number {
  const evaluator = new Function(`return (${expression});`);
  return evaluator();
}
'''
FIXED = '''import { evaluateArithmetic } from './arithmetic';
export function calculate(expression: string): number {
  return evaluateArithmetic(expression);
}
'''


@pytest.fixture
def dynamic_task(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    target = root / 'calculate.ts'
    target.write_text(UNSAFE, encoding='utf-8')
    scanner = NativeFunctionScanner()
    profile = TargetDetector().detect(root, ['calculate.ts'])
    context = ScanContext(str(root), ScanMode.RELEASE, tuple(profile.files))
    plan = scanner.plan_rules(profile, context)
    findings, run = scanner.scan(replace(context, rule_plan=plan), FindingNormalizer(root))
    assert len(findings) == 1 and run.status == 'SUCCESS'
    result = ScanResult('dynamic-fix-test', 'release', profile, 'COMPLETED', findings, [run],
                        'Candidate requiring context review', 'BLOCKED', run.duration_ms,
                        coverage='FULL', capability_results={'CODE_SAST': 'EXECUTED'})
    store = SQLiteStore(tmp_path / 'state' / 'scans.db')
    store.save(result)
    task = SecuritySummaryService(store).get(root, details=True)['tasks'][0]
    service = TaskFixService(store, ScannerRegistry([scanner], fallback_adapters=[]))
    return root, target, scanner, result, store, task, service


def test_real_dynamic_finding_keeps_security_plan_without_optional_test_offer(dynamic_task):
    root, target, _, result, _, task, service = dynamic_task
    original = target.read_bytes()
    prompt = issue_feedback(result.findings[0].__dict__)
    assert prompt['location'] == {'file': 'calculate.ts', 'line': 2}
    packet = service.prepare(task['task_ref'], root, bound_workspace=root)
    assert packet['status'] == 'READY_FOR_HOST_FIX'
    assert packet['affected_findings'][0]['rule_id'] == RULE_ID
    assert packet['authorization_requirements']['user_consent_required'] is True
    assert packet['authorization_requirements']['preparation_is_not_user_consent'] is True
    assert not any(packet['execution'].values())
    assert target.read_bytes() == original
    assert '正常算术' in packet['security_goal']
    assert any('任意 JavaScript' in item['requirement'] for item in packet['fix_constraints'])
    assert any('不能' in item['requirement'] or '不得' in item['requirement']
               for item in packet['fix_constraints'])
    assert packet['verification_plan']['arguments']['task_ref'] == task['task_ref']
    assert any('响应格式' in item for item in packet['regression_requirements'])
    assert 'optional_functional_regression' not in packet


def test_new_function_retest_preserves_presence_after_line_move(dynamic_task):
    root, target, _, _, _, task, service = dynamic_task
    first = service.verify(task['task_ref'], root, bound_workspace=root)
    assert first['status'] == 'STILL_PRESENT'
    target.write_text('\n' * 12 + UNSAFE, encoding='utf-8')
    moved = service.verify(task['task_ref'], root, bound_workspace=root)
    assert moved['status'] == 'STILL_PRESENT'
    assert moved['members'][0]['matched_by'] == 'equivalence_key'
    assert '尚未完成修复' in moved['user_feedback']['message']


def test_safe_replacement_uses_original_detector_and_does_not_claim_functional_success(dynamic_task):
    root, target, scanner, _, _, task, service = dynamic_task
    target.write_text(FIXED, encoding='utf-8')
    out = service.verify(task['task_ref'], root, bound_workspace=root,
                         host_reported_execution={'patch_applied': True, 'tests_run': True})
    assert out['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert out['members'][0]['scanner_runs'][0]['scanner'] == scanner.name
    assert out['runtime_observed_execution']['scanner_recheck'] is True
    assert out['runtime_observed_execution']['engine_process_observed'] is False
    assert out['runtime_observed_execution']['tests_run'] is False
    assert out['host_reported_execution']['trust'] == 'UNTRUSTED_HOST_REPORT'
    assert out['user_feedback']['functional_verification'] == 'NOT_PROVEN_BY_SCANNER'
    assert '仍需实际功能测试确认' in out['user_feedback']['message']
    assert out['user_feedback']['choices'] == []
    assert not {'functional_verification_offer', 'functional_verification'} & out.keys()


def test_replacing_function_with_eval_cannot_pass_same_dynamic_rule_retest(dynamic_task):
    root, target, _, _, _, task, service = dynamic_task
    target.write_text('export function calculate(expression: string): number { return eval(expression); }\n',
                      encoding='utf-8')
    assert service.verify(task['task_ref'], root, bound_workspace=root)['status'] == 'STILL_PRESENT'


def test_rule_identity_change_and_target_deletion_do_not_prove_resolution(dynamic_task):
    root, target, _, scan, store, task, service = dynamic_task
    scan.findings[0].technical_details['rule_pack_checksum'] = 'f' * 64
    store.save(scan)
    target.write_text(FIXED, encoding='utf-8')
    out = service.verify(task['task_ref'], root, bound_workspace=root)
    assert out['status'] == 'INCONCLUSIVE'
    assert 'ORIGINAL_RULE_FILE_COVERAGE_NOT_PROVEN' in out['members'][0]['reason']
    assert '不能认定风险已经消除' in out['user_feedback']['message']
    target.unlink()
    deleted = service.verify(task['task_ref'], root, bound_workspace=root)
    assert deleted['status'] == 'NOT_VERIFIED'
    assert not deleted['runtime_observed_execution']['scanner_recheck_attempted']
    assert not deleted['runtime_observed_execution']['scanner_recheck']
    assert deleted['members'][0]['reason'] == 'AFFECTED_FILE_MISSING_OR_NOT_IN_SCOPE'
    assert deleted['risk_ledger_recording']['status'] == 'NOT_REGISTERED'
    assert deleted['risk_ledger_recording']['recorded'] == 0
    assert '不能认定风险已经消除' in deleted['user_feedback']['message']


def test_another_workspace_cannot_reuse_selected_dynamic_task(dynamic_task, tmp_path):
    _, _, _, _, _, task, service = dynamic_task
    other = tmp_path / 'unrelated-project'
    other.mkdir()
    with pytest.raises(ValueError, match='workspace'):
        service.prepare(task['task_ref'], other)


def test_unknown_provider_or_rule_cannot_gain_code_task_eligibility():
    original = {'category': 'code-injection', 'scanner_sources': ['native-js-function'],
                'technical_details': {'rule_id': RULE_ID}}
    assert category(original) == 'code'
    assert category(dict(original, scanner_sources=['unknown-provider'])) == 'unsupported'
    assert category(dict(original, technical_details={'rule_id': 'unknown-rule'})) == 'unsupported'
