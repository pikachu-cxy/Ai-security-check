import hashlib
import time

import pytest

from security_runtime.dynamic_function import (
    NativeFunctionScanner, RULE_ID, VERSION, quick_function_candidate_scope,
)
from security_runtime.findings import FindingNormalizer
from security_runtime.models import RunStatus, ScanContext, ScanMode


FLYCRM_EXPRESSION = '''// 两种表达式实现的语法范围不同。

export function evaluateExpression(expression: string): unknown {
  const compute = new Function(`return (${expression});`);
  return compute();
}
'''


def scan(tmp_path, source, name='expressionEvaluator.ts'):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding='utf-8')
    adapter = NativeFunctionScanner()
    context = ScanContext(str(tmp_path), ScanMode.FEATURE, (name,))
    plan = adapter.plan_rules(None, context)
    from dataclasses import replace
    context = replace(context, rule_plan=plan)
    findings, run = adapter.scan(context, FindingNormalizer(tmp_path))
    return adapter, findings, run, plan


def test_flycrm_exact_sink_and_conditional_evidence(tmp_path):
    _, findings, run, plan = scan(tmp_path, FLYCRM_EXPRESSION)
    assert run.status == RunStatus.SUCCESS
    assert run.coverage_contract == 'FULL'
    assert len(findings) == 1
    finding = findings[0]
    assert finding.line_start == finding.line_end == 4
    assert finding.technical_details['dynamic_inputs'] == ['expression']
    assert finding.technical_details['dangerous_api'] == 'Function'
    assert finding.technical_details['sink_argument_kind'] == 'TEMPLATE_INTERPOLATION'
    assert finding.technical_details['exploitability'] == 'UNCONFIRMED'
    assert finding.technical_details['source_reachability'] == 'NOT_ANALYZED'
    assert finding.technical_details['confidence_scope'] == 'DYNAMIC_ARGUMENT_SYNTAX_ONLY'
    assert '如果外部输入能够到达' in finding.description
    assert finding.severity == 'HIGH' and finding.confidence == 'HIGH'
    assert finding.equivalence_key
    assert finding.technical_details['evidence_locator']['file_sha256'] == hashlib.sha256(
        (tmp_path / 'expressionEvaluator.ts').read_bytes()).hexdigest()
    assert plan.confirmed_rules == {RULE_ID}
    assert plan.scanned_files == {'expressionEvaluator.ts'}
    assert plan.coverage('SUCCESS')['per_language']['typescript']['executed_rule_ids'] == [RULE_ID]
    assert finding.technical_details['rule_pack_checksum'] == plan.pack.checksum


@pytest.mark.parametrize('source', [
    '// new Function(expression)\nconst count = 1;',
    '/* new Function(expression) */\nconst count = 1;',
    'const message = "new Function(expression)";',
    "const message = 'new Function(expression)';",
    'const message = `new Function(expression)`;',
    'const pattern = /new Function(expression)/gi;',
    'new Function("return 1 + 2");',
    'Function("x", "return x + 2");',
    'new Function(`return 1 + 2`);',
    'new Function(`return ${1 + 2}`);',
    'new Function("return " + "2");',
    'eval("2 + 2");',
    'const evaluate = (expression: string) => parseArithmetic(expression);',
    'const FunctionName = (expression: string) => parseArithmetic(expression);',
    'object.Function(expression);',
    'object.globalThis.Function(expression);',
])
def test_non_executable_text_and_literal_only_constructor_are_not_high_risk(tmp_path, source):
    _, findings, run, _ = scan(tmp_path, source)
    assert findings == []
    assert run.status == RunStatus.SUCCESS
    assert run.coverage_contract == 'FULL'


@pytest.mark.parametrize(('source', 'api'), [
    ('new Function(expression);', 'Function'),
    ('Function(expression);', 'Function'),
    ('Function?.(expression);', 'Function'),
    ('new Function("x", body);', 'Function'),
    ('new Function("return " + expression);', 'Function'),
    ('new\nFunction(\n  `return (${expression});`\n);', 'Function'),
    ('globalThis.Function(expression);', 'globalThis.Function'),
    ('window.Function(expression);', 'window.Function'),
    ('global.Function(expression);', 'global.Function'),
    ('eval(expression);', 'eval'),
    ('const text = `answer: ${new Function(expression)()}`;', 'Function'),
    ('new Function(`return ${object.expression}`);', 'Function'),
])
def test_dynamic_constructor_forms_and_eval_replacement_remain_in_family(tmp_path, source, api):
    _, findings, run, _ = scan(tmp_path, source)
    assert len(findings) == 1
    assert findings[0].technical_details['dangerous_api'] == api
    assert findings[0].technical_details['rule_id'] == RULE_ID
    assert run.coverage_contract == 'FULL'


def test_family_survives_line_move_and_eval_replacement(tmp_path):
    _, original, _, _ = scan(tmp_path, FLYCRM_EXPRESSION)
    _, moved, _, _ = scan(tmp_path, '\n' * 20 + FLYCRM_EXPRESSION)
    _, alternative, _, _ = scan(tmp_path, 'export function evaluateExpression(expression: string) {return eval(expression);}')
    assert moved[0].line_start == 24
    assert original[0].id != moved[0].id
    assert original[0].equivalence_key == moved[0].equivalence_key == alternative[0].equivalence_key


@pytest.mark.parametrize('source', [
    'const value = "new Function(expression)',
    'new Function(`return ${expression);',
    'new Function(expression;',
])
def test_unparseable_scope_cannot_attest_rule_absence(tmp_path, source):
    _, findings, run, plan = scan(tmp_path, source)
    assert findings == []
    assert run.status == RunStatus.FAILED
    assert run.coverage_contract == 'NONE'
    assert not plan.scanned_files
    assert plan.errored_files == {'expressionEvaluator.ts'}


def test_outside_workspace_is_never_read(tmp_path):
    outside = tmp_path.parent / 'outside-function.ts'
    outside.write_text('new Function(expression);', encoding='utf-8')
    adapter = NativeFunctionScanner()
    context = ScanContext(str(tmp_path), ScanMode.FEATURE, ('../outside-function.ts',))
    findings, run = adapter.scan(context, FindingNormalizer(tmp_path))
    assert not findings
    assert run.status == RunStatus.FAILED
    assert run.coverage_contract == 'NONE'
    assert run.scanner_diagnostics['skipped_targets'][0]['reason'] == 'UNSAFE_PATH'


def test_partial_file_failure_is_not_full_coverage(tmp_path):
    (tmp_path / 'good.ts').write_text(FLYCRM_EXPRESSION, encoding='utf-8')
    (tmp_path / 'broken.ts').write_text('new Function(`broken', encoding='utf-8')
    adapter = NativeFunctionScanner()
    context = ScanContext(str(tmp_path), ScanMode.FEATURE, ('good.ts', 'broken.ts'))
    findings, run = adapter.scan(context, FindingNormalizer(tmp_path))
    assert len(findings) == 1
    assert run.status == RunStatus.SUCCESS
    assert run.coverage_contract == 'PARTIAL'
    assert run.rule_coverage['per_language']['typescript']['scanned_files'] == 1


def test_fast_hook_selection_does_not_claim_other_rules(tmp_path):
    (tmp_path / 'danger.ts').write_text(FLYCRM_EXPRESSION, encoding='utf-8')
    (tmp_path / 'safe.ts').write_text('parseArithmetic(expression);', encoding='utf-8')
    selected = quick_function_candidate_scope(tmp_path, ('danger.ts',))
    assert selected['eligible']
    assert selected['coverage_scope'] == 'CANONICAL_DYNAMIC_CODE_ONLY'
    assert selected['candidate_files'] == ['danger.ts']
    assert 'not executed' in selected['omitted_code_checks']
    assert not quick_function_candidate_scope(tmp_path, ('safe.ts',))['eligible']
    assert quick_function_candidate_scope(tmp_path, ('safe.ts',), has_native_family=True)['eligible']
    assert not quick_function_candidate_scope(tmp_path, ('danger.ts', 'package.json'))['eligible']
    assert not quick_function_candidate_scope(tmp_path, ('missing.ts',))['eligible']


def test_one_file_native_scan_is_bounded_and_has_no_external_engine(tmp_path):
    started = time.perf_counter()
    adapter, findings, run, _ = scan(tmp_path, FLYCRM_EXPRESSION)
    assert findings
    assert time.perf_counter() - started < 1.0
    assert adapter.required_engines() == ()
    assert run.scanner_diagnostics['local_read_observed'] is True
    assert run.scanner_diagnostics['engine_process_observed'] is False
    assert run.provider == adapter.engine_id
    assert run.version == VERSION


def test_missing_rule_implementation_cannot_attest_absence(tmp_path, monkeypatch):
    import security_runtime.dynamic_function as module
    (tmp_path / 'safe.ts').write_text('parseArithmetic(expression);', encoding='utf-8')
    monkeypatch.setattr(module, '__file__', str(tmp_path / 'absent-provider.py'))
    adapter = NativeFunctionScanner()
    with pytest.raises(ValueError, match='NATIVE_RULE_IMPLEMENTATION_UNAVAILABLE'):
        adapter.plan_rules(None, ScanContext(str(tmp_path), ScanMode.FEATURE, ('safe.ts',)))
    findings, run = adapter.scan(ScanContext(str(tmp_path), ScanMode.FEATURE, ('safe.ts',)),
                                 FindingNormalizer(tmp_path))
    assert findings == []
    assert run.status == RunStatus.FAILED
    assert run.coverage_contract == 'NONE'
    assert run.error_code == 'NATIVE_RULE_IDENTITY_UNAVAILABLE'


def test_rule_identity_changes_fail_closed_even_when_scope_plan_is_retained(tmp_path):
    from dataclasses import replace
    from security_runtime.dynamic_function import NativeFunctionRulePlan, rule_pack
    (tmp_path / 'safe.ts').write_text('parseArithmetic(expression);', encoding='utf-8')
    pack = replace(rule_pack(), checksum='other-rule-version')
    plan = NativeFunctionRulePlan(pack, ('safe.ts',))
    context = ScanContext(str(tmp_path), ScanMode.FEATURE, ('safe.ts',), rule_plan=plan)
    findings, run = NativeFunctionScanner().scan(context, FindingNormalizer(tmp_path))
    assert not findings
    assert run.status == RunStatus.FAILED
    assert run.coverage_contract == 'NONE'


def test_adversarial_call_work_is_bounded_without_absence_claim(tmp_path, monkeypatch):
    import security_runtime.dynamic_function as module
    monkeypatch.setattr(module, 'MAX_CANDIDATE_WORK', 8)
    _, findings, run, plan = scan(tmp_path, 'new Function(new Function(new Function(expression)));')
    assert not findings
    assert run.status == RunStatus.FAILED
    assert run.coverage_contract == 'NONE'
    assert plan.skipped_files['expressionEvaluator.ts'] == 'CALL_ANALYSIS_BUDGET_EXCEEDED'
