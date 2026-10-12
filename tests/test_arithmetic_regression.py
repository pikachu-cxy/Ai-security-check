"""Run the fixed host template against real TS modules; Runtime only plans it."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from unittest.mock import patch

import pytest

from security_runtime.arithmetic_regression import build_arithmetic_regression_plan

UNSAFE = '''export function evaluateExpression(expression: string): unknown {
  return new Function(`return (${expression});`)();
}
'''
# This deliberately small fixture checks the host harness, not product rule
# remediation. The FlyCRM acceptance uses its actual bounded parser separately.
RESTRICTED_FIXTURE = '''export function evaluateExpression(expression: string): unknown {
  if (expression.length > 4096 || !/^[0-9eE+\\-*/%().\\s]+$/.test(expression) || expression.includes('**')) {
    throw new Error('outside fixed arithmetic fixture');
  }
  let depth = 0;
  let unary = 0;
  for (const char of expression) {
    if (char === '(' && ++depth > 64) throw new Error('depth budget');
    if (char === ')') depth -= 1;
    if (char === '+' || char === '-') {
      if (++unary > 64) throw new Error('unary budget');
    } else if (!/\\s/.test(char)) unary = 0;
  }
  return new Function(`return (${expression});`)();
}
'''


@pytest.fixture
def modules(tmp_path):
    before = tmp_path / 'before.ts'
    after = tmp_path / 'after.ts'
    before.write_text(UNSAFE)
    after.write_text(RESTRICTED_FIXTURE)
    return before, after


def plan(modules):
    return build_arithmetic_regression_plan(*modules, arithmetic_contract_confirmed=True)


def run_host(value):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node 24 is required for actual host-template execution')
    version = subprocess.run([node, '--version'], capture_output=True, text=True, timeout=5, check=True)
    if not version.stdout.startswith('v24.'):
        pytest.skip('The fixed template requires Node 24')
    argv = [node, *value['command']['argv'][1:]]
    executed = subprocess.run(argv, shell=False, capture_output=True, text=True, timeout=30, check=False)
    return executed, json.loads(executed.stdout)


def test_unconfirmed_contract_does_not_read_modules_or_spawn_processes():
    with patch.object(Path, 'read_bytes', side_effect=AssertionError('source read')), \
         patch('subprocess.run', side_effect=AssertionError('target execution')):
        value = build_arithmetic_regression_plan('not-a-file', 'not-a-file')
    assert value['status'] == 'ARITHMETIC_CONTRACT_CONFIRMATION_REQUIRED'
    assert 'command' not in value and 'modules' not in value
    assert value['automatic_execution'] is False


def test_confirmed_plan_is_only_hash_bound_command_data(modules):
    with patch('subprocess.run', side_effect=AssertionError('target execution')):
        value = plan(modules)
    assert value['status'] == 'HOST_ARITHMETIC_REGRESSION_READY'
    assert value['runtime_executes_target_code'] is False
    assert value['command']['shell'] is False
    assert value['command']['network_access'] == 'UNKNOWN'
    assert value['modules']['before']['sha256'] == hashlib.sha256(modules[0].read_bytes()).hexdigest()
    assert value['modules']['after']['sha256'] == hashlib.sha256(modules[1].read_bytes()).hexdigest()
    assert value['security_verification'] == 'SEPARATE_ORIGINAL_RULE_RESCAN_REQUIRED'
    assert value['production_correctness'] == 'UNKNOWN'
    assert any('tests_passed' in row for row in value['limitations'])


@pytest.mark.parametrize('export_name', ['x; process.exit()', '../evaluateExpression', '', 'x' * 81])
def test_export_name_cannot_inject_command_or_code(modules, export_name):
    with pytest.raises(ValueError, match='EXPORT_IDENTIFIER'):
        build_arithmetic_regression_plan(*modules, export_name=export_name,
            arithmetic_contract_confirmed=True)


def test_module_scope_rejects_relative_same_and_oversized_paths(modules):
    with pytest.raises(ValueError, match='ABSOLUTE_TYPESCRIPT'):
        build_arithmetic_regression_plan('before.ts', modules[1], arithmetic_contract_confirmed=True)
    with pytest.raises(ValueError, match='DISTINCT_MODULE'):
        build_arithmetic_regression_plan(modules[0], modules[0], arithmetic_contract_confirmed=True)
    modules[1].write_bytes(b' ' * 512001)
    with pytest.raises(ValueError, match='BUDGET_EXCEEDED'):
        plan(modules)


def test_real_host_execution_preserves_values_json_and_blocks_fixed_marker(modules):
    value = plan(modules)
    executed, report = run_host(value)
    assert executed.returncode == 0, report
    assert report['status'] == 'ARITHMETIC_REGRESSION_PASSED'
    assert len(report['comparisons']) == 32
    assert all(row['object_is_equivalent'] and row['response_json_equivalent'] for row in report['comparisons'])
    assert report['before']['marker']['marker_after'] == 1
    assert report['after']['marker']['marker_after'] == 0
    assert report['after']['marker']['returned'] is False
    assert all(row['passed'] for row in report['after']['budgets'])
    assert report['modules'] == value['modules']
    assert report['template_sha256'] == value['template_sha256']
    assert report['worker_sha256'] == value['worker_sha256']
    cases = {row['id']: row for row in report['after']['cases']}
    assert cases['negative_zero']['actual']['kind'] == 'NEGATIVE_ZERO'
    for name in ('positive_infinity', 'negative_infinity', 'nan', 'remainder_nan'):
        assert json.loads(cases[name]['response_json'])['result'] is None
    assert report['http_server_executed'] is False
    assert report['network_access'] == 'UNKNOWN'
    assert report['production_correctness'] == 'UNKNOWN'


@pytest.mark.parametrize('bad_after', [UNSAFE,
    RESTRICTED_FIXTURE.replace('return new Function', "expression = expression.replace('3 * 4', '3 * 5'); return new Function")])
def test_zero_or_changed_functional_results_cannot_pass_host_template(modules, bad_after):
    modules[1].write_text(bad_after)
    executed, report = run_host(plan(modules))
    assert executed.returncode == 1
    assert report['status'] == 'ARITHMETIC_REGRESSION_FAILED'
    assert report['after']['passed'] is False


@pytest.mark.parametrize('operation', ['write', 'child_process'])
def test_target_worker_cannot_write_or_launch_child_processes(modules, operation):
    sentinel = modules[1].parent / 'must-not-exist.txt'
    if operation == 'write':
        prefix = "import { writeFileSync } from 'node:fs';\n" + \
            f"writeFileSync({json.dumps(str(sentinel))}, 'PRIVATE_CANARY');\n"
    else:
        prefix = "import { spawnSync } from 'node:child_process';\nspawnSync(process.execPath, ['--version']);\n"
    modules[1].write_text(prefix + RESTRICTED_FIXTURE)
    executed, report = run_host(plan(modules))
    assert executed.returncode == 2
    assert report['status'] == 'ARITHMETIC_REGRESSION_INCONCLUSIVE'
    assert report['after']['status'] == 'WORKER_INCONCLUSIVE'
    assert not sentinel.exists()
    assert 'PRIVATE_CANARY' not in executed.stdout
