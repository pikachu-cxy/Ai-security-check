// Internal worker: fixed cases only. No expression, shell command or code input.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const [role, modulePath, exportName] = process.argv.slice(2);
const MAX_MODULE_BYTES = 512000;
const markerKey = '__AI_SECURITY_ARITHMETIC_BENCH_MARKER__';
const markerExpression = '(globalThis.__AI_SECURITY_ARITHMETIC_BENCH_MARKER__ = 1, 7)';
const normal = [
  ['addition', '1 + 2', 3], ['subtraction', '9 - 4', 5],
  ['multiplication', '3 * 4', 12], ['division', '12 / 4', 3],
  ['remainder', '10 % 3', 1], ['parentheses', '(1 + 2) * 3', 9],
  ['nested_parentheses', '((2 + 3) * (8 - 2)) / 3', 10],
  ['unary_plus', '+2', 2], ['unary_minus', '-2', -2],
  ['unary_parentheses', '-(2 + 3)', -5],
  ['spaced_double_unary', '- -2', 2], ['negative_operand', '2 * -3', -6],
  ['subtract_negative', '2 - -3', 5], ['add_negative', '2 + -3', -1],
  ['decimal', '1.5 + 2.25', 3.75], ['leading_decimal', '.5 * 8', 4],
  ['trailing_decimal', '1. + 2', 3], ['scientific_notation', '1e3 + 2', 1002],
  ['floating_point', '0.1 + 0.2', 0.30000000000000004],
  ['whitespace', ' \t1 +\n2 * 3  ', 7], ['precedence', '2 + 3 * 4', 14],
  ['mixed_precedence', '20 - 6 / 2 * 3 + 5 % 2', 12],
  ['left_subtraction', '10 - 3 - 2', 5], ['left_division', '8 / 4 / 2', 1],
  ['left_multiply_divide', '8 / 4 * 2', 4], ['negative_remainder', '-8 % 3', -2],
  ['zero', '0', 0], ['negative_zero', '-0', -0],
  ['positive_infinity', '1 / 0', Infinity], ['negative_infinity', '-1 / 0', -Infinity],
  ['nan', '0 / 0', NaN], ['remainder_nan', '1 % 0', NaN],
];
const invalid = ['', '   ', '1 +', '(1 + 2', '1 2', '1 /', '*2'];
const unsupported = ['Math.max(1, 2)', '[1, 2]', '({ value: 1 })', '2 ** 3'];
const digest = raw => createHash('sha256').update(raw).digest('hex');
function number(value) {
  if (typeof value !== 'number') return { kind: 'NON_NUMBER', type: typeof value };
  if (Number.isNaN(value)) return { kind: 'NAN' };
  if (value === Infinity) return { kind: 'POSITIVE_INFINITY' };
  if (value === -Infinity) return { kind: 'NEGATIVE_INFINITY' };
  if (Object.is(value, -0)) return { kind: 'NEGATIVE_ZERO', value: 0 };
  return { kind: 'FINITE', value };
}
function invoke(fn, expression) {
  try {
    return { returned: true, value: fn(expression) };
  } catch {
    return { returned: false };
  }
}
try {
  if (!['before', 'after'].includes(role) || !/^[A-Za-z_$][A-Za-z0-9_$]{0,79}$/.test(exportName)) {
    throw new Error('INVALID_WORKER_INPUT');
  }
  const original = readFileSync(modulePath);
  if (original.length > MAX_MODULE_BYTES) throw new Error('MODULE_BUDGET');
  const imported = await import(pathToFileURL(modulePath).href);
  const fn = imported[exportName];
  if (typeof fn !== 'function') throw new Error('EXPORT_NOT_FUNCTION');
  const cases = normal.map(([id, expression, expected]) => {
    const out = invoke(fn, expression);
    const objectIsExpected = out.returned && Object.is(out.value, expected);
    // This is the FlyCRM calculate response payload shape, not an HTTP test.
    const responseJson = out.returned && typeof out.value === 'number'
      ? JSON.stringify({ expression, result: out.value }) : null;
    const expectedResponseJson = JSON.stringify({ expression, result: expected });
    return { id, expression, returned: out.returned, actual: number(out.value),
      expected: number(expected), object_is_expected: objectIsExpected,
      response_json: responseJson, expected_response_json: expectedResponseJson,
      passed: objectIsExpected && responseJson === expectedResponseJson };
  });
  const rejected = invalid.map((expression, index) => ({
    id: `invalid_${index + 1}`, expression, passed: !invoke(fn, expression).returned,
  }));
  globalThis[markerKey] = 0;
  const probe = invoke(fn, markerExpression);
  const marker = { id: 'controlled_process_local_marker', returned: probe.returned,
    marker_before: 0, marker_after: globalThis[markerKey],
    passed: role === 'before'
      ? probe.returned && Object.is(probe.value, 7) && globalThis[markerKey] === 1
      : !probe.returned && globalThis[markerKey] === 0 };
  delete globalThis[markerKey];
  // Only the repaired implementation receives these fixed rejected inputs.
  const unsupportedRejections = role === 'after' ? unsupported.map((expression, index) => ({
    id: `unsupported_${index + 1}`, expression, passed: !invoke(fn, expression).returned,
  })) : [];
  const budgetInputs = [['length', ' '.repeat(4096) + '1'],
    ['parentheses', '('.repeat(65) + '1' + ')'.repeat(65)],
    ['unary', '- '.repeat(65) + '1']];
  const budgets = role === 'after' ? budgetInputs.map(([id, expression]) => ({
    id: `budget_${id}`, input_length: expression.length,
    passed: !invoke(fn, expression).returned,
  })) : [];
  const unchanged = digest(readFileSync(modulePath)) === digest(original);
  const report = { status: 'WORKER_COMPLETED', role, node_version: process.version,
    module: { path: modulePath, sha256: digest(original), bytes: original.length },
    cases, invalid_inputs: rejected, marker, unsupported_inputs: unsupportedRejections,
    budgets, module_hash_unchanged: unchanged,
    passed: cases.every(row => row.passed) && rejected.every(row => row.passed)
      && marker.passed && unsupportedRejections.every(row => row.passed)
      && budgets.every(row => row.passed) && unchanged };
  process.stdout.write(JSON.stringify(report));
} catch {
  // Module exception text can contain source, credentials or instructions.
  process.stdout.write(JSON.stringify({ status: 'WORKER_INCONCLUSIVE', role,
    reason: 'MODULE_IMPORT_OR_EXECUTION_FAILED', passed: false }));
  process.exitCode = 2;
}
