// Public host command: two absolute TypeScript module paths and one export name.
import { readFileSync, statSync, lstatSync, realpathSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { dirname, extname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';

const VERSION = 'arithmetic-regression-v1';
const WORKER = fileURLToPath(new URL('./arithmetic_regression_worker.mjs', import.meta.url));
const SCRIPT = fileURLToPath(import.meta.url);
const MAX_MODULE_BYTES = 512000;
const digest = raw => createHash('sha256').update(raw).digest('hex');
function decodedNumber(value) {
  if (value?.kind === 'FINITE') return value.value;
  if (value?.kind === 'NEGATIVE_ZERO') return -0;
  if (value?.kind === 'POSITIVE_INFINITY') return Infinity;
  if (value?.kind === 'NEGATIVE_INFINITY') return -Infinity;
  if (value?.kind === 'NAN') return NaN;
  return Symbol('non-number');
}
function moduleInfo(input) {
  if (!input || /[\u0000-\u001f]/.test(input) || !isAbsolute(input) || extname(input).toLowerCase() !== '.ts') {
    throw new Error('ABSOLUTE_TYPESCRIPT_MODULE_REQUIRED');
  }
  let ancestor = resolve(input);
  for (;;) {
    if (lstatSync(ancestor).isSymbolicLink()) throw new Error('MODULE_LINK_REJECTED');
    const parent = dirname(ancestor);
    if (parent === ancestor) break;
    ancestor = parent;
  }
  const path = realpathSync(input);
  const stat = statSync(path);
  if (!stat.isFile() || stat.size > MAX_MODULE_BYTES) throw new Error('MODULE_BUDGET');
  const raw = readFileSync(path);
  if (raw.length > MAX_MODULE_BYTES) throw new Error('MODULE_BUDGET');
  return { path, sha256: digest(raw), bytes: raw.length };
}
function worker(role, module, exportName) {
  const started = performance.now();
  // No shell. The target worker has read-only access to its module and this
  // fixed template; no child-process, file-write, native-addon or worker grants.
  const args = ['--permission', `--allow-fs-read=${WORKER}`, `--allow-fs-read=${module.path}`,
    '--experimental-transform-types', WORKER, role, module.path, exportName];
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  delete env.NODE_PATH;
  const result = spawnSync(process.execPath, args, {
    shell: false, env, encoding: 'utf8', timeout: 10000, maxBuffer: 262144,
    windowsHide: true, cwd: dirname(module.path),
  });
  const execution = { exit_code: result.status, duration_ms: Math.round(performance.now() - started),
    timed_out: result.error?.code === 'ETIMEDOUT' };
  if (result.error || result.status !== 0) {
    return { status: 'WORKER_INCONCLUSIVE', role, passed: false, execution,
      reason: execution.timed_out ? 'WORKER_TIMEOUT' : 'WORKER_FAILED' };
  }
  try {
    const report = JSON.parse(result.stdout);
    if (report.status !== 'WORKER_COMPLETED' || report.role !== role || report.module?.sha256 !== module.sha256) {
      throw new Error('WORKER_REPORT_MISMATCH');
    }
    return { ...report, execution };
  } catch {
    return { status: 'WORKER_INCONCLUSIVE', role, passed: false, execution,
      reason: 'WORKER_OUTPUT_NOT_VALID_JSON' };
  }
}
const started = performance.now();
try {
  const input = process.argv.slice(2);
  const [beforePath, afterPath, exportName = 'evaluateExpression'] = input;
  if (![2, 3].includes(input.length) || !/^[A-Za-z_$][A-Za-z0-9_$]{0,79}$/.test(exportName)) {
    throw new Error('INVALID_FIXED_TEMPLATE_ARGUMENTS');
  }
  if (Number(process.versions.node.split('.')[0]) !== 24) throw new Error('NODE_24_REQUIRED');
  const modules = { before: moduleInfo(beforePath), after: moduleInfo(afterPath) };
  if (modules.before.path === modules.after.path) throw new Error('DISTINCT_MODULE_COPIES_REQUIRED');
  const before = worker('before', modules.before, exportName);
  const after = worker('after', modules.after, exportName);
  const comparisons = (before.cases ?? []).map(row => {
    const other = (after.cases ?? []).find(value => value.id === row.id);
    return { id: row.id, object_is_equivalent: Boolean(other) &&
      Object.is(decodedNumber(row.actual), decodedNumber(other.actual)),
      response_json_equivalent: Boolean(other) && row.response_json === other.response_json };
  });
  const allCompleted = [before, after].every(row => row.status === 'WORKER_COMPLETED');
  const passed = allCompleted && before.passed && after.passed && comparisons.length === 32 &&
    comparisons.every(row => row.object_is_equivalent && row.response_json_equivalent);
  const status = !allCompleted ? 'ARITHMETIC_REGRESSION_INCONCLUSIVE'
    : passed ? 'ARITHMETIC_REGRESSION_PASSED' : 'ARITHMETIC_REGRESSION_FAILED';
  process.stdout.write(JSON.stringify({ version: VERSION, status, node_version: process.version,
    export_name: exportName, modules, template_sha256: digest(readFileSync(SCRIPT)),
    worker_sha256: digest(readFileSync(WORKER)), duration_ms: Math.round(performance.now() - started),
    before, after, comparisons,
    functional_coverage: 'FIXED_ARITHMETIC_CASES_AND_JSON_PAYLOAD_ONLY',
    http_server_executed: false, network_access: 'UNKNOWN',
    security_verification: 'SEPARATE_ORIGINAL_RULE_RESCAN_REQUIRED',
    production_correctness: 'UNKNOWN' }));
  process.exitCode = passed ? 0 : allCompleted ? 1 : 2;
} catch {
  process.stdout.write(JSON.stringify({ version: VERSION, status: 'ARITHMETIC_REGRESSION_INCONCLUSIVE',
    reason: 'INVALID_INPUT_OR_UNAVAILABLE_EXECUTION', production_correctness: 'UNKNOWN' }));
  process.exitCode = 2;
}
