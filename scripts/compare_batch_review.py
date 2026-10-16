"""Compare the frozen task flow and opt-in batch flow on identical local edits.

Both sides execute the actual bundled native JavaScript static scanner. AI
submissions are deterministic fixtures; no model accuracy/latency is measured.
The comparison never installs tools, calls a model, or runs fixture applications.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time


BASELINE_COMMIT = 'b3817b1168aa7d632e94afa3c4d3b1214bd607d6'
CONTRACT = 'batch-review-flow-comparison-v1'
FIXTURE_LIMITATION = 'Deterministic host review fixture; no actual model review observed.'
FILES = {
    'routes.js': 'import { loadOrder } from "./service.js";\nexport function getOrder(id) {\n    return loadOrder(id);\n}\n',
    'service.js': 'export function loadOrder(id) {\n    return repository.findById(id);\n}\n',
    'auth.js': 'export function owns(user, order) {\n    return user.id === order.ownerId;\n}\n',
    'dynamic.js': 'export function evaluate(value) {\n    return Number(value);\n}\n',
}
EDITS = (
    ('routes.js', 'import { loadOrder } from "./service.js";\nexport function getOrder(id, user) {\n    return loadOrder(id);\n}\n'),
    ('dynamic.js', 'export function evaluate(value) {\n    return new Function("return " + value)();\n}\n'),
)


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_fingerprint(source):
    files = {path.relative_to(source).as_posix():fingerprint(path)
        for path in sorted((source/'src/security_runtime').rglob('*'))
        if path.is_file() and path.suffix in {'.py','.md','.json','.yaml','.yml'}}
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


def candidate(primary, related):
    return dict(title='Order access may lack ownership enforcement', category='authorization',
        severity='MEDIUM', primary_evidence=primary, evidence_refs=[primary, related],
        impact='A caller able to select another order identifier may read that order.',
        preconditions=['The entry is reachable and no outer ownership check exists.'],
        unknowns=['Deployment reachability and outer authorization were not verified.'],
        counterevidence=['An ownership helper exists; these fixtures do not establish its use.'],
        fix_advice='Bind the read to the current user and verify order ownership.')


class ObservedRuntime:
    """Instrument real calls without changing their arguments or results."""
    def __init__(self, runtime):
        self.runtime = runtime
        self.registry = runtime.registry
        self.calls = []
        self.stage = 'setup'

    def scan(self, root, mode='quick', **kwargs):
        started = time.perf_counter()
        result = self.runtime.scan(root, mode, **kwargs)
        self.calls.append(dict(stage=self.stage, scope=list(kwargs.get('_hook_scope', ())),
            elapsed_ms=round((time.perf_counter()-started)*1000, 3), status=result.status,
            coverage=result.coverage, finding_count=len(result.findings),
            rules=sorted({f.technical_details.get('rule_id', '') for f in result.findings}),
            scanner_runs=[asdict(run) for run in result.scanner_runs]))
        return result


def run_worker(source, output, side):
    # Imports happen only after the controller selects this side's source tree.
    from security_runtime.codex_mcp_hook import handle_codex_hook
    from security_runtime.dynamic_function import NativeFunctionScanner, rule_pack
    from security_runtime.hook_runtime import HookCoordinator
    from security_runtime.hook_state import HookStateStore
    from security_runtime.integration_state import WorkspaceBinding
    from security_runtime.runtime import SecurityRuntime
    from security_runtime.scanners import ScannerRegistry
    from security_runtime.storage import SQLiteStore
    from security_runtime.task_security import TaskSecurityService

    starting_source_fingerprint = source_fingerprint(source)
    output.mkdir(parents=True, exist_ok=False)
    project = output/'project'
    project.mkdir()
    for name, text in FILES.items():
        (project/name).write_text(text, encoding='utf-8')
    subprocess.run(['git', 'init', '-q', str(project)], check=True, capture_output=True)
    subprocess.run(['git', '-C', str(project), 'add', '.'], check=True, capture_output=True)
    subprocess.run(['git', '-C', str(project), '-c', 'user.name=Local comparison',
        '-c', 'user.email=local-comparison@example.invalid', 'commit', '-qm', 'fixture baseline'],
        check=True, capture_output=True)
    hooks = HookStateStore(output/'state')
    registry = ScannerRegistry([NativeFunctionScanner()], fallback_adapters=[])
    runtime = ObservedRuntime(SecurityRuntime(registry, SQLiteStore(output/'scans.db')))
    core = HookCoordinator(runtime, hooks, cooldown_ms=0)
    binding = WorkspaceBinding('comparison', str(project), str(project), 'codex', 'PROJECT', '')
    timings = []

    def measured(name, call):
        started = time.perf_counter()
        result = call()
        timings.append(dict(stage=name, elapsed_ms=round((time.perf_counter()-started)*1000, 3)))
        return result

    runtime.stage = 'hook_baseline'
    baseline = measured('hook_baseline', lambda: core.handle('SESSION_START', project, 'codex', 'comparison'))
    tasks = TaskSecurityService(runtime, hooks)
    ref = measured('begin', lambda: tasks.begin(project, 'comparison-task'))['task_ref']
    batches = None
    if side == 'experimental':
        from security_runtime.task_security_batch import TaskSecurityBatchService
        batches = TaskSecurityBatchService(tasks)
    hook_rows, batch_rows = [], []
    for index, (name, text) in enumerate(EDITS, 1):
        (project/name).write_text(text, encoding='utf-8')
        runtime.stage = f'hook_edit_{index}'
        event = measured(runtime.stage, lambda: handle_codex_hook('PostToolUse', str(project),
            'comparison', 'Write', {'file_path':str(project/name)}, binding=binding, coordinator=core))
        hook_rows.append({key:event.get(key) for key in ('status', 'scanner_run',
            'changed_file_count', 'hook_scope_files', 'hook_check_recording')})
        if batches:
            before = len(runtime.calls)
            packet = measured(f'batch_prepare_{index}', lambda: batches.prepare(project, ref, f'function-{index}'))
            assert len(runtime.calls) == before, 'Preparing a batch must not execute static scans'
            batch_ref, session = packet['batch_ref'], packet['review_session']
            primary = measured(f'batch_read_changed_{index}', lambda: batches.read(project,
                ref, batch_ref, session, name, 1, 4))
            related = measured(f'batch_read_related_{index}', lambda: batches.read(project,
                ref, batch_ref, session, 'auth.js', 1, 3))
            findings = [candidate(primary['evidence_id'], related['evidence_id'])] if index == 1 else []
            review = measured(f'batch_submit_{index}', lambda: batches.submit(project, ref,
                batch_ref, session, findings, 'PARTIAL', [FIXTURE_LIMITATION]))
            batch_rows.append(dict(checkpoint=index, prepare_status=packet.get('status'),
                result=review, prepare_scanner_calls=len(runtime.calls)-before))

    runtime.stage = 'task_finish'
    finish = measured('task_finish', lambda: tasks.finish(project, ref))
    count_before_prepare = len(runtime.calls)
    final = measured('final_prepare', lambda: tasks.prepare(project, ref))
    assert len(runtime.calls) == count_before_prepare, 'Ready final preparation must not scan again'
    session = final['review_session']
    primary = tasks.read(project, ref, session, 'routes.js', 1, 4)
    related = tasks.read(project, ref, session, 'auth.js', 1, 3)
    dynamic = tasks.read(project, ref, session, 'dynamic.js', 1, 3)
    integration = {}
    if batches:
        batch_final = final['batch_review']
        history = batches.get(project, ref)['batches']
        dispositions = [dict(batch_ref=batch['batch_ref'], candidate_id=finding['id'],
            outcome='PRESENT', evidence_refs=[primary['evidence_id'], related['evidence_id']],
            primary_evidence=primary['evidence_id'], reason=FIXTURE_LIMITATION)
            for batch in history for finding in batch['findings']]
        integration['integration_review'] = dict(snapshot_id=batch_final['snapshot_id'], batch_refs=[],
            reviewed_paths=batch_final['review_scope'],
            evidence_refs=[primary['evidence_id'], related['evidence_id'], dynamic['evidence_id']],
            checks={name:'Deterministic protocol fixture only; actual model analysis not observed.'
                for name in ('authorization','data_flow','configuration','cross_batch_calls')},
            candidate_dispositions=dispositions, limitations=[FIXTURE_LIMITATION])
    result = measured('final_submit', lambda: tasks.submit(project, ref, session,
        [candidate(primary['evidence_id'], related['evidence_id'])], 'PARTIAL', [FIXTURE_LIMITATION],
        **integration))
    current = tasks.get(project, ref)
    get_batches = batches.get(project, ref) if batches else None
    if source_fingerprint(source) != starting_source_fingerprint:
        raise RuntimeError('Source implementation changed while this worker was executing')
    source_identity = subprocess.run(['git', '-C', str(source), 'rev-parse', 'HEAD'],
        check=True, capture_output=True, text=True).stdout.strip()
    payload = dict(side=side, source=str(source), source_commit=source_identity,
        source_task_sha256=fingerprint(source/'src/security_runtime/task_security.py'),
        source_tree_sha256=starting_source_fingerprint,
        static_provider='native-js-function', rules_identity=rule_pack().checksum,
        static_execution='REAL_BUNDLED_LOCAL_PROVIDER', model_observed=False,
        host_review_kind='DETERMINISTIC_FIXTURE', application_executed=False,
        installed_dependencies=False, network_requested=False,
        initial_hook_status=baseline['status'], hooks=hook_rows,
        scans=runtime.calls, scan_count=len(runtime.calls), timings=timings,
        final_files={name:fingerprint(project/name) for name in sorted(FILES)},
        static_final=dict(status=finish['static']['status'], coverage=finish['static']['coverage'],
            finding_count=finish['static']['finding_count']),
        finish_status=finish['status'], final_packet_batch_coverage=final.get('batch_review'),
        final_integration=(result.get('host_review') or {}).get('integration_review'),
        final_review_status=result['status'], current_version=current['current_version'],
        batches=batch_rows, batch_summary=get_batches)
    (output/'result.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return payload


def assess(before, after):
    """Only compatibility/coverage parity is assessed, never model quality."""
    checks = {
        'same_final_files':before['final_files'] == after['final_files'],
        'same_static_rules':before['rules_identity'] == after['rules_identity'],
        'same_scan_count':before['scan_count'] == after['scan_count'],
        'expected_scan_stages':all([r['stage'] for r in row['scans']] ==
            ['hook_edit_1','hook_edit_2','task_finish'] and row['scan_count'] == len(row['scans'])
            for row in (before, after)),
        'same_scanned_scopes':[r['scope'] for r in before['scans']] == [r['scope'] for r in after['scans']],
        'same_static_findings':[r['rules'] for r in before['scans']] == [r['rules'] for r in after['scans']],
        'same_static_coverage':before['static_final'] == after['static_final'],
        'hook_scans_synchronous':all(h['scanner_run'] for row in (before, after) for h in row['hooks']),
        'prepare_batch_does_not_scan':all(r['prepare_scanner_calls'] == 0 for r in after['batches']),
        'both_final_versions_current':before['current_version'] is True and after['current_version'] is True,
        'legacy_final_submission_compatible':before['final_review_status'] == after['final_review_status'] == 'COMPLETE',
        'experimental_final_integration_recorded':(after.get('final_integration') or {}).get('validation') ==
            'HOST_REPORTED_NOT_SCANNER_PROOF',
        'real_static_executed':all(r['scanner_runs'] and all(s['status'] == 'SUCCESS'
            for s in r['scanner_runs']) for row in (before, after) for r in row['scans']),
        'expected_native_candidate':all(any('ai-security.javascript.dynamic-function' in r['rules']
            for r in row['scans']) for row in (before, after)),
    }
    return dict(passed=all(checks.values()), checks=checks)


def markdown_report(receipt):
    rows = receipt['results']
    first = rows[0]
    before, after = first['baseline'], first['experimental']
    lines = ['# 批次审查流程同场景对照结果', '',
        f"基线：`{receipt['baseline_commit']}`。共 {receipt['iterations']} 轮，两侧交替先后执行。",
        '', '下列结果只核验流程兼容性和真实本地静态执行。AI 提交为固定测试数据，没有调用模型。', '',
        '| 检查项 | 原流程 | 实验批次流程 |', '|---|---:|---:|',
        f"| 每轮编辑 Hook 静态调用 | {sum(s['stage'].startswith('hook_edit') for s in before['scans'])} | {sum(s['stage'].startswith('hook_edit') for s in after['scans'])} |",
        f"| 每轮任务末静态调用 | {sum(s['stage']=='task_finish' for s in before['scans'])} | {sum(s['stage']=='task_finish' for s in after['scans'])} |",
        f"| 每轮批次 | {len(before['batches'])} | {len(after['batches'])} |",
        f"| 批次准备新增扫描 | 0 | {sum(b['prepare_scanner_calls'] for b in after['batches'])} |",
        f"| 最终静态候选数 | {before['static_final']['finding_count']} | {after['static_final']['finding_count']} |",
        f"| 最终静态覆盖 | {before['static_final']['coverage']} | {after['static_final']['coverage']} |",
        f"| 最终版本仍匹配 | {before['current_version']} | {after['current_version']} |", '',
        '各轮最终文件 hash、静态规则身份、扫描次数、范围、发现规则和旧提交接口逐项核对。', '',
        '实验批次在最终版本上的状态：'+ '；'.join(
            f"第 {index} 批 {batch['validity']} / {batch['coverage']}"
            for index, batch in enumerate(after['batch_summary']['batches'], 1))+'。', '',
        '最终整合保留当前版本证据、跨批检查字段和候选处理记录；fixture 的 PARTIAL 结论不会被升级为完整审查。', '',
        '| 本地阶段中位耗时（毫秒） | 原流程 | 实验批次流程 |', '|---|---:|---:|']
    stages = {'hook_edit_1':'第 1 次编辑 Hook', 'hook_edit_2':'第 2 次编辑 Hook',
        'task_finish':'任务末静态检查', 'final_prepare':'最终材料准备'}
    for stage, title in stages.items():
        lines.append(f"| {title} | {receipt['measured_stage_medians_ms']['baseline'][stage]:.3f} | {receipt['measured_stage_medians_ms']['experimental'][stage]:.3f} |")
    lines.append(f"| 两批准备、读取、提交总计 | 0.000 | {receipt['measured_batch_protocol_median_ms']:.3f} |")
    lines.extend(['', '这些时间包含实际文件盘点、状态处理和本地静态执行，不包含真实模型审查或真实并发开发，不能推导模型提速。', '',
        '流程对照结论：'+('列出的检查全部成立。' if receipt['passed'] else '存在未成立的检查，详见 JSON。'), '',
        '静态使用真实内置 `native-js-function`，仅覆盖特定动态执行语法；未启用完整静态扫描器组合，因此产品聚合覆盖为 PARTIAL。流程对照成立不代表完整安全核查通过。', '',
        '未测量：模型准确率、误报率、实际子 Agent 并行收益、生产可达性和运行时利用条件。', '',
        '原始逐轮记录见同目录 `comparison.json`。', ''])
    return '\n'.join(lines)


def compare(baseline, experimental, python, output, iterations=3):
    if output.exists():
        raise ValueError('Use a fresh output directory; prior results must not be overwritten')
    for source in (baseline, experimental):
        if not (source/'src/security_runtime/task_security.py').is_file():
            raise ValueError('Source path must contain the task security implementation')
    commit = subprocess.run(['git', '-C', str(baseline), 'rev-parse', 'HEAD'],
        check=True, capture_output=True, text=True).stdout.strip()
    if commit != BASELINE_COMMIT:
        raise ValueError('Baseline HEAD differs from the frozen comparison commit')
    baseline_changes = subprocess.run(['git', '-C', str(baseline), 'status', '--porcelain',
        '--untracked-files=all', '--', 'src'], check=True, capture_output=True, text=True).stdout
    if baseline_changes.strip():
        raise ValueError('Frozen baseline source has local changes')
    output.mkdir(parents=True)
    results = []
    script = Path(__file__).resolve()
    for index in range(iterations):
        pair = {}
        # Alternate order to make unavoidable process/cache effects visible.
        sides = ('baseline', 'experimental') if index % 2 == 0 else ('experimental', 'baseline')
        for side in sides:
            source = baseline if side == 'baseline' else experimental
            destination = output/f'iteration-{index+1}'/side
            env = dict(os.environ, PYTHONPATH=str(source/'src'), PYTHONUTF8='1',
                SECURITY_RUNTIME_OFFLINE='1', SECURITY_RUNTIME_STATE_DIR=str(destination/'state'),
                SECURITY_RUNTIME_EXPERIMENTAL_BATCH_REVIEW='1' if side == 'experimental' else '0')
            command = [str(python), str(script), '--worker', side, '--worker-source', str(source),
                '--output', str(destination)]
            completed = subprocess.run(command, cwd=source, env=env, capture_output=True, text=True,
                encoding='utf-8', timeout=180)
            if completed.returncode:
                (output/f'worker-{index+1}-{side}.stderr.txt').write_text(completed.stderr, encoding='utf-8')
                raise RuntimeError(f'{side} worker failed; see worker stderr in {output}')
            pair[side] = json.loads((destination/'result.json').read_text(encoding='utf-8'))
        results.append(dict(iteration=index+1, verdict=assess(pair['baseline'], pair['experimental']), **pair))
    stages = ('hook_edit_1', 'hook_edit_2', 'task_finish', 'final_prepare')
    medians = {side:{stage:round(statistics.median(t['elapsed_ms'] for row in results
        for t in row[side]['timings'] if t['stage'] == stage), 3) for stage in stages}
        for side in ('baseline', 'experimental')}
    stable_sources = all(len({row[side]['source_tree_sha256'] for row in results}) == 1
        for side in ('baseline', 'experimental'))
    batch_protocol_ms = round(statistics.median(sum(t['elapsed_ms'] for t in row['experimental']['timings']
        if t['stage'].startswith('batch_')) for row in results), 3)
    receipt = dict(contract=CONTRACT, passed=stable_sources and all(row['verdict']['passed'] for row in results),
        source_versions_stable_across_iterations=stable_sources,
        baseline_commit=BASELINE_COMMIT, iterations=iterations, results=results,
        measured_stage_medians_ms=medians, model_observed=False,
        measured_batch_protocol_median_ms=batch_protocol_ms,
        model_accuracy_comparison='NOT_MEASURED', parallel_model_speedup='NOT_MEASURED',
        limitations=['Native JavaScript rule subset only; not a full scanner portfolio benchmark.',
            FIXTURE_LIMITATION, 'Timing is real local orchestration/static work, not actual model concurrency.',
            'Application reachability, exploitability and production behavior were not tested.'])
    (output/'comparison.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    (output/'comparison.md').write_text(markdown_report(receipt), encoding='utf-8')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--experimental', type=Path)
    parser.add_argument('--python', type=Path, default=Path(sys.executable))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--iterations', type=int, choices=range(1, 11), default=3)
    parser.add_argument('--worker', choices=('baseline', 'experimental'), help=argparse.SUPPRESS)
    parser.add_argument('--worker-source', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        run_worker(args.worker_source.resolve(), args.output.resolve(), args.worker)
        return 0
    if args.baseline is None or args.experimental is None:
        parser.error('--baseline and --experimental are required')
    result = compare(args.baseline.resolve(), args.experimental.resolve(), args.python.resolve(),
        args.output.resolve(), args.iterations)
    print(json.dumps(dict(passed=result['passed'], receipt=str(args.output/'comparison.json'),
        medians_ms=result['measured_stage_medians_ms'], model_observed=False), ensure_ascii=False))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
