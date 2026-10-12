"""FlyCRM original-sample acceptance through scan/task APIs, never Hook replay.

Only a new independent Git copy of the eleven securityBench files is edited.
The Runtime scans/verifies; this explicitly authorized host harness edits/tests.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import html
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from security_runtime.arithmetic_regression import build_arithmetic_regression_plan
from security_runtime.dynamic_function import NativeFunctionScanner, RULE_ID
from security_runtime.findings import FindingNormalizer
from security_runtime.hook_user_feedback import issue_feedback
from security_runtime.models import ScanContext, ScanMode
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import GitleaksAdapter, ScannerRegistry
from security_runtime.security_summary import SecuritySummaryService
from security_runtime.storage import SQLiteStore
from security_runtime.task_fix import TaskFixService

SOURCE = Path(r'C:\Users\24170\Downloads\FlyCRM-AI-feat-ai-chat\FlyCRM-AI-feat-ai-chat')
BENCH = Path('src/securityBench')
TARGET = BENCH / 'services/expressionEvaluator.ts'
EXPECTED = {'app.ts', 'index.ts', 'db/benchConnection.ts', 'routes/bench.ts',
    'routes/loginDiagnostics.ts', 'routes/merchantSearch.ts',
    'services/expressionEvaluator.ts', 'services/htmlPreview.ts',
    'services/loginDiagnostics.ts', 'services/merchantSearch.ts',
    'sql/bench_merchants.fixture.sql'}


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def manifest(source):
    directory = source / BENCH
    names = {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()}
    if names != EXPECTED:
        raise ValueError('Only the original eleven securityBench files are accepted')
    return {str(BENCH / name).replace('\\', '/'): hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in sorted(EXPECTED)}


def independent_copy(source, destination):
    if destination.exists():
        raise ValueError('Acceptance copy already exists; preserve it and select a fresh artifact directory')
    destination.mkdir(parents=True)
    for name in manifest(source):
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source / name).read_bytes())
    subprocess.run(['git', 'init', '-q', '-b', 'main', str(destination)], check=True)
    subprocess.run(['git', '-C', str(destination), 'add', 'src/securityBench'], check=True)
    subprocess.run(['git', '-C', str(destination), '-c', 'user.name=Runtime acceptance',
        '-c', 'user.email=local-acceptance@example.invalid', 'commit', '-q', '-m',
        'Preserve exact FlyCRM securityBench originals'], check=True)
    if manifest(destination) != manifest(source):
        raise AssertionError('Copied sample bytes changed')


@contextmanager
def isolated_environment(state):
    names = ['SECURITY_RUNTIME_STATE_DIR', 'SECURITY_RUNTIME_WORKSPACE', 'SECURITY_RUNTIME_GLOBAL',
             'SECURITY_RUNTIME_OFFLINE', 'PYTHONUTF8', 'TEMP', 'TMP']
    saved = {name: os.environ.get(name) for name in names}
    # Temp must be outside this checkout, so independent non-Git helper targets
    # are not accidentally discovered as the source repository workspace.
    temporary = Path(os.environ.get('LOCALAPPDATA', '')) / 'Temp'
    os.environ.update(SECURITY_RUNTIME_STATE_DIR=str(state), SECURITY_RUNTIME_OFFLINE='1',
                      PYTHONUTF8='1', TEMP=str(temporary), TMP=str(temporary))
    os.environ.pop('SECURITY_RUNTIME_WORKSPACE', None)
    os.environ.pop('SECURITY_RUNTIME_GLOBAL', None)
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def patch_arithmetic_copy(path):
    """Host edit authorized by this selected-case task, never Runtime mutation."""
    original = path.read_bytes()
    newline = '\r\n' if b'\r\n' in original else '\n'
    source = original.decode('utf-8').replace('\r\n', '\n')
    replacements = [
        ('  const compute = new Function(`return (${expression});`);\n  return compute();',
         '  return evaluateArithmetic(expression);'),
        ('const NUMBER_PATTERN = /^(?:\\d+(?:\\.\\d+)?|\\.\\d+)/;',
         'const NUMBER_PATTERN = /^(?:\\d+(?:\\.\\d*)?|\\.\\d+)(?:[eE][+-]?\\d+)?/;'),
        ('  private position = 0;', '  private position = 0;\n  private nesting = 0;'),
        ('      const value = this.parseUnary();',
         "      if (++this.nesting > 64) throw new Error('表达式嵌套过深');\n"
         '      const value = this.parseUnary();\n      this.nesting -= 1;'),
        ('      const value = this.parseExpression();',
         "      if (++this.nesting > 64) throw new Error('表达式嵌套过深');\n"
         '      const value = this.parseExpression();\n      this.nesting -= 1;'),
        ('export function evaluateArithmetic(expression: string): number {\n  const trimmed',
         "export function evaluateArithmetic(expression: string): number {\n"
         "  if (expression.length > 4096) throw new Error('表达式过长');\n  const trimmed"),
    ]
    for old, new in replacements:
        if source.count(old) != 1:
            raise AssertionError('Original FlyCRM arithmetic source does not match the bounded patch')
        source = source.replace(old, new)
    fixed = source.replace('\n', newline).encode('utf-8')
    path.write_bytes(fixed)
    return {'before_sha256': hashlib.sha256(original).hexdigest(),
            'after_sha256': hashlib.sha256(fixed).hexdigest(),
            'host_edit': True, 'runtime_edit': False,
            'arithmetic_contract_confirmed_by': 'EXPLICIT_USER_REQUEST_FOR_NORMAL_ARITHMETIC',
            'compatible_grammar': 'decimal including trailing point and scientific notation; + - * / %, parentheses, unary signs, whitespace',
            'intentional_change': 'JavaScript code, object/property access and calls are rejected',
            'limits': {'characters': 4096, 'combined_parenthesis_or_unary_nesting': 64}}


def functional_run(before, after):
    plan = build_arithmetic_regression_plan(before, after, arithmetic_contract_confirmed=True)
    node = shutil.which('node')
    if not node:
        raise AssertionError('Node 24 is required for the actual arithmetic acceptance')
    command = [node, *plan['command']['argv'][1:]]
    started = time.perf_counter()
    execution = subprocess.run(command, capture_output=True, text=True, shell=False,
        check=False, timeout=plan['command']['timeout_seconds'])
    report = json.loads(execution.stdout)
    if execution.returncode != 0 or report['status'] != 'ARITHMETIC_REGRESSION_PASSED':
        raise AssertionError(report)
    if report['modules'] != plan['modules'] or report['template_sha256'] != plan['template_sha256']:
        raise AssertionError('Functional report does not match the preserved source modules/template')
    return {'plan': plan, 'process': {'exit_code': execution.returncode,
        'wall_time_ms': round((time.perf_counter() - started) * 1000, 3)}, 'report': report}


def source_acceptance(source, artifacts):
    root = artifacts / 'source-project'
    independent_copy(source, root)
    before = artifacts / 'source-before.ts'
    after = artifacts / 'source-after.ts'
    before.write_bytes((root / TARGET).read_bytes())
    state = artifacts / 'source-state'
    with isolated_environment(state):
        registry = ScannerRegistry([NativeFunctionScanner(), GitleaksAdapter()], fallback_adapters=[])
        store = SQLiteStore(state / 'scans.db')
        runtime = SecurityRuntime(registry, store)
        raw_scans, timings = [], []
        for index in range(3):
            started = time.perf_counter()
            result = runtime.scan(root, mode='release')
            timings.append({'phase': 'first' if index == 0 else f'repeat_{index}',
                'wall_time_ms': round((time.perf_counter() - started) * 1000, 3),
                'runtime_duration_ms': result.duration_ms,
                'providers': [{key: asdict(run)[key] for key in
                    ('scanner', 'status', 'duration_ms', 'coverage_contract')} for run in result.scanner_runs]})
            raw_scans.append(result.to_dict())
            assert result.status == 'COMPLETED', result.to_dict()
            assert sum(f.technical_details.get('rule_id') == RULE_ID for f in result.findings) == 1
        summary = SecuritySummaryService(store).get(root, result.scan_id, details=True)
        task = next(t for t in summary['tasks'] if any(m['rule_id'] == RULE_ID for m in t['members']))
        finding = next(f for f in result.findings if f.technical_details.get('rule_id') == RULE_ID)
        feedback = issue_feedback(asdict(finding))  # Pure formatter; no Hook handler/event is called.
        service = TaskFixService(store, registry)
        prepared = service.prepare(task['task_ref'], root)
        assert prepared['status'] == 'READY_FOR_HOST_FIX', prepared
        unchanged = service.verify(task['task_ref'], root)
        assert unchanged['status'] == 'STILL_PRESENT', unchanged
        path = root / TARGET
        original = path.read_bytes()
        path.write_bytes(b'\n' * 8 + original)
        moved = service.verify(task['task_ref'], root)
        assert moved['status'] == 'STILL_PRESENT', moved
        path.unlink()  # Only this explicitly created disposable copy.
        try:
            missing = service.verify(task['task_ref'], root)
            assert missing['status'] in {'INCONCLUSIVE', 'NOT_VERIFIED'}, missing
            assert all(row['verification_status'] == 'INCONCLUSIVE' for row in missing['members']), missing
        finally:
            path.write_bytes(original)
        patch = patch_arithmetic_copy(path)
        after.write_bytes(path.read_bytes())
        functional = functional_run(before, after)
        started = time.perf_counter()
        repaired = service.verify(task['task_ref'], root,
            host_reported_execution={'patch_applied': True, 'tests_run': True, 'target_build': False})
        repaired_wall = round((time.perf_counter() - started) * 1000, 3)
        assert repaired['status'] == 'SCANNER_VERIFIED_RESOLVED', repaired
        final_scan = runtime.scan(root, mode='release')
        assert final_scan.release_status == 'NO_FINDINGS' and not final_scan.findings, final_scan.to_dict()
        native_single = []
        for index in range(3):
            adapter = NativeFunctionScanner()
            context = ScanContext(str(root), ScanMode.FEATURE, (TARGET.as_posix(),))
            started = time.perf_counter()
            found, run = adapter.scan(context, FindingNormalizer(root))
            native_single.append({'phase': 'first' if index == 0 else f'repeat_{index}',
                'wall_time_ms': round((time.perf_counter() - started) * 1000, 3),
                'duration_ms': run.duration_ms, 'status': run.status, 'finding_count': len(found)})
        report = {'transport': 'LOCAL_SOURCE_API', 'manual_hook_handler_calls': False,
            'desktop_automatic_hook_tested': False, 'source_project': str(root),
            'scanner_scope': 'Native Function provider + real Gitleaks; not default full Semgrep pipeline',
            'samples_copied': 11, 'typescript_files_checked': 10,
            'scan_timings': timings, 'native_single_fixed_file_timings': native_single,
            'qoder_timing': {'milliseconds': 56, 'scope': 'ONE_RECORDED_INTERNAL_L1_EVENT',
                'end_to_end_available': False, 'direct_speed_ratio_supported': False},
            'original_scans': raw_scans, 'task_summary': summary,
            'user_feedback': feedback, 'feedback_evidence': 'PURE_TEMPLATE_FORMATTING; NOT DESKTOP DELIVERY',
            'prepare_task_fix': prepared, 'verify_before_patch': unchanged,
            'verify_after_line_movement': moved, 'verify_missing_file': missing,
            'host_patch': patch, 'functional_host_run': functional,
            'verify_after_patch': repaired, 'verify_after_patch_wall_ms': repaired_wall,
            'final_scan': final_scan.to_dict()}
    return report


async def native_sdk_acceptance(executable, source, artifacts):
    """Ordinary SDK tools only; never call handle_* or hook CLI commands."""
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    root = artifacts / 'native-project'
    independent_copy(source, root)
    before, after = artifacts / 'native-before.ts', artifacts / 'native-after.ts'
    before.write_bytes((root / TARGET).read_bytes())
    env = dict(os.environ, SECURITY_RUNTIME_STATE_DIR=str(artifacts / 'native-state'),
        SECURITY_RUNTIME_WORKSPACE=str(root), SECURITY_RUNTIME_OFFLINE='1', PYTHONUTF8='1')
    env.pop('SECURITY_RUNTIME_GLOBAL', None)
    params = StdioServerParameters(command=str(executable.resolve()), args=['mcp'], cwd=root, env=env)
    with (artifacts / 'native-stderr.txt').open('w', encoding='utf-8') as stderr:
        async with stdio_client(params, errlog=stderr) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                calls = []
                async def call(name, arguments):
                    assert name in {'get_runtime_info', 'scan_project', 'get_security_summary',
                        'prepare_task_fix', 'verify_task_fix', 'get_findings'}
                    started = time.perf_counter()
                    response = await client.call_tool(name, arguments)
                    if response.isError:
                        raise AssertionError(f'Ordinary SDK tool failed: {name}')
                    value = response.structuredContent or json.loads(response.content[0].text)
                    value = value.get('result', value)
                    calls.append({'tool': name, 'wall_time_ms': round((time.perf_counter() - started) * 1000, 3)})
                    return value
                info = await call('get_runtime_info', {})
                initial = await call('scan_project', {'workspace_path': str(root), 'summary': False})
                summary = await call('get_security_summary', {'workspace_path': str(root), 'details': True})
                task = next(t for t in summary['tasks'] if any(m['rule_id'] == RULE_ID for m in t['members']))
                arguments = {'task_ref': task['task_ref'], 'workspace_path': str(root)}
                prepared = await call('prepare_task_fix', arguments)
                assert prepared['status'] == 'READY_FOR_HOST_FIX', prepared
                unchanged = await call('verify_task_fix', arguments)
                assert unchanged['status'] == 'STILL_PRESENT', unchanged
                patch = patch_arithmetic_copy(root / TARGET)
                after.write_bytes((root / TARGET).read_bytes())
                functional = functional_run(before, after)
                repaired = await call('verify_task_fix', {**arguments,
                    'host_reported_execution': {'patch_applied': True, 'tests_run': True}})
                assert repaired['status'] == 'SCANNER_VERIFIED_RESOLVED', repaired
                final = await call('scan_project', {'workspace_path': str(root), 'summary': False})
                assert final['recommendation'] == 'NO_FINDINGS' and not final['findings'], final
    return {'transport': 'ACTUAL_NATIVE_MCP_STDIO', 'runtime_executable': str(executable.resolve()),
        'runtime_info': info, 'ordinary_tool_calls': calls, 'manual_hook_handler_calls': False,
        'desktop_automatic_hook_tested': False, 'initial_scan': initial, 'summary': summary,
        'prepare_task_fix': prepared, 'verify_before_patch': unchanged,
        'host_patch': patch, 'functional_host_run': functional,
        'verify_after_patch': repaired, 'final_scan': final}


def render_report(record):
    source = record.get('source_api', {})
    timings = source.get('scan_timings', [])
    rows = ''.join(f'<tr><td>{html.escape(row["phase"])}</td><td>{row["wall_time_ms"]}</td>'
                   f'<td>{row["runtime_duration_ms"]}</td></tr>' for row in timings)
    feedback = html.escape(source.get('user_feedback', {}).get('message', ''))
    native = record.get('installed_native_sdk', {})
    native_rows = ''.join(f'<tr><td>{html.escape(row["tool"])}</td><td>{row["wall_time_ms"]}</td></tr>'
                          for row in native.get('ordinary_tool_calls', []))
    build_id = native.get('runtime_info', {}).get('build_identity', {}).get('build_id', '')
    source_section = (f'<p>源码普通扫描／任务接口已验收。检测范围：原生 Function 规则 + 真实 Gitleaks；不是默认完整 Semgrep 流水线。</p>'
        f'<table><tr><th>普通源码 API 轮次</th><th>完整调用 ms</th><th>Runtime ms</th></tr>{rows}</table>') if source else ''
    native_section = (f'<h2>真实安装包普通 MCP 接口</h2><p>Build ID：<code>{html.escape(build_id)}</code>。</p>'
        f'<p>执行默认完整扫描流水线。此表记录实际 SDK 完整调用耗时；不是桌面自动 Hook 或风险提示送达时间。</p>'
        f'<table><tr><th>普通 SDK 工具</th><th>完整调用 ms</th></tr>{native_rows}</table>') if native else ''
    extra_source_checks = ('源码API额外验收：移动行号仍为 STILL_PRESENT；'
        '删除文件的任务为 NOT_VERIFIED、成员为 INCONCLUSIVE。') if source else ''
    if not feedback and native:
        finding = next((row for row in native.get('initial_scan', {}).get('findings', [])
                        if row.get('technical_details', {}).get('rule_id') == RULE_ID), None)
        if finding:
            feedback = html.escape(issue_feedback(finding)['message'])
    return f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>new Function 链路验收</title>
<style>body{{font:16px/1.6 system-ui;max-width:1000px;margin:40px auto;padding:0 24px}}table{{border-collapse:collapse}}td,th{{padding:8px 18px;border:1px solid #bbb}}pre{{white-space:pre-wrap;background:#f3f5f7;padding:18px}}</style>
<h1>FlyCRM new Function 发现、提示、修复与复测验收</h1>
<p>原项目只读，复制11个原样例文件，检查10个 TypeScript 文件。原文件哈希保持：{record['original_sha256_unchanged']}。</p>
<p>未手工调用 Hook handler；未验证桌面自动 Hook 到用户提示的耗时。普通 API／SDK 检查不能当作自动 Hook 验收。</p>
<p>安装包普通 MCP SDK 验收：{html.escape(native.get('transport', '尚未执行'))}。</p>
{source_section}{native_section}
<p>Qoder 56 ms 仅一条内部 L1 事件；没有双方相同口径的完整等待时间，不能计算倍数。</p>
<h2>实际提示模板</h2><pre>{feedback}</pre>
<h2>修复及结果</h2><p>仅在独立样例副本中将动态代码执行换为已有受限算术解析器，补充十进制尾点和科学记数支持，限制4096字符和64层嵌套。</p>
<p>原风险未修改复查为 STILL_PRESENT；修复后原 provider／rule／file 为 SCANNER_VERIFIED_RESOLVED。{extra_source_checks}</p>
<p>Node 24 实际导入前后模块，32个正常算术结果按 Object.is 与 JSON 载荷一致；7个错误输入均拒绝。修复后拒绝进程内标记、4个范围外 JavaScript 表达式、3个超预算输入。HTTP 载荷检查未启动 Express，也不证明路由或生产业务正确。</p>
<p>完整零发现改为 NO_FINDINGS：本次已执行规则范围内未发现候选安全问题；不能证明项目安全。</p>
<p>原始证据：<a href="acceptance-results.json">acceptance-results.json</a>。安全规则复查与宿主功能测试分别记录；未运行目标全项目构建／测试。</p></html>'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=SOURCE)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--executable', type=Path)
    parser.add_argument('--native-only', action='store_true')
    args = parser.parse_args()
    artifacts = args.artifacts.absolute()
    artifacts.mkdir(parents=True, exist_ok=True)
    output = artifacts / 'acceptance-results.json'
    record = json.loads(output.read_text(encoding='utf-8')) if args.native_only and output.exists() else {}
    original = manifest(args.source)
    record.setdefault('source_original', str(args.source))
    record.setdefault('original_manifest', original)
    record.setdefault('manual_hook_handler_calls', False)
    if not args.native_only:
        record.update(source_original=str(args.source), original_manifest=original,
            original_sha256_unchanged=False, manual_hook_handler_calls=False)
        record['source_api'] = source_acceptance(args.source, artifacts)
    if args.executable:
        with isolated_environment(artifacts / 'native-state'):
            record['installed_native_sdk'] = asyncio.run(native_sdk_acceptance(args.executable, args.source, artifacts))
    record['original_sha256_unchanged'] = original == manifest(args.source)
    assert record['original_sha256_unchanged']
    write_json(output, record)
    (artifacts / 'acceptance-report.zh-CN.html').write_text(render_report(record), encoding='utf-8')
    print(json.dumps({'status': 'ACCEPTANCE_PASSED', 'transport': list(key for key in
        ('source_api', 'installed_native_sdk') if key in record), 'original_unchanged': True,
        'manual_hook_handler_calls': False, 'report': str(artifacts / 'acceptance-report.zh-CN.html')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
