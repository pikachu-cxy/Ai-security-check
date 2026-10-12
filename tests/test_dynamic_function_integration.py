import subprocess

from security_runtime.dynamic_function import NativeFunctionScanner
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.models import ScannerRun
from security_runtime.runtime import SecurityRuntime, combined_rule_coverage
from security_runtime.scanners import ScannerRegistry, SemgrepAdapter, GitleaksAdapter
from security_runtime.storage import SQLiteStore


def test_extra_rule_provider_cannot_hide_incomplete_original_rules():
    original = ScannerRun('semgrep', 'x', 'FAILED', 1, rule_coverage={
        'status': 'FAILED', 'rule_pack_id': 'original', 'total_selected': 6, 'total_executed': 0})
    native = ScannerRun('native-js-function', '1', 'SUCCESS', 1, rule_coverage={
        'status': 'EXECUTED', 'rule_pack_id': 'native', 'total_selected': 1, 'total_executed': 1})
    result = combined_rule_coverage([original, native])
    assert result['status'] == 'PARTIAL'
    assert result['providers']['semgrep']['status'] == 'FAILED'
    assert result['total_provider_selected'] == 7
    assert result['total_provider_executed'] == 1


def test_native_hook_uses_bounded_fast_check_and_rechecks_original_family(tmp_path, monkeypatch):
    root = tmp_path / 'project'
    root.mkdir()
    subprocess.run(['git', 'init', '--quiet', str(root)], check=True)
    calls = []

    def external_scan(*args):
        calls.append(True)
        raise AssertionError('Immediate native scope must not launch Semgrep')

    monkeypatch.setattr(SemgrepAdapter, 'scan', external_scan)
    monkeypatch.setattr(GitleaksAdapter, 'scan', lambda *args: ([], ScannerRun('gitleaks', 'fixture', 'SUCCESS', 0)))
    native = NativeFunctionScanner()
    registry = ScannerRegistry([SemgrepAdapter(), native, GitleaksAdapter()])
    runtime = SecurityRuntime(registry, SQLiteStore(tmp_path / 'scans.sqlite'))
    coordinator = HookCoordinator(runtime, HookStateStore(tmp_path / 'hooks'), cooldown_ms=0)
    source = root / 'expression.ts'
    source.write_text('export function calc(x:string){return new Function(x)();}\n', encoding='utf-8')
    first = coordinator.handle('FILE_CHANGED', root, 'codex', 'native-chain')
    assert first['execution']['scanner_run'] is True
    assert first['execution']['engine_process_observed'] is False
    assert first['code_check_scope'] == 'CANONICAL_DYNAMIC_CODE_ONLY'
    assert first['coverage'] == 'SCOPED'
    assert first['deferred_code_providers'] == ['semgrep']
    assert len(runtime.store.get_scan(first['scan_id'])['findings']) == 1
    assert '其他代码安全规则尚未执行' in runtime.store.get_scan(first['scan_id'])['summary']
    source.write_text('export function calc(x:string){return 1;}\n', encoding='utf-8')
    second = coordinator.handle('FILE_CHANGED', root, 'codex', 'native-chain')
    assert second['delta']['resolved'] == 1
    scan = runtime.store.get_scan(second['scan_id'])
    assert scan['release_status'] == 'NO_FINDINGS'
    assert '这不能证明项目安全' in scan['summary']
    assert calls == []


def test_normal_hook_scope_keeps_external_rules(tmp_path, monkeypatch):
    root = tmp_path / 'project'
    root.mkdir()
    subprocess.run(['git', 'init', '--quiet', str(root)], check=True)
    (root / 'normal.ts').write_text('export const x = 1;\n', encoding='utf-8')
    calls = []

    def external_scan(adapter, context, normalizer):
        calls.append(context.files)
        return [], ScannerRun('semgrep', 'x', 'FAILED', 1, error_code='TEST_EXTERNAL_FAILED')

    monkeypatch.setattr(SemgrepAdapter, 'scan', external_scan)
    coordinator = HookCoordinator(SecurityRuntime(ScannerRegistry([SemgrepAdapter(), NativeFunctionScanner()]),
        SQLiteStore(tmp_path / 'scans.sqlite')), HookStateStore(tmp_path / 'hooks'), cooldown_ms=0)
    result = coordinator.handle('FILE_CHANGED', root, 'codex', 'ordinary')
    assert calls == [('normal.ts',)]
    assert 'code_check_scope' not in result
    assert result['capabilities']['CODE_SAST'] == 'PARTIAL'
