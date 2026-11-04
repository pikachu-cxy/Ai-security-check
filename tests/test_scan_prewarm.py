import json
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest

from test_scanner_hot_path import engine, scan
from test_development_check import check
from security_runtime import scan_prewarm
from security_runtime.preparation_cache import PreparationCache


@pytest.fixture(autouse=True)
def isolated_preparation(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_DATA_DIR', str(tmp_path / 'data'))
    monkeypatch.setenv('SECURITY_RUNTIME_CONFIG', str(tmp_path / 'missing.toml'))


def test_new_process_reuses_rules_config_and_version(tmp_path):
    pack = tmp_path / 'rules'
    pack.mkdir()
    (pack / 'test.yaml').write_text('rules:\n- id: example\n  languages: [python]\n  severity: ERROR\n  message: example\n  pattern: eval($X)\n')
    binary = tmp_path / 'gitleaks'
    binary.write_bytes(b'fixture')
    script = '''
import json, sys
from pathlib import Path
from security_runtime.rulepacks import RulePackManager
from security_runtime.rule_coverage import plan_rules
from security_runtime.scanners import OpenGrepAdapter
from security_runtime.toolchain import ToolManager
import yaml
root=Path(sys.argv[1])
manager=ToolManager(root/'tools')
calls=[]
manager._probe_version=lambda *args: calls.append('probe') or manager.versions['gitleaks']
if sys.argv[2]=='warm':
 def forbidden(*args, **kwargs): raise AssertionError('preparation repeated')
 RulePackManager._validate_uncached=staticmethod(forbidden)
 yaml.safe_load=forbidden
 yaml.safe_dump=forbidden
pack=RulePackManager().resolve(user_path=root/'rules')
plan=plan_rules(pack,('final.py',))
config=OpenGrepAdapter().prepare_config(pack,plan.rules,root)
version=manager._version('gitleaks',root/'gitleaks')
print(json.dumps(dict(config=config,checksum=pack.checksum,version=version,probes=len(calls))))
'''
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'))
    env.pop('__PYVENV_LAUNCHER__', None)
    cold, warm = [json.loads(subprocess.check_output([sys.executable, '-c', script, str(tmp_path), state], env=env))
                  for state in ('cold', 'warm')]
    assert cold.pop('probes') == 1
    assert warm.pop('probes') == 0
    assert cold == warm


def test_prewarmed_scan_uses_final_source_and_changed_rules(engine, monkeypatch):
    from security_runtime import scanner_cache
    root, source, pack, adapter, calls, _ = engine
    from security_runtime.rule_coverage import plan_rules
    rules = adapter.rule_packs.resolve()
    adapter.prepare_config(rules, plan_rules(rules, ('A.java',)).rules, root)
    # Simulate a fresh worker after the user continues editing.
    scanner_cache._process = scanner_cache.ProcessPreparations()
    source.write_text('connection.setHostnameVerifier((h,s)->true)')
    from security_runtime.runtime import SecurityRuntime
    from security_runtime.scanners import ScannerRegistry
    from security_runtime.storage import SQLiteStore
    runtime = SecurityRuntime(ScannerRegistry([adapter], fallback_adapters=[]), SQLiteStore(root.parent / 'scan.db'))
    result = runtime.scan(root, 'release')
    assert result.findings and result.scanner_runs[0].scanner_diagnostics['cache']['selected_config'] == 'HIT'
    rule_file = pack / 'java/trust-all-hostname.yml'
    rule_file.write_text(rule_file.read_text().replace('TLS fixture', 'Updated TLS fixture'))
    scanner_cache._process = scanner_cache.ProcessPreparations()
    _, changed = scan(engine)
    assert changed.scanner_diagnostics['cache']['selected_config'] == 'MISS'
    assert len(calls) == 2


def test_background_preparation_coalesces_without_blocking(tmp_path, monkeypatch):
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    calls = []
    def prepare(root, names):
        calls.append(names)
        entered.set()
        assert release.wait(5)
        if names:
            finished.set()
    monkeypatch.setattr(scan_prewarm, 'prepare', prepare)
    scan_prewarm.start(tmp_path)
    assert entered.wait(5)
    for _ in range(5):
        scan_prewarm.start(tmp_path, ['one.py', 'two.py'])
    release.set()
    assert finished.wait(5)
    assert calls == [(), ('target.py',)]


def test_prepare_never_reads_source_or_scans(tmp_path, monkeypatch):
    from security_runtime.scanners import OpenGrepAdapter
    from security_runtime.rulepacks import RulePackManager
    from security_runtime.toolchain import ToolManager
    calls = []
    def forbidden(*args, **kwargs):
        raise AssertionError('prewarm must not scan or read project')
    monkeypatch.setattr(OpenGrepAdapter, 'scan', forbidden)
    monkeypatch.setattr(OpenGrepAdapter, 'plan_rules', forbidden)
    monkeypatch.setattr(ToolManager, 'ensure', forbidden)
    monkeypatch.setattr(ToolManager, 'resolve', lambda *args: calls.append('resolve-installed'))
    # Use a small real rule pack without creating any target source file.
    pack = tmp_path / 'rules'
    pack.mkdir()
    (pack / 'r.yaml').write_text('rules:\n- id: test\n  languages: [python]\n  severity: ERROR\n  message: test\n  pattern: eval($X)\n')
    real_resolve = RulePackManager.resolve
    monkeypatch.setattr(RulePackManager, 'resolve', lambda self: real_resolve(self, user_path=pack))
    scan_prewarm.prepare(tmp_path, ('target.py',))
    assert calls == ['resolve-installed']
    assert not (tmp_path / 'target.py').exists()


def test_task_and_edit_hooks_request_preparation_without_submission(check, monkeypatch):
    from security_runtime.development_check import record_hook
    root, service, runtime, state = check
    service.launcher = None
    requests = []
    monkeypatch.setattr(scan_prewarm, 'start', lambda root, paths=(): requests.append(tuple(paths)))
    opened = service.begin(root, 'prewarm')
    edited = service.record(root, opened['check_ref'], ['app.ts'])
    hooked = record_hook(service.hooks, root, service.owner, ['app.ts'], scope_unknown=False)
    assert requests == [(), ('app.ts',), ('app.ts',)]
    assert opened['dirty_seq'] == 0
    assert not edited['finish_requested'] and not hooked['scanner_run']
    assert state['calls'] == 0


def test_unusable_cache_is_optional(tmp_path, monkeypatch):
    cache = PreparationCache(tmp_path / 'data')
    def unavailable(*args):
        raise PermissionError('fixture')
    monkeypatch.setattr(cache.store, 'read', unavailable)
    monkeypatch.setattr(cache.hooks, 'key', unavailable)
    assert cache.get('test', 'identity') is None
    cache.put('test', 'identity', {'prepared': True})
