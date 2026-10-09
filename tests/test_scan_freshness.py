from pathlib import Path

from security_runtime.runtime import SecurityRuntime
from security_runtime.scan_freshness import capture, complete, summary
from security_runtime.storage import SQLiteStore, ReadOnlySQLiteStore


def context_scan(tmp_path, monkeypatch, mode='release'):
    root = tmp_path / 'source'
    root.mkdir()
    (root / 'app.py').write_text('print("fixture")\n')
    store = SQLiteStore(tmp_path / 'state/scans.db')
    value = capture(root, store, mode=mode, staged=False, rules_path=None, hook_scope=None)
    value = complete(value, root, store)
    return root, store, {'mode': mode, 'scan_context': value, 'target_profile': {'files': ['app.py'], 'languages': ['Python']},
                        'status': 'COMPLETED', 'coverage': 'FULL', 'execution_state': 'EXECUTED', 'scanner_runs': []}


def test_zero_findings_inventory_changes_invalidate_freshness(tmp_path, monkeypatch):
    root, store, scan = context_scan(tmp_path, monkeypatch)
    ro = ReadOnlySQLiteStore(store.path)
    current = summary(scan, ro, root)
    assert current['source_freshness'] == 'CURRENT'
    assert not current['full_project_reusable']  # Current engine/DB proof is not obtained by summary.
    (root / 'new.py').write_text('print("new untracked file")\n')
    stale = summary(scan, ro, root)
    assert stale['source_freshness'] == 'STALE' and stale['reuse_reason'] == 'SOURCE_CHANGED'


def test_quick_full_never_claims_whole_project(tmp_path, monkeypatch):
    root, store, scan = context_scan(tmp_path, monkeypatch, mode='quick')
    value = summary(scan, ReadOnlySQLiteStore(store.path), root)
    assert not value['full_project_reusable'] and value['reuse_reason'] == 'NOT_WHOLE_PROJECT_SCAN'


def test_missing_key_summary_does_not_recreate_it(tmp_path, monkeypatch):
    root, store, scan = context_scan(tmp_path, monkeypatch)
    key = store.path.parent / 'triage-evidence.key'
    key.unlink()
    value = summary(scan, ReadOnlySQLiteStore(store.path), root)
    assert not key.exists() and value['source_freshness'] == 'UNKNOWN'


def test_build_rules_and_custom_exclusions_are_not_reused(tmp_path, monkeypatch):
    root, store, scan = context_scan(tmp_path, monkeypatch)
    monkeypatch.setenv('SECURITY_RUNTIME_EXCLUDE_DIRS', 'generated')
    assert summary(scan, ReadOnlySQLiteStore(store.path), root)['reuse_reason'] == 'BUILD_RULES_OR_SCOPE_CHANGED'
