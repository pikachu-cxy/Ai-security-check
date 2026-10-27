"""Actual Runtime/store proof boundaries with deterministic external engines."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3

import pytest

from security_runtime.runtime import SecurityRuntime
from security_runtime.scan_reuse import try_reuse
from security_runtime.scanners import BaseScanner, GitleaksAdapter, ScannerRegistry, TrivyAdapter, TrivyMisconfigAdapter
from security_runtime.storage import SQLiteStore
from security_runtime.toolchain import ToolManager, ResolvedTool, ToolStatus
from test_scanner_hot_path import engine  # noqa: F401


def resolved(manager, name, binary):
    return ResolvedTool(name, manager.versions[name], str(binary), None, ToolStatus.READY)


@pytest.fixture
def reusable(engine, tmp_path, monkeypatch):
    root, path, pack, adapter, calls, failure = engine
    monkeypatch.delenv('GITLEAKS_CONFIG', raising=False)
    monkeypatch.delenv('TRIVY_CONFIG', raising=False)
    selected = adapter.tool_manager.ensure('semgrep')
    monkeypatch.setattr(adapter.tool_manager, 'resolve', lambda _name: selected)
    manager = ToolManager(tmp_path / 'secret-tool')
    binary = tmp_path / 'gitleaks.exe'
    binary.write_bytes(b'fixture real identity, process mocked')
    secret = GitleaksAdapter(manager)
    monkeypatch.setattr(manager, 'resolve', lambda name: resolved(manager, name, binary))
    monkeypatch.setattr(manager, 'ensure', lambda name, **_kwargs: resolved(manager, name, binary))
    monkeypatch.setattr(secret, '_scan', lambda *_args: [])
    # Pytest changes this environment variable between fixture setup and the
    # assertion phase. It is a test harness detail, unlike user engine config.
    for provider in (adapter, secret):
        original_environment = provider._environment
        def environment(binary, context, original=original_environment):
            values = original(binary, context)
            values.pop('PYTEST_CURRENT_TEST', None)
            return values
        monkeypatch.setattr(provider, '_environment', environment)
    # Other agents may be editing this shared Runtime checkout during tests.
    # Engine/rule/source identities below still use real changed file bytes.
    from security_runtime.build_identity import build_identity
    stable_build = build_identity()
    monkeypatch.setattr('security_runtime.scan_reuse.build_identity', lambda: stable_build)
    monkeypatch.setattr('security_runtime.scan_freshness.build_identity', lambda: stable_build)
    runtime = SecurityRuntime(ScannerRegistry([adapter, secret], fallback_adapters=[]),
                              SQLiteStore(tmp_path / 'state' / 'scans.db'))
    result = runtime.scan(root, 'release')
    assert result.status == 'COMPLETED' and result.coverage == 'FULL'
    assert result.scanner_diagnostics.get('result_reuse'), result.scanner_diagnostics
    return runtime, root, path, pack, adapter, calls, result, secret, binary


def test_unchanged_scan_reused_without_scanning_or_state_writes(reusable, monkeypatch):
    runtime, root, _, _, _, calls, result, *_ = reusable
    before = runtime.store.path.read_bytes()
    key = runtime.store.path.parent / 'triage-evidence.key'
    key_bytes = key.read_bytes()
    monkeypatch.setattr(runtime, 'scan', lambda *_a, **_k: pytest.fail('new scan'))
    monkeypatch.setattr(runtime.store, 'save', lambda *_a: pytest.fail('state write'))
    decision = try_reuse(runtime, root)
    assert decision.reused, decision.reason_code
    assert decision.scan['scan_id'] == result.scan_id and len(calls) == 1
    assert decision.receipt['scanner_run'] is decision.receipt['repair_authorized'] is False
    assert decision.receipt['provider_freshness'] == 'CURRENT_IDENTITY_REVALIDATED'
    assert runtime.store.path.read_bytes() == before and key.read_bytes() == key_bytes
    timings = result.scanner_diagnostics['timing_ms']
    assert timings['reuse_proof_prepare'] >= 0 and timings['reuse_proof_seal'] >= 0


@pytest.mark.parametrize('change', ['edited', 'added', 'deleted', 'renamed', 'same_mtime'])
def test_source_content_and_inventory_changes_require_fresh_scan(reusable, change):
    runtime, root, path, *_ = reusable
    if change == 'edited':
        path.write_text('class Changed {}')
    elif change == 'same_mtime':
        info = path.stat()
        path.write_text('class B {}')
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    elif change == 'added':
        (root / 'new.py').write_text('print(1)')
    elif change == 'renamed':
        path.rename(root / 'B.java')
    else:
        path.unlink()
    assert try_reuse(runtime, root).reason_code == 'SOURCE_CHANGED'


@pytest.mark.parametrize('change', ['engine', 'rules', 'configuration', 'registry', 'exclusion', 'limits'])
def test_real_engine_rules_and_configuration_changes_invalidate_reuse(reusable, monkeypatch, change):
    runtime, root, _, pack, adapter, _, _, secret, binary = reusable
    if change == 'engine':
        binary.write_bytes(b'changed actual executable bytes')
    elif change == 'rules':
        rule = pack / 'java' / 'trust-all-hostname.yml'
        rule.write_bytes(rule.read_bytes() + b'\n')
    elif change == 'configuration':
        monkeypatch.setenv('SCANNER_TEST_SEMANTICS', 'changed')
    elif change == 'registry':
        runtime.registry.adapters.remove(secret)
    elif change == 'exclusion':
        monkeypatch.setenv('SECURITY_RUNTIME_EXCLUDE_DIRS', 'extra')
    else:
        monkeypatch.setenv('SECURITY_RUNTIME_MAX_DEPTH', '11')
    decision = try_reuse(runtime, root)
    assert not decision.reused and decision.reason_code == 'BUILD_RULES_ENGINE_OR_CONFIGURATION_CHANGED'


@pytest.mark.parametrize('target', ['proof', 'finding', 'status', 'context', 'key'])
def test_corrupt_or_missing_proof_never_reused(reusable, target):
    runtime, root, *_ = reusable
    scan = runtime.store.latest_scan(root)
    if target == 'key':
        key = runtime.store.path.parent / 'triage-evidence.key'
        key.unlink()
        assert not try_reuse(runtime, root).reused and not key.exists()
        return
    if target == 'proof':
        scan['scanner_diagnostics']['result_reuse']['identity']['workspace'] = 'other'
    elif target == 'finding':
        scan['findings'].append({'id': 'forged'})
    elif target == 'status':
        scan['release_status'] = 'forged'
    else:
        scan['scan_context']['source_consistent'] = False
    with sqlite3.connect(runtime.store.path) as db:
        db.execute('UPDATE scans SET data=? WHERE id=?', (json.dumps(scan), scan['scan_id']))
    decision = try_reuse(runtime, root)
    assert decision.reason_code == ('REUSE_PROOF_INVALID' if target == 'proof' else 'RESULT_PROOF_INVALID')


def test_another_workspace_and_legacy_scan_are_not_eligible(reusable, tmp_path):
    runtime, root, _, _, _, _, result, *_ = reusable
    other = tmp_path / 'other'
    other.mkdir()
    assert try_reuse(runtime, other, scan_id=result.scan_id).reason_code == 'WORKSPACE_MISMATCH'
    scan = runtime.store.latest_scan(root)
    scan['scanner_diagnostics'].pop('result_reuse')
    with sqlite3.connect(runtime.store.path) as db:
        db.execute('UPDATE scans SET data=? WHERE id=?', (json.dumps(scan), scan['scan_id']))
    assert try_reuse(runtime, root).reason_code == 'REUSE_PROOF_UNAVAILABLE'


def test_scoped_and_partial_results_never_receive_proof(reusable):
    from security_runtime.scan_input import scoped_request
    runtime, root, _, _, _, _, _, secret, _ = reusable
    scoped = runtime.scan(root, request=scoped_request(root, ['A.java']))
    assert 'result_reuse' not in scoped.scanner_diagnostics
    assert scoped.scanner_diagnostics['timing_ms']['reuse_proof_prepare'] is None
    assert scoped.scanner_diagnostics['timing_ms']['reuse_proof_seal'] is None
    runtime.registry.adapters.remove(secret)
    partial = runtime.scan(root, 'release')
    assert partial.status == 'PARTIAL' and 'result_reuse' not in partial.scanner_diagnostics


def test_database_fingerprint_disabled_preserves_reuse_and_expiry_check(reusable, tmp_path, monkeypatch):
    runtime, root, *_ = reusable
    (root / 'package-lock.json').write_text('{"lockfileVersion":3,"packages":{}}')
    manager = ToolManager(tmp_path / 'dependency-tool')
    binary = tmp_path / 'trivy.exe'
    binary.write_bytes(b'fixture trivy actual identity')
    adapter = TrivyAdapter(manager)
    monkeypatch.setattr(manager, 'resolve', lambda name: resolved(manager, name, binary))
    monkeypatch.setattr(manager, 'ensure', lambda name, **_kwargs: resolved(manager, name, binary))
    monkeypatch.setattr(adapter, '_prepare', lambda *_args: ToolStatus.READY)
    monkeypatch.setattr(adapter, '_scan', lambda *_args: [])
    monkeypatch.setattr(manager, 'execution_data_identity', lambda *_a, **_k:
        pytest.fail('vulnerability database content must not be fingerprinted'))
    db = manager.trivy_cache_dir() / 'db'
    db.mkdir(parents=True)
    data = db / 'trivy.db'
    data.write_bytes(b'original data')
    now = datetime.now(timezone.utc)
    metadata = {'UpdatedAt': (now - timedelta(hours=1)).isoformat(),
                'NextUpdate': (now + timedelta(hours=1)).isoformat()}
    (db / 'metadata.json').write_text(json.dumps(metadata))
    # This deterministic native fixture represents complete lockfile inventory.
    monkeypatch.setattr(adapter, 'scan', lambda context, normalizer:
        BaseScanner.scan(adapter, context, normalizer))
    runtime.registry.adapters.append(adapter)
    result = runtime.scan(root, 'release')
    assert result.status == 'COMPLETED' and result.scanner_diagnostics.get('result_reuse')
    assert try_reuse(runtime, root).reused
    data.write_bytes(b'new database, metadata unchanged')
    assert try_reuse(runtime, root).reused
    data.write_bytes(b'original data')
    monkeypatch.setattr(manager, 'now', lambda: now + timedelta(hours=2))
    assert try_reuse(runtime, root).reason_code == 'PROVIDER_DATABASE_NOT_FRESH'
    # The fixed-input artifact cache must also keep its existing hit path.
    from security_runtime.explicit_scan import run_explicit_scan
    monkeypatch.setattr(manager, 'now', lambda: now)
    executions = []
    monkeypatch.setattr(adapter, '_scan', lambda *_args: executions.append('scan') or [])
    run_explicit_scan(runtime, root, mode='release')
    cached = run_explicit_scan(runtime, root, mode='release')
    assert executions == ['scan']
    assert cached.scanner_diagnostics['result_reuse']['reused'] is True


def test_unselected_default_providers_do_not_disable_valid_reuse(reusable):
    from security_runtime.dataflow import BoundedDataflowScanner
    from security_runtime.dynamic_function import NativeFunctionScanner
    from security_runtime.go_sql import GoSQLScanner
    runtime, root, *_ = reusable
    runtime.registry.adapters.extend([NativeFunctionScanner(), BoundedDataflowScanner(), GoSQLScanner(),
                                      TrivyAdapter(), TrivyMisconfigAdapter()])
    result = runtime.scan(root, 'release')
    assert any(run.status == 'NOT_APPLICABLE' for run in result.scanner_runs)
    assert result.status == 'COMPLETED' and result.scanner_diagnostics.get('result_reuse')
    assert try_reuse(runtime, root).reused


def test_build_change_requires_new_scan(reusable, monkeypatch):
    from security_runtime.scan_reuse import build_identity
    runtime, root, *_ = reusable
    changed = dict(build_identity(), build_id='f' * 64)
    monkeypatch.setattr('security_runtime.scan_reuse.build_identity', lambda: changed)
    assert try_reuse(runtime, root).reason_code == 'BUILD_RULES_ENGINE_OR_CONFIGURATION_CHANGED'


def test_legacy_current_directory_workspace_is_supported(reusable, monkeypatch):
    runtime, root, *_ = reusable
    monkeypatch.chdir(root)
    assert try_reuse(runtime, None).reused


@pytest.mark.parametrize('outcome', ['COMPLETED', 'FAILED', 'STALE', 'CANCELLED'])
def test_explicit_scan_requires_current_successful_publication(reusable, monkeypatch, outcome):
    from security_runtime.explicit_scan import run_explicit_scan
    from security_runtime.hook_state import HookStateStore
    from security_runtime.scan_attempt import ScanAttemptStore
    runtime, root, *_ = reusable
    hooks = HookStateStore(runtime.store.path.parent / 'explicit-hooks')
    result = run_explicit_scan(runtime, root, mode='release', hooks=hooks)
    assert result.scanner_diagnostics.get('result_reuse')
    state = ScanAttemptStore(hooks, root)
    if outcome != 'COMPLETED':
        # A real signed lane update models a failed/cancelled publication.
        with hooks.lock(root) as acquired:
            assert acquired
            value = state.read()
            value['lane']['state'] = outcome
            state._save(value)
    decision = try_reuse(runtime, root, hooks=hooks)
    assert decision.reused == (outcome == 'COMPLETED')
    if not decision.reused:
        assert decision.reason_code == 'EXECUTION_PUBLICATION_NOT_CURRENT'


def test_source_edit_during_provider_revalidation_is_detected(reusable, monkeypatch):
    runtime, root, path, _, adapter, *_ = reusable
    actual = adapter.tool_manager.execution_identity
    def edit(*args, **kwargs):
        result = actual(*args, **kwargs)
        path.write_text('class ChangedDuringVerification {}')
        return result
    monkeypatch.setattr(adapter.tool_manager, 'execution_identity', edit)
    assert try_reuse(runtime, root).reason_code == 'SOURCE_CHANGED_DURING_VERIFICATION'


def test_read_only_history_summary_still_does_not_claim_revalidation(reusable):
    from security_runtime.scan_freshness import summary
    from security_runtime.storage import ReadOnlySQLiteStore
    runtime, root, *_ = reusable
    scan = runtime.store.latest_scan(root)
    facts = summary(scan, ReadOnlySQLiteStore(runtime.store.path), root)
    assert facts['full_project_reusable'] is False
    assert facts['provider_freshness'] == 'NOT_REVALIDATED_READ_ONLY'


def test_identity_capture_shares_only_duplicate_reads_in_one_operation(tmp_path, monkeypatch):
    from security_runtime.scan_reuse import capture_reuse_identity
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'data.txt').write_text('public fixture')
    manager = ToolManager(tmp_path / 'managed')
    binary = tmp_path / 'trivy.exe'
    binary.write_bytes(b'actual fixture engine bytes')
    database = manager.trivy_cache_dir() / 'db'
    database.mkdir(parents=True)
    (database / 'trivy.db').write_bytes(b'actual fixture database bytes')
    now = datetime.now(timezone.utc)
    (database / 'metadata.json').write_text(json.dumps({
        'UpdatedAt': (now - timedelta(hours=1)).isoformat(),
        'NextUpdate': (now + timedelta(hours=1)).isoformat()}))
    calls = {'resolve': 0, 'engine': 0, 'data': []}
    def resolve(name):
        calls['resolve'] += 1
        return resolved(manager, name, binary)
    engine_identity, data_identity = manager.execution_identity, manager.execution_data_identity
    def engine_reader(*args, **kwargs):
        calls['engine'] += 1
        return engine_identity(*args, **kwargs)
    def data_reader(*args, **kwargs):
        calls['data'].append(kwargs['kind'])
        return data_identity(*args, **kwargs)
    monkeypatch.setattr(manager, 'resolve', resolve)
    monkeypatch.setattr(manager, 'execution_identity', engine_reader)
    monkeypatch.setattr(manager, 'execution_data_identity', data_reader)
    adapters = [TrivyAdapter(manager), TrivyAdapter(manager), TrivyMisconfigAdapter(manager)]
    registry = ScannerRegistry(adapters, fallback_adapters=[])
    first = capture_reuse_identity(registry, root, files=['data.txt'], selected=adapters)
    assert calls == {'resolve': 1, 'engine': 1, 'data': ['misconfig']}
    second = capture_reuse_identity(registry, root, files=['data.txt'], selected=adapters)
    assert calls == {'resolve': 2, 'engine': 2, 'data': ['misconfig'] * 2}
    assert first == second
    before = binary.stat()
    binary.write_bytes(b'changed fixture engine content')
    os.utime(binary, ns=(before.st_atime_ns, before.st_mtime_ns))
    third = capture_reuse_identity(registry, root, files=['data.txt'], selected=adapters)
    assert third['providers'][0]['engine'] != first['providers'][0]['engine']
    assert calls['resolve'] == calls['engine'] == 3


def test_identity_capture_does_not_merge_distinct_complete_environments(tmp_path, monkeypatch):
    from security_runtime.scan_reuse import capture_reuse_identity
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'data.txt').write_text('public fixture')
    manager = ToolManager(tmp_path / 'managed')
    binary = tmp_path / 'gitleaks.exe'
    binary.write_bytes(b'actual fixture engine bytes')
    monkeypatch.setattr(manager, 'resolve', lambda name: resolved(manager, name, binary))
    first, second = GitleaksAdapter(manager), GitleaksAdapter(manager)
    original = second._environment
    monkeypatch.setattr(second, '_environment', lambda *args:
        dict(original(*args), SCANNER_FIXTURE_SEMANTICS='different'))
    registry = ScannerRegistry([first, second], fallback_adapters=[])
    identity = capture_reuse_identity(registry, root, files=['data.txt'], selected=[first, second])
    assert identity['providers'][0]['engine'] != identity['providers'][1]['engine']
