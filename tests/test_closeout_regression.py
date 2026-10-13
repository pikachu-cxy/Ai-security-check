"""Regression contracts. Synthetic engines/events are NOT desktop acceptance."""
import json
from dataclasses import asdict
from pathlib import Path
import subprocess

import pytest

from test_secret_recheck_coverage import secret_engine, original, recheck
from security_runtime.hook_runtime import family_multiset
from security_runtime.hook_user_feedback import rule_delta_message, secret_verification_feedback


def test_duplicate_absence_messages_keep_count_and_mixed_status():
    rows = [dict(file_path='fixture.ts', rule_id=r, status='UNCONFIRMED_ABSENCE')
            for r in ('github-pat', 'generic-api-key')]
    message = rule_delta_message({'delta': {'families': rows}})
    assert message.count('复查结果：') == 1
    assert '2 条' in message
    rows[0]['status'] = 'RESOLVED_FAMILY'
    assert rule_delta_message({'delta': {'families': rows}}).count('复查结果：') == 2


def test_trace_skip_diagnostics_distinguish_types():
    from security_runtime.secret_coverage import trace_summary, trace_complete
    log = ('TRC scanning path path=other.ts\nINF scanned ~10 bytes\n'
           'TRC skipping file: permission denied\n'
           'TRC skipping rule rule-id=github-pat\n'
           'TRC skipping finding due to allowlist\n')
    summary = trace_summary(log, {'other.ts': 10})
    assert summary['skip_kinds'] == {'FILE': 1, 'RULE': 1, 'FINDING': 1, 'UNKNOWN': 0}
    assert not trace_complete(log, {'other.ts': 10})


def test_independent_proof_updates_only_its_rule_and_invalidates_on_edit(secret_engine, tmp_path):
    from security_runtime.risk_closure import RiskClosureService
    from security_runtime.hook_state import HookStateStore
    findings, run = original(secret_engine)
    root, path, _, _, _ = secret_engine
    family = family_multiset(findings, [run], {})
    hooks = HookStateStore(tmp_path / 'hooks')
    service = RiskClosureService(hooks)
    path.write_text('// comments retained\n', encoding='utf-8')
    results = recheck(secret_engine, findings[:1], run)
    service.record(root, [asdict(findings[0])], results, source='MANUAL_INDEPENDENT_RECHECK')
    updated, delta = service.overlay(root, family, {'families': []})
    assert len(updated) == 1
    assert sum(r['status'] == 'RESOLVED_FAMILY' for r in delta['families']) == 1
    assert findings[1].equivalence_key in updated
    path.write_text('// next content version\n', encoding='utf-8')
    updated, delta = service.overlay(root, updated, delta)
    assert len(updated) == 2
    assert all(r['status'] != 'RESOLVED_FAMILY' for r in delta['families'])


def test_closeout_state_receipt_cas_and_reconnect(tmp_path):
    from security_runtime.closeout_state import CloseoutStateStore
    key = b'k' * 32
    store = CloseoutStateStore(tmp_path / 'closeout.db', lambda: key)
    job = store.prepare('workspace', ['fixture.ts'], 'v1', 'plan')
    assert store.prepare('workspace', ['fixture.ts'], 'v1', 'plan')['closeout_ref'] == job['closeout_ref']
    running, owner = store.claim(job['closeout_ref'], 'workspace', 'v1', 'plan')
    assert store.claim(job['closeout_ref'], 'workspace', 'v1', 'plan')[1] is None
    store.mark_pending(job['closeout_ref'], 'workspace')
    _, saved = store.finish(job['closeout_ref'], 'workspace', running['generation'], owner,
                          status='COMPLETED', coverage='FULL', receipt={'version': 'v1'})
    assert not saved
    reopened = CloseoutStateStore(store.path, lambda: key)
    assert reopened.get(job['closeout_ref'], 'workspace')['status'] == 'PENDING'


def closeout_fixture(secret_engine, tmp_path):
    import os
    from security_runtime.closeout import CloseoutService
    from security_runtime.hook_runtime import HookSnapshot, capture_snapshot
    from security_runtime.hook_state import HookStateStore, identity
    from security_runtime.runtime import SecurityRuntime
    from security_runtime.scanners import ScannerRegistry
    from security_runtime.storage import SQLiteStore
    root, path, adapter, state, _ = secret_engine
    subprocess.run(['git', 'init', str(root)], check=True, capture_output=True)
    findings, run = original(secret_engine)
    runtime = SecurityRuntime(ScannerRegistry([adapter]), SQLiteStore(tmp_path / 'state' / 'runtime.db'))
    scan = runtime.scan(root, _hook_scope=['fixture.ts'])
    hooks = HookStateStore(tmp_path / 'hooks')
    capture = capture_snapshot(root, hooks.key(root))
    families = family_multiset(findings, [run], {})
    delta = {'new': 0, 'persisting': 2, 'resolved': 0, 'additional_occurrences': 0,
        'removed_occurrences': 0, 'families': [{k: f[k] for k in
        ('equivalence_key', 'file_path', 'rule_id', 'category')} | {
        'status': 'PERSISTING', 'previous_count': 1, 'current_count': 1, 'occurrence_delta': 0,
        'count_certainty': 'COMPLETE_RULE_FILE_SCOPE'} for f in families.values()]}
    summary = dict(status='SCANNED', last_check_status='SCANNED', coverage='SCOPED',
                   execution_state='EXECUTED', capabilities={}, scanner_runs=[], delta=delta)
    snapshot = HookSnapshot('hook-v1', identity(os.path.normcase(str(root))), 'codex', identity('session'),
                            capture[0], capture[1], families, scan.scan_id, 0, summary, capture.file_digests)
    hooks.save(hooks.path(root, 'codex', 'session'), asdict(snapshot))
    path.write_text('// explanation one\n// explanation two\n', encoding='utf-8')
    return CloseoutService(runtime, hooks), findings, run


@pytest.mark.parametrize('unfinished', [False, True])
def test_automatic_closeout_uses_last_actual_scope_and_preserves_unfinished_inputs(
        secret_engine, tmp_path, unfinished):
    from security_runtime.hook_runtime import capture_snapshot
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root, path, _, _, _ = secret_engine
    for index in range(24):
        (root / f'unchanged{index}.ts').write_text('// previously staged fixture\n')
    subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
    captured = capture_snapshot(root, service.hooks.key(root))
    state_path = service.hooks.path(root, 'codex', 'session')
    state, _ = service.hooks.load(state_path)
    state.update(file_digests=captured.file_digests, change_digest=captured[0], changed_files=captured[1])
    if unfinished:
        state['last_result']['status'] = 'PARTIAL'
    service.hooks.save(state_path, state)
    path.write_text('// new safe fixture content\n')
    job = service.prepare(root, host='codex', session='session', source='HOOK_SCHEDULED_CLOSEOUT')
    assert len(job['original_recheck_scope']) == 2
    if unfinished:
        assert len(job['scope_files']) == 25
    else:
        assert job['scope_files'] == ['fixture.ts']


def test_other_batch_file_skip_gets_original_file_proof_and_readonly_converges(secret_engine, tmp_path, monkeypatch):
    from security_runtime.hook_runtime import HookCoordinator
    from security_runtime.hooks import HookEvent
    from security_runtime import scanners
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root, _, _, state, _ = secret_engine
    (root / 'other.ts').write_text('// other file\n', encoding='utf-8')
    execute = scanners._execute
    def skip_other(argv, cwd, timeout):
        target = Path(argv[2])
        state['skip'] = len(list(target.rglob('*'))) > 1
        return execute(argv, cwd, timeout)
    monkeypatch.setattr(scanners, '_execute', skip_other)
    service.hooks.pending_activity(root, 'codex', 'session', mark=True)
    job = service.prepare(root, ['fixture.ts', 'other.ts'], host='codex', session='session', source='HOOK_SCHEDULED_CLOSEOUT')
    result = service.run(job['closeout_ref'], root)
    assert result['status'] == 'COMPLETED', result
    assert result['receipt']['risk_fix_complete']
    assert all(r['verification_status'] == 'SCANNER_VERIFIED_RESOLVED' for r in result['receipt']['risk_verification'])
    assert len(result['receipt']['risk_verification']) == 2
    scan = service.runtime.store.get_scan(result['receipt']['scan_id'])
    batch = next(r for r in scan['scanner_runs'] if r['scanner'] == 'gitleaks')
    assert batch['scanner_diagnostics']['secret_coverage']['status'] == 'UNPROVEN'
    hook_state, _ = service.hooks.load(service.hooks.path(root, 'codex', 'session'))
    assert not hook_state['families']
    assert 'UNCONFIRMED_ABSENCE' not in json.dumps(hook_state['last_result'])
    count = state['calls']
    assert service.run(job['closeout_ref'], root)['reused']
    assert state['calls'] == count
    # Synthetic reconciliation only, never reported as real desktop acceptance.
    coordinator = HookCoordinator(service.runtime, service.hooks, cooldown_ms=0)
    checked = coordinator.handle(HookEvent.FILE_CHANGED, root, 'codex', 'session')
    readonly = coordinator.handle(HookEvent.FILE_CHANGED, root, 'codex', 'session')
    assert 'UNCONFIRMED_ABSENCE' not in json.dumps(readonly['delta'])


@pytest.mark.parametrize('change', ['skip', 'rules', 'legacy', 'custom_config'])
def test_closeout_missing_original_proof_remains_unconfirmed(secret_engine, tmp_path, change):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root, _, _, state, _ = secret_engine
    if change == 'skip': state['skip'] = True
    elif change == 'rules': state['rules'] = ()
    elif change == 'custom_config': (root / '.gitleaks.toml').write_text('[extend]\nuseDefault=true\n')
    else:
        snapshot, _ = service.hooks.load(service.hooks.path(root, 'codex', 'session'))
        for f in snapshot['families'].values(): f['proof'].update(engine='', rule_version='', rule_pack_checksum='', rule_versions={})
        service.hooks.save(service.hooks.path(root, 'codex', 'session'), snapshot)
    job = service.prepare(root, ['fixture.ts'], host='codex', session='session')
    result = service.run(job['closeout_ref'], root)
    assert result['status'] == 'COMPLETED', result
    assert not result['receipt']['risk_fix_complete']
    snapshot, _ = service.hooks.load(service.hooks.path(root, 'codex', 'session'))
    assert len(snapshot['families']) == 2


def test_new_edit_during_closeout_keeps_new_generation_and_intent(secret_engine, tmp_path, monkeypatch):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root, path, _, _, _ = secret_engine
    job = service.prepare(root, ['fixture.ts'], host='codex', session='session')
    from security_runtime.verification import VerificationService
    verify = VerificationService.verify_many
    def new_arrival(self, *args):
        results = verify(self, *args)
        path.write_text('// next edit\n')
        service.hooks.pending_activity(root, 'codex', 'session', mark=True)
        service._store(root).mark_pending(job['closeout_ref'], service._workspace(root))
        return results
    monkeypatch.setattr(VerificationService, 'verify_many', new_arrival)
    result = service.run(job['closeout_ref'], root)
    assert result['status'] == 'PENDING'
    assert result['generation'] > job['generation']
    assert not result['execution_accepted']
    assert service.hooks.pending_activity(root, 'codex', 'session')
    assert not service.closures._read(root)


@pytest.mark.parametrize('arrival', ['edit', 'event', 'config'])
def test_arrival_at_proof_persistence_cannot_report_closed(secret_engine, tmp_path, monkeypatch, arrival):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root, path, _, _, _ = secret_engine
    job = service.prepare(root, ['fixture.ts'], host='codex', session='session')
    record = service.closures.record
    def arrive(*args, **kwargs):
        if arrival == 'edit':
            path.write_text('// changed while saving proof\n', encoding='utf-8')
        elif arrival == 'config':
            (root / '.gitleaksignore').write_text('# protection changed\n', encoding='utf-8')
        service.hooks.pending_activity(root, 'codex', 'session', mark=True)
        return record(*args, **kwargs)
    monkeypatch.setattr(service.closures, 'record', arrive)
    result = service.run(job['closeout_ref'], root)
    assert result['status'] == 'NEEDS_RETRY'
    assert not result['execution_accepted']
    assert not result['receipt']['credential_closure_complete']
    assert '检查未完成' in result['user_feedback']['message']
    assert len(result['pending_recheck']) == 2
    assert service.hooks.pending_activity(root, 'codex', 'session')
    assert not service.closures._read(root)


def test_stop_budget_reconnect_busy_and_partial_code_coverage(secret_engine, tmp_path):
    from security_runtime.closeout import CloseoutService
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    job = service.prepare(root, host='codex', session='session')
    first = service.stop(root, 'codex', 'session', False)
    second = service.stop(root, 'codex', 'session', False)
    assert first['closeout_ref'] == second['closeout_ref'] == job['closeout_ref']
    assert 'decision' not in first and 'systemMessage' not in first
    assert 'decision' not in service.stop(root, 'codex', 'session', False)
    assert 'decision' not in service.stop(root, 'codex', 'session', True)
    ref = job['closeout_ref']
    with service.hooks.lock(root) as acquired:
        assert acquired
        assert service.run(ref, root)['status'] == 'BUSY'
    reopened = CloseoutService(service.runtime, service.hooks)
    result = reopened.run(ref, root)
    assert result['status'] == 'COMPLETED', result
    assert result['coverage'] in {'PARTIAL', 'SCOPED'}
    assert result['receipt']['risk_fix_complete']
    assert 'decision' not in reopened.stop(root, 'codex', 'session', False)


def test_closeout_stop_is_quiet_and_does_not_prepare_or_dispatch(secret_engine, tmp_path, monkeypatch):
    """An ordinary chat end is neither a scan request nor a continuation."""
    from security_runtime.codex_mcp_hook import codex_hook_output
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    monkeypatch.setattr(service, 'prepare', lambda *a, **k: pytest.fail('Stop must not create a plan'))
    monkeypatch.setattr(service, '_present', lambda *a, **k: pytest.fail('Stop must not recapture source'))
    for active in [False, True] * 5:
        result = service.stop(root, 'codex', 'session', active)
        assert codex_hook_output(result) == {}
        assert result['scanner_run'] is False


def test_budget_exhaustion_retains_job_without_unlimited_execution(secret_engine, tmp_path):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    job = service.prepare(root, ['fixture.ts'], host='codex', session='session')
    secret_engine[3]['failed'] = True
    for _ in range(3):
        assert service.run(job['closeout_ref'], root)['status'] == 'NEEDS_RETRY'
    count = secret_engine[3]['calls']
    exhausted = service.run(job['closeout_ref'], root)
    assert exhausted['reason'] == 'CLOSEOUT_BUDGET_EXHAUSTED'
    assert secret_engine[3]['calls'] == count


def test_one_provider_proof_never_closes_another_provider(secret_engine, tmp_path):
    from security_runtime.risk_closure import original_family
    service, findings, run = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    originals = [asdict(f) for f in findings]
    originals[1]['scanner_sources'] = ['other-secret-detector']
    rows = recheck(secret_engine, findings, run)
    assert service.closures.record(root, originals, rows, source='MANUAL_INDEPENDENT_RECHECK')['confirmed'] == 1
    families = {original_family(f)['equivalence_key']: original_family(f) for f in originals}
    current, _ = service.closures.overlay(root, families, {'families': []})
    assert len(current) == 1 and next(iter(current.values()))['scanner_sources'] == ['other-secret-detector']


def test_manual_recheck_updates_summary_without_rewriting_scan(secret_engine, tmp_path):
    from security_runtime.security_summary import SecuritySummaryService
    from security_runtime.task_fix import TaskFixService
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    before = service.runtime.store.latest_scan(root)
    summary = SecuritySummaryService(service.runtime.store, hooks=service.hooks).get(root, details=True)
    tasks = [t for t in summary['tasks'] if t['topic'] == 'secret']
    assert len(tasks) == 2
    fixer = TaskFixService(service.runtime.store, service.runtime.registry, hooks=service.hooks)
    result = fixer.verify(tasks[0]['task_ref'], root)
    assert result['persistent_closure']['confirmed'] == 1
    after = SecuritySummaryService(service.runtime.store, hooks=service.hooks).get(root, before['scan_id'], details=True)
    assert sum(t['current_closure'] == 'CONFIRMED_CLOSED' for t in after['tasks'] if t['topic'] == 'secret') == 1
    assert service.runtime.store.get_scan(before['scan_id']) == before


def test_status_read_does_not_recreate_missing_key(secret_engine, tmp_path):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    job = service.prepare(root, ['fixture.ts'])
    key = service.hooks.workspace_directory(root) / 'snapshot.key'
    key.unlink()
    with pytest.raises((ValueError, OSError)):
        service.get(job['closeout_ref'], root)
    assert not key.exists()


def test_arrival_after_independent_scan_prevents_persistent_closure(secret_engine, tmp_path):
    service, findings, run = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    epoch = service.closures.generation(root)
    results = recheck(secret_engine, findings, run)
    service.hooks.pending_activity(root, 'codex', 'session', mark=True)
    saved = service.closures.record(root, [asdict(f) for f in findings], results,
        source='MANUAL_INDEPENDENT_RECHECK', expected_activity=epoch)
    assert saved['status'] == 'NEW_ACTIVITY' and not saved['confirmed']
    assert not service.closures._read(root)


def test_persistence_failure_is_retryable_not_reported_complete(secret_engine, tmp_path, monkeypatch):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    job = service.prepare(root, ['fixture.ts'], host='codex', session='session')
    assert len(job['pending_recheck']) == 2
    def unavailable(*args, **kwargs):
        raise OSError('simulated persistence failure')
    monkeypatch.setattr(service.closures, 'record', unavailable)
    result = service.run(job['closeout_ref'], root)
    assert result['status'] == 'NEEDS_RETRY'
    assert result['reason'] == 'CLOSURE_PERSISTENCE_INCOMPLETE'


def test_status_session_read_never_creates_pending_database(secret_engine, tmp_path):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    job = service.prepare(root, ['fixture.ts'], host='codex', session='session')
    pending = service.hooks.workspace_directory(root) / 'pending-activity.db'
    assert not pending.exists()
    before = {p.name: p.read_bytes() for p in pending.parent.iterdir() if p.is_file()}
    service.get(job['closeout_ref'], root)
    assert {p.name: p.read_bytes() for p in pending.parent.iterdir() if p.is_file()} == before


def test_deferred_provider_survives_no_change_and_clears_only_after_execution(secret_engine, tmp_path, monkeypatch):
    from security_runtime.hook_runtime import HookCoordinator, capture_snapshot
    from security_runtime.hooks import HookEvent
    from security_runtime.models import ScannerRun
    from security_runtime.scanners import SemgrepAdapter
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    state_path = service.hooks.path(root, 'codex', 'session')
    snapshot, _ = service.hooks.load(state_path)
    capture = capture_snapshot(root, service.hooks.key(root))
    snapshot.update(change_digest=capture[0], file_digests=capture.file_digests)
    snapshot['last_result']['deferred_code_providers'] = ['semgrep']
    service.hooks.save(state_path, snapshot)
    coordinator = HookCoordinator(service.runtime, service.hooks, cooldown_ms=0)
    assert coordinator.handle(HookEvent.FILE_CHANGED, root, 'codex', 'session')['status'] == 'CLOSEOUT_PENDING'
    job = service.prepare(root, ['fixture.ts'], host='codex', session='session')
    stored = service._store(root).get(job['closeout_ref'], service._workspace(root))
    assert stored['deferred_providers'] == ['semgrep']
    assert service.run(job['closeout_ref'], root)['status'] == 'NEEDS_RETRY'
    snapshot, _ = service.hooks.load(state_path)
    assert snapshot['last_result']['deferred_code_providers'] == ['semgrep']
    adapter = SemgrepAdapter()
    monkeypatch.setattr(adapter, 'supports', lambda *args: True)
    monkeypatch.setattr(adapter, 'scan', lambda *args: ([], ScannerRun('semgrep', 'test', 'SUCCESS', 1,
        capabilities=('CODE_SAST',), provider='semgrep')))
    service.runtime.registry.adapters.append(adapter)
    assert service.run(job['closeout_ref'], root)['status'] == 'COMPLETED'
    snapshot, _ = service.hooks.load(state_path)
    assert snapshot['last_result']['deferred_code_providers'] == []


def test_extended_state_path_stays_readonly(tmp_path):
    import os
    import sqlite3
    from security_runtime.closeout_state import readonly_uri
    from security_runtime.hook_state import native_io_path
    if os.name != 'nt':
        pytest.skip('Windows extended path contract')
    path = native_io_path(tmp_path / ('a' * 65) / ('b' * 65) / ('c' * 65) / 'state #1.db')
    path.parent.mkdir(parents=True)
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE fixture(value)')
    before = path.read_bytes()
    with sqlite3.connect(readonly_uri(path), uri=True) as db:
        assert db.execute('SELECT count(*) FROM fixture').fetchone()[0] == 0
        with pytest.raises(sqlite3.OperationalError):
            db.execute('INSERT INTO fixture VALUES(1)')
    assert path.read_bytes() == before


def test_expired_closure_preserves_current_positive_detection(secret_engine, tmp_path):
    from security_runtime.risk_closure import RiskClosureService
    from security_runtime.hook_state import HookStateStore
    findings, run = original(secret_engine)
    root, path, _, _, _ = secret_engine
    text = path.read_text(encoding='utf-8')
    service = RiskClosureService(HookStateStore(tmp_path / 'hooks'))
    path.write_text('// removed fixture\n', encoding='utf-8')
    service.record(root, [asdict(f) for f in findings], recheck(secret_engine, findings, run),
                   source='MANUAL_INDEPENDENT_RECHECK')
    path.write_text(text, encoding='utf-8')
    current, observed = original(secret_engine)
    families = family_multiset(current, [observed], {})
    rows = [{k: f[k] for k in ('equivalence_key', 'file_path', 'rule_id', 'category')} | {
        'status': 'PERSISTING', 'previous_count': 1, 'current_count': 1, 'occurrence_delta': 0,
        'count_certainty': 'COMPLETE_RULE_FILE_SCOPE'} for f in families.values()]
    retained, delta = service.overlay(root, families, {'families': rows})
    assert len(retained) == 2
    assert all(r['status'] == 'PERSISTING' and r['current_count'] == 1 for r in delta['families'])


@pytest.mark.parametrize('environment_path', ['.env', '.env.local', 'config/.env.production'])
def test_automatic_closeout_records_environment_exclusions_without_blocking(secret_engine, tmp_path, environment_path):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    environment = root / environment_path
    environment.parent.mkdir(exist_ok=True)
    environment.write_text('PUBLIC_FIXTURE_ONLY=example\n', encoding='utf-8')
    job = service.prepare(root, host='codex', session='session')
    assert 'decision' not in service.stop(root, 'codex', 'session', False)
    assert environment_path not in job['scope_files']
    assert job['scope_exclusions'] == [{'file_path': environment_path,
                                       'reason': 'ENVIRONMENT_FILE_OUTSIDE_CLOSEOUT_SCOPE'}]
    result = service.run(job['closeout_ref'], root)
    assert result['status'] == 'COMPLETED', result
    assert result['coverage'] == 'PARTIAL'
    assert not result['receipt']['risk_fix_complete']
    assert not result['receipt']['credential_closure_complete']
    assert environment_path in result['user_feedback']['message']
    assert environment.read_text(encoding='utf-8') == 'PUBLIC_FIXTURE_ONLY=example\n'
    repeated = service.stop(root, 'codex', 'session', False)
    assert repeated['status'] == 'ALLOW_STOP'
    assert repeated['closeout_ref'] == job['closeout_ref']


def test_excluded_environment_finding_keeps_original_risk_unconfirmed(secret_engine, tmp_path, monkeypatch):
    from security_runtime.risk_closure import original_family
    from security_runtime.verification import VerificationService
    service, findings, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    (root / '.env').write_text('PUBLIC_FIXTURE_ONLY=example\n', encoding='utf-8')
    state_path = service.hooks.path(root, 'codex', 'session')
    snapshot, _ = service.hooks.load(state_path)
    excluded = original_family(asdict(findings[0]) | {'file_path': '.env'})
    snapshot['families'][excluded['equivalence_key']] = excluded
    service.hooks.save(state_path, snapshot)
    original_verify = VerificationService.verify_many
    def eligible_only(self, workspace, members, context):
        assert all(m['file_path'] != '.env' for m in members)
        return original_verify(self, workspace, members, context)
    monkeypatch.setattr(VerificationService, 'verify_many', eligible_only)
    job = service.prepare(root, host='codex', session='session', source='HOOK_SCHEDULED_CLOSEOUT')
    result = service.run(job['closeout_ref'], root)
    assert result['status'] == 'COMPLETED', result
    assert result['risk_status'] == 'UNCONFIRMED_OR_PRESENT'
    assert any(row['file_path'] == '.env' and row['rule_id'] == excluded['rule_id']
               for row in result['pending_recheck'])
    persisted, _ = service.hooks.load(state_path)
    remaining, _ = service.closures.overlay(root, persisted['families'], persisted['last_result']['delta'])
    assert excluded['equivalence_key'] in remaining
    assert not result['receipt']['credential_closure_complete']


def test_explicit_environment_closeout_remains_rejected(secret_engine, tmp_path):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    (root / '.env').write_text('PUBLIC_FIXTURE_ONLY=example\n', encoding='utf-8')
    with pytest.raises(ValueError, match='Environment files are outside this closeout request'):
        service.prepare(root, ['.env'])
    assert not service._store(root).path.exists()
