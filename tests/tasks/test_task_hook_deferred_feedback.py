"""Real edit revisions + durable scanner/episode records, deferred presentation."""
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from security_runtime.codex_mcp_hook import codex_hook_output, handle_codex_hook
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.remediation import RemediationService
from security_runtime.remediation_policy import RULE
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.security_state import TaskSecurityStore
from test_codex_mcp_hook import binding
from test_hook_runtime import coordinator, dirty, FakeRuntime, repo, row
from test_remediation import FIXED, UNSAFE, SavedRuntime
from test_task_fix import LocalProvider


@pytest.fixture
def development(repo, tmp_path):
    store = SQLiteStore(tmp_path / 'scans/scans.db')
    runtime = SavedRuntime(store)
    hooks = HookStateStore(tmp_path / 'hooks')
    core = HookCoordinator(runtime, hooks, clock=lambda: 1000)
    provider = LocalProvider()
    original = provider.scan
    def same_version(*args):
        found, run = original(*args)
        run.version = '1.178.0'
        return found, run
    provider.scan = same_version
    remediation = RemediationService(store, registry=ScannerRegistry([provider]), hooks=hooks)
    def hook():
        return handle_codex_hook('PostToolUse', str(repo), 'session', 'apply_patch',
            binding=binding(repo), coordinator=core, remediation=remediation)
    (repo / 'A.java').write_text(FIXED)
    assert hook()['status'] == 'BASELINE_ESTABLISHED'
    task = TaskSecurityService(runtime, hooks)
    ref = task.begin(repo, 'normal-development')['task_ref']
    return repo, runtime, provider, remediation, core, hook, task, ref


def introduce_risk(sample):
    root, runtime, provider, *_ = sample
    finding = row(root, 6, RULE, category='trust-all-tls')
    finding.technical_details.update(rule_pack='ai-security-core', rule_pack_checksum='a'*64,
        rule_pack_version='0.1', engine='semgrep')
    runtime.findings = provider.findings = [finding]
    (root / 'A.java').write_text(UNSAFE)
    return sample[5]()


def ledger(sample):
    return TaskSecurityStore(sample[4].store, sample[0]).get(sample[-1])


def test_risky_edit_runs_and_persists_without_prompting_or_granting_repair(development):
    root, runtime, _, service, core, _, _, ref = development
    result = introduce_risk(development)
    assert result['scanner_run'] and result['new_families'] == 1
    assert runtime.calls == [('A.java',), ('A.java',)]
    assert runtime.store.get_scan(result['scan_id'])['findings']
    episodes = service._read(service.state.path(root, 'codex', 'session'), service.state.key(root))
    assert next(iter(episodes.values()))['phase'] == 'PENDING_CONFIRMATION'
    assert not service.authorized and not service.prepared
    assert result['remediation']['action'] == 'CONFIRM_REQUIRED'
    assert result['continue'] is True and not {'systemMessage', 'stopReason'} & result.keys()
    context = codex_hook_output(result)['hookSpecificOutput']['additionalContext']
    assert '任务结束时' in context and '没有授予修复权限' in context
    assert context.startswith('任务内检查记录') and '用户提示' not in context
    assert '仍需说明风险并询问选择' not in context
    assert 'CONFIRM_REQUIRED' not in context and result['remediation']['confirmation_ref'] not in context
    record = ledger(development)
    assert record['hook_recheck_files'] == ['A.java']
    assert record['hook_checks'][0]['scan_id'] == result['scan_id']
    persisted = json.dumps(record)
    assert result['remediation']['confirmation_ref'] not in persisted
    assert UNSAFE not in persisted


def test_rapid_actual_mutations_each_scan_but_no_op_and_read_only_do_not(development):
    root, runtime, _, _, core, hook, _, _ = development
    introduce_risk(development)
    for index in range(3):
        (root / 'A.java').write_text(UNSAFE + f'// revision {index}\n')
        result = hook()
        assert result['scanner_run'] and not result['debounced']
        assert result['task_edit_check_policy'] == 'EVERY_OBSERVED_MUTATION'
    assert len(runtime.calls) == 5  # one baseline, four actual edit checks
    count = len(ledger(development)['hook_checks'])
    unchanged = hook()
    assert not unchanged['scanner_run'] and codex_hook_output(unchanged) == {}
    read_only = handle_codex_hook('PostToolUse', str(root), 'session', 'Bash', {'command':'git status'},
        binding=binding(root), coordinator=core)
    assert not read_only['scanner_run'] and codex_hook_output(read_only) == {}
    assert len(runtime.calls) == 5 and len(ledger(development)['hook_checks']) == count


def test_outside_task_preserves_legacy_cooldown_and_risk_choice(development):
    root, runtime, _, _, _, hook, task, ref = development
    task.skip(root, ref, 'Fixture explicitly ends the task.')
    # The fixture clock does not move: outside a registered task the legacy
    # cooldown applies and its skipped scan is accurately reported.
    (root / 'A.java').write_text(FIXED + '// outside edit\n')
    result = hook()
    assert result['debounced'] and not result['scanner_run'] and len(runtime.calls) == 1
    # A fresh coordinator with the same persisted comparison point checks the
    # change and retains the ordinary per-edit choice behavior outside tasks.
    core = HookCoordinator(runtime, development[4].store, cooldown_ms=0)
    risk = row(root, 6, RULE, category='trust-all-tls')
    risk.technical_details.update(rule_pack='ai-security-core', rule_pack_checksum='a'*64,
        rule_pack_version='0.1', engine='semgrep')
    runtime.findings = development[2].findings = [risk]
    (root / 'A.java').write_text(UNSAFE)
    result = handle_codex_hook('PostToolUse', str(root), 'session', 'apply_patch', binding=binding(root),
        coordinator=core, remediation=development[3])
    assert result['remediation']['action'] == 'CONFIRM_REQUIRED'
    assert result['continue'] is False and result['systemMessage']


def test_transient_risk_is_history_and_verified_absence_clears_recheck_scope(development):
    risk = introduce_risk(development)
    root, runtime, provider, *_ = development
    (root / 'A.java').write_text(FIXED)
    runtime.findings = provider.findings = []
    resolved = development[5]()
    record = ledger(development)
    assert resolved['resolved_families'] == 1
    assert record['hook_recheck_files'] == [] and record['hook_pending_scope_files'] == []
    assert len(record['hook_checks']) == 2
    assert record['hook_checks'][0]['delta']['new'] == 1
    assert record['hook_checks'][1]['delta']['resolved'] == 1
    assert runtime.store.get_scan(risk['scan_id'])['findings']  # historical record retained


def test_failed_recheck_retains_unresolved_path_and_missing_check(development):
    introduce_risk(development)
    root, runtime, provider, *_ = development
    (root / 'A.java').write_text(FIXED)
    runtime.findings = provider.findings = []
    runtime.status = 'FAILED'
    result = development[5]()
    record = ledger(development)
    assert result['resolved_families'] == 0 and result['status'] == 'PARTIAL'
    assert record['hook_recheck_files'] == ['A.java']
    assert record['hook_pending_scope_files'] == ['A.java']
    assert record['hook_checks'][-1]['capabilities']['CODE_SAST'] == 'FAILED'
    assert not {'systemMessage', 'stopReason'} & result.keys()


def test_unapproved_transient_issue_verification_stays_in_task_summary(development):
    root, runtime, provider, service, _, hook, *_ = development
    service.config.write('report_only')
    introduce_risk(development)
    (root / 'A.java').write_text(FIXED)
    runtime.findings = provider.findings = []
    result = hook()
    assert result['resolved_families'] == 1
    assert result['remediation']['action'] == 'NONE'
    assert result['continue'] is True and not {'systemMessage', 'stopReason'} & result.keys()
    assert not service.authorized and ledger(development)['hook_recheck_files'] == []


def test_dependency_advice_and_preparation_warning_are_deferred_but_facts_persist(repo, tmp_path, monkeypatch):
    from test_quick_dependency_runtime import runtime as dependency_runtime
    engine, dependency, _, _ = dependency_runtime(tmp_path, dependency_coverage='PARTIAL', issue=True)
    original = dependency.scan
    def stale_data(context, normalizer):
        found, run = original(context, normalizer)
        run.dependency_inventory['vulnerability_db_freshness'] = 'STALE'
        return found, run
    dependency.scan = stale_data
    monkeypatch.setattr('security_runtime.background_preparation.current_preparation',
        lambda: {'status':'PREPARING', 'ready':False})
    core = HookCoordinator(engine, HookStateStore(tmp_path/'hooks'))
    core.handle('SESSION_START', repo, 'codex', 'session', _lifecycle=True)
    ref = TaskSecurityService(engine, core.store).begin(repo, 'dependency-change')['task_ref']
    (repo/'requirements.txt').write_text('fixture-vulnerable-package==1.0\n')
    result = handle_codex_hook('PostToolUse', str(repo), 'session', 'apply_patch',
        binding=binding(repo), coordinator=core)
    assert result['scanner_run'] and len(dependency.calls) == 1, result
    assert engine.store.get_scan(result['scan_id'])['findings']
    assert result['remediation']['action'] == 'ADVISE'
    assert result['dependency_check_reason'] == 'VULNERABILITY_DB_STALE'
    assert result['background_preparation']['status'] == 'PREPARING'
    assert result['continue'] is True and not {'systemMessage', 'stopReason'} & result.keys()
    context = result['hookSpecificOutput']['additionalContext']
    assert '回复“修复”' not in context and '回复“忽略”' not in context
    assert '扫描能力正在后台准备' not in context
    record = TaskSecurityStore(core.store, repo).get(ref)
    assert record['hook_recheck_files'] == ['requirements.txt']
    assert record['hook_pending_scope_files'] == ['requirements.txt']
    assert record['hook_checks'][-1]['dependency_check_reason'] == 'VULNERABILITY_DB_STALE'


def test_retained_existing_risk_outside_current_task_diff_keeps_recheck_scope(development):
    root, runtime, provider, _, _, hook, task, ref = development
    # The risk file was already dirty before this task's actual edits. The
    # ordinary Hook still rechecks it when later editing another file.
    task.skip(root, ref, 'Fixture resets only the task boundary.')
    (root / 'A.java').write_text(UNSAFE)
    ref = task.begin(root, 'edit-another-file')['task_ref']
    finding = row(root, 6, RULE, category='trust-all-tls')
    finding.technical_details.update(rule_pack='ai-security-core', rule_pack_checksum='a'*64,
        rule_pack_version='0.1', engine='semgrep')
    runtime.findings = provider.findings = [finding]
    (root / 'Other.java').write_text('class Other {}\n')
    result = hook()
    assert runtime.calls[-1] == ('A.java', 'Other.java')
    record = TaskSecurityStore(development[4].store, root).get(ref)
    assert record['hook_recheck_files'] == ['A.java']
    assert result['scanner_run'] and not {'systemMessage', 'stopReason'} & result.keys()


def test_scanner_exception_is_recorded_as_unfinished_without_user_interruption(development, monkeypatch):
    root, runtime, _, _, _, hook, *_ = development
    monkeypatch.setattr(runtime, 'scan', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('fixture private text')))
    (root / 'A.java').write_text(FIXED + '// next version\n')
    result = hook()
    assert result['status'] == 'INCONCLUSIVE' and not result['scanner_run']
    assert codex_hook_output(result) == {}
    assert ledger(development)['hook_checks'][-1]['status'] == 'INCONCLUSIVE'
    assert 'fixture private text' not in json.dumps(result)


def test_explicit_approved_repair_and_verification_survive_task_deferral(development):
    result = introduce_risk(development)
    root, runtime, provider, service, _, hook, *_ = development
    pending = result['remediation']
    approved = service.confirm(pending['confirmation_ref'], pending['task_ref'], root, approve=True)
    assert approved['authorization_kind'] == 'USER_CONFIRMED'
    args = approved['prepare']['arguments']
    assert service.prepare(args['remediation_ref'], args['task_ref'], root)['status'] == 'READY_FOR_HOST_FIX'
    (root / 'A.java').write_text(UNSAFE + '// first approved attempt\n')
    retry = hook()
    assert retry['remediation']['action'] == 'AUTO_FIX'
    assert retry['continue'] is False and retry['systemMessage']
    assert retry['remediation']['prepare']['arguments']['remediation_ref'] in (
        retry['hookSpecificOutput']['additionalContext'])
    args = retry['remediation']['prepare']['arguments']
    assert service.prepare(args['remediation_ref'], args['task_ref'], root)['status'] == 'READY_FOR_HOST_FIX'
    (root / 'A.java').write_text(FIXED)
    runtime.findings = provider.findings = []
    verified = hook()
    assert verified['remediation']['reason_code'] == 'SCANNER_VERIFIED_RESOLVED'
    assert verified['remediation']['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert '原规则的重新检查' in verified['systemMessage']
    assert 'functional_verification_offer' not in verified['remediation']
    assert '执行功能验证' not in verified['systemMessage']


def test_ledger_limit_keeps_recent_observations_and_discloses_omissions(repo, tmp_path, monkeypatch):
    monkeypatch.setattr('security_runtime.codex_mcp_hook.MAX_TASK_HOOK_CHECKS', 2)
    runtime = FakeRuntime()
    core = coordinator(tmp_path, runtime, clock=lambda: 1000)
    core.handle('SESSION_START', repo, 'codex', 'session')
    task = TaskSecurityService(runtime, core.store)
    ref = task.begin(repo, 'rapid-development')['task_ref']
    for index in range(3):
        dirty(repo, f'class A {{ int value = {index}; }}\n')
        result = handle_codex_hook('PostToolUse', str(repo), 'session', 'apply_patch',
            binding=binding(repo), coordinator=core)
        assert result['scanner_run']
    record = TaskSecurityStore(core.store, repo).get(ref)
    assert len(record['hook_checks']) == 2 and record['hook_checks_omitted'] == 1
    assert record['hook_checks'][-1]['scan_id'] == result['scan_id']


def test_task_ledger_save_failure_has_independent_signed_scope_receipt(development, monkeypatch):
    def failed_save(*args, **kwargs):
        raise ValueError('Task record budget exceeded')
    monkeypatch.setattr(TaskSecurityStore, 'save', failed_save)
    result = introduce_risk(development)
    assert result['scanner_run'] and result['hook_check_recording'] == 'FAILURE_MARKER_RECORDED'
    assert result['continue'] is True and not {'systemMessage','stopReason'} & result.keys()
    store = TaskSecurityStore(development[4].store, development[0])
    marker = store.get_hook_failure(development[-1])
    assert marker['scope_files'] == ['A.java'] and marker['scan_ids'] == [result['scan_id']]
    assert marker['failure_count'] == marker['revision'] == 1
    assert not store.get(development[-1]).get('hook_checks')
    assert result['remediation']['confirmation_ref'] not in json.dumps(marker)
    assert UNSAFE not in json.dumps(marker)
    assert '保存失败' in result['hookSpecificOutput']['additionalContext']


def test_concurrent_failure_receipts_merge_same_task_scope_without_losing_an_edit(development):
    store = TaskSecurityStore(development[4].store, development[0])
    ref = development[-1]
    created = store.get(ref)['created_at']
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(store.record_hook_failure, ref, task_created_at=created,
                   scope_files=[name], scan_id=scan) for name,scan in (
                       ('A.java','scan-failed-a'), ('Other.java','scan-failed-b'))]
        for future in futures:
            future.result(timeout=5)
    marker = store.get_hook_failure(ref)
    assert marker['scope_files'] == ['A.java','Other.java']
    assert set(marker['scan_ids']) == {'scan-failed-a','scan-failed-b'}
    assert marker['revision'] == marker['failure_count'] == 2


@pytest.mark.parametrize('corruption', ['payload','mac','wrong-ref','directory'])
def test_failure_receipt_tampering_or_wrong_reference_is_not_absence(development, corruption):
    store = TaskSecurityStore(development[4].store, development[0])
    ref = development[-1]
    store.record_hook_failure(ref, task_created_at=store.get(ref)['created_at'],
        scope_files=['A.java'], scan_id='scan-current')
    path = store._hook_failure_path(ref)
    if corruption in {'payload','mac'}:
        value = json.loads(path.read_bytes())
        if corruption == 'payload':
            value['data']['scope_files'] = []
        else:
            value['mac'] = '坏'
        path.write_text(json.dumps(value))
    elif corruption == 'wrong-ref':
        wrong_ref = 'ts1-'+'0'*32
        store._hook_failure_path(wrong_ref).write_bytes(path.read_bytes())
        ref = wrong_ref
    else:
        path.unlink()
        path.mkdir()
    with pytest.raises(ValueError):
        store.get_hook_failure(ref)


def test_failure_receipt_cannot_be_read_through_state_link(development):
    store = TaskSecurityStore(development[4].store, development[0])
    ref = development[-1]
    store.record_hook_failure(ref, task_created_at=store.get(ref)['created_at'], scope_files=['A.java'])
    path = store._hook_failure_path(ref)
    original = path.with_suffix('.original')
    path.rename(original)
    try:
        path.symlink_to(original)
    except OSError:
        pytest.skip('OS does not permit symlink fixture')
    with pytest.raises(ValueError, match='links'):
        store.get_hook_failure(ref)


def test_failure_receipt_uses_original_task_ttl_and_bounded_scope(development, monkeypatch):
    from security_runtime.tasks.security_state import TTL
    monkeypatch.setattr('security_runtime.tasks.security_state.MAX_HOOK_FAILURE_FILES', 1)
    store = TaskSecurityStore(development[4].store, development[0])
    ref = development[-1]
    created = store.get(ref)['created_at']
    marker = store.record_hook_failure(ref, task_created_at=created, scope_files=['A.java','Other.java'])
    assert marker['scope_files'] == ['A.java'] and marker['scope_paths_omitted'] == 1
    assert store.get_hook_failure(ref)['scope_paths_omitted'] == 1
    store.now = lambda: created+TTL+1
    assert store.get_hook_failure(ref) is None


def test_task_and_failure_receipt_write_failures_require_explicit_final_coverage_gap(development, monkeypatch):
    def cannot_write(*args, **kwargs):
        raise OSError('Fixture storage unavailable')
    monkeypatch.setattr(TaskSecurityStore, 'save', cannot_write)
    monkeypatch.setattr(TaskSecurityStore, 'record_hook_failure', cannot_write)
    result = introduce_risk(development)
    assert result['scanner_run'] and result['hook_check_recording'] == 'UNAVAILABLE'
    assert result['unpersisted_hook_scope_files'] == ['A.java']
    context = result['hookSpecificOutput']['additionalContext']
    assert '均未能保存' in context and '最终总结必须明确' in context and '不得声称这些结果已持久保留' in context
    assert not {'systemMessage','stopReason'} & result.keys()
    store = TaskSecurityStore(development[4].store, development[0])
    assert store.get_hook_failure(development[-1]) is None


def test_scanner_exception_and_double_recording_failure_keep_internal_final_gap(development, monkeypatch):
    def cannot_complete(*args, **kwargs):
        raise OSError('Fixture storage/scanner unavailable')
    monkeypatch.setattr(TaskSecurityStore, 'save', cannot_complete)
    monkeypatch.setattr(TaskSecurityStore, 'record_hook_failure', cannot_complete)
    monkeypatch.setattr(development[1], 'scan', cannot_complete)
    (development[0]/'A.java').write_text(FIXED+'// new version\n')
    result = development[5]()
    assert result['status'] == 'INCONCLUSIVE' and not result['scanner_run']
    assert result['hook_check_recording'] == 'UNAVAILABLE'
    wire = codex_hook_output(result)
    assert wire['continue'] is True and not {'systemMessage','stopReason'} & wire.keys()
    context = wire['hookSpecificOutput']['additionalContext']
    assert context.startswith('任务内检查记录') and '均未能保存' in context and '最终总结必须明确' in context
    assert 'Fixture storage/scanner unavailable' not in json.dumps(result)


def test_advisory_zero_findings_and_double_recording_failure_keep_internal_final_gap(development, monkeypatch):
    def cannot_record(*args, **kwargs):
        raise OSError('Fixture storage unavailable')
    monkeypatch.setattr(TaskSecurityStore, 'save', cannot_record)
    monkeypatch.setattr(TaskSecurityStore, 'record_hook_failure', cannot_record)
    root, _, _, _, core, *_ = development
    (root/'A.java').write_text(FIXED+'// ordinary edit\n')
    # Advisory-only transport has no remediation service/decision at all.
    # This must keep the final gap even when the scanner's result is clean.
    result = handle_codex_hook('PostToolUse', str(root), 'session', 'apply_patch',
        binding=binding(root), coordinator=core)
    assert result['status'] == 'SCANNED' and result['scanner_run'] and result['coverage'] == 'FULL'
    assert result['new_families'] == result['additional_occurrences'] == 0
    assert 'remediation' not in result and result['hook_check_recording'] == 'UNAVAILABLE'
    wire = codex_hook_output(result)
    assert wire['continue'] is True and not {'systemMessage','stopReason'} & wire.keys()
    assert '均未能保存' in wire['hookSpecificOutput']['additionalContext']
