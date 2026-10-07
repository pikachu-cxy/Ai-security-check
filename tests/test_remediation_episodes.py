"""Family recurrence needs positive scanner absence, never a new host claim."""
import pytest
import subprocess

from test_remediation import setup, args, prepare, UNSAFE, FIXED, CANARY
from test_hook_runtime import repo
from test_remediation import SavedRuntime
from test_task_fix import LocalProvider
from test_codex_mcp_hook import binding as workspace_binding
from security_runtime.codex_mcp_hook import handle_codex_hook
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.remediation import RemediationService


def record(setup):
    service = setup[3]
    path = service.state.path(setup[0], 'codex', 'session')
    return next(iter(service._read(path, service.state.key(setup[0])).values()))


def resolve(setup):
    prepare(setup)
    setup[0].joinpath('A.java').write_text(FIXED)
    setup[1].findings = setup[2].findings = []
    result = setup[4]()
    assert result['remediation']['reason_code'] == 'SCANNER_VERIFIED_RESOLVED'
    return result


def recur(setup):
    # Use the original persisted scanner member, not fabricated references.
    scan = setup[1].store.get_scan(record(setup)['origin_scan_id'])
    from security_runtime.models import Finding
    finding = Finding(**scan['findings'][0])
    setup[1].findings = setup[2].findings = [finding]
    setup[0].joinpath('A.java').write_text(UNSAFE)
    return setup[4]()


def test_first_episode_allocates_first_bounded_attempt(setup):
    r = record(setup)
    assert r['episode_number'] == 1 and r['attempt_count'] == 1
    assert r['resolution'] is None and r['episode_history'] == []
    assert setup[-1]['remediation']['action'] == 'AUTO_FIX'
    assert setup[-1]['remediation']['episode_id'] == r['episode_id']
    assert args(setup)['task_ref'] and args(setup)['remediation_ref']


def test_active_retry_keeps_episode_and_rotates_grant(setup):
    first = record(setup)
    prepare(setup)
    setup[0].joinpath('A.java').write_text(UNSAFE + '// repair attempt\n')
    retry = setup[4]()
    assert record(setup)['episode_id'] == first['episode_id']
    assert record(setup)['episode_number'] == 1
    assert retry['remediation']['attempt_count'] == 2
    assert retry['remediation']['prepare']['arguments']['remediation_ref'] != args(setup)['remediation_ref']


def exhaust(setup):
    prepare(setup)
    setup[0].joinpath('A.java').write_text(UNSAFE + '// attempt one\n')
    retry = setup[4]()['remediation']['prepare']['arguments']
    assert setup[3].prepare(retry['remediation_ref'], retry['task_ref'], setup[0])['status'] == 'READY_FOR_HOST_FIX'
    setup[0].joinpath('A.java').write_text(UNSAFE + '// attempt two\n')
    assert setup[4]()['remediation']['reason_code'] == 'EPISODE_ATTEMPT_BUDGET_EXCEEDED'


def test_exhaustion_and_repeated_edits_restart_do_not_reset(setup):
    first = record(setup)['episode_id']
    exhaust(setup)
    for n in range(3):
        setup[0].joinpath('A.java').write_text(UNSAFE + f'// still present {n}\n')
        out = setup[4]()['remediation']
        assert out['reason_code'] == 'EPISODE_ATTEMPT_BUDGET_EXCEEDED'
        assert 'prepare' not in out
        assert record(setup)['episode_id'] == first
    restarted = RemediationService(setup[3].store, registry=setup[3].registry, hooks=setup[3].hooks)
    result = HookCoordinator(setup[1], setup[3].hooks, cooldown_ms=0).handle('FILE_CHANGED', setup[0], 'codex', 'session')
    assert restarted.on_hook(result, setup[0], 'session', host='codex')['reason_code'] == 'EPISODE_ATTEMPT_BUDGET_EXCEEDED'


def test_resolved_then_same_family_recurrence_new_episode_and_refs(setup):
    first = record(setup)
    resolved = resolve(setup)
    assert record(setup)['phase'] == 'CLOSED'
    assert record(setup)['resolution']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    out = recur(setup)['remediation']
    second = record(setup)
    assert out['action'] == 'AUTO_FIX'
    assert out['episode_reason_code'] == 'RECURRENCE_AFTER_RESOLUTION'
    assert out['reason_code'] == 'SAFE_DETERMINISTIC_FIX'
    assert first['family_key'] == second['family_key']
    assert first['episode_id'] != second['episode_id'] and second['episode_number'] == 2
    assert second['attempt_count'] == 1 and second['resolution'] is None
    assert second['episode_history'][0]['attempt_count'] == first['attempt_count']
    fresh = out['prepare']['arguments']
    assert fresh['task_ref'] != args(setup)['task_ref']
    assert fresh['remediation_ref'] != args(setup)['remediation_ref']
    assert setup[3].prepare(fresh['remediation_ref'], fresh['task_ref'], setup[0])['status'] == 'READY_FOR_HOST_FIX'


def test_no_prepare_or_unconfirmed_absence_never_creates_recurrence(setup):
    first = record(setup)['episode_id']
    setup[0].joinpath('A.java').write_text(FIXED)
    setup[1].findings = setup[2].findings = []
    assert setup[4]()['remediation']['action'] == 'ESCALATE'
    assert record(setup)['resolution'] is None
    assert recur(setup)['remediation']['action'] != 'AUTO_FIX'
    assert record(setup)['episode_id'] == first


def test_exhausted_manual_scanner_resolved_allows_recurrence(setup):
    first = record(setup)['episode_id']
    exhaust(setup)
    setup[0].joinpath('A.java').write_text(FIXED)
    setup[1].findings = setup[2].findings = []
    out = setup[4]()['remediation']
    assert out['reason_code'] == 'SCANNER_VERIFIED_RESOLVED' and out['action'] == 'NONE'
    assert record(setup)['attempt_count'] == 2 and record(setup)['phase'] == 'CLOSED'
    assert recur(setup)['remediation']['action'] == 'AUTO_FIX'
    assert record(setup)['episode_number'] == 2 and record(setup)['attempt_count'] == 1
    assert record(setup)['episode_id'] != first


@pytest.mark.parametrize('failure', ['FAILED', 'UNAVAILABLE', 'TIMEOUT', 'partial', 'guard'])
def test_exhausted_absence_without_coverage_or_guard_cannot_reset(setup, failure):
    exhaust(setup)
    setup[0].joinpath('A.java').write_text(FIXED.replace('1000', '9999') if failure == 'guard' else FIXED)
    setup[1].findings = setup[2].findings = []
    if failure == 'partial':
        setup[1].complete = False
        original = setup[2].scan
        def partial(*a):
            found, run = original(*a)
            run.coverage_contract = 'PARTIAL'
            return found, run
        setup[2].scan = partial
    elif failure != 'guard':
        setup[1].status = setup[2].status = failure
    setup[4]()
    assert record(setup)['resolution'] is None and record(setup)['phase'] == 'ESCALATED'


def test_old_references_receipt_and_plain_task_cannot_authorize_new_episode(setup):
    old = dict(args(setup))
    resolve(setup)
    assert setup[3].functional_receipt(old['remediation_ref'], old['task_ref'], setup[0]) is not None
    fresh = recur(setup)['remediation']['prepare']['arguments']
    for ref, task in [(old['remediation_ref'], old['task_ref']),
                      (old['remediation_ref'], fresh['task_ref']),
                      (fresh['remediation_ref'], old['task_ref'])]:
        assert setup[3].prepare(ref, task, setup[0])['action'] == 'ADVISE'
        assert setup[3].functional_receipt(ref, task, setup[0]) is None
        assert setup[3].verify(ref, task, setup[0])['verification_status'] == 'INCONCLUSIVE'
    assert setup[3].task_gate(old['task_ref'], setup[0])['reason_code'] == 'REMEDIATION_EPISODE_SUPERSEDED'


def test_legacy_closed_never_infers_resolution_and_lazy_migration(setup):
    resolve(setup)
    service = setup[3]
    path = service.state.path(setup[0], 'codex', 'session')
    key = service.state.key(setup[0])
    rows = service._read(path, key)
    for r in rows.values():
        for k in ('episode_id', 'episode_number', 'episode_history', 'resolution'):
            del r[k]
        r['last_verification'] = 'NOT_VERIFIED'  # CLOSED alone is not positive proof.
    service._save(path, rows, key)
    before = path.read_bytes()
    assert record(setup)['resolution'] is None
    assert path.read_bytes() == before
    assert recur(setup)['remediation']['reason_code'] == 'EPISODE_RESOLUTION_NOT_PROVEN'
    assert record(setup)['attempt_count'] == 1
    # Fresh scanner evidence can migrate the legacy closed row conservatively.
    setup[0].joinpath('A.java').write_text(FIXED)
    setup[1].findings = setup[2].findings = []
    assert setup[4]()['remediation']['reason_code'] == 'SCANNER_VERIFIED_RESOLVED'
    assert recur(setup)['remediation']['action'] == 'AUTO_FIX'


def test_legacy_scanner_verified_closed_migrates_positive_proof_without_rescan(setup):
    resolve(setup)
    service = setup[3]
    path = service.state.path(setup[0], 'codex', 'session')
    key = service.state.key(setup[0])
    rows = service._read(path, key)
    for r in rows.values():
        for k in ('episode_id', 'episode_number', 'episode_history', 'resolution'):
            del r[k]
    service._save(path, rows, key)
    before = path.read_bytes()
    assert record(setup)['resolution']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert path.read_bytes() == before
    out = recur(setup)['remediation']
    assert out['action'] == 'AUTO_FIX' and out['episode_number'] == 2
    assert out['episode_reason_code'] == 'RECURRENCE_AFTER_RESOLUTION'


@pytest.mark.parametrize('kind', ['active', 'exhausted'])
def test_new_host_session_cannot_reset_existing_episode(setup, kind):
    if kind == 'exhausted':
        exhaust(setup)
    before = record(setup)
    core = HookCoordinator(setup[1], setup[3].hooks, cooldown_ms=0)
    # Explicit fresh NEW delta in another session still cannot bypass a family.
    baseline = core.handle('FILE_CHANGED', setup[0], 'codex', 'new-session')
    result = dict(baseline, status='SCANNED')
    result['delta'] = {'families': [{
        'equivalence_key': before['family_key'], 'status': 'NEW_FAMILY', 'current_count': 1,
        'count_certainty': 'COMPLETE_RULE_FILE_SCOPE'}]}
    out = setup[3].on_hook(result, setup[0], 'new-session', host='codex')
    assert out['reason_code'] == ('EPISODE_ALREADY_EXISTS' if kind == 'active' else 'EPISODE_ATTEMPT_BUDGET_EXCEEDED')
    assert record(setup)['episode_id'] == before['episode_id']


def test_episode_metadata_never_persists_source_secret_or_bearer(setup):
    resolve(setup)
    fresh = recur(setup)['remediation']['prepare']['arguments']
    text = setup[3].state.path(setup[0], 'codex', 'session').read_text()
    for token in (args(setup)['remediation_ref'], fresh['remediation_ref'], CANARY, UNSAFE):
        assert token not in text
    assert 'setHostnameVerifier' not in text


def test_workspace_lifecycle_and_budget_are_isolated(setup, tmp_path):
    exhaust(setup)
    other = tmp_path / 'other-project'
    other.mkdir()
    subprocess.run(['git', 'init', str(other)], check=True, capture_output=True)
    service = setup[3]
    store = SQLiteStore(tmp_path / 'other-db/scans.db')
    runtime = SavedRuntime(store)
    provider = LocalProvider()
    new_service = RemediationService(store, registry=ScannerRegistry([provider]), hooks=service.hooks,
                                     directory=service.state.directory)
    core = HookCoordinator(runtime, service.hooks, cooldown_ms=0)
    binding = workspace_binding(other)
    def hook():
        return handle_codex_hook('PostToolUse', str(other), 'session', 'apply_patch',
                                 binding=binding, coordinator=core, remediation=new_service)
    other.joinpath('A.java').write_text(FIXED)
    assert hook()['status'] == 'BASELINE_ESTABLISHED'
    from test_hook_runtime import row
    from security_runtime.remediation_policy import RULE
    finding = row(other, 6, RULE, category='trust-all-tls')
    finding.technical_details.update(rule_pack='ai-security-core', rule_pack_checksum='a'*64,
                                    rule_pack_version='0.1', engine='semgrep')
    runtime.findings = provider.findings = [finding]
    other.joinpath('A.java').write_text(UNSAFE)
    out = hook()['remediation']
    assert out['action'] == 'AUTO_FIX' and out['episode_number'] == 1 and out['attempt_count'] == 1
    assert new_service.state.path(other, 'codex', 'session') != service.state.path(setup[0], 'codex', 'session')
    old = args(setup)
    assert new_service.prepare(old['remediation_ref'], old['task_ref'], other)['reason_code'] == 'REPAIR_GRANT_REJECTED'
    assert record(setup)['phase'] == 'ESCALATED' and record(setup)['attempt_count'] == 2


def test_resolved_family_can_recur_in_new_session_old_authority_is_rejected(setup):
    old = dict(args(setup))
    resolve(setup)
    core = HookCoordinator(setup[1], setup[3].hooks, cooldown_ms=0)
    root = setup[0]
    binding = workspace_binding(root)
    def hook():
        return handle_codex_hook('PostToolUse', str(root), 'new-session', 'apply_patch',
                                 binding=binding, coordinator=core, remediation=setup[3])
    assert hook()['status'] == 'BASELINE_ESTABLISHED'
    scan = setup[1].store.get_scan(record(setup)['origin_scan_id'])
    from security_runtime.models import Finding
    setup[1].findings = setup[2].findings = [Finding(**scan['findings'][0])]
    root.joinpath('A.java').write_text(UNSAFE)
    out = hook()['remediation']
    assert out['action'] == 'AUTO_FIX' and out['episode_number'] == 2
    assert setup[3].prepare(old['remediation_ref'], old['task_ref'], root)['reason_code'] == 'REPAIR_GRANT_REJECTED'
    assert setup[3].functional_receipt(old['remediation_ref'], old['task_ref'], root) is None
    assert setup[3].task_gate(old['task_ref'], root)['reason_code'] == 'REMEDIATION_EPISODE_SUPERSEDED'


@pytest.mark.parametrize('mode,expected', [('report_only', 'ADVISE'), ('ask_before_fix', 'CONFIRM_REQUIRED')])
def test_recurrence_rechecks_current_policy(setup, mode, expected):
    resolve(setup)
    setup[3].config.write(mode)
    out = recur(setup)['remediation']
    assert out['action'] == expected
    assert 'prepare' not in out
    assert out['episode_number'] == 2 and out['episode_reason_code'] == 'RECURRENCE_AFTER_RESOLUTION'
    assert record(setup)['attempt_count'] == 0
    if expected == 'CONFIRM_REQUIRED':
        assert record(setup)['phase'] == 'PENDING_CONFIRMATION'
    else:
        assert record(setup)['phase'] == 'OBSERVED'
        assert 'token_hash' not in record(setup)
    old = args(setup)
    assert setup[3].prepare(old['remediation_ref'], old['task_ref'], setup[0])['reason_code'] == 'REPAIR_GRANT_REJECTED'


def test_old_legacy_active_budget_preserved_on_read(setup):
    exhaust(setup)
    service = setup[3]
    path = service.state.path(setup[0], 'codex', 'session')
    key = service.state.key(setup[0])
    rows = service._read(path, key)
    for r in rows.values():
        for k in ('episode_id', 'episode_number', 'episode_history', 'resolution'):
            del r[k]
    service._save(path, rows, key)
    before = path.read_bytes()
    assert record(setup)['attempt_count'] == 2 and record(setup)['episode_number'] == 1
    assert path.read_bytes() == before
    setup[0].joinpath('A.java').write_text(UNSAFE + '// legacy repeat\n')
    assert setup[4]()['remediation']['reason_code'] == 'EPISODE_ATTEMPT_BUDGET_EXCEEDED'


def test_history_retention_limit_fails_closed(setup, monkeypatch):
    resolve(setup)
    # Existing state remains valid; next issuance cannot silently drop history.
    import security_runtime.remediation as module
    monkeypatch.setattr(module, 'MAX_EPISODES', 1)
    out = recur(setup)['remediation']
    assert out['reason_code'] == 'EPISODE_HISTORY_BUDGET_EXCEEDED'
    assert record(setup)['episode_number'] == 1 and record(setup)['phase'] == 'CLOSED'


@pytest.mark.parametrize('status', ['NO_CHANGE', 'REUSED_LAST_RESULT', 'DEBOUNCED', 'PARTIAL', 'FAILED'])
def test_reused_or_incomplete_observation_cannot_issue_recurrence(setup, status):
    resolve(setup)
    scan = setup[1].store.get_scan(record(setup)['origin_scan_id'])
    from security_runtime.models import Finding
    setup[1].findings = setup[2].findings = [Finding(**scan['findings'][0])]
    setup[0].joinpath('A.java').write_text(UNSAFE)
    result = HookCoordinator(setup[1], setup[3].hooks, cooldown_ms=0).handle(
        'FILE_CHANGED', setup[0], 'codex', 'session')
    result['status'] = status
    out = setup[3].on_hook(result, setup[0], 'session', host='codex')
    assert out['reason_code'] == 'EPISODE_RESOLUTION_NOT_PROVEN'
    assert record(setup)['episode_number'] == 1


def test_current_episode_still_present_never_resets_on_hook_delta_new(setup):
    before = record(setup)
    result = HookCoordinator(setup[1], setup[3].hooks, cooldown_ms=0).handle(
        'FILE_CHANGED', setup[0], 'codex', 'session')
    result['delta']['families'] = [{
        'equivalence_key': before['family_key'], 'status': 'NEW_FAMILY', 'current_count': 1,
        'count_certainty': 'COMPLETE_RULE_FILE_SCOPE'}]
    out = setup[3].on_hook(result, setup[0], 'session', host='codex')
    assert out['reason_code'] == 'EPISODE_ALREADY_EXISTS'
    assert record(setup)['episode_id'] == before['episode_id']


@pytest.mark.parametrize('field,value', [('episode_number', True), ('episode_id', 'bad'),
                                        ('episode_history', ['bad']), ('resolution', {'status': 'HOST_RESOLVED'})])
def test_malformed_signed_episode_metadata_fails_closed(setup, field, value):
    service = setup[3]
    path = service.state.path(setup[0], 'codex', 'session')
    key = service.state.key(setup[0])
    rows = service._read(path, key)
    next(iter(rows.values()))[field] = value
    service._save(path, rows, key)
    out = setup[4]()['remediation']
    assert out['action'] == 'ADVISE' and out['verification_status'] == 'INCONCLUSIVE'


def test_episode_policy_attempt_limit_enum():
    from security_runtime.remediation_policy import RemediationPolicy, RULE
    out = RemediationPolicy().decide(rule=RULE, priority='ACTIONABLE', coverage=True,
                                     deterministic=True, attempts=2)
    assert out.action == 'ESCALATE' and out.reason_code == 'EPISODE_ATTEMPT_BUDGET_EXCEEDED'
