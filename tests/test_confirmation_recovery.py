"""Choice recovery never renews active consent TTL or resets used repair budgets."""
import asyncio
import copy
import json
import time

import pytest

from test_remediation import setup, UNSAFE, CANARY
from test_hook_runtime import repo
from test_confirmation import pending, state
from security_runtime.remediation_recovery import refresh_confirmation, USER_MESSAGE
from security_runtime.remediation import CONFIRMATION_TTL
from security_runtime.hook_runtime import HookCoordinator

pytestmark = pytest.mark.parametrize('setup', ['ask_before_fix'], indirect=True)


def record(setup):
    return next(iter(state(setup).values()))


def refresh(setup, **changes):
    args = dict(task_ref=pending(setup)['task_ref'],
                scan_id=setup[1].store.latest_scan(setup[0])['scan_id'], root=setup[0])
    args.update(changes)
    return refresh_confirmation(setup[3], **args)


def signed_change(setup, **changes):
    root, _, _, service, _, _ = setup
    path = service.state.path(root, 'codex', 'session')
    with service.state.lock(root) as acquired:
        assert acquired
        key = service.state.key(root)
        rows = service._read(path, key)
        next(iter(rows.values())).update(changes)
        service._save(path, rows, key)


def replace_scan(setup, scan):
    with setup[1].store._connect() as db:
        db.execute('UPDATE scans SET data=? WHERE id=?', (json.dumps(scan), scan['scan_id']))


def assert_no_grant(setup, output):
    assert not {'prepare', 'verify', 'remediation_ref', 'grant_id'} & output.keys()
    assert not setup[3].authorized and not setup[3].prepared and not setup[2].calls


def test_pending_rotation_keeps_original_scope_and_deadline_invalidates_old_token(setup):
    before = record(setup)
    original_scan = setup[1].store.latest_scan(setup[0])
    output = refresh(setup)
    after = record(setup)
    assert output['status'] == 'PENDING_CONFIRMATION' and output['issues_edit_grant'] is False
    assert output['confirmation_ref'] != pending(setup)['confirmation_ref']
    assert output['task_ref'] == pending(setup)['task_ref']
    assert 0 < output['expires_in_seconds'] <= CONFIRMATION_TTL
    assert_no_grant(setup, output)
    for field in ('episode_id', 'episode_number', 'episode_history', 'task_ref', 'origin_scan_id',
                  'target', 'source_guard', 'preservation_guard', 'attempt_count', 'host_id', 'session_id',
                  'workspace_id', 'host_session_namespace', 'confirmation_issued_at_epoch',
                  'confirmation_expires_at_epoch', 'policy_binding'):
        assert after[field] == before[field]
    assert after['confirmation_hash'] != before['confirmation_hash']
    assert (setup[0] / 'A.java').read_text() == UNSAFE
    assert setup[1].store.latest_scan(setup[0]) == original_scan
    old = setup[3].confirm(pending(setup)['confirmation_ref'], output['task_ref'], setup[0], approve=True)
    assert old['diagnostic_reason'] == 'CONFIRMATION_REFERENCE_MISMATCH'
    assert setup[3].confirm(output['confirmation_ref'], output['task_ref'], setup[0], approve='true')[
        'reason_code'] == 'EXPLICIT_BOOLEAN_CHOICE_REQUIRED'
    assert_no_grant(setup, old)
    accepted = setup[3].confirm(output['confirmation_ref'], output['task_ref'], setup[0], approve=True)
    assert accepted['status'] == 'AUTHORIZED' and record(setup)['attempt_count'] == 1


@pytest.mark.parametrize('phase', ['DECLINED', 'EXPIRED', 'PENDING_CONFIRMATION'])
def test_new_selected_fix_intent_reopens_unused_choice_with_no_grant(setup, phase):
    before = record(setup)
    if phase == 'DECLINED':
        assert setup[3].confirm(pending(setup)['confirmation_ref'], before['task_ref'], setup[0],
                                approve=False)['status'] == 'DECLINED'
    else:
        issued = time.time() - 1800
        signed_change(setup, phase=phase, confirmation_issued_at_epoch=issued,
                      confirmation_expires_at_epoch=issued + CONFIRMATION_TTL)
    old_deadline = record(setup)['confirmation_expires_at_epoch']
    output = refresh(setup)
    assert output['status'] == 'PENDING_CONFIRMATION'
    assert record(setup)['confirmation_expires_at_epoch'] > old_deadline
    assert record(setup)['attempt_count'] == 0
    assert record(setup)['episode_id'] == before['episode_id']
    assert record(setup)['task_ref'] == before['task_ref']
    assert_no_grant(setup, output)


@pytest.mark.parametrize('phase,attempt', [('AUTHORIZED', 1), ('OFFERED', 0), ('ESCALATED', 2),
                                        ('DECLINED', 1), ('EXPIRED', 2), ('OBSERVED', 0)])
def test_used_or_nonpending_scope_cannot_reset_its_episode(setup, phase, attempt):
    signed_change(setup, phase=phase, attempt_count=attempt)
    before = state(setup)
    output = refresh(setup)
    assert output['diagnostic_reason'] == 'CONFIRMATION_RECOVERY_ALREADY_AUTHORIZED_OR_CONSUMED'
    assert output['user_message'] == USER_MESSAGE and state(setup) == before
    assert_no_grant(setup, output)


@pytest.mark.parametrize('marker', ['authorization_kind', 'token_hash', 'inline_agent_ticket', 'host_continuation'])
def test_unused_record_with_authorization_marker_is_never_reopened(setup, marker):
    # Even a null marker is not proof that a historical authorization was unused.
    signed_change(setup, **{marker: None})
    before = state(setup)
    output = refresh(setup)
    assert output['action'] == 'ADVISE' and output['user_message'] == USER_MESSAGE
    assert state(setup) == before
    assert_no_grant(setup, output)


@pytest.mark.parametrize('kind', ['partial', 'failed', 'cached', 'capability', 'scanner', 'scanner-partial',
                                 'engine-version', 'file', 'rule', 'multiple', 'member', 'detector-version'])
def test_changed_or_incomplete_evidence_keeps_original_record(setup, kind):
    scan = setup[1].store.latest_scan(setup[0])
    if kind == 'partial': scan['coverage'] = 'PARTIAL'
    elif kind == 'failed': scan['status'] = 'FAILED'
    elif kind == 'cached': scan['execution_state'] = 'REUSED_LAST_RESULT'
    elif kind == 'capability': scan['capability_results']['CODE_SAST'] = 'FAILED'
    elif kind == 'scanner': scan['scanner_runs'][0]['status'] = 'TIMEOUT'
    elif kind == 'scanner-partial': scan['scanner_runs'][0]['coverage_contract'] = 'PARTIAL'
    elif kind == 'engine-version': scan['scanner_runs'][0]['version'] = 'changed'
    elif kind == 'file': scan['findings'][0]['file_path'] = 'Other.java'
    elif kind == 'rule': scan['findings'][0]['technical_details']['rule_id'] = 'other.rule'
    elif kind == 'detector-version': scan['findings'][0]['technical_details']['rule_version'] = 'changed'
    elif kind == 'multiple':
        second = copy.deepcopy(scan['findings'][0]); second['id'] += '-other'; second['line_start'] += 1
        scan['findings'].append(second)
    else:
        # Original task membership is no longer the selected one.
        scan['findings'][0]['id'] = 'changed-member'
    replace_scan(setup, scan)
    before = state(setup)
    output = refresh(setup)
    assert output['action'] == 'ADVISE' and output['user_message'] == USER_MESSAGE
    assert state(setup) == before and setup[1].store.latest_scan(setup[0]) == scan
    assert_no_grant(setup, output)


def test_existing_ai_review_is_not_replaced_by_an_untriaged_recovery_scope(setup):
    from security_runtime.triage import TriageService
    scan = setup[1].store.latest_scan(setup[0])
    triage = TriageService(setup[1].store)
    packet = triage.prepare(scan['scan_id'], finding_ids=[scan['findings'][0]['id']])['packets'][0]
    triage.submit(scan['scan_id'], [dict(finding_id=packet['finding_id'], context_hash=packet['context_hash'],
        verdict='NEEDS_REVIEW', confidence='HIGH', exploitability='UNKNOWN', reason='Bounded fixture review',
        attack_path='', evidence_refs=[dict(file=packet['file'], start_line=packet['line']['start'],
        end_line=packet['line']['end'], claim='Local candidate')], preconditions_met=[],
        preconditions_unknown=['Production use'], recommended_action='Review')])
    before, reviews = state(setup), setup[1].store.triage_records(scan['scan_id'])
    output = refresh(setup)
    assert output['diagnostic_reason'] == 'CONFIRMATION_RECOVERY_ORIGINAL_TASK_CHANGED'
    assert state(setup) == before and setup[1].store.triage_records(scan['scan_id']) == reviews
    assert setup[1].store.latest_scan(setup[0]) == scan
    assert_no_grant(setup, output)


@pytest.mark.parametrize('kind', ['source', 'other-file', 'policy-revision', 'policy-mode', 'namespace'])
def test_source_policy_and_namespace_guards_are_preserved(setup, kind):
    if kind == 'source': (setup[0] / 'A.java').write_text(UNSAFE + '// changed\n')
    elif kind == 'other-file': (setup[0] / 'Other.java').write_text('class Other {}')
    elif kind == 'policy-revision': setup[3].config.write('ask_before_fix')
    elif kind == 'policy-mode': setup[3].config.write('report_only')
    else: signed_change(setup, host_session_namespace='a' * 64)
    before = state(setup)
    output = refresh(setup)
    assert output['user_message'] == USER_MESSAGE and state(setup) == before
    assert_no_grant(setup, output)


def test_other_family_selection_and_forged_scan_never_redirect_original_task(setup):
    before = state(setup)
    for changes in ({'task_ref': 'T01'}, {'scan_id': 'scan-other'}, {'root': setup[0].parent}):
        output = refresh(setup, **changes)
        assert output['user_message'] == USER_MESSAGE and state(setup) == before
        assert_no_grant(setup, output)


@pytest.mark.parametrize('phase', ['EXPIRED', 'PENDING_CONFIRMATION'])
def test_new_session_proof_does_not_move_original_repair_namespace(setup, phase):
    from test_remediation import FIXED
    root, runtime, _, service, _, _ = setup
    before = record(setup)
    original_finding = copy.deepcopy(runtime.findings)
    issued = time.time() - 1800
    signed_change(setup, phase=phase, confirmation_issued_at_epoch=issued,
                  confirmation_expires_at_epoch=issued + CONFIRMATION_TTL)
    core = HookCoordinator(runtime, service.hooks, cooldown_ms=0)
    (root / 'A.java').write_text(FIXED)
    runtime.findings = []
    core.handle('FILE_CHANGED', root, 'codex', 'session')
    core.handle('FILE_CHANGED', root, 'codex', 'new-session')
    (root / 'A.java').write_text(UNSAFE)
    runtime.findings = original_finding
    current = core.handle('FILE_CHANGED', root, 'codex', 'new-session')
    assert current['status'] == 'SCANNED'
    output = refresh(setup, scan_id=current['scan_id'])
    assert output['status'] == 'PENDING_CONFIRMATION'
    for field in ('episode_id', 'episode_number', 'episode_history', 'task_ref', 'origin_scan_id',
                  'host_id', 'session_id', 'workspace_id', 'host_session_namespace'):
        assert record(setup)[field] == before[field]
    assert not service.state.path(root, 'codex', 'new-session').exists()
    assert_no_grant(setup, output)


def test_latest_scan_changes_before_save_without_consuming_old_choice(setup, monkeypatch):
    latest = setup[3].store.latest_scan(setup[0])
    original = record(setup)
    calls = []
    def changed_scan(root):
        calls.append(root)
        return latest if len(calls) <= 2 else dict(latest, scan_id='scan-raced')
    monkeypatch.setattr(setup[3].store, 'latest_scan', changed_scan)
    output = refresh(setup, scan_id=latest['scan_id'])
    assert output['diagnostic_reason'] == 'CONFIRMATION_RECOVERY_SCAN_NOT_CURRENT'
    assert record(setup) == original
    assert_no_grant(setup, output)


def test_full_pending_budget_is_not_reset_by_refresh(setup):
    root, _, _, service, _, _ = setup
    original = record(setup)
    with service.state.lock(root) as acquired:
        assert acquired
        key = service.state.key(root)
        for session, count in (('second', 16), ('third', 15)):
            rows = {f'{session}-{n}': dict(original, family_key=f'{session}-{n}',
                    task_ref=f'other-{session}-{n}') for n in range(count)}
            service._save(service.state.path(root, 'codex', session), rows, key)
    before = state(setup)
    output = refresh(setup)
    assert output['diagnostic_reason'] == 'CONFIRMATION_BUDGET_EXCEEDED'
    assert state(setup) == before
    assert_no_grant(setup, output)


def test_mcp_recovery_schema_and_bound_workspace(setup, monkeypatch, tmp_path):
    from security_runtime.mcp_server import create_server
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', str(setup[0]))
    monkeypatch.setattr('security_runtime.remediation.RemediationService', lambda *a, **k: setup[3])
    server = create_server(setup[1])
    tool = server._tool_manager.get_tool('refresh_remediation_confirmation')
    assert set(tool.parameters['required']) == {'task_ref', 'scan_id'}
    assert tool.parameters['additionalProperties'] is False
    assert tool.annotations.readOnlyHint is False and tool.annotations.openWorldHint is False
    args = {'task_ref': pending(setup)['task_ref'], 'scan_id': setup[1].store.latest_scan(setup[0])['scan_id']}
    denied = tool.fn(**args, workspace_path=str(tmp_path))
    assert denied['diagnostic_reason'] == 'WORKSPACE_CLAIM_REJECTED'
    output = tool.fn(**args)
    assert output['status'] == 'PENDING_CONFIRMATION'
    assert_no_grant(setup, output)


@pytest.mark.parametrize('extra', ['approve', 'source', 'secret', 'prompt', 'transcript'])
def test_mcp_recovery_rejects_untrusted_extra_values_without_echo(setup, monkeypatch, extra):
    from security_runtime.mcp_server import create_server
    from mcp.server.fastmcp.exceptions import ToolError
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', str(setup[0]))
    tool = create_server(setup[1])._tool_manager.get_tool('refresh_remediation_confirmation')
    with pytest.raises(ToolError) as error:
        asyncio.run(tool.run({'task_ref': 'T01', 'scan_id': 'scan-1', extra: CANARY}))
    assert CANARY not in str(error.value)
