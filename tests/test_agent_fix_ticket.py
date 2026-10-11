"""Inline preparation reuses old checks; no source writer, atomic bridge or Deep work."""
import asyncio
import copy
import json
import os

import pytest

from test_hook_runtime import repo
from test_remediation import setup as legacy_setup, UNSAFE, FIXED, CANARY
from test_remediation_episodes import record, recur
from security_runtime.agent_fix_ticket import VERSION, encoded, MAX_BYTES
from security_runtime.codex_mcp_hook import codex_hook_output
from security_runtime.hook_state import identity
from security_runtime.remediation import RemediationService


@pytest.fixture
def inline_setup(repo, tmp_path, request, monkeypatch):
    original = RemediationService.__init__
    def enabled(self, *args, **kwargs):
        kwargs.setdefault('inline_agent_tickets', True)
        original(self, *args, **kwargs)
    monkeypatch.setattr(RemediationService, '__init__', enabled)
    return legacy_setup.__wrapped__(repo, tmp_path, request)


def ticket(setup):
    return setup[-1]['remediation']['agent_fix_ticket']


def fix(setup, *, suffix=''):
    setup[0].joinpath('A.java').write_text(FIXED + suffix)
    setup[1].findings = setup[2].findings = []
    return setup[4]()


def test_native_fast_path_is_not_given_agent_prepare_requirement(legacy_setup, monkeypatch):
    from test_fast_fix import HOST_CONTRACT, simulated_host_apply
    root, _, _, service, hook, grant = legacy_setup
    service.fast_fix.host_contract = HOST_CONTRACT
    service.agent_tickets.enabled = True
    output = copy.deepcopy(grant['remediation'])
    output.pop('agent_fix_ticket_diagnostics', None)
    with service.state.lock(root) as acquired:
        assert acquired
        current = record(legacy_setup)
        service.fast_fix.offer(output, root, current, service.state.key(root))
        assert output['fix_path'] == 'DETERMINISTIC_FAST_FIX'
        original = copy.deepcopy(output)
        monkeypatch.setattr(service, '_prepare', lambda *a, **k: pytest.fail('Agent prepare on Fast Fix'))
        service.agent_tickets.offer(output, root, current, service.state.key(root), None, {}, {}, {})
        assert output == original
        assert 'agent_fix_ticket_diagnostics' not in output and 'agent_fix_ticket' not in output
    assert simulated_host_apply(legacy_setup, output['fast_fix_plan'])['status'] == 'FAST_FIX_APPLY_AUTHORIZED'
    legacy_setup[1].findings = legacy_setup[2].findings = []
    assert hook()['remediation']['reason_code'] == 'SCANNER_VERIFIED_RESOLVED'


def test_complete_source_free_ticket_original_refs_and_no_prepare(inline_setup):
    data = inline_setup; grant = data[-1]['remediation']; t = ticket(data); r = record(data)
    assert t['version'] == VERSION and len(encoded(t)) <= MAX_BYTES
    assert t['task_ref'] == grant['prepare']['arguments']['task_ref'] == r['task_ref']
    assert t['remediation_ref'] == grant['prepare']['arguments']['remediation_ref']
    assert t['workspace_id'] == identity(os.path.normcase(str(data[0])))
    assert t['episode_id'] == r['episode_id'] and t['grant_id'] == r['token_hash']
    assert t['origin_scan_id'] == r['origin_scan_id'] and t['snapshot_digest'] == r['last_snapshot_digest']
    assert t['finding_id'] == grant['security_fix_context']['binding']['finding_id']
    assert t['security_context_ref'] == grant['security_fix_context_ref']
    assert t['allowed_target_paths'] == ['A.java'] and t['attempt_count'] == 1
    assert t['expiry']['expires_in_seconds'] == 900 and t['prepared_attestation']
    assert t['success']['original_rule_real_scanner_required']
    assert not t['success']['deep_verification_authorized']
    assert not grant['prepare']['required'] and not grant['security_fix_context']['authorization']['prepare_required']
    assert r['token_hash'] in data[3].prepared and not data[3].agent_tickets.prepare_calls
    assert UNSAFE not in json.dumps(t) and CANARY not in json.dumps(t)
    assert 'Do not call prepare_task_fix' in grant['guidance']
    assert grant['agent_fix_ticket_diagnostics']['structured_handoff_complete']
    assert grant['agent_fix_ticket_diagnostics']['handoff_retry_count'] is None


@pytest.mark.parametrize('prose', ['truncated', 'absent'])
def test_structured_ticket_survives_prose_loss_and_closes(inline_setup, prose):
    data = inline_setup; wire = copy.deepcopy(data[-1])
    if prose == 'absent':
        for key in codex_hook_output(wire): wire.pop(key, None)
        wire['remediation'].pop('guidance')
    else:
        wire['stopReason'] = '...'; wire.setdefault('hookSpecificOutput', {})['additionalContext'] = '...'
    t = wire['remediation']['agent_fix_ticket']
    assert t['remediation_ref'] == ticket(data)['remediation_ref']
    checked = fix(data)
    assert checked['remediation'].get('reason_code') == 'SCANNER_VERIFIED_RESOLVED', checked['remediation']
    assert checked['remediation']['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert checked['remediation']['security_verification']['task_ref'] == t['task_ref']
    assert checked['remediation']['security_verification']['grant_id'] == t['grant_id']
    assert record(data)['phase'] == 'CLOSED'
    assert checked['remediation']['agent_fix_ticket_diagnostics']['prepare_task_fix_call_count'] == 0
    assert data[2].calls  # The original verification scanner actually ran (unit provider).


def test_hook_text_projection_uses_same_ticket_not_duplicate_report(inline_setup):
    # The new ticket comes from the explicit confirmation response, not the
    # pre-consent Hook text. Structured consent response remains source-free.
    response = inline_setup[-1]['remediation']
    assert response['agent_fix_ticket'] == ticket(inline_setup)
    assert response['authorization_kind'] == 'USER_CONFIRMED'
    assert len(encoded(response['agent_fix_ticket'])) <= MAX_BYTES
    assert 'already prepared' in response['guidance']


def test_original_prepare_checks_reused_and_prepared_cannot_skip_them(inline_setup, monkeypatch):
    service = inline_setup[3]; original = service._prepare; seen = []
    def failing(*args, **kwargs):
        seen.append(args); return service._fail('TEST_PREPARE_REJECTED')
    # Fresh recurrence tests the initial offer again, never reuses the old grant.
    fix(inline_setup); monkeypatch.setattr(service, '_prepare', failing)
    out = recur(inline_setup)['remediation']
    assert len(seen) == 1 and 'agent_fix_ticket' not in out
    assert out['agent_fix_ticket_diagnostics']['prepare_task_fix_required']
    assert not service.prepared
    monkeypatch.setattr(service, '_prepare', original)
    args = out['prepare']['arguments']
    assert service.prepare(args['remediation_ref'], args['task_ref'], inline_setup[0])['status'] == 'READY_FOR_HOST_FIX'


@pytest.mark.parametrize('field', ['snapshot_digest', 'episode_id', 'grant_id', 'allowed_target_paths',
                                   'remediation_ref', 'task_ref', 'origin_scan_id', 'scope_hash'])
def test_changed_canonical_ticket_never_closes(inline_setup, field):
    data = inline_setup; item = data[3].agent_tickets.items[ticket(data)['grant_id']]
    item['ticket'][field] = ['Other.java'] if field == 'allowed_target_paths' else 'changed'
    out = fix(data)['remediation']
    assert out['action'] == 'ESCALATE' and record(data)['resolution'] is None
    assert out['agent_fix_ticket_diagnostics']['ticket_stale_reason'] == 'TICKET_BINDING_CHANGED'


@pytest.mark.parametrize('change', ['same_target_extra', 'other_file', 'wrong_target', 'intervening_hook'])
def test_unexpected_edit_is_sticky_and_never_manual_recovery_closes(inline_setup, change):
    data = inline_setup
    if change == 'same_target_extra': out = fix(data, suffix='// unrelated\n')
    elif change == 'other_file':
        data[0].joinpath('Other.java').write_text('class Other {}'); out = fix(data)
    elif change == 'wrong_target':
        data[0].joinpath('Other.java').write_text('class Other {}'); out = data[4]()
    else:
        data[0].joinpath('A.java').write_text(UNSAFE + '// intervening\n'); out = data[4]()
    assert out['remediation']['action'] == 'ESCALATE' and record(data)['phase'] != 'CLOSED'
    assert record(data)['inline_agent_ticket']['status'] == 'STALE'
    # Even a later exact removal cannot launder an already invalidated ticket.
    fix(data)
    assert record(data)['resolution'] is None
    t = ticket(data)
    assert data[3].verify(t['remediation_ref'], t['task_ref'], data[0])['verification_status'] == 'INCONCLUSIVE'


@pytest.mark.parametrize('loss', ['expiry', 'clock', 'restart', 'policy'])
def test_expiry_restart_policy_fail_closed(inline_setup, loss):
    data = inline_setup; service = data[3]; t = ticket(data)
    if loss == 'expiry': service.agent_tickets.clock = lambda: service.agent_tickets.items[t['grant_id']]['deadline'] + 1
    elif loss == 'clock': service.agent_tickets.clock = lambda: float('nan')
    elif loss == 'restart': service.agent_tickets.items.clear(); service.prepared.clear()
    else: service.config.write('report_only')
    out = fix(data)['remediation']
    assert record(data)['phase'] == 'ESCALATED' and record(data)['resolution'] is None
    expected = {'expiry':'TICKET_EXPIRED','clock':'TICKET_CLOCK_UNAVAILABLE',
                'restart':'TICKET_ATTESTATION_LOST','policy':'TICKET_POLICY_CHANGED'}[loss]
    assert out['agent_fix_ticket_diagnostics']['ticket_stale_reason'] == expected


def test_expired_unused_ticket_can_fall_back_to_fresh_legacy_prepare(inline_setup):
    data = inline_setup; service = data[3]; t = ticket(data)
    service.agent_tickets.items[t['grant_id']]['deadline'] = 0
    before = data[0].joinpath('A.java').read_bytes()
    prepared = service.prepare(t['remediation_ref'], t['task_ref'], data[0])
    assert prepared['status'] == 'READY_FOR_HOST_FIX'
    assert 'inline_agent_ticket' not in record(data)
    assert before == data[0].joinpath('A.java').read_bytes()
    assert fix(data)['remediation']['reason_code'] == 'SCANNER_VERIFIED_RESOLVED'


def test_recurrence_new_ticket_and_old_refs_rejected(inline_setup):
    data = inline_setup; first = copy.deepcopy(ticket(data)); fix(data)
    out = recur(data)['remediation']; second = out['agent_fix_ticket']
    assert second['episode_id'] != first['episode_id']
    assert second['grant_id'] != first['grant_id'] and second['task_ref'] != first['task_ref']
    assert second['prepared_attestation'] != first['prepared_attestation']
    # Same file bytes can recur: the opaque snapshot digest may equal episode 1;
    # fresh scan/Episode/grant prevent reuse (do not invent a different digest).
    assert second['origin_scan_id'] != first['origin_scan_id']
    assert first['grant_id'] not in data[3].agent_tickets.items
    rejected = data[3].verify(first['remediation_ref'], first['task_ref'], data[0])
    assert rejected['verification_status'] == 'INCONCLUSIVE'
    with pytest.raises(ValueError, match='REMEDIATION_EPISODE_SUPERSEDED'):
        data[3]._reference(data[0], first['remediation_ref'], first['task_ref'])
    assert record(data)['phase'] == 'AUTHORIZED'
    assert fix(data)['remediation']['reason_code'] == 'SCANNER_VERIFIED_RESOLVED'


def test_closed_security_proof_does_not_expire_with_ticket(inline_setup):
    data = inline_setup; t = ticket(data); fix(data)
    proof = record(data)['resolution']
    data[3].agent_tickets.items.clear()
    out = data[3].verify(t['remediation_ref'], t['task_ref'], data[0])
    assert out['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert record(data)['resolution'] == proof


def test_wrong_workspace_and_wrong_opaque_refs_fail_closed(inline_setup, tmp_path):
    data = inline_setup; t = ticket(data)
    for ref, task, root in [(t['remediation_ref'], t['task_ref'], tmp_path/'other'),
                            (t['remediation_ref'] + '0', t['task_ref'], data[0]),
                            (t['remediation_ref'], t['task_ref'] + '0', data[0])]:
        assert data[3].verify(ref, task, root)['verification_status'] == 'INCONCLUSIVE'
    assert record(data)['phase'] == 'AUTHORIZED'


def test_no_deep_calls_and_nonoverlapping_monotonic_cycle(inline_setup, monkeypatch):
    from security_runtime.functional_verification import FunctionalVerificationService
    def forbidden(*args, **kwargs): pytest.fail('Deep Verification entered Core')
    monkeypatch.setattr(FunctionalVerificationService, 'prepare', forbidden)
    out = fix(inline_setup)
    assert out['remediation']['next_action'] == 'RETURN_TO_HOST'
    segments = out['remediation_cycle_breakdown_ms']
    assert segments['prepare_fix'] is None and segments['host_fix_window'] is None
    assert segments['inline_host_edit_window'] >= 0 and segments['unaccounted'] >= 0
    assert abs(sum(v for v in segments.values() if v is not None) - out['remediation_cycle_wall_ms']) < .05
    assert out['remediation_cycle_timepoints_ms']['inline_prepare_finished'] >= out['remediation_cycle_timepoints_ms']['inline_prepare_started']
    assert out['remediation_cycle_timepoints_ms']['host_received_advisory'] is None


def test_legacy_embedded_host_unchanged(legacy_setup):
    assert 'agent_fix_ticket' not in legacy_setup[-1]['remediation']
    assert not legacy_setup[3].prepared


@pytest.mark.parametrize('inline_setup', ['ask_before_fix'], indirect=True)
def test_confirmed_policy_is_not_inline(inline_setup):
    grant = inline_setup[-1]['remediation']
    assert grant['action'] == 'CONFIRM_REQUIRED' and 'agent_fix_ticket' not in grant


def test_default_mcp_activation_and_exact_input_schema(inline_setup, monkeypatch):
    from security_runtime.mcp_server import create_server
    from security_runtime.hook_runtime import HookCoordinator
    data = inline_setup; holder = []; original = RemediationService.__init__
    def captured(self, *args, **kwargs):
        kwargs['inline_agent_tickets'] = False; original(self, *args, **kwargs); holder.append(self)
    monkeypatch.setattr(RemediationService, '__init__', captured)
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', str(data[0]))
    server = create_server(data[1], hook_coordinator=HookCoordinator(data[1], data[3].hooks, cooldown_ms=0))
    assert holder[-1].agent_tickets.enabled
    async def check():
        tools = await server.list_tools()
        schema = next(t.inputSchema for t in tools if t.name == 'handle_hook_event')
        assert set(schema['properties']) == {'event','workspace_path','session_id','tool_name','tool_input',
                                            'turn_id','tool_use_id','permission_mode'}
        assert not schema['additionalProperties']
    asyncio.run(check())


def test_ambiguous_whole_line_keeps_legacy_prepare(inline_setup):
    data = inline_setup
    from security_runtime.models import Finding
    finding = Finding(**data[1].store.get_scan(record(data)['origin_scan_id'])['findings'][0])
    fix(data)
    data[0].joinpath('A.java').write_text(UNSAFE.replace('-> true);', '-> true); // preserve this comment'))
    data[1].findings = data[2].findings = [finding]
    from test_remediation import approve_hook
    out = approve_hook(data[3], data[0], data[4]())['remediation']
    assert out['action'] == 'AUTO_FIX' and 'agent_fix_ticket' not in out
    assert out['agent_fix_ticket_diagnostics']['prepare_task_fix_required']
    args = out['prepare']['arguments']
    assert data[3].prepare(args['remediation_ref'], args['task_ref'], data[0])['status'] == 'READY_FOR_HOST_FIX'


def test_reloaded_signed_marker_cannot_restore_connection_authority(inline_setup):
    data = inline_setup; t = ticket(data)
    restarted = RemediationService(data[3].store, registry=data[3].registry, hooks=data[3].hooks,
                                    inline_agent_tickets=True)
    data[0].joinpath('A.java').write_text(FIXED)
    data[2].findings = []
    out = restarted.verify(t['remediation_ref'], t['task_ref'], data[0])
    assert out['reason_code'] == 'TICKET_ATTESTATION_LOST'
    assert record(data)['resolution'] is None


def test_observed_mismatched_hook_snapshot_invalidates_ticket(inline_setup):
    data = inline_setup; service = data[3]
    result = {'change_digest':'0'*64}
    out = service.on_hook(result, data[0], 'session', host='codex')
    assert out['reason_code'] == 'HOOK_SNAPSHOT_CHANGED'
    assert record(data)['inline_agent_ticket']['status'] == 'STALE'
    fix(data)
    assert record(data)['resolution'] is None


@pytest.mark.parametrize('status', ['FAILED', 'UNAVAILABLE'])
def test_inline_edit_without_real_scanner_proof_cannot_close(inline_setup, status):
    data = inline_setup; data[2].status = status
    out = fix(data)['remediation']
    assert out['verification']['verification_status'] == 'INCONCLUSIVE'
    assert record(data)['resolution'] is None and record(data)['phase'] == 'ESCALATED'


def test_post_policy_does_not_deduct_previous_hook_preparation(inline_setup):
    data = inline_setup; token = ticket(data)['grant_id']
    # Deterministic accounting test, not a scanner performance benchmark.
    data[3].phase_timing[token]['preparation_ms'] = 1_000_000
    out = fix(data)
    assert out['timing_ms']['remediation_preparation'] == 1_000_000
    assert out['timing_ms']['finding_policy'] > 0
    assert out['remediation']['reason_code'] == 'SCANNER_VERIFIED_RESOLVED'


def test_old_host_can_prepare_with_current_inline_context_hint(inline_setup):
    data = inline_setup; t = ticket(data)
    out = data[3].prepare(t['remediation_ref'], t['task_ref'], data[0],
                          security_context_ref=t['security_context_ref'])
    assert out['status'] == 'READY_FOR_HOST_FIX' and out['security_context_status'] == 'REUSE_HOOK_CONTEXT'
    assert out['security_fix_context_ref'] == t['security_context_ref']
    assert out['verification_plan']['arguments']['remediation_ref'] == t['remediation_ref']
    assert record(data)['token_hash'] in data[3].prepared
    assert 'inline_agent_ticket' not in record(data)
    assert out['agent_fix_ticket_diagnostics']['prepare_task_fix_call_count'] == 1
    assert fix(data)['remediation']['reason_code'] == 'SCANNER_VERIFIED_RESOLVED'
