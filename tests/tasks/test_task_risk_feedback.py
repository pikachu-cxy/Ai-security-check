"""Host candidate feedback stays distinct from fixes and scanner proof."""
import copy
import json
import subprocess
import sys

import pytest

from security_runtime.tasks.risk_feedback import TaskRiskFeedbackService
from security_runtime.tasks.risk_ledger import TaskRiskLedger
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.security import TaskSecurityService
from test_task_security import service, candidate  # noqa: F401; shared fixture
from task_review_helpers import review_all, evidence_id
from test_task_review_protocol_mcp import local_call
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.mcp_server import create_server
from security_runtime.tasks.ownership import issue_session_ref


@pytest.fixture(autouse=True)
def frozen_review_identity(monkeypatch):
    # Model a single immutable installed build while other tests develop code.
    import security_runtime.build_identity as builds
    import security_runtime.tasks.security as tasks
    monkeypatch.setattr(builds, 'build_identity', lambda: dict(status='IDENTIFIED', build_id='a'*64))
    original = tasks.method
    monkeypatch.setattr(tasks, 'method', lambda version=3: dict(original(version), sha256='b'*64))


def host_risk(sample, *, category=None):
    s, root, _ = sample
    ref = s.begin(root, 'host-risk-feedback')['task_ref']
    (root/'routes.py').write_text('def get_order(order_id, user):\n    return load_order(order_id)\n')
    packet = s.prepare(root, ref, protocol_version=3)
    main = s.read(root, ref, packet['review_session'], 'routes.py', 1, 2, source_version='CURRENT')
    related = s.read(root, ref, packet['review_session'], 'auth.py', 1, 2)
    review_all(s, root, ref, dict(packet, plan=s.review_plan(root, ref, packet['review_session'])))
    finding = candidate(evidence_id(main), evidence_id(related))
    if category:
        finding['category'] = category
    result = s.submit(root, ref, packet['review_session'], [finding], 'REVIEWED', [])
    assert result['result_saved'] and not result['scanner_run']
    return s, root, ref, s.get(root, ref)['findings'][0]['detail']['id']


def submit_false_positive(feedback, s, root, ref, finding_id, packet):
    return feedback.submit(s, root, ref, finding_id, packet['feedback_ref'], 'FALSE_POSITIVE',
        'The recorded control protects this original call path.',
        ['The issued control source contains an ownership comparison.'],
        [source['evidence_ref'] for source in packet['sources']],
        ['Ownership control is present.'], [])


def test_prepare_is_read_only_bounded_and_does_not_restart_or_renew_task(service):
    s, root, ref, finding_id = host_risk(service)
    feedback = TaskRiskFeedbackService()
    saved = copy.deepcopy(s.load(root, ref))
    ledger = TaskRiskLedger(s.hooks, root)
    before = ledger.path.read_bytes()
    packet = feedback.prepare(s, root, ref, finding_id)
    assert packet['context_complete'] and len(packet['sources']) == 2
    assert all('file_sha256' not in source for source in packet['sources'])
    assert packet['review_type'] == 'HOST_CODE_REVIEW_NOT_SCANNER_PROOF'
    assert not packet['scanner_run'] and not packet['repair_authorized']
    assert all('technical_details' not in source for source in packet['sources'])
    assert s.load(root, ref) == saved and ledger.path.read_bytes() == before


@pytest.mark.parametrize('flag', [False, 1, 'true', None])
def test_user_marking_requires_literal_true_and_is_never_auto_confirmed(service, flag):
    s, root, ref, finding_id = host_risk(service)
    feedback = TaskRiskFeedbackService()
    with pytest.raises(ValueError, match='explicit user'):
        feedback.mark(s, root, ref, finding_id, 'User believes this is a false positive.', user_requested=flag)
    result = feedback.mark(s, root, ref, finding_id, 'User believes this is a false positive.', user_requested=True)
    assert result['feedback']['status'] == 'USER_MARKED_FALSE_POSITIVE'
    assert result['feedback']['folded'] is False
    assert result['original_risk_status'] == 'OPEN'


def test_host_confirmation_folds_only_unchanged_evidence_and_retains_original_open_and_audit(service):
    s, root, ref, finding_id = host_risk(service)
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding_id)
    result = submit_false_positive(feedback, s, root, ref, finding_id, packet)
    assert result['feedback']['status'] == 'HOST_FALSE_POSITIVE'
    assert result['feedback']['folded'] is True
    assert result['feedback']['evidence_type'] == 'HOST_CODE_REVIEW_NOT_SCANNER_PROOF'
    assert result['original_risk_status'] == 'OPEN'
    row = s.risk_ledger(root, ref)['items'][0]
    assert row['status'] == 'OPEN' and row['feedback']['folded']
    assert 'feedback_events' not in row and row['feedback_audit_event_count'] == 1
    assert row['feedback_detail']['tool'] == 'get_task_risk_feedback'
    history = s.get(root, ref)
    assert history['host_review']['finding_count'] == 1
    assert history['current_feedback']['folded_host_risk_count'] == 1
    assert history['current_feedback']['visible_host_risk_count'] == 0
    assert history['findings'][0]['detail']['feedback']['folded']
    assert not history['risk_choices']
    ledger = TaskRiskLedger(s.hooks, root)
    assert ledger.read()[ref+':'+finding_id]['status'] == 'OPEN'
    assert len(ledger.read()[ref+':'+finding_id]['feedback_events']) == 1
    with pytest.raises(ValueError, match='consumed'):
        submit_false_positive(feedback, s, root, ref, finding_id, packet)


@pytest.mark.parametrize('change', ['source', 'control', 'config-add', 'policy'])
def test_current_source_control_configuration_or_policy_changes_unfold_without_losing_history(service, monkeypatch, change):
    s, root, ref, finding_id = host_risk(service)
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding_id)
    submit_false_positive(feedback, s, root, ref, finding_id, packet)
    if change == 'source':
        (root/'routes.py').write_text('def route(user):\n    return policy.other(user)\n')
    elif change == 'control':
        (root/'auth.py').write_text('def owns(user, order):\n    return True\n')
    elif change == 'config-add':
        (root/'rules.yml').write_text('rules: []\n')
    else:
        monkeypatch.setenv('SECURITY_RUNTIME_EXCLUDE_DIRS', 'other-directory')
    result = feedback.get(s, root, ref, finding_id)
    assert result['feedback']['status'] == 'NEEDS_RECHECK'
    assert result['feedback']['recorded_status'] == 'HOST_FALSE_POSITIVE'
    assert not result['feedback']['folded']
    assert result['audit_events'][0]['status'] == 'HOST_FALSE_POSITIVE'


def test_changed_source_between_prepare_and_submit_rejects_old_confirmation(service):
    s, root, ref, finding_id = host_risk(service)
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding_id)
    (root/'auth.py').write_text('def owns(user, order):\n    return True\n')
    with pytest.raises(ValueError, match='evidence changed'):
        submit_false_positive(feedback, s, root, ref, finding_id, packet)
    assert feedback.get(s, root, ref, finding_id)['feedback']['status'] == 'NOT_MARKED'


def test_masked_secret_source_cannot_be_host_confirmed_as_false_positive(service):
    s, root, ref, finding_id = host_risk(service, category='secret')
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding_id)
    assert not packet['context_complete']
    assert 'SECRET_VALUE_NOT_AVAILABLE_FOR_HOST_VERIFICATION' in packet['limitations']
    result = submit_false_positive(feedback, s, root, ref, finding_id, packet)
    assert result['feedback']['status'] == 'INCONCLUSIVE'
    assert not result['feedback']['folded']


def test_missing_issued_context_reference_never_folds_a_false_positive(service):
    s, root, ref, finding_id = host_risk(service)
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding_id)
    result = feedback.submit(s, root, ref, finding_id, packet['feedback_ref'], 'FALSE_POSITIVE',
        'The control seems present.', ['An ownership check was observed.'],
        [packet['sources'][0]['evidence_ref']])
    assert result['feedback']['status'] == 'INCONCLUSIVE' and not result['feedback']['folded']


def test_expired_other_connection_and_wrong_owner_cannot_reuse_a_feedback_token(service):
    s, root, ref, finding_id = host_risk(service)
    now = [100.0]
    feedback = TaskRiskFeedbackService(now=lambda: now[0])
    packet = feedback.prepare(s, root, ref, finding_id)
    other_connection = TaskRiskFeedbackService(now=lambda: now[0])
    with pytest.raises(ValueError, match='another session'):
        submit_false_positive(other_connection, s, root, ref, finding_id, packet)
    now[0] += 901
    with pytest.raises(ValueError, match='expired'):
        submit_false_positive(feedback, s, root, ref, finding_id, packet)
    outsider = TaskSecurityService(s.runtime, s.hooks, owner=session_owner('codex', 'other-feedback-owner'))
    with pytest.raises(ValueError, match='another session'):
        feedback.prepare(outsider, root, ref, finding_id)


def test_revoke_restores_visible_risk_and_retains_prior_event(service):
    s, root, ref, finding_id = host_risk(service)
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding_id)
    submit_false_positive(feedback, s, root, ref, finding_id, packet)
    with pytest.raises(ValueError, match='explicit user'):
        feedback.revoke(s, root, ref, finding_id, 'Undo the decision.')
    revoked = feedback.revoke(s, root, ref, finding_id, 'Undo the decision.', user_requested=True)
    assert revoked['feedback']['status'] == 'REVOKED' and not revoked['feedback']['folded']
    assert revoked['audit_event_count'] == 2 and revoked['original_risk_status'] == 'OPEN'
    view = feedback.get(s, root, ref, finding_id)
    assert [event['status'] for event in view['audit_events']] == ['HOST_FALSE_POSITIVE', 'REVOKED']


@pytest.mark.parametrize('verdict,expected', [('STILL_RISK', 'STILL_PRESENT'), ('NEEDS_CONTEXT', 'INCONCLUSIVE')])
def test_other_host_verdicts_keep_risk_expanded(service, verdict, expected):
    s, root, ref, finding_id = host_risk(service)
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding_id)
    result = feedback.submit(s, root, ref, finding_id, packet['feedback_ref'], verdict,
        'The protection is not sufficient to dismiss this candidate.',
        ['The known protection has limited scope.'],
        [source['evidence_ref'] for source in packet['sources']])
    assert result['feedback']['status'] == expected and not result['feedback']['folded']


def test_actual_local_mcp_feedback_flow_uses_signed_owner_and_strict_arguments(service):
    s, root, runtime = service
    s.owner = session_owner('codex', 'task-feedback-conversation')
    token = issue_session_ref(s.hooks, root, 'codex', 'task-feedback-conversation')
    s, root, ref, finding_id = host_risk(service)
    server = create_server(runtime, hook_coordinator=HookCoordinator(runtime, s.hooks), global_mode=False)
    base = dict(task_ref=ref, finding_id=finding_id, workspace_path=str(root), session_ref=token)
    packet = local_call(server, 'prepare_task_risk_feedback', **base)
    assert packet['context_complete']
    with pytest.raises(Exception):
        local_call(server, 'mark_task_risk_false_positive', **base, reason='A user mark.', user_requested=1)
    marked = local_call(server, 'mark_task_risk_false_positive', **base,
                        reason='The user reports a missing countercheck.', user_requested=True)
    assert not marked['feedback']['folded']
    result = local_call(server, 'submit_task_risk_feedback', **base,
        feedback_ref=packet['feedback_ref'], verdict='FALSE_POSITIVE',
        rationale='The provided control source covers the original risk path.',
        counterevidence=['The issued comparison binds ownership.'],
        evidence_refs=[source['evidence_ref'] for source in packet['sources']])
    assert result['feedback']['folded'] and result['original_risk_status'] == 'OPEN'
    viewed = local_call(server, 'get_task_risk_feedback', task_ref=ref,
                        finding_id=finding_id, workspace_path=str(root))
    assert viewed['feedback']['status'] == 'HOST_FALSE_POSITIVE'
    revoked = local_call(server, 'revoke_task_risk_feedback', **base,
                        reason='The user withdraws the mark.', user_requested=True)
    assert not revoked['feedback']['folded'] and revoked['audit_event_count'] == 3
    assert len(runtime.calls) == 1


def test_current_feedback_projection_does_not_rewrite_saved_history_summary(service):
    s, root, ref, finding_id = host_risk(service)
    original = s.get(root, ref)
    saved = copy.deepcopy(s.load(root, ref))
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding_id)
    submit_false_positive(feedback, s, root, ref, finding_id, packet)
    result = s.get(root, ref)
    assert result['development_summary'] == original['development_summary']
    assert result['host_review']['finding_count'] == 1
    assert result['current_feedback']['visible_host_risk_count'] == 0
    assert s.load(root, ref) == saved
    (root/'auth.py').write_text('def owns(user, order):\n    return True\n')
    changed = s.get(root, ref)
    assert changed['current_feedback']['visible_host_risk_count'] == 1
    assert changed['current_feedback']['folded_host_risk_count'] == 0


@pytest.mark.parametrize('kind', ['build', 'method', 'unavailable'])
def test_runtime_build_or_method_changes_unfold_existing_confirmation(service, monkeypatch, kind):
    import security_runtime.build_identity as builds
    import security_runtime.tasks.security as tasks
    s, root, ref, finding_id = host_risk(service)
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding_id)
    submit_false_positive(feedback, s, root, ref, finding_id, packet)
    if kind == 'build':
        monkeypatch.setattr(builds, 'build_identity', lambda: dict(status='IDENTIFIED', build_id='c'*64))
    elif kind == 'method':
        original = tasks.method
        monkeypatch.setattr(tasks, 'method', lambda version=3: dict(original(version), sha256='d'*64))
    else:
        monkeypatch.setattr(builds, 'build_identity', lambda: dict(status='UNVERIFIABLE_LEGACY_BUNDLE'))
    result = feedback.get(s, root, ref, finding_id)
    assert result['feedback']['status'] == 'NEEDS_RECHECK'
    assert not result['feedback']['folded']


def test_unknown_build_identity_prevents_false_positive_confirmation(service, monkeypatch):
    import security_runtime.build_identity as builds
    s, root, ref, finding_id = host_risk(service)
    monkeypatch.setattr(builds, 'build_identity', lambda: dict(status='UNVERIFIABLE_LEGACY_BUNDLE'))
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding_id)
    assert 'RUNTIME_BUILD_OR_REVIEW_METHOD_UNAVAILABLE' in packet['limitations']
    result = submit_false_positive(feedback, s, root, ref, finding_id, packet)
    assert not result['feedback']['folded'] and result['feedback']['status'] == 'INCONCLUSIVE'


def test_known_opaque_secret_lines_and_free_text_never_escape_or_persist_in_feedback(service):
    s, root, _ = service
    opaque = 'opaqueCanaryValueForPrivacyBoundary'
    (root/'auth.py').write_text('def owns(user, order):\n    marker = '+repr(opaque)+'\n    return user.id == order.owner_id\n')
    s, root, ref, finding_id = host_risk(service)
    saved = s.load(root, ref)
    saved['static']['findings'].append(dict(id='known-secret', category='secret', title='Known secret marker',
        file_path='auth.py', line_start=2, line_end=2))
    saved['review']['findings'][0]['impact'] += ' '+opaque
    s.store(root).save(saved)
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding_id)
    assert opaque not in json.dumps(packet)
    assert any(value.startswith('KNOWN_SECRET_RANGE_MASKED:') for value in packet['limitations'])
    result = feedback.mark(s, root, ref, finding_id,
        'The original value '+opaque+' is a test marker.', user_requested=True)
    assert opaque not in json.dumps(result)
    raw = TaskRiskLedger(s.hooks, root).read()[ref+':'+finding_id]
    assert opaque not in json.dumps(raw['feedback_events'])
    assert '[REDACTED_SECRET]' in json.dumps(raw['feedback_events'])


def test_feedback_audit_capacity_keeps_one_final_revocation_without_deleting_events(service):
    s, root, ref, finding_id = host_risk(service)
    ledger = TaskRiskLedger(s.hooks, root)
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding_id)
    submit_false_positive(feedback, s, root, ref, finding_id, packet)
    rows = ledger.read()
    key = ref+':'+finding_id
    original_event = rows[key]['feedback_events'][0]
    rows[key]['feedback_events'] = [dict(original_event, event_id=f'event-{index}') for index in range(20)]
    with s.hooks.lock(root) as acquired:
        assert acquired
        ledger.save(rows)
    with pytest.raises(ValueError, match='audit limit'):
        feedback.mark(s, root, ref, finding_id, 'Another mark.', user_requested=True)
    result = feedback.revoke(s, root, ref, finding_id, 'Undo the mark.', user_requested=True)
    assert result['audit_event_count'] == 21 and not result['feedback']['folded']
    again = feedback.revoke(s, root, ref, finding_id, 'Undo again.', user_requested=True)
    assert again['audit_event_count'] == 21
    assert len(ledger.read()[key]['feedback_events']) == 21


def test_unverifiable_known_secret_context_withholds_source_and_reason_text(service):
    s, root, _ = service
    opaque = 'opaquePrivacyCanaryFromPreviousSource'
    (root/'auth.py').write_text('def owns(user, order):\n    marker = '+repr(opaque)+'\n    return True\n')
    s, root, ref, finding_id = host_risk(service)
    record = s.load(root, ref)
    record['static']['findings'].append(dict(id='known-secret', category='secret', title='Known secret marker',
        file_path='auth.py', line_start=2, line_end=2))
    s.store(root).save(record)
    (root/'auth.py').write_text('def owns(user, order):\n    return user.id == order.owner_id\n')
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding_id)
    assert 'KNOWN_SECRET_CONTEXT_UNAVAILABLE' in packet['limitations']
    assert not packet['sources'] and not packet['context_complete']
    result = feedback.mark(s, root, ref, finding_id, opaque, user_requested=True)
    assert opaque not in json.dumps(result)
    audit = feedback.get(s, root, ref, finding_id)['audit_events']
    assert opaque not in json.dumps(audit)
    assert audit[0]['reason'] == '[REDACTED_REASON_UNVERIFIABLE_SECRET_CONTEXT]'


def test_unclosed_thousand_character_escaped_string_has_bounded_secret_parsing(tmp_path):
    # A child timeout protects the test run itself from reintroducing an
    # exponential regex when untrusted source contains an unterminated string.
    script = r'''
import hashlib
import json
from pathlib import Path
import sys
from security_runtime.tasks.risk_feedback import _known_secrets, _quoted_literals
root = Path(sys.argv[1])
line = '"' + '\\' * 998
assert len(line) == 999 and list(_quoted_literals(line)) == []
raw = (line + '\n').encode()
(root / 'sample.py').write_bytes(raw)
record = {'end': {'hashes': {'sample.py': hashlib.sha256(raw).hexdigest()}},
          'static': {'findings': [{'category': 'secret', 'file_path': 'sample.py',
                                   'line_start': 1, 'line_end': 1}]}}
values, incomplete = _known_secrets(root, record)
assert incomplete and line in values
print('linear parsing completed')
'''
    result = subprocess.run([sys.executable, '-c', script, str(tmp_path)],
                            capture_output=True, text=True, timeout=5, check=True)
    assert 'linear parsing completed' in result.stdout


@pytest.mark.parametrize('line', [
    'api_key = `synth\\u0065tic-material`',
    'api_key = "synthetic-material"; other = "unterminated',
])
def test_unsupported_or_partly_unclosed_known_secret_marks_context_unknown(tmp_path, line):
    import hashlib
    from security_runtime.tasks.risk_feedback import _known_secrets
    raw = (line + '\n').encode()
    (tmp_path/'sample.py').write_bytes(raw)
    record = {'end': {'hashes': {'sample.py': hashlib.sha256(raw).hexdigest()}},
              'static': {'findings': [{'category':'secret', 'file_path':'sample.py',
                                       'line_start':1, 'line_end':1}]}}
    _, incomplete = _known_secrets(tmp_path, record)
    assert incomplete


@pytest.mark.parametrize('source', ['HUMAN', 'AI'])
def test_twenty_first_known_secret_range_never_leaks_in_feedback_text(service, source):
    s, root, _ = service
    values = [f'opaqueKnownCredential{index:02d}' for index in range(21)]
    lines = ['def owns(user, order):']
    lines.extend(f'    marker_{index} = {value!r}' for index, value in enumerate(values))
    lines.append('    return user.id == order.owner_id')
    (root/'auth.py').write_text('\n'.join(lines) + '\n')
    s, root, ref, finding_id = host_risk(service)
    saved = s.load(root, ref)
    saved['static']['findings'].extend(dict(id=f'known-secret-{index}', category='secret',
        title='Known credential context', file_path='auth.py', line_start=index+2,
        line_end=index+2) for index in range(21))
    s.store(root).save(saved)
    feedback = TaskRiskFeedbackService()
    if source == 'HUMAN':
        result = feedback.mark(s, root, ref, finding_id,
            'The last value ' + values[-1] + ' is synthetic.', user_requested=True)
    else:
        packet = feedback.prepare(s, root, ref, finding_id)
        assert 'KNOWN_SECRET_CONTEXT_UNAVAILABLE' in packet['limitations']
        assert not packet['sources'] and not packet['context_complete']
        result = feedback.submit(s, root, ref, finding_id, packet['feedback_ref'], 'NEEDS_CONTEXT',
            'The last value ' + values[-1] + ' is unverified.', [], [], unknowns=['Validity unknown'])
    assert values[-1] not in json.dumps(result)
    audit = feedback.get(s, root, ref, finding_id)['audit_events']
    assert values[-1] not in json.dumps(audit)
    assert '[REDACTED_REASON_UNVERIFIABLE_SECRET_CONTEXT]' in json.dumps(audit)
