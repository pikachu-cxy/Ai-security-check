"""User handling never needs AI approval or rewrites a risk's truth/history."""
from datetime import datetime, timezone
import json

import pytest

from security_runtime.task_ownership import session_owner
from security_runtime.task_risk_feedback import TaskRiskFeedbackService
from security_runtime.task_risk_ledger import TaskRiskLedger
from security_runtime.task_security import TaskSecurityService
from security_runtime.task_review_results import bounded_history_result
from test_task_security import service, candidate  # noqa: F401
from task_review_helpers import review_all, evidence_id
from test_task_risk_feedback import host_risk, submit_false_positive, frozen_review_identity  # noqa: F401


def repeat_risk(sample):
    s, root, _ = sample
    ref = s.begin(root, 'new-development-context')['task_ref']
    (root/'routes.py').write_text('# A harmless comment moves the same issue.\n' +
        'def get_order(order_id, user):\n    return load_order(order_id)\n')
    packet = s.prepare(root, ref, protocol_version=3)
    main = s.read(root, ref, packet['review_session'], 'routes.py', 1, 3, source_version='CURRENT')
    related = s.read(root, ref, packet['review_session'], 'auth.py', 1, 2)
    review_all(s, root, ref, dict(packet, plan=s.review_plan(root, ref, packet['review_session'])))
    result = s.submit(root, ref, packet['review_session'],
        [candidate(evidence_id(main), evidence_id(related))], 'REVIEWED', [])
    assert result['result_saved'] and not result['scanner_run']
    return s, root, ref, s.get(root, ref)['findings'][0]['detail']['id']


@pytest.mark.parametrize('requested', [False, None, 1, 'true'])
def test_user_choice_requires_explicit_boolean_request(service, requested):
    s, root, ref, finding = host_risk(service)
    with pytest.raises(ValueError, match='direct user request'):
        TaskRiskFeedbackService().set_disposition(
            s, root, ref, finding, 'EXCLUDE', user_requested=requested)


def test_exclude_saves_without_agent_approval_and_keeps_original_technical_state(service):
    s, root, ref, finding = host_risk(service)
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding)
    feedback.submit(s, root, ref, finding, packet['feedback_ref'], 'STILL_RISK',
        'The known protection does not cover the call.', ['The call still skips the check.'],
        [source['evidence_ref'] for source in packet['sources']])
    result = feedback.set_disposition(s, root, ref, finding, 'EXCLUDE', user_requested=True)
    assert result['handling_status'] == 'EXCLUDED'
    assert result['handling_source'] == 'USER_DECISION'
    assert result['technical_feedback']['status'] == 'STILL_PRESENT'
    assert result['original_risk_status'] == 'OPEN'
    assert result['reminder_suppressed'] and not result['repair_authorized']
    history = s.get(root, ref)
    assert not history['risk_choices']
    assert history['current_feedback']['folded_host_risk_count'] == 0
    assert history['current_feedback']['suppressed_host_risk_count'] == 1
    ledger = s.risk_ledger(root, ref)
    assert ledger['counts'] == {'OPEN': 1} and ledger['pending_count'] == 0
    assert ledger['items'][0]['handling_label'] == '已排除'
    restored_connection = TaskRiskFeedbackService()
    saved = restored_connection.get(s, root, ref, finding)
    assert saved['disposition_audit_events'][0]['disposition'] == 'EXCLUDE'
    assert saved['technical_feedback']['status'] == 'STILL_PRESENT'


def test_excluding_one_occurrence_does_not_hide_same_category_in_sibling_function(service):
    s, root, _ = service
    ref = s.begin(root, 'two-risk-occurrences')['task_ref']
    (root/'routes.py').write_text('def first(user):\n    return load_order(user)\n\n'
                                'def second(user):\n    return load_order(user)\n')
    packet = s.prepare(root, ref, protocol_version=3)
    first = s.read(root, ref, packet['review_session'], 'routes.py', 2, 2)
    second = s.read(root, ref, packet['review_session'], 'routes.py', 5, 5)
    related = s.read(root, ref, packet['review_session'], 'auth.py', 1, 2)
    review_all(s, root, ref, dict(packet, plan=s.review_plan(root, ref, packet['review_session'])))
    candidates = [candidate(evidence_id(item), evidence_id(related)) for item in (first, second)]
    s.submit(root, ref, packet['review_session'], candidates, 'REVIEWED', [])
    findings = s.load(root, ref)['review']['findings']
    feedback = TaskRiskFeedbackService()
    feedback.set_disposition(s, root, ref, findings[0]['id'], 'EXCLUDE', user_requested=True)
    history = s.get(root, ref)
    assert [item['finding_id'] for item in history['risk_choices']] == [findings[1]['id']]
    assert history['current_feedback']['visible_host_risk_count'] == 1


def test_same_issue_across_new_task_line_movement_and_new_owner_reuses_user_choice(service):
    s, root, ref, finding = host_risk(service)
    feedback = TaskRiskFeedbackService()
    result = feedback.set_disposition(s, root, ref, finding, 'EXCLUDE', user_requested=True)
    original_key = result['disposition']['issue_key']
    s.owner = session_owner('codex', 'new-development-conversation')
    s, root, new_ref, new_finding = repeat_risk(service)
    assert new_ref != ref and new_finding != finding
    state = feedback.get(s, root, new_ref, new_finding)
    assert state['disposition']['issue_key'] == original_key
    assert state['handling_status'] == 'EXCLUDED' and state['reminder_suppressed']
    assert not s.get(root, new_ref)['risk_choices']
    assert not state['disposition']['reassessment_required']
    immediate = s._view(s.load(root, new_ref))
    assert not immediate['risk_choices']
    assert '发现 1 项安全风险' not in immediate['development_summary']
    assert '回复' not in immediate['development_summary']


def test_new_comment_unrelated_function_or_unreadable_source_never_cancels_choice(service):
    s, root, ref, finding = host_risk(service)
    feedback = TaskRiskFeedbackService()
    feedback.set_disposition(s, root, ref, finding, 'EXCLUDE', user_requested=True)
    (root/'routes.py').write_text((root/'routes.py').read_text() +
        '\n# unrelated\ndef health():\n    return True\n')
    state = feedback.get(s, root, ref, finding)
    assert state['reminder_suppressed']
    assert not state['disposition']['reassessment_required']
    (root/'auth.py').unlink()
    state = feedback.get(s, root, ref, finding)
    assert state['reminder_suppressed']
    assert state['disposition']['reassessment_required']


def test_source_material_change_requests_reassessment_without_overriding_user(service):
    s, root, ref, finding = host_risk(service)
    feedback = TaskRiskFeedbackService()
    feedback.set_disposition(s, root, ref, finding, 'EXCLUDE', user_requested=True)
    (root/'auth.py').write_text('def owns(user, order):\n    return True\n')
    state = feedback.get(s, root, ref, finding)
    assert state['reminder_suppressed'] and state['disposition']['reassessment_required']
    assert not s.get(root, ref)['risk_choices']


def test_only_fresh_evidence_of_material_change_reopens_manual_choice(service):
    s, root, ref, finding = host_risk(service)
    feedback = TaskRiskFeedbackService()
    feedback.set_disposition(s, root, ref, finding, 'EXCLUDE', user_requested=True)
    unchanged = feedback.prepare(s, root, ref, finding)
    feedback.submit(s, root, ref, finding, unchanged['feedback_ref'], 'STILL_RISK',
        'A different AI still considers this risky.', ['The original call remains.'],
        [source['evidence_ref'] for source in unchanged['sources']])
    assert feedback.get(s, root, ref, finding)['reminder_suppressed']
    (root/'auth.py').write_text('def owns(user, order):\n    return True\n')
    s, root, new_ref, new_finding = repeat_risk(service)
    assert feedback.get(s, root, new_ref, new_finding)['reminder_suppressed']
    changed = feedback.prepare(s, root, new_ref, new_finding)
    assert changed['context_complete']
    feedback.submit(s, root, new_ref, new_finding, changed['feedback_ref'], 'STILL_RISK',
        'The ownership guard was removed from the related control.',
        ['The changed control now unconditionally returns True.'],
        [source['evidence_ref'] for source in changed['sources']])
    state = feedback.get(s, root, new_ref, new_finding)
    assert not state['reminder_suppressed']
    assert state['disposition']['decision']['disposition'] == 'EXCLUDE'
    assert state['disposition']['decision']['reopened']
    assert state['disposition_audit_events'][-1]['event_kind'] == 'MATERIAL_RISK_CHANGE'


def test_restore_overrides_old_ai_false_positive_but_retains_both_histories(service):
    s, root, ref, finding = host_risk(service)
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding)
    submit_false_positive(feedback, s, root, ref, finding, packet)
    feedback.set_disposition(s, root, ref, finding, 'EXCLUDE', user_requested=True)
    result = feedback.set_disposition(s, root, ref, finding, 'RESTORE', user_requested=True)
    assert not result['reminder_suppressed'] and result['handling_status'] == 'OPEN'
    assert result['technical_feedback']['status'] == 'HOST_FALSE_POSITIVE'
    state = feedback.get(s, root, ref, finding)
    assert [event['disposition'] for event in state['disposition_audit_events']] == ['EXCLUDE', 'RESTORE']
    assert state['audit_events'][0]['status'] == 'HOST_FALSE_POSITIVE'
    assert len(s.get(root, ref)['risk_choices']) == 1


def test_defer_and_expiration_keep_risk_open_and_history_durable(service):
    s, root, ref, finding = host_risk(service)
    now = [1_800_000_000.0]
    feedback = TaskRiskFeedbackService(now=lambda: now[0])
    until = datetime.fromtimestamp(now[0]+60, timezone.utc).isoformat()
    result = feedback.set_disposition(s, root, ref, finding, 'DEFER',
        user_requested=True, until=until)
    assert result['handling_status'] == 'DEFERRED' and result['reminder_suppressed']
    assert result['original_risk_status'] == 'OPEN'
    now[0] += 61
    result = feedback.get(s, root, ref, finding)
    assert result['handling_status'] == 'OPEN' and not result['reminder_suppressed']
    assert result['disposition']['expired']
    assert result['disposition_audit_events'][0]['disposition'] == 'DEFER'


def test_idempotent_repeat_does_not_duplicate_history_or_delete_choice(service):
    s, root, ref, finding = host_risk(service)
    feedback = TaskRiskFeedbackService()
    first = feedback.set_disposition(s, root, ref, finding, 'EXCLUDE',
        user_requested=True, request_id='one-choice')
    second = feedback.set_disposition(s, root, ref, finding, 'EXCLUDE',
        user_requested=True, request_id='one-choice')
    assert first['audit_event_count'] == second['audit_event_count'] == 1
    with pytest.raises(ValueError, match='different reminder choice'):
        feedback.set_disposition(s, root, ref, finding, 'RESTORE',
            user_requested=True, request_id='one-choice')
    assert feedback.get(s, root, ref, finding)['reminder_suppressed']


def test_other_owner_cannot_change_original_task_choice(service):
    s, root, ref, finding = host_risk(service)
    other = TaskSecurityService(s.runtime, s.hooks,
        owner=session_owner('codex', 'unrelated-conversation'))
    with pytest.raises(ValueError, match='another session'):
        TaskRiskFeedbackService().set_disposition(
            other, root, ref, finding, 'EXCLUDE', user_requested=True)


def test_deleted_source_can_be_excluded_for_exact_historical_finding(service):
    s, root, ref, finding = host_risk(service)
    ledger = TaskRiskLedger(s.hooks, root)
    rows = ledger.read()
    rows[ref+':'+finding].pop('disposition_scope')
    rows[ref+':'+finding].pop('disposition_locations')
    with s.hooks.lock(root) as acquired:
        assert acquired
        ledger.save(rows)  # Model a pre-feature historical task.
    (root/'routes.py').unlink()
    feedback = TaskRiskFeedbackService()
    result = feedback.set_disposition(s, root, ref, finding, 'EXCLUDE', user_requested=True)
    assert result['reminder_suppressed']
    assert result['disposition']['issue_key'].startswith('rd1-history-')
    assert result['original_risk_status'] == 'OPEN'
    restored = feedback.set_disposition(s, root, ref, finding, 'RESTORE', user_requested=True)
    assert not restored['reminder_suppressed']


def test_legacy_user_opinion_does_not_overwrite_ai_assessment(service):
    s, root, ref, finding = host_risk(service)
    feedback = TaskRiskFeedbackService()
    packet = feedback.prepare(s, root, ref, finding)
    feedback.submit(s, root, ref, finding, packet['feedback_ref'], 'STILL_RISK',
        'The current protection does not cover this call.', ['The call bypasses ownership.'],
        [source['evidence_ref'] for source in packet['sources']])
    feedback.mark(s, root, ref, finding, 'Please check this.', user_requested=True)
    state = feedback.get(s, root, ref, finding)
    assert state['feedback']['status'] == 'USER_MARKED_FALSE_POSITIVE'
    assert state['technical_feedback']['status'] == 'STILL_PRESENT'
    assert not state['reminder_suppressed']


def test_known_secret_in_reason_is_not_returned_or_written(service):
    s, root, _ = service
    secret = 'opaqueDispositionPrivacyBoundary'
    (root/'auth.py').write_text('def owns(user, order):\n    marker = '+repr(secret)+
                              '\n    return user.id == order.owner_id\n')
    s, root, ref, finding = host_risk(service)
    record = s.load(root, ref)
    record['static']['findings'].append(dict(id='known-secret', category='secret',
        title='Known marker', file_path='auth.py', line_start=2, line_end=2))
    s.store(root).save(record)
    feedback = TaskRiskFeedbackService()
    result = feedback.set_disposition(s, root, ref, finding, 'EXCLUDE', secret, user_requested=True)
    assert secret not in json.dumps(result)
    assert secret not in json.dumps(feedback.get(s, root, ref, finding))
    assert TaskRiskLedger(s.hooks, root).read()[ref+':'+finding]['status'] == 'OPEN'


def test_handling_metadata_does_not_repeat_large_assessments_in_bounded_history():
    from test_task_review_results import record, assert_bounded
    saved = record(static_count=0, host_count=5)
    feedback = {finding['id']: dict(status='STILL_PRESENT', folded=True,
        technical_feedback=dict(status='STILL_PRESENT', folded=False,
                                rationale='large assessment '*1000),
        disposition=dict(disposition='EXCLUDE', active=True, suppressed=True,
                         decision=dict(reason='large reason '*1000)),
        handling_status='EXCLUDED', handling_source='USER_DECISION')
        for finding in saved['review']['findings']}
    packet = bounded_history_result(saved, feedback=feedback)
    assert_bounded(packet)
    assert not packet['risk_choices']
    assert packet['current_feedback']['visible_host_risk_count'] == 0
    assert 'large assessment' not in json.dumps(packet)
    assert 'large reason' not in json.dumps(packet)
