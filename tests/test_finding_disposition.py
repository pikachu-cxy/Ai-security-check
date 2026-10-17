"""Product decisions survive scans while technical truth stays independent."""
import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
import sqlite3

import pytest

from security_runtime.finding_feedback import FindingFeedbackService
from security_runtime.findings import FindingNormalizer
from security_runtime.local_evidence import snapshot_fingerprint
from security_runtime.models import ScanResult, ScannerRun, TargetProfile
from security_runtime.risk_disposition import RiskDispositionStore, issue_scope
from test_finding_feedback import setup, stable_package, submit_fp


def rescan(store, root, source, *, line=2, scan_id='s2'):
    (root/'app.py').write_text(source, encoding='utf-8')
    finding = FindingNormalizer(root).make(scanner='semgrep', category='sql-injection',
        title='Synthetic candidate', description='A scanner match requires review',
        severity='HIGH', confidence='MEDIUM', file_path='app.py', line=line,
        rule_id='fixture.rule', evidence='synthetic rule match')
    finding.technical_details['evidence_locator'] = snapshot_fingerprint(root, 'app.py')
    store.save(ScanResult(scan_id, 'quick', TargetProfile(str(root), files=['app.py']),
        'COMPLETED', [finding], [ScannerRun('semgrep', '1.0', 'SUCCESS', 1)], '', 'REVIEW', 1))
    return finding


def test_user_exclusion_needs_no_ai_approval_and_survives_rescan_restart(tmp_path):
    root, store, finding, service = setup(tmp_path)
    before = copy.deepcopy(store.get_scan('s1'))
    decided = service.set_disposition('s1', finding.id, 'EXCLUDE', '认为误报', user_requested=True)
    assert decided['handling_status'] == 'EXCLUDED' and decided['reminder_suppressed']
    assert decided['agent_review'] is None and not decided['technical_false_positive']
    assert not decided['fix_authorized'] and store.get_scan('s1') == before
    moved = rescan(store, root, '# harmless comment\n\ndef query(db, value):\n'
        '    db.execute("select value where id = ?", (value,))\n', line=4)
    restarted = FindingFeedbackService(store, root)
    state = restarted.status('s2', moved.id)
    assert state['reminder_suppressed'] and not state['disposition']['reassessment_required']
    assert state['disposition']['issue_key'] == decided['disposition']['issue_key']
    assert restarted.hook_projection('s2')['folded_finding_ids'] == [moved.id]
    assert restarted.status('s1', finding.id)['reminder_suppressed']


@pytest.mark.parametrize('flag', [False, None, 1, 'true', [], {}])
def test_disposition_requires_literal_user_authorization(tmp_path, flag):
    _, _, finding, service = setup(tmp_path)
    with pytest.raises(ValueError, match='direct user request'):
        service.set_disposition('s1', finding.id, 'EXCLUDE', user_requested=flag)
    assert not service.dispositions.path.exists()


def test_exclusion_targets_one_occurrence_and_exact_workspace(tmp_path):
    text = ('def query(db, value):\n    db.execute(value)\n'
            'def other(db, value):\n    db.execute(value)\n')
    root, store, finding, service = setup(tmp_path, text=text)
    other = FindingNormalizer(root).make(scanner='semgrep', category='sql-injection',
        title='Other', description='Other', severity='HIGH', confidence='MEDIUM',
        file_path='app.py', line=4, rule_id='fixture.rule')
    other.technical_details['evidence_locator'] = snapshot_fingerprint(root, 'app.py')
    scan = store.get_scan('s1')
    scan['findings'].append(asdict(other))
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE scans SET data=? WHERE id=?', (json.dumps(scan), 's1'))
    service.set_disposition('s1', finding.id, 'EXCLUDE', user_requested=True)
    assert not service.status('s1', other.id)['reminder_suppressed']
    assert service.hook_projection('s1')['fully_folded_families'] == []
    other_root = tmp_path/'other'
    other_root.mkdir()
    with pytest.raises(ValueError, match='workspace'):
        FindingFeedbackService(store, other_root).set_disposition('s1', finding.id, 'EXCLUDE', user_requested=True)


def test_legacy_user_mark_remains_an_opinion_and_restore_overrides_ai(tmp_path):
    _, _, finding, service = setup(tmp_path)
    assert not service.user_mark('s1', finding.id, 'Please investigate')['reminder_suppressed']
    assert submit_fp(service, finding)['reminder_suppressed']
    restored = service.set_disposition('s1', finding.id, 'RESTORE', user_requested=True)
    assert not restored['reminder_suppressed']
    assert restored['agent_review']['verdict'] == 'FALSE_POSITIVE'
    assert restored['handling_status'] == 'PENDING'
    repeated = submit_fp(service, finding)
    assert not repeated['reminder_suppressed']
    assert repeated['agent_review']['verdict'] == 'FALSE_POSITIVE'


def test_revoked_ai_review_can_be_reviewed_again_without_rebuilding_identity(tmp_path):
    _, _, finding, service = setup(tmp_path)
    original = submit_fp(service, finding)
    key = original['disposition']['issue_key']
    revoked = service.revoke('s1', finding.id, 'Recheck the prior review')
    assert not revoked['reminder_suppressed'] and revoked['agent_review'] is None
    repeated = submit_fp(service, finding)
    assert repeated['reminder_suppressed'] and repeated['technical_assessment_current']
    assert repeated['disposition']['issue_key'] == key


def test_missing_source_or_model_disagreement_does_not_overrule_user(tmp_path):
    root, _, finding, service = setup(tmp_path)
    service.set_disposition('s1', finding.id, 'EXCLUDE', user_requested=True)
    state = submit_fp(service, finding, verdict='STILL_RISK', reason='A different AI opinion.')
    assert state['reminder_suppressed'] and state['agent_review']['verdict'] == 'STILL_RISK'
    (root/'app.py').unlink()
    state = service.status('s1', finding.id)
    assert state['reminder_suppressed'] and state['disposition']['reassessment_required']
    restored = service.set_disposition('s1', finding.id, 'RESTORE', user_requested=True)
    assert not restored['reminder_suppressed']


def test_first_historical_decision_with_missing_source_is_saved_but_never_matches_rescan(tmp_path):
    root, store, finding, service = setup(tmp_path)
    original = (root/'app.py').read_text()
    (root/'app.py').unlink()
    state = service.set_disposition('s1', finding.id, 'EXCLUDE', user_requested=True)
    assert state['reminder_suppressed'] and state['disposition']['reassessment_required']
    assert state['disposition']['decision']['metadata']['historical_only']
    assert '仅关联这次历史告警' in state['message']
    restarted = FindingFeedbackService(store, root)
    assert restarted.status('s1', finding.id)['reminder_suppressed']
    current = rescan(store, root, original)
    assert not restarted.status('s2', current.id)['reminder_suppressed']
    restored = restarted.set_disposition('s1', finding.id, 'RESTORE', user_requested=True)
    assert not restored['reminder_suppressed']


def test_local_material_change_requires_fresh_evidence_before_reminding(tmp_path):
    root, store, finding, service = setup(tmp_path,
        text='def query(db, value):\n    db.execute(value)\n    return False\n')
    service.set_disposition('s1', finding.id, 'EXCLUDE', user_requested=True)
    changed = rescan(store, root, 'def query(db, value):\n    db.execute(value)\n    return True\n')
    pending = service.status('s2', changed.id)
    assert pending['reminder_suppressed'] and pending['disposition']['reassessment_required']
    state = submit_fp(service, changed, scan='s2', verdict='STILL_RISK', reason='The relevant guard changed.')
    assert not state['reminder_suppressed']
    assert service.status('s2', changed.id, True)['disposition_history'][-1]['event_kind'] == 'MATERIAL_RISK_CHANGE'


def test_unrelated_function_edit_does_not_restart_reminder(tmp_path):
    source = ('def query(db, value):\n    db.execute(value)\n'
              'def unrelated():\n    return False\n')
    root, store, finding, service = setup(tmp_path, text=source)
    service.set_disposition('s1', finding.id, 'EXCLUDE', user_requested=True)
    current = rescan(store, root, source.replace('return False', 'return True'))
    assert not service.status('s2', current.id)['disposition']['reassessment_required']
    state = submit_fp(service, current, scan='s2', verdict='STILL_RISK')
    assert state['reminder_suppressed']


def test_ai_exclusion_tolerates_line_movement_without_human_disposition(tmp_path):
    root, store, finding, service = setup(tmp_path)
    submit_fp(service, finding)
    moved = rescan(store, root, '# harmless\n\ndef query(db, value):\n'
        '    db.execute("select value where id = ?", (value,))\n', line=4)
    state = service.status('s2', moved.id)
    assert state['reminder_suppressed'] and state['technical_false_positive']
    assert state['handling_status'] == 'EXCLUDED'
    assert state['technical_assessment_current'] and state['agent_review_current']
    assert state['assessment_source'] == 'HOST_CODE_REVIEW_NOT_RUNTIME_PROOF'


def test_latest_ai_risk_assessment_stays_separate_from_retained_reminder_choice(tmp_path):
    from security_runtime.finding_quality import FindingQualityService
    from security_runtime.security_summary import SecuritySummaryService
    root, store, finding, service = setup(tmp_path)
    submit_fp(service, finding)
    state = submit_fp(service, finding, verdict='STILL_RISK', reason='A later model disagrees on the same code.')
    assert state['agent_review']['verdict'] == 'STILL_RISK'
    assert state['state'] == 'STILL_RISK' and not state['technical_false_positive']
    assert state['technical_assessment_current'] and state['agent_review_current']
    assert state['reminder_suppressed'] and state['handling_status'] == 'EXCLUDED'
    assert state['handling_source'] == 'AI_REVIEW_EXCLUSION'
    assert state['disposition']['automatic_excluded']
    quality = FindingQualityService(store).view('s1')
    assert quality['findings'][0]['triage_status'] == 'TRUE_POSITIVE'
    assert quality['metrics']['overall']['FP'] == 0
    summary = SecuritySummaryService(store).get(root, 's1', details=True)
    assert summary['false_positive_feedback']['technical_false_positive_count'] == 0
    assert summary['risk_handling']['excluded_by_agent'] == 1
    assert summary['risk_handling']['pending_finding_count'] == 0


def test_indentation_change_invalidates_ai_exclusion_but_not_user_choice(tmp_path):
    source = ('def query(db, value):\n    if value:\n        db.execute(value)\n'
              '        return True\n')
    root, store, _, service = setup(tmp_path, text=source)
    finding = rescan(store, root, source, line=3)
    submit_fp(service, finding, scan='s2', evidence_refs=[dict(file='app.py', start_line=3,
        end_line=3, claim='The matched call is inside the guard.')])
    modified = rescan(store, root, source.replace('        db.execute(value)', '    db.execute(value)'),
                      line=3, scan_id='s3')
    assert not service.status('s3', modified.id)['reminder_suppressed']


def test_multiline_scope_refresh_tolerates_inserted_comments(tmp_path):
    from security_runtime.risk_disposition import refresh_scope
    file = tmp_path/'app.py'
    file.write_text('def query(db, value):\n    db.execute(\n        value\n    )\n')
    before = issue_scope(tmp_path, 'app.py', 2, 4, category='sql-injection')
    file.write_text('# intro\ndef query(db, value):\n    db.execute(\n        # comment\n        value\n    )\n')
    after = refresh_scope(tmp_path, before['metadata'])
    assert after['issue_key'] == before['issue_key']
    assert after['evidence_revision'] == before['evidence_revision']


def test_empty_store_still_risk_confirmation_is_safe_and_readonly_status_does_not_create(tmp_path):
    store = RiskDispositionStore(tmp_path/'risk.db')
    assert not store.status(tmp_path, 'issue')['suppressed']
    assert not store.path.exists()
    assert not store.confirm_material_change(tmp_path, 'issue', 'revision', assessment_id='a1',
        verdict='STILL_RISK', fresh=True, evidence_backed=True)['suppressed']


@pytest.mark.skipif(os.name != 'nt', reason='Windows native task storage paths')
def test_extended_windows_storage_path_roundtrips_saved_choice(tmp_path):
    from pathlib import Path
    path = Path('\\\\?\\'+str((tmp_path/'risk.db').resolve()))
    store = RiskDispositionStore(path)
    state = store.set(tmp_path, 'issue', 'EXCLUDE', user_requested=True)
    assert state['suppressed']
    assert store.status(tmp_path, 'issue')['suppressed']


def test_request_id_is_atomic_idempotent_and_conflicting_payload_rejected(tmp_path):
    root, _, finding, service = setup(tmp_path)
    def exclude(_):
        return FindingFeedbackService(service.store, root).set_disposition(
            's1', finding.id, 'EXCLUDE', user_requested=True, request_id='one-request')
    with ThreadPoolExecutor(max_workers=4) as pool:
        values = list(pool.map(exclude, range(8)))
    assert len({value['disposition']['event_id'] for value in values}) == 1
    assert len(values[-1]['disposition_history']) == 1
    with pytest.raises(ValueError, match='different reminder choice'):
        service.set_disposition('s1', finding.id, 'RESTORE', user_requested=True, request_id='one-request')


def test_deferral_expiry_and_history_are_persisted_without_mutating_findings(tmp_path):
    instant = [1800000000.0]
    store = RiskDispositionStore(tmp_path/'risk.db', now=lambda: instant[0])
    deadline = datetime.fromtimestamp(instant[0]+60, timezone.utc).isoformat()
    state = store.set(tmp_path, 'specific-occurrence', 'DEFER', user_requested=True,
                      until=deadline, evidence_revision='revision', request_id='defer-once')
    assert state['suppressed'] and state['until'] == deadline
    instant[0] += 61
    state = store.status(tmp_path, 'specific-occurrence', current_revision='revision', include_history=True)
    assert not state['suppressed'] and state['expired'] and len(state['history']) == 1
    retried = store.set(tmp_path, 'specific-occurrence', 'DEFER', user_requested=True,
                        until=deadline, evidence_revision='revision', request_id='defer-once')
    assert retried['event_id'] == state['event_id'] and len(retried['history']) == 1
    with pytest.raises(ValueError, match='future'):
        store.set(tmp_path, 'other-issue', 'DEFER', user_requested=True, until=deadline)


def test_source_identity_distinguishes_javascript_echo_from_native_call(tmp_path):
    (tmp_path/'case.js').write_text('export function echoText(body) {\n'
        '  const Function = (text) => () => text;\n  return Function(body)();\n}\n\n'
        'export function executeText(body) {\n  return globalThis.Function(body)();\n}\n')
    one = issue_scope(tmp_path, 'case.js', 3, category='code-execution', rule_id='fixture')
    two = issue_scope(tmp_path, 'case.js', 7, category='code-execution', rule_id='fixture')
    assert one['issue_key'] != two['issue_key']
    assert one['metadata']['symbol'] == 'echoText' and two['metadata']['symbol'] == 'executeText'
    assert one['metadata']['material_change_confirmable']


def test_leading_comment_in_evidence_range_keeps_symbol_identity(tmp_path):
    file = tmp_path/'app.py'
    file.write_text('def query(db, value):\n    db.execute(value)\n')
    before = issue_scope(tmp_path, 'app.py', 1, 2, category='sql-injection')
    file.write_text('# intro\ndef query(db, value):\n    db.execute(value)\n')
    after = issue_scope(tmp_path, 'app.py', 1, 3, category='sql-injection')
    assert before['issue_key'] == after['issue_key']
    assert before['evidence_revision'] == after['evidence_revision']


def test_unreadable_user_decisions_never_fall_back_to_older_ai_exclusion(tmp_path, monkeypatch):
    from security_runtime.risk_disposition import DispositionUnavailable
    _, _, finding, service = setup(tmp_path)
    submit_fp(service, finding)
    service.set_disposition('s1', finding.id, 'RESTORE', user_requested=True)
    def unreadable(*args):
        raise ValueError('Saved reminder choices could not be read safely')
    monkeypatch.setattr(service.dispositions, 'find_reference', unreadable)
    with pytest.raises(DispositionUnavailable):
        service.status('s1', finding.id)
    with pytest.raises(DispositionUnavailable):
        service.hook_projection('s1')


def test_optional_reason_is_redacted_and_write_failure_is_not_acknowledged(tmp_path, monkeypatch):
    _, _, finding, service = setup(tmp_path, category='secret',
        text='def fixture():\n    api_key = "synthetic-private-material"\n')
    state = service.set_disposition('s1', finding.id, 'EXCLUDE',
        'The synthetic-private-material value is a fixture', user_requested=True)
    assert 'synthetic-private-material' not in json.dumps(state['disposition_history'])
    def fail(*args, **kwargs):
        raise OSError('disk unavailable')
    monkeypatch.setattr(service.dispositions, '_connect', fail)
    with pytest.raises(OSError):
        service.set_disposition('s1', finding.id, 'RESTORE', user_requested=True)
