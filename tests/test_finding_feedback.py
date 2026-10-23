"""Feedback is independently auditable and never turns user opinion into proof."""
import copy
import json
import sqlite3

import pytest

import security_runtime.finding_feedback as module
from security_runtime.finding_feedback import FindingFeedbackService
from security_runtime.finding_quality import FindingQualityService
from security_runtime.findings import FindingNormalizer
from security_runtime.local_evidence import snapshot_fingerprint
from security_runtime.models import ScanResult, TargetProfile, ScannerRun
from security_runtime.storage import SQLiteStore, ReadOnlySQLiteStore


@pytest.fixture(autouse=True)
def stable_package(monkeypatch):
    # Other agents may edit the working package while tests run. Model a stable
    # installed build; explicit identity-change tests replace this value.
    monkeypatch.setattr(module, 'build_identity', lambda: {'build_id': 'test-build-one'})


def setup(tmp_path, *, category='sql-injection', text=None, extra=None):
    root = tmp_path / 'project'
    root.mkdir()
    name = 'app.py'
    text = text or 'def query(db, value):\n    db.execute("select value where id = ?", (value,))\n'
    (root / name).write_text(text, encoding='utf-8')
    if extra:
        for file, body in extra.items():
            (root / file).write_text(body, encoding='utf-8')
    normalizer = FindingNormalizer(root)
    finding = normalizer.make(scanner='semgrep', category=category,
        title='Synthetic candidate', description='A scanner match requires review',
        severity='HIGH', confidence='MEDIUM', file_path=name, line=2,
        rule_id='fixture.rule', evidence='synthetic rule match')
    finding.technical_details['evidence_locator'] = snapshot_fingerprint(root, name)
    store = SQLiteStore(tmp_path / 'state' / 'scans.db')
    profile = TargetProfile(str(root), files=[name, *(extra or {})])
    store.save(ScanResult('s1', 'quick', profile, 'COMPLETED', [finding],
        [ScannerRun('semgrep', '1.0', 'SUCCESS', 1)], '', 'REVIEW', 1))
    return root, store, finding, FindingFeedbackService(store, root)


def submit_fp(service, finding, *, scan='s1', related_files=None, **changes):
    prepared = service.prepare(scan, finding.id, related_files=related_files)
    assert prepared['status'] == 'READY'
    value = dict(context_hash=prepared['packet']['context_hash'], verdict='FALSE_POSITIVE',
                 reason='The call supplies a separate bound parameter tuple.',
                 evidence_refs=[dict(file='app.py', start_line=2, end_line=2,
                                     claim='A separate parameter tuple is passed at the matched call.')],
                 confidence='HIGH', unknowns=[], context_complete=True,
                 related_files=related_files)
    value.update(changes)
    return service.submit(scan, finding.id, **value)


def test_user_label_alone_never_folds_and_agent_opinion_is_separate(tmp_path):
    root, store, finding, service = setup(tmp_path)
    before = copy.deepcopy(store.get_scan('s1'))
    human = service.user_mark('s1', finding.id, 'There is a parameter tuple.')
    assert human['state'] == 'USER_MARKED_UNCONFIRMED' and not human['folded']
    quality = FindingQualityService(store).view('s1')
    assert quality['findings'][0]['triage_status'] == 'NEEDS_CONTEXT'
    assert quality['metrics']['overall']['FP'] == 0
    assert quality['metrics']['overall']['precision_denominator'] == 0
    approved = submit_fp(service, finding)
    assert approved['state'] == 'AGENT_FALSE_POSITIVE' and approved['folded']
    assert approved['user_mark']['triage_source'] == 'HUMAN'
    assert approved['agent_review']['triage_source'] == 'AI'
    assert approved['assessment_source'] == 'HOST_CODE_REVIEW_NOT_RUNTIME_PROOF'
    assert not approved['raw_findings_changed'] and not approved['fix_authorized']
    assert store.get_scan('s1') == before and store.triage_records('s1') == {}
    assert len(service.status('s1', finding.id, True)['history']) == 2
    quality = FindingQualityService(store).view('s1')['findings'][0]
    assert quality['triage_source'] == 'AI' and quality['triage_status'] == 'FALSE_POSITIVE'


@pytest.mark.parametrize('changes', [dict(confidence='MEDIUM'), dict(context_complete=False),
    dict(unknowns=['Caller unknown']), dict(evidence_refs=[]),
    dict(evidence_refs=[dict(file='app.py', start_line=1, end_line=1, claim='Function header only')])])
def test_false_positive_requires_specific_complete_counterevidence(tmp_path, changes):
    _, store, finding, service = setup(tmp_path)
    with pytest.raises(ValueError):
        submit_fp(service, finding, **changes)
    assert not service.status('s1', finding.id)['folded']
    assert store.finding_review_history(service.workspace) == []


@pytest.mark.parametrize('ref', [dict(file='../escape.py', start_line=2, end_line=2, claim='bad'),
    dict(file='app.py', start_line=2, end_line=900, claim='outside'),
    dict(file='app.py', start_line=True, end_line=2, claim='boolean is not a line')])
def test_fabricated_refs_cannot_publish_review(tmp_path, ref):
    _, _, finding, service = setup(tmp_path)
    with pytest.raises(ValueError):
        submit_fp(service, finding, evidence_refs=[ref])


def test_source_changes_invalidate_without_retroactive_baseline(tmp_path):
    root, store, finding, service = setup(tmp_path)
    submit_fp(service, finding)
    (root/'app.py').write_text('def query(db, value):\n    db.execute(value)\n')
    state = service.status('s1', finding.id)
    assert state['state'] == 'REVIEW_STALE' and not state['folded']
    assert state['agent_review']['verdict'] == 'FALSE_POSITIVE'
    quality = FindingQualityService(store).view('s1')
    assert quality['findings'][0]['triage_status'] == 'NEEDS_CONTEXT'
    assert quality['findings'][0]['recorded_review']['triage_status'] == 'FALSE_POSITIVE'
    assert quality['metrics']['overall']['FP'] == 0
    prepared = service.prepare('s1', finding.id)
    with pytest.raises(ValueError):
        submit_fp(service, finding)
    assert prepared['packet']['local_evidence']['evidence_status'] == 'STALE'


def test_explicit_related_change_even_outside_excerpt_invalidates(tmp_path):
    root, _, finding, service = setup(tmp_path, extra={'guard.py':'def guard(value):\n    return bool(value)\n'})
    submit_fp(service, finding, related_files=['guard.py'])
    (root/'guard.py').write_text('def guard(value):\n    return True\n')
    state = service.status('s1', finding.id)
    assert not state['folded'] and state['stale_reason'] == 'CODE_RULE_OR_CONTEXT_CHANGED'


def test_missing_evidence_never_preserves_folded_state(tmp_path):
    root, _, finding, service = setup(tmp_path)
    submit_fp(service, finding)
    (root/'app.py').unlink()
    state = service.status('s1', finding.id)
    assert state['stale_reason'] == 'CONTEXT_UNAVAILABLE' and not state['folded']
    assert service.prepare('s1', finding.id)['status'] == 'EVIDENCE_UNAVAILABLE'


def test_same_code_rescan_reuses_ai_opinion_but_not_human_label(tmp_path):
    _, store, finding, service = setup(tmp_path)
    service.user_mark('s1', finding.id, 'User opinion')
    submit_fp(service, finding)
    scan = store.get_scan('s1')
    with sqlite3.connect(store.path) as db:
        new_scan = dict(scan, scan_id='s2')
        db.execute('INSERT INTO scans VALUES (?, ?)', ('s2', json.dumps(new_scan)))
    state = service.status('s2', finding.id)
    assert state['folded'] and state['user_mark'] is None
    assert state['agent_review']['review_scan_id'] == 's1'
    assert service.presentations('s2')[finding.id]['folded']


def test_smaller_quick_scope_does_not_discard_valid_local_review(tmp_path):
    _, store, finding, service = setup(tmp_path, extra={'unrelated.py':'def unrelated():\n    return 0\n'})
    submit_fp(service, finding)
    scan = store.get_scan('s1')
    scan['scan_id'] = 's2'
    scan['target_profile']['files'] = ['app.py']
    with sqlite3.connect(store.path) as db:
        db.execute('INSERT INTO scans VALUES (?, ?)', ('s2', json.dumps(scan)))
    assert service.status('s2', finding.id)['folded']


def test_rule_scanner_and_build_versions_invalidate(tmp_path, monkeypatch):
    _, store, finding, service = setup(tmp_path)
    submit_fp(service, finding)
    monkeypatch.setattr(module, 'build_identity', lambda: {'build_id':'changed-build'})
    assert not service.status('s1', finding.id)['folded']
    monkeypatch.setattr(module, 'build_identity', lambda: {'build_id':'test-build-one'})
    scan = store.get_scan('s1')
    scan['scanner_runs'][0]['version'] = '2.0'
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE scans SET data=? WHERE id=?', (json.dumps(scan), 's1'))
    assert not service.status('s1', finding.id)['folded']


def test_revoke_keeps_audit_and_does_not_repair_finding(tmp_path):
    _, store, finding, service = setup(tmp_path)
    service.user_mark('s1', finding.id, 'User opinion')
    submit_fp(service, finding)
    state = service.revoke('s1', finding.id, 'Reconsider after checking the call')
    assert state['state'] == 'UNREVIEWED' and not state['folded']
    assert len(service.status('s1', finding.id, True)['history']) == 3
    assert store.get_scan('s1')['findings'][0]['status'] == 'OPEN'


def test_agent_can_disagree_or_record_missing_context(tmp_path):
    _, _, finding, service = setup(tmp_path)
    service.user_mark('s1', finding.id, 'Only an internal deployment')
    state = submit_fp(service, finding, verdict='STILL_RISK', reason='Internal deployment does not eliminate input exposure.')
    assert state['state'] == 'STILL_RISK' and state['user_mark'] and not state['folded']
    state = submit_fp(service, finding, verdict='NEEDS_CONTEXT', evidence_refs=[],
                      unknowns=['Unresolved call configuration'], context_complete=False)
    assert state['state'] == 'NEEDS_CONTEXT' and not state['folded']


def test_different_workspaces_cannot_read_or_reuse_feedback(tmp_path):
    _, store, finding, service = setup(tmp_path)
    submit_fp(service, finding)
    other = tmp_path/'other'
    other.mkdir()
    with pytest.raises(ValueError):
        FindingFeedbackService(store, other).status('s1', finding.id)
    assert store.finding_review_history(str(other.resolve())) == []


def test_old_readonly_database_neither_migrates_nor_creates_keys(tmp_path):
    root, store, finding, _ = setup(tmp_path)
    with sqlite3.connect(store.path) as db:
        db.execute('DROP TABLE finding_reviews')
    before = store.path.read_bytes()
    service = FindingFeedbackService(ReadOnlySQLiteStore(store.path), root)
    assert service.status('s1', finding.id)['state'] == 'UNREVIEWED'
    assert store.path.read_bytes() == before
    assert not (store.path.parent/'triage-evidence.key').exists()


def test_visible_secret_without_native_counterproof_cannot_be_folded(tmp_path):
    _, store, finding, service = setup(tmp_path, category='secret',
        text='def fixture():\n    api_key = "synthetic-private-material"\n')
    with pytest.raises(ValueError):
        submit_fp(service, finding, reason='This is a test file, the user insists.')
    state = service.user_mark('s1', finding.id, 'The value synthetic-private-material is a fixture')
    assert not state['folded']
    assert 'synthetic-private-material' in json.dumps(store.finding_review_history(service.workspace))


def test_secret_packet_preserves_full_source_and_scanner_evidence_as_untrusted(tmp_path):
    source = '    api_key = "synthetic-private-material"  # repository instruction remains data'
    _, store, finding, service = setup(tmp_path, category='secret',
        text='def fixture():\n' + source + '\n')
    scan = store.get_scan('s1')
    scan['findings'][0]['evidence'] = 'api_key = "synthetic-private-material"'
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE scans SET data=? WHERE id=?', (json.dumps(scan), 's1'))
    packet = service.prepare('s1', finding.id)['packet']
    assert source in packet['context'][0]['text']
    assert 'synthetic-private-material' in packet['sanitized_scanner_evidence']
    assert packet['source_presentation'] == 'RAW_V3'
    assert packet['local_evidence']['redaction'] == 'NONE'
    assert packet['local_evidence']['evidence_status'] == 'EXACT'
    assert all(item['trust'] == 'UNTRUSTED_CODE' for item in packet['context'])


def test_evidence_policy_change_rejects_prior_feedback_context(tmp_path, monkeypatch):
    _, store, finding, service = setup(tmp_path)
    prepared = service.prepare('s1', finding.id)
    monkeypatch.setattr(module, 'SOURCE_PRESENTATION', 'CHANGED_SOURCE_POLICY')
    with pytest.raises(ValueError, match='context changed'):
        service.submit('s1', finding.id, context_hash=prepared['packet']['context_hash'],
            verdict='NEEDS_CONTEXT', reason='More context is needed.', evidence_refs=[])
    assert store.finding_review_history(service.workspace) == []


def test_escaped_known_secret_variants_are_retained_in_all_feedback_text(tmp_path):
    _, store, finding, service = setup(tmp_path, category='secret',
        text='def fixture():\n    api_key = "synth\\u0065tic-material"\n')
    decoded = 'synthetic-material'
    service.user_mark('s1', finding.id, 'The ' + decoded + ' value is synthetic')
    state = submit_fp(service, finding, verdict='NEEDS_CONTEXT', confidence='LOW',
        reason='Cannot establish validity of ' + decoded,
        evidence_refs=[dict(file='app.py',start_line=2,end_line=2,claim='The ' + decoded + ' value is visible')],
        unknowns=['Validity of ' + decoded], context_complete=False)
    assert state['state'] == 'NEEDS_CONTEXT' and not state['folded']
    history = json.dumps(store.finding_review_history(service.workspace))
    assert decoded in history and '[REDACTED_SECRET]' not in history


@pytest.mark.parametrize('old_line,old_value', [
    ('    api_key = "opaquePreviousSecretMaterial"', 'opaquePreviousSecretMaterial'),
    ('    api_key = "synth\\u0065tic-material"', 'synthetic-material'),
])
def test_changed_known_secret_snapshot_preserves_mark_and_revoke_reasons(tmp_path, old_line, old_value):
    root, store, finding, service = setup(tmp_path, category='secret',
        text='def fixture():\n' + old_line + '\n')
    (root/'app.py').write_text('def fixture():\n    pass\n')
    marked = service.user_mark('s1', finding.id, 'Old value ' + old_value)
    revoked = service.revoke('s1', finding.id, 'Old value ' + old_value)
    assert old_value in marked['user_mark']['triage_reason']
    assert revoked['state'] == 'UNREVIEWED' and not revoked['folded']
    assert old_value in json.dumps(store.finding_review_history(service.workspace))


def test_missing_original_secret_locator_preserves_user_reason(tmp_path):
    _, store, finding, service = setup(tmp_path, category='secret',
        text='def fixture():\n    api_key = "synth\\u0065tic-material"\n')
    scan = store.get_scan('s1')
    scan['findings'][0]['technical_details'].pop('evidence_locator')
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE scans SET data=? WHERE id=?', (json.dumps(scan),'s1'))
    state = service.user_mark('s1', finding.id, 'Old value synthetic-material')
    assert 'synthetic-material' in state['user_mark']['triage_reason']
    assert 'synthetic-material' in json.dumps(store.finding_review_history(service.workspace))


def test_unrelated_changed_secret_does_not_block_bounded_feedback_prose(tmp_path):
    root, store, finding, service = setup(tmp_path,
        extra={'credentials.py':'api_key = "synth\\u0065tic-material"\n'})
    secret = FindingNormalizer(root).make(scanner='gitleaks', category='secret',
        title='Synthetic secret',description='Known credential context',severity='HIGH',
        confidence='HIGH',file_path='credentials.py',line=1,rule_id='fixture.secret')
    secret.technical_details['evidence_locator'] = snapshot_fingerprint(root, 'credentials.py')
    scan = store.get_scan('s1')
    from dataclasses import asdict
    scan['findings'].append(asdict(secret))
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE scans SET data=? WHERE id=?',(json.dumps(scan),'s1'))
    prepared = service.prepare('s1',finding.id)
    assert prepared['status'] == 'READY'
    (root/'credentials.py').write_text('pass\n')
    current = service.prepare('s1',finding.id)
    state = service.submit('s1',finding.id,context_hash=current['packet']['context_hash'],
        verdict='NEEDS_CONTEXT',reason='Old value synthetic-material',
        evidence_refs=[dict(file='app.py',start_line=2,end_line=2,claim='Old value synthetic-material')],
        confidence='LOW',unknowns=['Old value synthetic-material'],context_complete=False)
    assert state['state'] == 'NEEDS_CONTEXT' and not state['folded']
    assert 'synthetic-material' in json.dumps(store.finding_review_history(service.workspace))


def test_unreadable_or_malformed_known_secret_preserves_the_user_reason(tmp_path):
    root, _, finding, service = setup(tmp_path, category='secret',
        text='def fixture():\n    api_key = "' + '\\'*999 + '\n')
    state = service.user_mark('s1', finding.id, 'Do not echo this unverified reason')
    assert 'Do not echo' in state['user_mark']['triage_reason']
    (root/'app.py').unlink()
    state = service.user_mark('s1', finding.id, 'Do not echo this missing-source reason')
    assert 'Do not echo' in state['user_mark']['triage_reason']


@pytest.mark.parametrize('line', [
    '    api_key = `synth\\u0065tic-material`',
    '    api_key = "synthetic-material"; other = "unterminated',
])
def test_unsupported_or_partly_unclosed_secret_syntax_preserves_reason(tmp_path, line):
    _, _, finding, service = setup(tmp_path, category='secret', text='def fixture():\n' + line + '\n')
    state = service.user_mark('s1', finding.id, 'Do not echo this synthetic-material opinion')
    assert 'Do not echo' in state['user_mark']['triage_reason']
    assert 'synthetic-material' in state['user_mark']['triage_reason']


def test_truncated_code_cannot_be_called_complete(tmp_path):
    text = 'def query(db, value):\n    db.execute(value' + ' + value' * 180 + ')\n'
    _, _, finding, service = setup(tmp_path, text=text)
    prepared = service.prepare('s1', finding.id)
    assert prepared['packet']['evidence_gaps'][0]['reason'] == 'SOURCE_LINE_TRUNCATED'
    with pytest.raises(ValueError):
        submit_fp(service, finding)


def test_changed_context_hash_is_rejected_before_any_record(tmp_path):
    _, store, finding, service = setup(tmp_path)
    with pytest.raises(ValueError):
        submit_fp(service, finding, context_hash='not-the-prepared-version')
    assert store.finding_review_history(service.workspace) == []


def test_hook_projection_never_folds_another_occurrence_in_same_family(tmp_path):
    text = ('def query(db, value):\n    db.execute("select value where id = ?", (value,))\n'
            'def other(db, value):\n    db.execute(value)\n')
    root, store, finding, service = setup(tmp_path, text=text)
    submit_fp(service, finding)
    first = service.hook_projection('s1')
    assert first['folded_finding_ids'] == [finding.id]
    assert len(first['fully_folded_families']) == 1
    other = FindingNormalizer(root).make(scanner='semgrep', category='sql-injection',
        title='Synthetic candidate', description='Another occurrence', severity='HIGH',
        confidence='MEDIUM', file_path='app.py', line=4, rule_id='fixture.rule')
    other.technical_details['evidence_locator'] = snapshot_fingerprint(root, 'app.py')
    profile = TargetProfile(str(root), files=['app.py'])
    store.save(ScanResult('s2', 'quick', profile, 'COMPLETED', [finding, other],
        [ScannerRun('semgrep', '1.0', 'SUCCESS', 1)], '', 'REVIEW', 1))
    projection = service.hook_projection('s2')
    assert projection['folded_finding_ids'] == [finding.id]
    assert projection['fully_folded_families'] == []
    assert projection['alert_finding_count'] == 1
    assert len(store.get_scan('s2')['findings']) == 2


def test_hook_projection_does_not_treat_human_label_as_a_review(tmp_path):
    _, _, finding, service = setup(tmp_path)
    service.user_mark('s1', finding.id, 'I insist this is a false positive')
    projection = service.hook_projection('s1')
    assert projection['folded_count'] == 0 and projection['alert_finding_count'] == 1
    assert projection['evidence_revalidations'] == 0


def test_presentations_reads_scan_and_history_once(tmp_path, monkeypatch):
    _, store, finding, service = setup(tmp_path)
    calls = {'scan':0, 'history':0}
    old_scan, old_history = store.get_scan, store.finding_review_history
    def scan(*args):
        calls['scan'] += 1
        return old_scan(*args)
    def history(*args):
        calls['history'] += 1
        return old_history(*args)
    monkeypatch.setattr(store, 'get_scan', scan)
    monkeypatch.setattr(store, 'finding_review_history', history)
    assert service.presentations('s1')[finding.id]['state'] == 'UNREVIEWED'
    assert calls == {'scan':1, 'history':1}


def test_folded_hook_copy_does_not_repeat_risk_or_claim_a_fix(tmp_path):
    from security_runtime.hook_user_feedback import scan_status_message
    _, _, finding, service = setup(tmp_path)
    submit_fp(service, finding)
    result = dict(status='SCANNED', coverage='FULL', delta=dict(new=1,persisting=0,
                  additional_occurrences=0), finding_feedback_projection=service.hook_projection('s1'))
    assert scan_status_message(result) == ''
    assert result['delta']['new'] == 1
    result['coverage'] = 'PARTIAL'
    assert '部分' in scan_status_message(result)


def test_false_positive_not_used_for_unverifiable_runtime_package(tmp_path, monkeypatch):
    _, _, finding, service = setup(tmp_path)
    monkeypatch.setattr(module, 'build_identity', lambda: {'status':'UNVERIFIABLE_LEGACY_BUNDLE'})
    with pytest.raises(ValueError):
        submit_fp(service, finding)


def test_feedback_choices_keep_false_positive_review_separate_from_deferral(tmp_path):
    from security_runtime.hook_user_feedback import issue_feedback
    _, store, finding, _ = setup(tmp_path)
    feedback = issue_feedback(store.get_scan('s1')['findings'][0])
    assert feedback['choices'] == ['修复', '稍后处理']
    assert feedback['secondary_choices'] == ['请复核', '不再提醒此项']
    assert '按你的决定排除' not in feedback['message']
    assert '原告警和不同意见仍保留' not in feedback['message']


def test_bounded_dependency_context_cannot_fold_on_claimed_non_use(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    (root/'requirements.txt').write_text('fixture-package==1.0\n')
    finding = FindingNormalizer(root).dependency(scanner='osv-scanner',
        package='fixture-package', version='1.0', ecosystem='pypi',
        manifest='requirements.txt', vulnerability_id='CVE-2099-0001')
    finding.technical_details['evidence_locator'] = snapshot_fingerprint(root, 'requirements.txt')
    store = SQLiteStore(tmp_path/'state.db')
    store.save(ScanResult('s1','quick',TargetProfile(str(root),files=['requirements.txt']),
        'COMPLETED',[finding],[], '', 'REVIEW',1))
    service = FindingFeedbackService(store, root)
    prepared = service.prepare('s1', finding.id)
    assert prepared['status'] == 'READY'
    with pytest.raises(ValueError):
        service.submit('s1', finding.id, context_hash=prepared['packet']['context_hash'],
            verdict='FALSE_POSITIVE', reason='Only tests use this package on an internal network',
            evidence_refs=[dict(file='requirements.txt',start_line=1,end_line=1,claim='Package declared')],
            confidence='HIGH',unknowns=[],context_complete=True)
    assert not service.status('s1',finding.id)['folded']
