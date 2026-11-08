"""Delivery integration: fixed scan identity, bounded output and atomic saves."""
import copy
import json
import pytest
from test_development_risks import sample, scanner
from security_runtime.development_views import read_contexts, EvidenceWindow
from security_runtime.review_delivery import json_bytes
from security_runtime.user_config import DEFAULTS, validate_preferences


def seed(sample, monkeypatch, count=27, budget=65536):
    root, service, ref, risks = sample
    finding = scanner(sample, monkeypatch)
    findings = [dict(finding, id=f's{i}', fingerprint=f'f{i}') for i in range(count)]
    monkeypatch.setattr('security_runtime.storage.ReadOnlySQLiteStore.get_scan',
                        lambda *_: dict(target_profile=dict(path=str(root)), findings=findings))
    with service.store(root).transaction() as db:
        check = service.store(root)._get(db, ref)
        check['effective_config']['values']['agent']['audit_business_logic'] = False
        check['effective_config']['values']['development']['review_response_bytes'] = budget
        check['stop_closeout_notice'] = dict(mode='REVIEW', seq=check['dirty_seq'], scan_id=check['scan_id'])
        service.store(root)._put(db, ref, check)
    risks.sync_scanner()
    return risks


def test_27_alerts_two_calls_shared_evidence_one_save_whole_report(sample, monkeypatch):
    risks = seed(sample, monkeypatch)
    page = risks.get(limit=None, review_only=True)
    assert len(page['candidates']) == 27 and page['next_offset'] is None
    assert len(page['evidence']) == 1
    assert all(c['evidence_status'] == 'READY' for c in page['candidates'])
    assert json_bytes(page) < 65536
    decisions = [dict(same_issue_as=c['id'], decision='DISMISSED', rationale='Synthetic known-safe input',
                      evidence_refs=c['evidence_refs']) for c in page['candidates']]
    saved = risks.submit(decisions, page['dirty_seq'], scan_id=page['scan_id'], return_risks=True, final_report=True)
    assert saved['view'] == 'final_report' and saved['review_saved'] and saved['post_commit_read']
    assert saved['next_action'] is None and saved['summary']['false_positives'] == 27
    assert saved['report_text'].count('27 条') == 1 and '20 条' not in saved['report_text']
    assert 'session_url' in saved
    row = risks.load()
    assert len(row['reviews']) == 1 and all(len(r['assessments']) == 1 for r in row['risks'].values())


def test_budget_pages_keep_fixed_scope_after_partial_save(sample, monkeypatch):
    risks = seed(sample, monkeypatch, 90, 16384)
    offset, seen = 0, []
    while offset is not None:
        page = risks.get(offset, None, review_only=True)
        assert json_bytes(page) < 16384
        ids = [c['id'] for c in page['candidates']]
        assert ids and not set(ids) & set(seen)
        seen.extend(ids)
        values = [dict(same_issue_as=c['id'], decision='DISMISSED', rationale='Fixture safe',
                       evidence_refs=c['evidence_refs']) for c in page['candidates']]
        saved = risks.submit(values, page['dirty_seq'], scan_id=page['scan_id'], return_risks=True, final_report=True)
        assert json_bytes(saved) < 16384
        if saved['view'] == 'review_receipt':
            assert not saved['host_review_completed'] and saved['review_progress']['pending_scanner_count'] > 0
        offset = page['next_offset']
    assert len(seen) == 90


def test_batch_missing_file_preserves_success_and_merges_ranges(sample):
    root, service, ref, risks = sample
    result = read_contexts(risks, [EvidenceWindow(file_path='query.py', start_line=1, end_line=1),
        EvidenceWindow(file_path='query.py', start_line=1, end_line=2),
        EvidenceWindow(file_path='absent.py', related=True)])
    assert len(result['evidence']) == 1 and len(result['errors']) == 1
    assert result['evidence'][0]['line_end'] == 2
    assert not result['review_saved']


def test_source_mutation_still_rejects_shared_evidence(sample, monkeypatch):
    risks = seed(sample, monkeypatch)
    page = risks.get(limit=None, review_only=True)
    (sample[0]/'query.py').write_text('changed = True\n')
    with pytest.raises(ValueError, match='EVIDENCE_STALE'):
        risks.submit([dict(same_issue_as=c['id'], decision='DISMISSED', rationale='Fixture',
                           evidence_refs=c['evidence_refs']) for c in page['candidates']],
                     page['dirty_seq'], scan_id=page['scan_id'])
    assert not risks.load()['reviews']


def test_report_fragments_reconstruct_without_loss_and_detect_changes(sample, monkeypatch):
    from security_runtime.review_delivery import report_page
    risks = seed(sample, monkeypatch, 1, 16384)
    page = dict(check_ref=risks.ref, dirty_seq=1, scan_id='scan-1', risks=[], total=0,
                gaps=[], scope_unknown=False, session_url='http://127.0.0.1/risks',
                review_progress=dict(host_review_completed=True), report_text=('风险代码\\n中文\"' * 9000))
    check = risks.current_check()
    pieces, offset, digest = [], 0, None
    while offset is not None:
        result = report_page(page, check, risks.root, offset, digest)
        assert json_bytes(result) < 16384
        pieces.append(result['report_text'])
        offset, digest = result['next_offset'], result['report_digest']
    assert ''.join(pieces) == page['report_text']
    page['report_text'] += 'changed'
    with pytest.raises(ValueError, match='VERSION_STALE'):
        report_page(page, check, risks.root, 1, digest)


@pytest.mark.parametrize('budget', [0, 16383, 262145, True])
def test_invalid_budget_rejected(budget):
    values = copy.deepcopy(DEFAULTS)
    values['development']['review_response_bytes'] = budget
    with pytest.raises(ValueError, match='REVIEW_RESPONSE'):
        validate_preferences(values)


def test_single_oversized_description_is_explicitly_omitted_not_candidate(sample, monkeypatch):
    risks = seed(sample, monkeypatch, 1, 16384)
    with risks.store.transaction() as db:
        row = risks.load(db)
        risk = next(iter(row['risks'].values()))
        risk['observations'][0]['finding']['description'] = '长描述' * 20000
        risks.store._put(db, risks.ref, row)
    page = risks.get(limit=None, review_only=True)
    assert len(page['candidates']) == 1 and page['next_offset'] is None
    assert 'description' in page['candidates'][0]['metadata_omitted']
    assert json_bytes(page) <= 16384


def test_development_time_final_receipt_preserves_wait_for_static_scan(sample):
    from test_development_risks import observation
    risks = sample[3]
    saved = risks.submit([observation(risks)], 1, return_risks=True, final_report=True)
    assert saved['review_saved'] and saved['post_commit_read']
    assert saved['delivery_status'] == 'WAITING_FOR_STATIC_SCAN'
    assert saved['next_action'] is None and not saved['host_review_completed']
    assert 'report_text' not in saved and saved['delivery_instruction']


def test_non_adjacent_findings_share_overlapping_expanded_context(sample, monkeypatch):
    from security_runtime.review_delivery import collect_evidence
    root, _, _, risks = sample
    (root/'query.py').write_text('\n'.join(f'line_{n} = {n}' for n in range(1,31)))
    calls = []
    original = risks.read
    def read(*args, **kwargs):
        calls.append(args)
        return original(*args, **kwargs)
    monkeypatch.setattr(risks, 'read', read)
    evidence, errors, metrics = collect_evidence(risks, [dict(file_path='query.py', line_start=n, line_end=n) for n in (5,11)], [], 16384)
    assert len(calls) == len(evidence) == 1 and not errors
    assert evidence[0]['line_start'] <= 5 and evidence[0]['line_end'] >= 11


def test_budget_setting_round_trip_only_applies_to_next_check(sample):
    from security_runtime.user_config import read_config, save_config, batch_config
    root, service, ref, risks = sample
    config = read_config()
    config['values']['development']['review_response_bytes'] = 131072
    saved = save_config(config['values'], config['revision'])
    assert saved['saved'] and read_config()['values']['development']['review_response_bytes'] == 131072
    assert batch_config(risks.current_check())['development']['review_response_bytes'] == 65536
    next_ref = service.begin(root, 'next-budget')['check_ref']
    assert next_ref != ref
    assert batch_config(service.store(root).load(next_ref, service.owner))['development']['review_response_bytes'] == 131072


def test_final_report_keeps_gap_facts_but_hides_internal_codes(sample, monkeypatch):
    risks = seed(sample, monkeypatch, count=1)
    root, service, ref, _ = sample
    store = service.store(root)
    with store.transaction() as db:
        check = store._get(db, ref)
        store._put(db, ref, dict(check, result=dict(check.get('result') or {}, gaps=['SCANNER_COVERAGE_LIMITED'])))
    page = risks.get(limit=None, review_only=True)
    saved = risks.submit([dict(same_issue_as=c['id'], decision='DISMISSED',
        rationale='Known safe fixture', evidence_refs=c['evidence_refs']) for c in page['candidates']],
        page['dirty_seq'], scan_id=page['scan_id'], return_risks=True, final_report=True)
    assert saved['gaps'] == ['SCANNER_COVERAGE_LIMITED']
    assert 'SCANNER_COVERAGE_LIMITED' not in saved['report_text']
    assert '覆盖限制' in saved['report_text']
    assert saved['summary']['false_positives'] == 1
    assert saved['review_saved'] and saved['next_action'] is None


@pytest.mark.parametrize('gaps', [[], ['SCANNER_COVERAGE_LIMITED']])
def test_recorded_file_completion_is_independent_of_watch_diagnostics(sample, monkeypatch, gaps):
    risks = seed(sample, monkeypatch, count=1)
    root, service, ref, _ = sample
    store = service.store(root)
    with store.transaction() as db:
        check = store._get(db, ref)
        store._put(db, ref, dict(check, scope_unknown=True,
            file_watch_gaps=['FILE_WATCH_INTERRUPTED'],
            result=dict(check.get('result') or {}, gaps=gaps)))
    page = risks.get(limit=None, review_only=True)
    saved = risks.submit([dict(same_issue_as=c['id'], decision='DISMISSED',
        rationale='Known safe fixture', evidence_refs=c['evidence_refs']) for c in page['candidates']],
        page['dirty_seq'], scan_id=page['scan_id'], return_risks=True, final_report=True)
    assert saved['review_saved'] and saved['next_action'] is None
    assert saved['scope_unknown'] and saved['gaps'] == gaps
    assert store.load(ref)['file_watch_gaps'] == ['FILE_WATCH_INTERRUPTED']
    assert '范围未知' not in saved['report_text']
    assert '1 条扫描告警为误报' in saved['report_text']
    assert saved['host_review_completed']
    assert saved['gaps'] == gaps
    assert '经复核，1 条扫描告警为误报，无需处理。' in saved['report_text']
    assert ('覆盖限制' in saved['report_text']) == bool(gaps)
