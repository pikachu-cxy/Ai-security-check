"""Synthetic development risks; no real scanner or worker is permitted."""
import pytest

from security_runtime.development_check import DevelopmentCheckService
from security_runtime.development_risks import DevelopmentRisks
from security_runtime.hook_state import HookStateStore
from security_runtime.models import Finding
from dataclasses import asdict

OWNER = dict(host='codex', session='1'*64)
IMPACT = dict(impact_summary='Only binds input; return shape and authorized access stay unchanged', critical_unknowns=[], repair_paths=['query.py'])


@pytest.fixture
def sample(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    config = tmp_path/'config.toml'
    config.write_text('[agent]\naudit_business_logic=true\n', encoding='utf-8')
    monkeypatch.setenv('SECURITY_RUNTIME_CONFIG', str(config))
    def forbidden(*a, **kw):
        pytest.fail('Unexpected scanner or worker')
    monkeypatch.setattr('security_runtime.runtime.SecurityRuntime.scan', forbidden)
    monkeypatch.setattr('security_runtime.development_check_worker.launch_worker', forbidden)
    root = tmp_path/'project'
    root.mkdir()
    (root/'query.py').write_text('def query(conn, name):\n    return conn.execute(name)\n', encoding='utf-8')
    service = DevelopmentCheckService(None, HookStateStore(tmp_path/'private'), owner=OWNER,
        scan_path_provider=tmp_path/'scans.db', launcher=forbidden)
    ref = service.begin(root, 'query')['check_ref']
    service.record(root, ref, ['query.py'])
    return root, service, ref, DevelopmentRisks(service, root, ref)


def observation(risks, **kwargs):
    evidence = risks.read('query.py', 1, 2)
    if kwargs.get('same_issue_as'):
        kwargs.setdefault('scan_id', risks.current_check().get('scan_id'))
    return dict(issue_key='query-sql', file_path='query.py', line_start=2, line_end=2,
                category='sql-injection', title='Unsafe query', description='Unbound SQL input',
                impact='May read unintended rows', fix_advice='Bind values', severity='HIGH',
                decision='CONFIRMED', rationale='Input reaches execute', evidence_refs=[evidence['evidence_ref']],
                **kwargs)


def submit(sample, value=None):
    root, service, ref, risks = sample
    value = value or observation(risks)
    result = risks.submit([value], service.store(root).load(ref, OWNER)['dirty_seq'])
    return result['risks'][0], value


def scanner(sample, monkeypatch):
    root, service, ref, risks = sample
    finding = asdict(Finding('s1', 'sql-injection', 'SQL', 'SQL', 'desc', 'impact', 'HIGH', 'HIGH',
                            'query.py', 2, 2, 'evidence', 'bind', ['semgrep'], 'fingerprint'))
    monkeypatch.setattr('security_runtime.storage.ReadOnlySQLiteStore.get_scan',
                        lambda *a: dict(target_profile=dict(path=str(root)), findings=[finding]))
    store = service.store(root)
    with store.transaction() as db:
        check = store._get(db, ref)
        check.update(scan_id='scan-1', scanned_seq=check['dirty_seq'])
        store._put(db, ref, check)
    return finding


@pytest.mark.parametrize("delivery", ["fast", "wait"])
def test_large_ledger_accepts_scanner_reviews_and_new_business_finding(sample, monkeypatch, delivery):
    root, service, ref, risks = sample
    # This test exercises the legacy fast/wait contract, not streaming audit.
    from security_runtime.business_audit import operate
    operate(risks, 'prepare')
    with service.store(root).transaction() as db:
        check = service.store(root)._get(db, ref)
        check["effective_config"]["values"]["development"]["business_audit_delivery"] = delivery
        service.store(root)._put(db, ref, check)
    finding = scanner(sample, monkeypatch)
    store = service.store(root)
    for scan, count in [('previous', 100), ('current', 14)]:
        findings = [dict(finding, id=f'{scan}-{i}', fingerprint=f'{scan}-{i}') for i in range(count)]
        monkeypatch.setattr('security_runtime.storage.ReadOnlySQLiteStore.get_scan',
                            lambda *_: dict(target_profile=dict(path=str(root)), findings=findings))
        with store.transaction() as db:
            check = store._get(db, ref)
            store._put(db, ref, dict(check, scan_id=scan))
        risks.sync_scanner()
    before = risks.get()
    pending = before['review_progress']['pending_scanner_ids']
    assert before['total'] == 114 and len(pending) == 14
    compact = risks.get(limit=20, review_only=True)
    assert compact['total'] == (14 if delivery == 'fast' else 15) and compact['next_offset'] is None
    assert {item['id'] for item in compact['candidates']} == set(pending)
    assert compact['business_paths'] == ([] if delivery == 'fast' else ['query.py']) and compact['evidence']
    assert compact['deferred_business_paths'] == (['query.py'] if delivery == 'fast' else [])
    evidence = risks.read('query.py', 1, 2)['evidence_ref']
    batch = [dict(same_issue_as=key, scan_id='current', decision='DISMISSED',
                  rationale='Synthetic test alert', evidence_refs=[evidence]) for key in pending]
    new_risk = observation(risks)
    reviews = [dict(file_path='query.py', rationale='Reviewed query construction',
                    evidence_refs=[evidence], limitations=[])]
    saved = risks.submit([*batch, new_risk], check['dirty_seq'], business_reviews=reviews, return_risks=True)
    assert saved['post_commit_read'] and saved['view'] == 'batch' and saved['total'] == 15
    assert risks.get()['total'] == 115
    assert {r['id'] for r in saved['risks'] if r['decision'] == 'DISMISSED'} == set(pending)
    assert saved['review_progress']['host_review_completed']
    after = risks.get(limit=20, review_only=True)
    assert after['total'] == (14 if delivery == 'fast' else 15) and not (after['candidates'] or after['business_paths'] or after['evidence'])
    risks.submit([new_risk], check['dirty_seq'], business_reviews=reviews)
    restored = DevelopmentRisks(service, root, ref).load()
    assert len(restored['risks']) == 115
    assert sum(r['decision'] == 'CONFIRMED' for r in restored['risks'].values()) == 1


def test_ai_finding_persists_shared_finding_schema_without_scanner(sample):
    item, _ = submit(sample)
    root, service, ref, risks = sample
    restored = DevelopmentRisks(service, root, ref).get()['risks'][0]
    assert restored['id'] == item['id']
    assert Finding(**restored['finding']).scanner_sources == []
    assert restored['sources'] == ['HOST_REVIEW']


def test_batch_report_is_saved_read_back_and_respects_disposition(sample, monkeypatch):
    _, _, _, risks = sample
    scanner(sample, monkeypatch)
    risks.sync_scanner()
    seq = risks.current_check()['dirty_seq']
    value = observation(risks, same_issue_as='s1', report_text='SQL at query.py:2 — bind the name.')
    coverage = [dict(file_path='query.py', rationale='Reviewed', limitations=[],
                     evidence_refs=value['evidence_refs'])]
    with pytest.raises(ValueError):
        risks.submit([dict(value, evidence_refs=['invalid'])], seq, business_reviews=coverage)
    page = risks.submit([value], seq, business_reviews=coverage, return_risks=True)
    assert '**问题**' in page['report_text'] and '**修复／暂不处理**' in page['report_text']
    key = page['risks'][0]['id']
    assert risks.load()['risks'][key]['assessment']['report_text'] == value['report_text']
    risks.disposition(key, 'DEFER', True)
    assert '**问题**' not in risks.get(batch_version=(seq, 'scan-1'))['report_text']
    with pytest.raises(ValueError, match='VERSION_STALE'):
        risks.get(batch_version=(seq, 'another-scan'))


def test_repeated_submission_is_idempotent(sample):
    item, value = submit(sample)
    _, service, ref, risks = sample
    again = risks.submit([value], risks.current_check()['dirty_seq'])['risks'][0]
    assert again['id'] == item['id']
    assert again['observation_count'] == again['assessment_count'] == 1


def test_timing_records_only_saved_reviews(sample, monkeypatch):
    events = []
    monkeypatch.setattr('security_runtime.performance_trace.review_event',
        lambda action, check, progress=None: events.append((action, progress)))
    risks = sample[3]
    value = observation(risks)
    assert [e[0] for e in events] == ['evidence_read']
    with pytest.raises(ValueError):
        risks.submit([value], -1)
    assert [e[0] for e in events] == ['evidence_read']
    result = risks.submit([value], risks.current_check()['dirty_seq'])
    assert events[-1] == ('saved', result['review_progress'])


@pytest.mark.parametrize('decision', ['CONFIRMED', 'DISMISSED', 'INCONCLUSIVE'])
def test_scanner_and_ai_share_one_risk_ai_decision_wins(sample, monkeypatch, decision):
    original = scanner(sample, monkeypatch)
    risks = sample[3]
    value = observation(risks, same_issue_as='s1')
    value['decision'] = decision
    item, value = submit(sample, value)
    assert item['sources'] == ['HOST_REVIEW', 'SCANNER']
    assert item['decision'] == decision
    raw = risks.load()['risks'][item['id']]['observations'][0]
    assert raw['finding'] == original
    again = risks.submit([value], risks.current_check()['dirty_seq'])
    assert again['total'] == 1
    assert again['risks'][0]['observation_count'] == 2


def test_ai_first_then_scanner_preserves_original_id(sample, monkeypatch):
    item, _ = submit(sample)
    scanner(sample, monkeypatch)
    risks = sample[3]
    result = risks.submit([observation(risks, same_issue_as='s1')], risks.current_check()['dirty_seq'])
    assert result['total'] == 1
    assert result['risks'][0]['id'] == item['id']
    assert len(result['risks'][0]['sources']) == 2


def test_same_location_different_issue_stays_separate(sample):
    submit(sample)
    risks = sample[3]
    value = observation(risks)
    value.update(issue_key='authorization', category='authorization', title='Missing owner check')
    assert risks.submit([value], risks.current_check()['dirty_seq'])['total'] == 2


def test_stale_and_forged_evidence_rejected(sample):
    root, service, ref, risks = sample
    value = observation(risks)
    (root/'query.py').write_text('changed\n', encoding='utf-8')
    with pytest.raises(ValueError, match='EVIDENCE_STALE'):
        risks.submit([value], risks.current_check()['dirty_seq'])
    value['evidence_refs'] = ['forged']
    with pytest.raises(ValueError, match='EVIDENCE_UNKNOWN'):
        risks.submit([value], risks.current_check()['dirty_seq'])
    assert risks.get()['total'] == 0


def test_foreign_owner_and_unobserved_paths_rejected(sample):
    root, service, ref, risks = sample
    (root/'other.py').write_text('pass\n')
    with pytest.raises(ValueError, match='NOT_OBSERVED'):
        risks.read('other.py')
    other = DevelopmentCheckService(None, service.hooks, owner=dict(host='codex', session='2'*64))
    with pytest.raises(ValueError):
        DevelopmentRisks(other, root, ref)


def test_version_conflict_does_not_publish(sample):
    risks = sample[3]
    with pytest.raises(ValueError, match='VERSION_STALE'):
        risks.submit([observation(risks)], 999)
    assert risks.get()['total'] == 0


def test_authorized_repair_and_original_risk_recheck(sample):
    root, service, ref, risks = sample
    item, value = submit(sample)
    args = (item['id'], 'Bind name without changing API', ['Keep returned rows'], value['evidence_refs'])
    with pytest.raises(ValueError, match='AUTHORIZATION_REQUIRED'):
        risks.prepare_fix(*args, False, **IMPACT)
    fix = risks.prepare_fix(*args, True, **IMPACT)
    assert fix['ready_for_host_fix']
    assert risks.prepare_fix(*args, True, **IMPACT)['repair_ref'] == fix['repair_ref']
    with pytest.raises(ValueError, match='NO_REPAIR_CHANGE'):
        risks.resolve(item['id'], fix['repair_ref'], 'CODE_REVIEWED_RESOLVED', value['evidence_refs'], 'Fixed')
    (root/'query.py').write_text('def query(conn, name):\n    return conn.execute("SELECT ?", (name,))\n')
    evidence = risks.read('query.py', 1, 2)
    result = risks.resolve(item['id'], fix['repair_ref'], 'CODE_REVIEWED_RESOLVED', [evidence['evidence_ref']],
                           'The original argument is now a bound value; signature and rows preserved')
    assert result['proof'] == 'HOST_CODE_REVIEW_NOT_SCANNER_PROOF'
    assert DevelopmentRisks(service, root, ref).get()['risks'][0]['status'] == 'CODE_REVIEWED_RESOLVED'


def test_repair_in_related_unobserved_file_preserves_original_risk(sample):
    root, service, ref, risks = sample
    (root/'permissions.py').write_text('def allowed(user):\n    return True\n')
    item, value = submit(sample)
    related = risks.read('permissions.py', 1, 2, related=True)
    refs = value['evidence_refs'] + [related['evidence_ref']]
    with pytest.raises(ValueError, match='REPAIR_PATH_INVALID'):
        risks.prepare_fix(item['id'], 'fix access', ['keep sharing'], refs, True,
                          **dict(IMPACT, repair_paths=['missing.py']))
    fix = risks.prepare_fix(item['id'], 'fix access', ['keep sharing'], refs, True,
                            **dict(IMPACT, repair_paths=['permissions.py']))
    assert fix['scope'] == ['permissions.py']
    assert risks.current_check()['observed_paths'] == ['query.py']
    with pytest.raises(ValueError, match='NO_REPAIR_CHANGE'):
        risks.resolve(item['id'], fix['repair_ref'], 'CODE_REVIEWED_RESOLVED', refs, 'No change')
    (root/'permissions.py').write_text('def allowed(user):\n    return user == "owner"\n')
    after = risks.read('permissions.py', 1, 2, related=True)
    result = risks.resolve(item['id'], fix['repair_ref'], 'CODE_REVIEWED_RESOLVED',
                           value['evidence_refs'] + [after['evidence_ref']], 'Access now checked')
    assert result['proof'] == 'HOST_CODE_REVIEW_NOT_SCANNER_PROOF'


def test_repair_requires_explicit_scope_and_preserves_active_preparation(sample):
    root, service, ref, risks = sample
    item, value = submit(sample)
    impact = dict(IMPACT, repair_paths=None)
    with pytest.raises(ValueError, match='REPAIR_PATH_INVALID'):
        risks.prepare_fix(item['id'], 'fix', ['keep'], value['evidence_refs'], True, **impact)
    first = risks.prepare_fix(item['id'], 'fix', ['keep'], value['evidence_refs'], True, **IMPACT)
    (root/'permissions.py').write_text('def allowed(user):\n    return True\n')
    related = risks.read('permissions.py', 1, 2, related=True)
    with pytest.raises(ValueError, match='FIX_ALREADY_ACTIVE'):
        risks.prepare_fix(item['id'], 'fix related file', ['keep'],
                          value['evidence_refs'] + [related['evidence_ref']], True,
                          **dict(IMPACT, repair_paths=['permissions.py']))
    assert risks.get()['risks'][0]['repairs'][0]['repair_ref'] == first['repair_ref']


def test_dismissed_risk_cannot_prepare_repair(sample):
    risks = sample[3]
    value = observation(risks)
    value['decision'] = 'DISMISSED'
    item, value = submit(sample, value)
    with pytest.raises(ValueError, match='NOT_ACTIVE'):
        risks.prepare_fix(item['id'], 'fix', ['keep'], value['evidence_refs'], True, **IMPACT)


def test_scanner_proof_cannot_be_forged(sample):
    item, value = submit(sample)
    risks = sample[3]
    fix = risks.prepare_fix(item['id'], 'fix', ['keep'], value['evidence_refs'], True, **IMPACT)
    with pytest.raises(ValueError, match='OUTCOME_INVALID'):
        risks.resolve(item['id'], fix['repair_ref'], 'SCANNER_VERIFIED_RESOLVED', value['evidence_refs'], 'zero alerts')


def test_reintroduced_risk_retains_repair_history(sample):
    test_authorized_repair_and_original_risk_recheck(sample)
    root, service, ref, risks = sample
    (root/'query.py').write_text('def query(conn, name):\n    return conn.execute(name)\n')
    service.record(root, ref, ['query.py'])
    item, _ = submit(sample)
    assert item['status'] == 'OPEN'
    assert item['repairs'][0]['status'] == 'COMPLETE'


def test_defer_persists_and_does_not_close_or_restore_on_resubmit(sample):
    item, value = submit(sample)
    risks = sample[3]
    risks.disposition(item['id'], 'DEFER', True)
    again = risks.submit([value], risks.current_check()['dirty_seq'])['risks'][0]
    assert again['status'] == 'OPEN' and again['reminder_suppressed']
    with pytest.raises(ValueError, match='DISPOSITION_INACTIVE'):
        risks.prepare_fix(item['id'], 'fix', ['keep'], value['evidence_refs'], True, **IMPACT)
    risks.disposition(item['id'], 'RESTORE', True)
    assert not risks.get()['risks'][0]['reminder_suppressed']


def test_critical_impact_unknown_prevents_preparation(sample):
    item, value = submit(sample)
    with pytest.raises(ValueError, match='IMPACT_UNRESOLVED'):
        sample[3].prepare_fix(item['id'], 'fix', ['keep'], value['evidence_refs'], True,
                             impact_summary='Unknown authorization behavior', critical_unknowns=['caller unread'])


def test_risk_journal_survives_metadata_retention(sample):
    item, _ = submit(sample)
    root, service, ref, risks = sample
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        row.update(state='RESULTS_READY', finish_requested=True, updated_at=0)
        store._put(db, ref, row)
        for entry in store._all(db):
            if entry.get('kind') == 'focus':
                db.execute('DELETE FROM records WHERE key=?', (entry['key'],))
        store.prune(db)
    assert DevelopmentRisks(service, root, ref).get()['risks'][0]['id'] == item['id']
    assert service.get(root, ref)['risk_access']['tool'] == 'get_development_risks'


def test_legacy_link_uses_original_scanner_location(sample, monkeypatch):
    scanner(sample, monkeypatch)
    risks = sample[3]
    value = observation(risks, same_issue_as='s1')
    value['line_start'] = value['line_end'] = 1
    item, _ = submit(sample, value)
    assert item['finding']['line_start'] == item['finding']['line_end'] == 2


def test_unknown_remediation_cannot_close_risk(sample):
    item, value = submit(sample)
    with pytest.raises(ValueError, match='REPAIR_UNKNOWN'):
        sample[3].resolve(item['id'], 'forged', 'CODE_REVIEWED_RESOLVED', value['evidence_refs'], 'fixed')


def test_repeated_review_does_not_reopen_resolved_risk(sample):
    item, value = submit(sample)
    risks = sample[3]
    # Simulate a completed saved outcome, retaining its original assessment.
    with risks.store.transaction() as db:
        row = risks.load(db)
        row['risks'][item['id']]['status'] = 'CODE_REVIEWED_RESOLVED'
        risks.store._put(db, risks.ref, row)
    again = risks.submit([value], risks.current_check()['dirty_seq'])['risks'][0]
    assert again['status'] == 'CODE_REVIEWED_RESOLVED'
    assert again['finding']['status'] == again['status']


def test_early_review_bound_to_scan_result(sample, monkeypatch):
    root, service, ref, risks = sample
    submit(sample)
    assert not service.get(root, ref)['host_review_completed']
    scanner(sample, monkeypatch)
    row = risks.load()
    assert not any(r['dirty_seq'] == risks.current_check()['dirty_seq'] and
                   r.get('scan_id') == risks.current_check()['scan_id'] for r in row['reviews'])
    risks.submit([observation(risks, same_issue_as='s1')], risks.current_check()['dirty_seq'])
    assert risks.load()['reviews'][-1]['scan_id'] == 'scan-1'


def test_review_scanner_context_manifest_without_marking_it_edited(sample, monkeypatch):
    root, service, ref, risks = sample
    (root / 'pyproject.toml').write_text('[project]\nname="sample"\n')
    original = scanner(sample, monkeypatch)
    original.update(file_path='pyproject.toml', line_start=1, line_end=1)
    evidence = risks.read('pyproject.toml', 1, 2, related=True)
    review = dict(same_issue_as='s1', scan_id='scan-1', decision='DISMISSED',
                  rationale='Synthetic dependency context review', evidence_refs=[evidence['evidence_ref']])
    result = risks.submit([review], risks.current_check()['dirty_seq'])
    assert result['risks'][0]['decision'] == 'DISMISSED'
    assert risks.current_check()['observed_paths'] == ['query.py']
    # An independent AI observation still cannot use this unedited location.
    value = observation(risks)
    value.update(file_path='pyproject.toml', line_start=1, line_end=1,
                 evidence_refs=[evidence['evidence_ref']])
    with pytest.raises(ValueError, match='DEVELOPMENT_RISK_LOCATION_INVALID'):
        risks.submit([value], risks.current_check()['dirty_seq'])


def test_batch_evidence_deduplicates_and_keeps_stale_submission_guard(sample):
    from security_runtime.development_views import EvidenceWindow, read_contexts
    root, service, ref, risks = sample
    window = EvidenceWindow(file_path='query.py', start_line=1, end_line=2)
    batch = read_contexts(risks, [window, window])
    assert len(batch['evidence']) == 1
    value = observation(risks)
    value['evidence_refs'] = [batch['evidence'][0]['evidence_ref']]
    (root/'query.py').write_text('def query(conn, name):\n    return conn.execute("fixed")\n')
    with pytest.raises(ValueError, match='EVIDENCE_STALE'):
        risks.submit([value], batch['dirty_seq'])


def test_batch_rejects_cross_version_and_unobserved_paths(sample, monkeypatch):
    from security_runtime.development_views import EvidenceWindow, read_contexts
    root, service, ref, risks = sample
    result = read_contexts(risks, [EvidenceWindow(file_path='other.py')])
    assert not result['evidence'] and result['errors'][0]['reason_code'] == 'DEVELOPMENT_RISK_PATH_NOT_OBSERVED'
    original = risks.read
    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        service.record(root, ref, ['query.py'])
        return result
    monkeypatch.setattr(risks, 'read', changed)
    with pytest.raises(ValueError, match='VERSION_STALE'):
        read_contexts(risks, [EvidenceWindow(file_path='query.py', end_line=2)])


def test_mcp_compact_review_defaults_preserve_findings_and_full_access(sample):
    import asyncio
    import json
    from types import SimpleNamespace
    from mcp.server.fastmcp import FastMCP
    from security_runtime.mcp_tools.development_check import register
    root, service, ref, risks = sample
    server = FastMCP('compact-test')
    register(server, SimpleNamespace(harden=lambda names: None), application=SimpleNamespace(
        development_service=lambda *a, **kw: service, bound_path=lambda p: root))
    async def call(name, args):
        result = await server.call_tool(name, dict(check_ref=ref, **args))
        # FastMCP returns the structured dict alongside the text blocks.
        return result[1] if isinstance(result, tuple) else json.loads(result[0].text)
    async def run():
        windows = [dict(file_path='query.py', start_line=1, end_line=2)] * 2
        batch = await call('read_development_risk_context', dict(windows=windows))
        assert len(batch['evidence']) == 1
        value = observation(risks)
        receipt = await call('submit_development_review', dict(
            expected_seq=risks.current_check()['dirty_seq'], observations=[value]))
        assert receipt['review_saved'] and receipt['reread_required']
        assert 'risks' not in receipt and receipt['next_action']['arguments']['offset'] == 0
        short = await call('get_development_risks', {})
        combined = await call('submit_development_review', dict(
            expected_seq=risks.current_check()['dirty_seq'], observations=[value], return_risks=True))
        assert combined['post_commit_read'] and combined['review_saved']
        assert combined['risks'] == short['risks'] and combined['next_offset'] == short['next_offset']
        full = await call('get_development_risks', dict(view='full'))
        assert short['risks'][0]['finding'] == full['risks'][0]['finding']
        assert short['review_progress'] == full['review_progress']
        assert short['risks'][0]['disposition'] == full['risks'][0]['disposition']
        assert 'finding' not in short['risks'][0]['assessment']
        assert 'finding' in full['risks'][0]['assessment']
        schema = next(t.inputSchema for t in await server.list_tools() if t.name == 'get_development_risks')
        assert schema['properties']['limit']['default'] is None
        print('compact_bytes', len(json.dumps(short)), 'full_bytes', len(json.dumps(full)),
              'receipt_bytes', len(json.dumps(receipt)))
    asyncio.run(run())


@pytest.mark.parametrize('decision', ['CONFIRMED', 'DISMISSED', 'INCONCLUSIVE'])
def test_final_report_requires_complete_committed_single_page(sample, monkeypatch, decision):
    from security_runtime.development_views import final_report_receipt
    _, _, _, risks = sample
    scanner(sample, monkeypatch)
    risks.sync_scanner()
    report = (
        '**SQL 注入**\n\n评级及来源：高危，扫描规则评级。\n\n'
        '位置：[query.py:2](query.py:2)\n\n'
        '**问题**\n请求参数直接拼入 SQL。\n\n'
        '**可能影响**\n可控输入可能改变查询条件。\n\n'
        '**建议修复**\n使用参数绑定。\n\n'
        '**尚未确认**\n外部调用路径尚未核实。'
    )
    value = observation(risks, same_issue_as='s1', report_text=report)
    value['decision'] = decision
    seq = risks.current_check()['dirty_seq']
    coverage = [dict(file_path='query.py', rationale='Checked', evidence_refs=value['evidence_refs'])]
    import asyncio
    import json
    from types import SimpleNamespace
    from mcp.server.fastmcp import FastMCP
    from security_runtime.mcp_tools.development_check import register
    root, service, ref, _ = sample
    server = FastMCP('final-report-test')
    register(server, SimpleNamespace(harden=lambda names: None), application=SimpleNamespace(
        development_service=lambda *args: service, bound_path=lambda _: root))
    batch_scan_id = value.pop('scan_id')
    output = asyncio.run(server.call_tool('submit_development_review', dict(
        check_ref=ref, expected_seq=seq, scan_id=batch_scan_id, observations=[value], business_reviews=coverage,
        response_view='final_report', return_risks=True)))
    receipt = output[1] if isinstance(output, tuple) else json.loads(output[0].text)
    offsets = receipt['review_timing']['offsets_us']
    assert offsets['before_write'] <= offsets['committed'] <= offsets['readback_done'] <= offsets['response_ready']
    page = risks.get(batch_version=(seq, 'scan-1'))
    page.update(review_saved=True, post_commit_read=True, reread_required=False)
    if decision == 'INCONCLUSIVE':
        assert receipt['view'] == 'final_report' and 'risks' not in receipt
        assert receipt['summary']['INCONCLUSIVE'] == 1
        assert receipt['host_review_completed'] and receipt['next_action'] is None
        assert 'Agent 复核后待确认' in receipt['report_text']
    else:
        assert receipt['report_text'] == page['report_text']
        if decision == 'CONFIRMED':
            assert '请求参数直接拼入 SQL。' in receipt['report_text']
            assert '外部调用路径尚未核实。' in receipt['report_text']
        assert receipt['view'] == 'final_report' and 'risks' not in receipt
        assert receipt['dirty_seq'] == seq and receipt['scan_id'] == page['scan_id']
        for key, override in [('next_offset', 20), ('next_action', {'tool':'read'}),
                              ('reread_required', True), ('post_commit_read', False)]:
            fallback = dict(page, **{key: override})
            assert final_report_receipt(fallback) is fallback
        assert len(risks.load()['reviews']) == 1


def test_final_report_after_readback_failure_recovers_only_by_reading(sample, monkeypatch):
    from security_runtime.development_views import final_report_receipt
    _, _, _, risks = sample
    scanner(sample, monkeypatch)
    risks.sync_scanner()
    seq = risks.current_check()['dirty_seq']
    value = observation(risks, same_issue_as='s1', report_text='Bind the parameter.')
    coverage = [dict(file_path='query.py', rationale='Checked', evidence_refs=value['evidence_refs'])]
    with monkeypatch.context() as patch:
        def unavailable(*args, **kwargs):
            raise OSError('readback unavailable')
        patch.setattr(risks, 'get', unavailable)
        saved = risks.submit([value], seq, business_reviews=coverage, return_risks=True)
    receipt = final_report_receipt(saved)
    assert receipt['review_saved'] and receipt['reread_required'] and not receipt['post_commit_read']
    assert receipt['next_action']['tool'] == 'get_development_risks'
    assert '**问题**' in risks.get(batch_version=(seq, 'scan-1'))['report_text']
    assert len(risks.load()['reviews']) == 1


def test_duplicate_links_are_verified_in_the_same_batch(sample, monkeypatch):
    root, _, _, risks = sample
    first = scanner(sample, monkeypatch)
    other = dict(first, id='s2', fingerprint='second', title='Second detector')
    monkeypatch.setattr('security_runtime.storage.ReadOnlySQLiteStore.get_scan',
        lambda *_: dict(target_profile=dict(path=str(root)), findings=[first, other]))
    risks.sync_scanner()
    page = risks.get(review_only=True)
    primary, repeated = page['candidates']
    primary_review = dict(same_issue_as=primary['id'], decision='CONFIRMED',
        rationale='Input reaches SQL', evidence_refs=primary['evidence_refs'], report_text='Bind the query.')
    secondary = dict(same_issue_as=repeated['id'], decision='DISMISSED', rationale='Same input and sink',
                     evidence_refs=repeated['evidence_refs'], duplicate_of=primary['id'])
    def save(items):
        return risks.submit(items, page['dirty_seq'], scan_id=page['scan_id'], return_risks=True,
            business_reviews=[dict(file_path='query.py', rationale='Checked', evidence_refs=primary['evidence_refs'])])
    for target in ('unknown', repeated['id']):
        with pytest.raises(ValueError, match='DEVELOPMENT_DUPLICATE_INVALID'):
            save([primary_review, dict(secondary, duplicate_of=target)])
        assert not risks.load()['reviews']
    result = save([secondary, primary_review])
    assert '1 条重复告警' in result['report_text'] and '误报' not in result['report_text']
    with pytest.raises(ValueError, match='DEVELOPMENT_DUPLICATE_INVALID'):
        save([dict(primary_review, decision='DISMISSED')])


def test_shell_only_finding_keeps_writer_uncertainty_in_evidence_and_delivery(sample, monkeypatch):
    root, service, ref, risks = sample
    scanner(sample, monkeypatch)
    store = service.store(root)
    with store.transaction() as db:
        check = store._get(db, ref)
        store._put(db, ref, dict(check, explicit_paths=[], file_watch={'attribution':'TIME_WINDOW_NOT_WRITER'}))
    risks.sync_scanner()
    page = risks.get(review_only=True)
    item = page['candidates'][0]
    assert item['edit_attribution'] == 'OBSERVED_ONLY_WRITER_UNKNOWN'
    report = risks.submit([dict(same_issue_as=item['id'], decision='CONFIRMED', rationale='Unsafe SQL',
        report_text='Unsafe query.', evidence_refs=item['evidence_refs'])], page['dirty_seq'],
        scan_id=page['scan_id'], return_risks=True, business_reviews=[dict(file_path='query.py',
            rationale='Checked', evidence_refs=item['evidence_refs'])])
    assert '写入会话未经确认' not in report['report_text']
    assert 'query.py:2' in report['report_text']


def test_complete_report_keeps_details_and_adds_stable_session_link(sample, monkeypatch):
    from security_runtime import dashboard_service
    root, _, _, risks = sample
    scanner(sample, monkeypatch)
    risks.sync_scanner()
    monkeypatch.setattr(dashboard_service, 'endpoint', lambda: dict(port=12345, token='x'*32))
    seq = risks.current_check()['dirty_seq']
    value = observation(risks, same_issue_as='s1', report_text='Complete saved vulnerability description.')
    coverage = [dict(file_path='query.py', rationale='Checked', evidence_refs=value['evidence_refs'])]
    first = risks.submit([value], seq, business_reviews=coverage, return_risks=True)
    second = risks.get(batch_version=(seq, 'scan-1'))
    assert first['report_text'] == second['report_text']
    assert '**问题**' in first['report_text'] and '**可能影响**' in first['report_text']
    assert 'http://127.0.0.1:12345/risks?project=' in first['report_text']
    assert '&session=' in first['report_text'] and 'x'*32 not in first['report_text']
