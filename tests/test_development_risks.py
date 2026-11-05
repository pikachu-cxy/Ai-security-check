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


def test_ai_finding_persists_shared_finding_schema_without_scanner(sample):
    item, _ = submit(sample)
    root, service, ref, risks = sample
    restored = DevelopmentRisks(service, root, ref).get()['risks'][0]
    assert restored['id'] == item['id']
    assert Finding(**restored['finding']).scanner_sources == []
    assert restored['sources'] == ['HOST_REVIEW']


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
    with pytest.raises(ValueError, match='PATH_NOT_OBSERVED'):
        read_contexts(risks, [EvidenceWindow(file_path='other.py')])
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
        full = await call('get_development_risks', dict(view='full'))
        assert short['risks'][0]['finding'] == full['risks'][0]['finding']
        assert short['review_progress'] == full['review_progress']
        assert short['risks'][0]['disposition'] == full['risks'][0]['disposition']
        assert 'finding' not in short['risks'][0]['assessment']
        assert 'finding' in full['risks'][0]['assessment']
        schema = next(t.inputSchema for t in await server.list_tools() if t.name == 'get_development_risks')
        assert schema['properties']['limit']['default'] == 20
        print('compact_bytes', len(json.dumps(short)), 'full_bytes', len(json.dumps(full)),
              'receipt_bytes', len(json.dumps(receipt)))
    asyncio.run(run())
