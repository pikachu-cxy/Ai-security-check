"""History remains usable after source removal; never scan or admit a workspace."""
import hashlib
import json
import sqlite3
import pytest

from security_runtime import risk_dashboard as dashboard, dashboard_catalog, dashboard_entities
from security_runtime.development_check import DevelopmentCheckStore
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.durable import SignedRecords
from test_risk_dashboard import save_editor


def seed_history(tmp_path, monkeypatch):
    root = tmp_path/'removed-project'
    root.mkdir()
    state = tmp_path/'state'
    monkeypatch.setattr(dashboard, 'STATE', state)
    monkeypatch.setattr(dashboard_catalog, 'directory', lambda: state/'dashboard')
    wd = save_editor(state, root, 'global-workspaces')
    hooks = HookStateStore(wd/'hooks')
    ledger = SignedRecords(hooks, root, 'development-risks.db')
    owner = dict(host='codex', session='a'*64)
    with ledger.transaction() as db:
        row = ledger._get(db, 'same-check')
        ledger._put(db, 'same-check', dict(row, owner=owner))
    checks = SignedRecords(hooks, root, 'development-checks.db')
    with checks.transaction() as db:
        checks._put(db, 'same-check', dict(kind='check', owner=owner, state='RESULTS_READY',
            dirty_seq=1, scanned_seq=1, observed_paths=[], effective_config={'values': {'agent': {'audit_business_logic': False}}}))
    with sqlite3.connect(wd/'scans.db') as db:
        for i in range(125):
            scan = dict(scan_id=f'scan-{i}', target_profile=dict(path=str(root)), findings=[
                dict(id=f'finding-{i}', title='Historical candidate', severity='HIGH', file_path='api.py')])
            db.execute('INSERT INTO scans VALUES (?,?)', (scan['scan_id'], json.dumps(scan)))
    root.rmdir()
    return root, wd, hooks


def saved_bytes(wd):
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in wd.rglob('*') if p.is_file() and (p.suffix == '.db' or p.name == 'snapshot.key')}


@pytest.mark.parametrize('kind', ['editor', 'project', 'workspace', 'session'])
def test_removed_project_complete_history_management_and_recovery(tmp_path, monkeypatch, kind):
    root, wd, hooks = seed_history(tmp_path, monkeypatch)
    def forbidden(*a, **kw):
        pytest.fail('History read must not scan, launch work, or admit a live workspace')
    monkeypatch.setattr('security_runtime.runtime.SecurityRuntime.scan', forbidden)
    monkeypatch.setattr('security_runtime.development_check_worker.launch_worker', forbidden)
    monkeypatch.setattr('security_runtime.development_check.workspace_root', forbidden)
    # Former dashboard caps do not truncate the asynchronous full index.
    monkeypatch.setattr(dashboard, 'MAX_WORKSPACES', 0)
    monkeypatch.setattr(dashboard, 'MAX_RISKS', 1)
    before = saved_bytes(wd)
    catalog = dashboard_catalog.Catalog()
    catalog.refresh()
    result = catalog.query({})
    assert not result['partial'] and result['total'] == 126
    assert result['finding_metrics']['scanner']['total'] == 126
    assert result['finding_metrics']['confirmed']['total'] == 1
    assert len(result['sessions']) == 1 and result['warnings'] and not result['diagnostics']
    entity = dashboard_entities.listing(catalog, kind)['items'][0]
    req = dict(action='delete', kind=kind, id=entity['id'], expected_revision=entity['revision'], request_id='history-delete-001')
    assert dashboard_entities.change(catalog, req)['saved']
    assert dashboard_entities.change(catalog, req)['repeated']
    assert catalog.query({}, export=True)['total'] == 126-entity['risk_count']
    assert catalog.query({})['finding_metrics']['confirmed']['total'] == 0
    catalog.signature = None
    catalog.refresh()
    assert catalog.query({})['total'] == 126-entity['risk_count']
    trash = dashboard_entities.listing(catalog, 'trash')['items'][0]
    dashboard_entities.change(catalog, dict(req, action='restore', id=trash['id'], expected_revision=trash['revision']))
    assert catalog.query({})['total'] == 126
    assert catalog.query({})['finding_metrics']['confirmed']['total'] == 1
    assert saved_bytes(wd) == before and not root.exists()


def test_removed_root_does_not_relax_signature_checks_or_active_admission(tmp_path, monkeypatch):
    root, wd, hooks = seed_history(tmp_path, monkeypatch)
    with pytest.raises(FileNotFoundError):
        DevelopmentCheckStore(hooks, root)
    path = wd/'hooks'/wd.name/'development-checks.db'
    with sqlite3.connect(path) as db:
        db.execute('UPDATE records SET mac=?', ('0'*64,))
    result = dashboard.records(complete=True)
    assert result['partial']
    assert result['diagnostics'][0]['code'] == 'HISTORY_SIGNATURE_INVALID'
    assert result['diagnostics'][0]['workspace_id'] == wd.name
    assert not any(r.get('confirmed_risk') for r in result['risks'])
    catalog = dashboard_catalog.Catalog()
    catalog.replace(result)
    with pytest.raises(ValueError, match='INCOMPLETE'):
        dashboard_entities.listing(catalog, 'project')


def test_missing_key_and_invalid_database_have_different_diagnostics(tmp_path, monkeypatch):
    _, wd, _ = seed_history(tmp_path, monkeypatch)
    key = wd/'hooks'/wd.name/'snapshot.key'
    key.unlink()
    result = dashboard.records(complete=True)
    assert result['diagnostics'][0]['code'] == 'HISTORY_FILE_MISSING'
    (wd/'scans.db').write_bytes(b'not a sqlite database')
    result = dashboard.records(complete=True)
    assert {d['code'] for d in result['diagnostics']} == {'HISTORY_FILE_MISSING', 'HISTORY_DATABASE_UNREADABLE'}


def test_more_than_128_signed_history_rows_are_not_truncated(tmp_path, monkeypatch):
    root = tmp_path/'project'
    root.mkdir()
    wd = save_editor(tmp_path/'state', root, 'global-workspaces')
    ledger = SignedRecords(HookStateStore(wd/'hooks'), root, 'development-risks.db')
    ledger.max_rows = None
    with ledger.transaction() as db:
        for i in range(130):
            ledger._put(db, f'check-{i}', dict(risks={}))
    root.rmdir()
    assert len(dashboard.signed_rows(ledger.path, wd)) == 131
