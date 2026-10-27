import json
import os
import sqlite3

from security_runtime import risk_dashboard
from security_runtime.hook_state import HookStateStore, identity
from security_runtime.tasks.durable import SignedRecords
from test_development_check_mcp import development_server, call, projects, installed  # noqa: F401


def test_dashboard_reads_bound_signed_risks_and_unlinked_scan_candidates(tmp_path, monkeypatch):
    project = tmp_path / 'project'
    project.mkdir()
    base = tmp_path / 'state'
    monkeypatch.setattr(risk_dashboard, 'STATE', base)
    wd = base / 'global-workspaces' / identity(os.path.normcase(str(project)))
    hooks = HookStateStore(wd / 'hooks')
    private = hooks.workspace_directory(project)
    private.mkdir(parents=True)
    (private / 'snapshot.key').write_bytes(b'k' * 32)
    ledger = SignedRecords(hooks, project, 'development-risks.db')
    finding = dict(id='finding-1', title='Missing access check', severity='HIGH', file_path='api.py', line_start=3)
    with ledger.transaction() as db:
        ledger._put(db, 'check-1', dict(risks={'risk-1': dict(id='risk-1', finding=finding,
            decision='CONFIRMED', disposition='DEFER', status='OPEN',
            observations=[dict(source='SCANNER', scan_id='scan-1', scanner_id='finding-1')])}))
    with sqlite3.connect(wd / 'scans.db') as db:
        db.execute('CREATE TABLE scans (id TEXT PRIMARY KEY, data TEXT NOT NULL)')
        scan = dict(scan_id='scan-1', target_profile=dict(path=str(project)), findings=[finding,
            dict(id='finding-2', title='Unreviewed', severity='LOW', file_path='other.py')])
        db.execute('INSERT INTO scans VALUES (?, ?)', ('scan-1', json.dumps(scan)))
    result = risk_dashboard.records()
    assert result['partial'] is False
    assert [(r['title'], r['status']) for r in result['risks']] == [
        ('Missing access check', '已暂缓'), ('Unreviewed', '处置未知')]
    assert all(r['project'] == str(project) for r in result['risks'])


def test_dashboard_reports_invalid_signature_without_publishing_record(tmp_path, monkeypatch):
    project = tmp_path / 'project'
    project.mkdir()
    base = tmp_path / 'state'
    monkeypatch.setattr(risk_dashboard, 'STATE', base)
    wd = base / 'global-workspaces' / identity(os.path.normcase(str(project)))
    hooks = HookStateStore(wd / 'hooks')
    private = hooks.workspace_directory(project)
    private.mkdir(parents=True)
    (private / 'snapshot.key').write_bytes(b'k' * 32)
    ledger = SignedRecords(hooks, project, 'development-risks.db')
    with ledger.transaction() as db:
        ledger._put(db, 'check-1', dict(risks={}))
    with sqlite3.connect(ledger.path) as db:
        db.execute("UPDATE records SET mac=?", ('0' * 64,))
    result = risk_dashboard.records()
    assert result['partial'] is True
    assert result['risks'] == []


def test_risk_dashboard_mcp_entry_does_not_scan(development_server, monkeypatch):
    server, _, _, launches = development_server
    monkeypatch.setattr(risk_dashboard, 'launch', lambda: 'http://127.0.0.1:12345/capability/')
    result = call(server, 'start_risk_dashboard')
    assert result['status'] == 'AVAILABLE'
    assert result['url'] == 'http://127.0.0.1:12345/capability/'
    assert result['scanner_run'] is False and not launches
