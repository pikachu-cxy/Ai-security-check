import json
import os
import sqlite3
import pytest

from security_runtime import risk_dashboard
from security_runtime.hook_state import HookStateStore, identity, native_io_path
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


def save_editor(base, project, directory, *, decision='CONFIRMED', ledger_enabled=True):
    wd = base / directory / identity(os.path.normcase(str(project)))
    hooks = HookStateStore(wd / 'hooks')
    private = hooks.workspace_directory(project)
    private.mkdir(parents=True)
    (private / 'snapshot.key').write_bytes(b'k' * 32)
    finding = dict(id='same-finding', title='Same candidate', severity='HIGH', file_path='api.py')
    if ledger_enabled:
        ledger = SignedRecords(hooks, project, 'development-risks.db')
        with ledger.transaction() as db:
            ledger._put(db, 'same-check', dict(risks={'same-risk': dict(id='same-risk', finding=finding,
                decision=decision, disposition='ACTIVE', status='OPEN',
                observations=[dict(source='SCANNER', scan_id='same-scan', scanner_id='same-finding')])}))
    with sqlite3.connect(wd / 'scans.db') as db:
        db.execute('CREATE TABLE scans (id TEXT PRIMARY KEY, data TEXT NOT NULL)')
        db.execute('INSERT INTO scans VALUES (?, ?)', ('same-scan', json.dumps(dict(
            scan_id='same-scan', target_profile=dict(path=str(project)), findings=[finding]))))
    return wd


def test_cursor_only_and_cross_editor_dispositions_are_independent(tmp_path, monkeypatch):
    project = tmp_path / 'project'
    project.mkdir()
    base = tmp_path / 'state'
    monkeypatch.setattr(risk_dashboard, 'STATE', base)
    save_editor(base, project, 'cursor-workspaces', decision='DISMISSED')
    cursor_only = risk_dashboard.records()
    assert not cursor_only['partial']
    assert [(r['editor'], r['status']) for r in cursor_only['risks']] == [('cursor', 'AI 排除')]
    save_editor(base, project, 'global-workspaces')
    before = {p: native_io_path(p).read_bytes() for p in base.rglob('*.db')}
    combined = risk_dashboard.records()
    assert [(r['editor'], r['status']) for r in combined['risks']] == [
        ('codex', '待处理'), ('cursor', 'AI 排除')]
    assert len({r['id'] for r in combined['risks']}) == 2
    assert {p: native_io_path(p).read_bytes() for p in before} == before


def test_linked_candidate_in_one_editor_does_not_hide_other_editor(tmp_path, monkeypatch):
    project = tmp_path / 'project'
    project.mkdir()
    monkeypatch.setattr(risk_dashboard, 'STATE', tmp_path)
    save_editor(tmp_path, project, 'global-workspaces')
    save_editor(tmp_path, project, 'cursor-workspaces', ledger_enabled=False)
    rows = risk_dashboard.records()['risks']
    assert {(r['editor'], r['status']) for r in rows} == {('codex', '待处理'), ('cursor', '处置未知')}


@pytest.mark.parametrize('damage', ['scan', 'signature', 'directory', 'limit'])
def test_bad_or_truncated_cursor_data_is_not_reported_as_complete_zero(tmp_path, monkeypatch, damage):
    project = tmp_path / 'project'
    project.mkdir()
    monkeypatch.setattr(risk_dashboard, 'STATE', tmp_path)
    wd = save_editor(tmp_path, project, 'cursor-workspaces')
    if damage == 'scan':
        with sqlite3.connect(wd/'scans.db') as db:
            db.execute('UPDATE scans SET data=?', ('[]',))
    elif damage == 'signature':
        with sqlite3.connect(native_io_path(wd/'hooks'/wd.name/'development-risks.db')) as db:
            db.execute('UPDATE records SET mac=?', ('0'*64,))
    elif damage == 'directory':
        original = risk_dashboard.no_links
        def fail(path):
            if path == tmp_path/'cursor-workspaces':
                raise OSError('private details')
            return original(path)
        monkeypatch.setattr(risk_dashboard, 'no_links', fail)
    else:
        monkeypatch.setattr(risk_dashboard, 'MAX_SCANS', 0)
    result = risk_dashboard.records()
    assert result['partial'] and result['issues']
    assert 'private details' not in json.dumps(result)


def test_unreviewed_ledger_candidate_is_not_confirmed_risk(tmp_path, monkeypatch):
    project = tmp_path / 'project'
    project.mkdir()
    monkeypatch.setattr(risk_dashboard, 'STATE', tmp_path)
    save_editor(tmp_path, project, 'cursor-workspaces', decision=None)
    assert risk_dashboard.records()['risks'][0]['status'] == '待确认'
