"""Batch-scoped local delivery links: identity, liveness, open reads, ordering."""
from contextlib import closing
import json
import socket
import time

import pytest

from security_runtime import dashboard_service as service, risk_dashboard as dashboard
from test_dashboard_service import running, request, post

SESSION = 'a' * 64


def closed_port():
    with closing(socket.socket()) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def test_session_url_requires_live_service_and_carries_batch_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(service, 'directory', lambda: tmp_path)
    owner = dict(host='codex', session=SESSION)
    (tmp_path / 'endpoint.json').write_text(json.dumps(dict(port=closed_port(), token='t' * 32)))
    assert service.session_url(tmp_path, owner) is None
    with running() as server:
        service.save_endpoint(server.server_port, server.token)
        url = service.session_url(tmp_path, owner, check_ref='dc1-abc', scan_id='scan-1', seq=3)
        assert url and url.startswith('http://127.0.0.1:%d/risks?' % server.server_port)
        for part in ('check=dc1-abc', 'scan=scan-1', 'seq=3', 'session=' + SESSION):
            assert part in url
        assert service.session_url(tmp_path, owner, check_ref='bad value') is None
        assert service.session_url(tmp_path, owner, scan_id='bad/value') is None
        assert service.session_url(tmp_path, owner, seq='3') is None


def test_read_routes_need_no_cookie_while_writes_keep_csrf(monkeypatch):
    monkeypatch.setattr(dashboard, 'records', lambda **kw: dict(risks=[], total=0, sessions=[], note=''))
    with running() as server:
        assert request(server, '/risks')[0] == 200
        assert request(server, '/api/risks')[0] == 200
        status, _, body = request(server, '/api/session')
        assert status == 200 and json.loads(body)['csrf'] is None
        assert post(server, '/api/actions', dict(items=[]))[0] == 403
        _, headers, _ = request(server, '/' + server.token + '/')
        cookie = headers['Set-Cookie'].split(';')[0]
        _, _, body = request(server, '/api/session', {'Cookie': cookie})
        assert json.loads(body)['csrf'] == server.token
        assert request(server, '/risks', {'Host': 'example.com'})[0] == 403
        assert request(server, '/api/risks', {'Host': 'example.com'})[0] == 403


def test_enrich_derives_batch_keys_and_trusted_activity_time():
    from security_runtime.dashboard_records import enrich
    row = dict(workspace='/p', key='dc1-a', updated_at=1700000000.0, owner=dict(session=SESSION))
    risk = dict(id='dr1-x', finding=dict(file_path='a.py'), decision='CONFIRMED',
                observations=[dict(source='SCANNER', scan_id='scan-1', scanner_id='f1', scanned_seq=2)],
                assessments=[dict(dirty_seq=3, scan_id='scan-1', decision='CONFIRMED')], management={})
    item = enrich(dict(id='x', location='a.py:1'), row, risk)
    assert item['activity_at'] == 1700000000.0
    assert {'scan:scan-1', 'seq:3'} <= set(item['batch_keys'])


def make_risk(identifier, *, check='dc1-a', scans=(), seq=1, activity=1.0):
    return dict(id='codex:' + SESSION + ':' + check + ':' + identifier, editor='codex',
                editor_label='Codex', project='/p', project_id='b' * 64, workspace_id=SESSION,
                session_id=SESSION, check_id=check, category='code', severity='高', status='待处理',
                archived=False, scanner_candidate=False, confirmed_risk=True, revision='r',
                title=identifier, activity_at=activity,
                batch_keys=sorted({'scan:' + value for value in scans} | {'seq:' + str(seq)}))


def catalog_at(tmp_path, monkeypatch):
    from security_runtime import dashboard_catalog as module
    monkeypatch.setattr(module, 'directory', lambda: tmp_path)
    return module.Catalog()


def seed(catalog):
    items = [make_risk('r1', scans=['scan-1'], seq=1, activity=100.0),
             make_risk('r2', scans=['scan-1'], seq=1, activity=100.0),
             make_risk('r3', scans=['scan-2'], seq=2, activity=200.0),
             make_risk('r4', check='dc1-b', scans=['scan-3'], seq=1, activity=300.0)]
    catalog.replace(dict(risks=items, sessions=[], note='', projects=[], sources=[],
                         issues=[], diagnostics=[], warnings=[]))
    return items


def identifiers(page):
    return [row['id'].rsplit(':', 1)[1] for row in page['risks']]


def test_catalog_batch_filter_isolates_other_batches_of_same_session(tmp_path, monkeypatch):
    catalog = catalog_at(tmp_path, monkeypatch)
    seed(catalog)
    assert identifiers(catalog.query(dict(session=SESSION, limit='10'))) == ['r4', 'r3', 'r1', 'r2']
    assert identifiers(catalog.query(dict(check='dc1-a', scan='scan-1', seq='1', limit='10'))) == ['r1', 'r2']
    assert identifiers(catalog.query(dict(check='dc1-a', scan='scan-2', seq='2', limit='10'))) == ['r3']
    assert identifiers(catalog.query(dict(check='dc1-b', limit='10'))) == ['r4']


def test_catalog_time_order_is_stable_across_pages_and_export(tmp_path, monkeypatch):
    catalog = catalog_at(tmp_path, monkeypatch)
    seed(catalog)
    whole = identifiers(catalog.query(dict(session=SESSION, limit='10')))
    first = catalog.query(dict(session=SESSION, limit='2', offset='0'))
    second = catalog.query(dict(session=SESSION, limit='2', offset='2'))
    assert identifiers(first) + identifiers(second) == whole
    assert identifiers(catalog.query(dict(session=SESSION, limit='1'), export=True)) == whole
    assert first['next_offset'] == 2 and second['next_offset'] is None


def test_catalog_rejects_unknown_batch_parameters(tmp_path, monkeypatch):
    catalog = catalog_at(tmp_path, monkeypatch)
    seed(catalog)
    with pytest.raises(ValueError, match='DASHBOARD_QUERY_INVALID'):
        catalog.query(dict(batch='nope'))


def test_start_background_records_failure_reason(tmp_path, monkeypatch):
    monkeypatch.setattr(service, 'directory', lambda: tmp_path)
    def boom(*args, **kwargs):
        raise ValueError('RISK_DASHBOARD_START_FAILED')
    monkeypatch.setattr(service, 'ensure', boom)
    service.start_background().join(2)
    status = service.startup_status()
    assert status and status['status'] == 'FAILED'
    assert status['reason_code'] == 'RISK_DASHBOARD_START_FAILED'


def test_start_background_records_ready_state(tmp_path, monkeypatch):
    monkeypatch.setattr(service, 'directory', lambda: tmp_path)
    monkeypatch.setattr(service, 'ensure', lambda *a, **k: dict(port=1, token='t' * 32))
    service.start_background().join(2)
    assert service.startup_status()['status'] == 'READY'


def test_ensure_reuses_healthy_service_without_taking_the_lock(tmp_path, monkeypatch):
    monkeypatch.setattr(service, 'directory', lambda: tmp_path)
    with running() as server:
        service.save_endpoint(server.server_port, server.token)
        monkeypatch.setattr(service.sqlite3, 'connect',
                            lambda *a, **k: pytest.fail('healthy service must skip the startup lock'))
        assert service.ensure()['port'] == server.server_port


def report_page_for(monkeypatch, url, *, risks=None, totals=None, gaps=None, total=0):
    from security_runtime import dashboard_service
    from security_runtime.development_views import batch_report_page
    monkeypatch.setattr(dashboard_service, 'session_url', lambda *a, **k: url)
    page = batch_report_page(dict(
        check_ref='dc1-a', risks=risks or [], dirty_seq=3, scan_id='scan-1',
        next_action=None, next_offset=None, total=total, report_totals=totals or {},
        review_progress=dict(scanner_review='COMPLETE', pending_business_paths=[],
                             host_review_completed=True, business_review='SKIPPED_BY_CONFIG')),
        dict(workspace='fixture', owner=dict(host='codex', session=SESSION),
             scanned_seq=3, result=dict(gaps=gaps or [])))
    return page


LINK = 'http://127.0.0.1:1234/risks?check=dc1-a&scan=scan-1&seq=3'


def test_link_is_appended_once_at_the_very_end_for_false_positive_only_batch(monkeypatch):
    page = report_page_for(monkeypatch, LINK, totals=dict(false_positives=2), total=2)
    text = page['report_text']
    assert text.count(LINK) == 1
    assert text.rstrip().endswith('](' + LINK + ')')
    assert page['link_in_report'] is True


def test_link_is_appended_for_confirmed_findings(monkeypatch):
    page = report_page_for(monkeypatch, LINK, totals=dict(confirmed=1, actionable_confirmed=1), total=1)
    assert page['report_text'].rstrip().endswith('](' + LINK + ')')
    assert page['link_in_report'] is True


def test_no_link_when_batch_has_nothing_to_explain(monkeypatch):
    page = report_page_for(monkeypatch, LINK, total=0)
    assert LINK not in page['report_text']
    assert '链接暂不可用' not in page['report_text']
    assert page['link_in_report'] is False


def test_report_link_opens_only_this_batch_over_real_http(tmp_path, monkeypatch):
    """Report link -> real HTTP -> only this batch, without any browser cookie."""
    from security_runtime import dashboard_catalog as module
    from security_runtime.project_identity import describe
    from security_runtime.development_views import batch_report_page
    project = tmp_path/'project'
    project.mkdir()
    state = tmp_path/'state'
    monkeypatch.setattr(service, 'directory', lambda: state/'dashboard')
    monkeypatch.setattr(module, 'directory', lambda: state/'dashboard')
    scope = describe(project)
    catalog = module.Catalog()
    items = []
    for identifier, check, scan, seq, activity in (
            ('r1', 'dc1-a', 'scan-1', 3, 100.0), ('r2', 'dc1-a', 'scan-1', 3, 100.0),
            ('r3', 'dc1-a', 'scan-2', 4, 200.0), ('r4', 'dc1-b', 'scan-3', 1, 300.0)):
        item = make_risk(identifier, check=check, scans=[scan], seq=seq, activity=activity)
        item.update(project=str(project), project_id=scope['project_id'],
                    workspace_id=scope['workspace_id'])
        items.append(item)
    catalog.replace(dict(risks=items, sessions=[], note='', projects=[], sources=[],
                         issues=[], diagnostics=[], warnings=[]))
    with running() as server:
        server.catalog = catalog
        service.save_endpoint(server.server_port, server.token)
        page = batch_report_page(dict(
            check_ref='dc1-a', risks=[], dirty_seq=3, scan_id='scan-1', next_action=None,
            next_offset=None, total=2, report_totals=dict(confirmed=2),
            review_progress=dict(scanner_review='COMPLETE', pending_business_paths=[],
                                 host_review_completed=True, business_review='SKIPPED_BY_CONFIG')),
            dict(workspace=str(project), owner=dict(host='codex', session=SESSION),
                 scanned_seq=3, result=dict(gaps=[])))
        url = page['session_url']
        assert url and page['link_in_report']
        assert page['report_text'].rstrip().endswith('](' + url + ')')
        status, _, body = request(server, url[url.index('/risks?'):])
        assert status == 200
        query = url.split('?', 1)[1]
        status, _, body = request(server, '/api/risks?' + query)
        assert status == 200
        assert identifiers(json.loads(body)) == ['r1', 'r2']


def test_missing_link_keeps_gap_reason_inline_without_dead_url(monkeypatch):
    page = report_page_for(monkeypatch, None, gaps=['SCANNER_COVERAGE_LIMITED'], total=2)
    text = page['report_text']
    assert 'SCANNER_COVERAGE_LIMITED' in text
    assert '链接暂不可用' in text
    assert 'http://' not in text
    assert page['link_in_report'] is False

