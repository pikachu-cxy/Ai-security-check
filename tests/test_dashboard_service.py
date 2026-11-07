"""Local HTTP and identity regression tests, with isolated state."""
from contextlib import contextmanager
from http.client import HTTPConnection
import json
import threading

import pytest
from security_runtime import dashboard_service as service, risk_dashboard as dashboard


@contextmanager
def running(settings=None):
    server = dashboard.Server(settings)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(server, path, headers=None):
    conn = HTTPConnection('127.0.0.1', server.server_port, timeout=2)
    try:
        conn.request('GET', path, headers=headers or {})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def test_authorization_and_scope_never_disclose_before_cookie(monkeypatch):
    queries = []
    monkeypatch.setattr(dashboard, 'records', lambda **kw: queries.append(kw) or {'risks': []})
    with running() as server:
        assert request(server, '/api/risks')[0] == 403
        status, headers, _ = request(server, '/' + server.token + '/')
        assert status == 303 and headers['Location'] == '/risks'
        cookie = headers['Set-Cookie'].split(';')[0]
        assert 'HttpOnly' in headers['Set-Cookie']
        assert request(server, '/api/risks?project=bad', {'Cookie': cookie})[0] == 400
        assert queries == []
        url = '/api/risks?project=' + 'a'*64 + '&session=' + 'b'*64 + '&editor=codex'
        assert request(server, url, {'Cookie': cookie})[0] == 200
        assert queries == [dict(project_id='a'*64, session_id='b'*64, editor_id='codex')]
        assert request(server, '/risks', {'Cookie': cookie, 'Host': 'example.com'})[0] == 403


def test_address_survives_restart_and_lookup_never_starts_service(tmp_path, monkeypatch):
    monkeypatch.setattr(service, 'directory', lambda: tmp_path)
    with running() as first:
        service.save_endpoint(first.server_port, first.token)
        saved = service.endpoint()
        url = service.session_url(tmp_path, dict(host='codex', session='a'*64))
        assert service.healthy(saved)
        monkeypatch.setattr(service.subprocess, 'Popen', lambda *a, **kw: pytest.fail('unexpected spawn'))
        assert service.ensure() == saved
    with running(saved) as second:
        assert service.healthy(saved)
        assert service.session_url(tmp_path, dict(host='codex', session='a'*64)) == url
        assert second.server_port == saved['port']


@pytest.mark.parametrize('content', ['[]', '{"port":12345,"token":null}'])
def test_corrupt_endpoint_never_spawns_or_changes_address(tmp_path, monkeypatch, content):
    monkeypatch.setattr(service, 'directory', lambda: tmp_path)
    (tmp_path/'endpoint.json').write_text(content)
    assert service.session_url(tmp_path, dict(host='codex', session='a'*64)) is None
    with pytest.raises(ValueError, match='ENDPOINT_INVALID'):
        service.ensure()


def post(server, path, payload, headers=None):
    conn = HTTPConnection('127.0.0.1', server.server_port, timeout=3)
    try:
        conn.request('POST', path, body=json.dumps(payload), headers={'Content-Type':'application/json', **(headers or {})})
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def test_write_routes_require_cookie_origin_csrf_and_return_per_item(monkeypatch):
    from security_runtime import dashboard_records
    calls = []
    def mutate(identifier, value):
        calls.append(identifier)
        if identifier == 'stale':
            raise ValueError('MANAGEMENT_VERSION_CONFLICT')
        return dict(saved=True, repeated=False)
    monkeypatch.setattr(dashboard_records,'mutate',mutate)
    with running() as server:
        data = dict(items=[dict(id='valid',request={}),dict(id='stale',request={})])
        assert post(server,'/api/actions',data)[0] == 403
        _,headers,_ = request(server,'/'+server.token+'/')
        authorized = {'Cookie':headers['Set-Cookie'].split(';')[0], 'Origin':server.origin, 'X-CSRF-Token':server.token}
        assert post(server,'/api/actions',data,dict(authorized,Origin='https://foreign.invalid'))[0] == 403
        assert post(server,'/api/actions',data,{k:v for k,v in authorized.items() if k!='X-CSRF-Token'})[0] == 403
        assert not calls
        status,body = post(server,'/api/actions',data,authorized)
        assert status==200
        result=json.loads(body)['results']
        assert result[0]['saved'] and not result[1]['saved'] and result[1]['error']=='VERSION_CONFLICT'
        assert calls == ['valid','stale']


def test_removed_history_entities_delete_and_restore_through_http(tmp_path, monkeypatch):
    from test_dashboard_history import seed_history
    from security_runtime.dashboard_catalog import Catalog
    seed_history(tmp_path, monkeypatch)
    catalog = Catalog()
    catalog.refresh()
    with running() as server:
        server.catalog = catalog
        _, headers, _ = request(server, '/'+server.token+'/')
        authorized = {'Cookie': headers['Set-Cookie'].split(';')[0],
                      'Origin': server.origin, 'X-CSRF-Token': server.token}
        for kind in ('editor', 'project', 'workspace', 'session'):
            status, _, body = request(server, '/api/entities?kind='+kind, authorized)
            assert status == 200
            item = json.loads(body)['items'][0]
            data = dict(action='delete', kind=kind, id=item['id'],
                        expected_revision=item['revision'], request_id='http-delete-'+kind)
            assert post(server, '/api/entities', data)[0] == 403
            status, body = post(server, '/api/entities', data, authorized)
            assert status == 200 and json.loads(body)['saved']
            _, _, body = request(server, '/api/risks', authorized)
            assert json.loads(body)['total'] == 126-item['risk_count']
            _, _, body = request(server, '/api/entities?kind=trash', authorized)
            trash = json.loads(body)['items'][0]
            status, body = post(server, '/api/entities', dict(data, action='restore',
                id=trash['id'], expected_revision=trash['revision']), authorized)
            assert status == 200 and json.loads(body)['saved']
            _, _, body = request(server, '/api/risks', authorized)
            assert json.loads(body)['total'] == 126
