import json
import threading
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler

import pytest

from security_runtime.context_cost import ContextCostStore
from security_runtime.monitoring.server import MonitorServer
from security_runtime.monitoring.service import MonitorService

urlopen = build_opener(ProxyHandler({})).open


def test_monitor_startup_never_performs_reverse_dns(monkeypatch):
    import socket
    def blocked(*args):
        raise AssertionError('Loopback monitoring must not wait for DNS')
    monkeypatch.setattr(socket, 'getfqdn', blocked)
    monitor = MonitorServer(MonitorService(None))
    try:
        assert monitor.server_name == '127.0.0.1'
        assert monitor.server_port > 0
    finally:
        monitor.server_close()


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MODE', raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MONITOR', raising=False)
    store = ContextCostStore(tmp_path/'metrics.sqlite3')
    service = MonitorService(store)
    server = MonitorServer(service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, store
    server.shutdown()
    server.server_close()
    thread.join(3)


def request(server, path='api/data', data=None, origin=None, host=None):
    headers = {}
    if data is not None:
        headers['Content-Type'] = 'application/json'
        if origin:
            headers['Origin'] = origin
    if host:
        headers['Host'] = host
    r = Request(server.url+path, data=json.dumps(data).encode() if data is not None else None, headers=headers)
    return urlopen(r, timeout=3)


def test_page_and_api_are_loopback_only_private_and_readonly(server):
    server, store = server
    assert server.server_address[0] == '127.0.0.1'
    with request(server, '') as r:
        page = r.read().decode()
        assert '消耗观察' in page and '__NONCE__' not in page
        assert 'script-src \'nonce-' in r.headers['Content-Security-Policy']
        assert r.headers['Cache-Control'] == 'no-store'
        assert r.headers['Referrer-Policy'] == 'no-referrer'
    with request(server) as r:
        data = json.load(r)
        assert data['calls'] == 0 and data['usage'] is None
        assert 'Access-Control-Allow-Origin' not in r.headers
    assert not store.path.exists()


@pytest.mark.parametrize('kind', ['token', 'host', 'scope'])
def test_unknown_capability_host_and_scope_are_rejected(server, kind):
    server, store = server
    with pytest.raises(HTTPError) as error:
        if kind == 'token':
            urlopen(server.origin+'/wrong/api/data', timeout=3)
        elif kind == 'host':
            request(server, host='attacker.example')
        else:
            request(server, 'api/data?scope=arbitrary')
    assert error.value.code in (400, 403)
    assert not store.path.exists()


@pytest.mark.parametrize('origin', [None, 'https://attacker.example'])
def test_cross_origin_writes_never_change_preferences(server, origin):
    server, store = server
    with pytest.raises(HTTPError) as error:
        request(server, 'api/mode', {'mode':'debug'}, origin)
    assert error.value.code == 403
    assert not store.path.exists()


def test_explicit_mode_and_window_controls_only_affect_monitor(server):
    server, store = server
    with request(server, 'api/mode', {'mode':'debug'}, server.origin) as r:
        assert json.load(r)['effective']['mode'] == 'debug'
    with request(server, 'api/task', {'action':'start'}, server.origin) as r:
        assert json.load(r)['window']['finished_at'] is None
    with request(server, 'api/task', {'action':'stop'}, server.origin) as r:
        assert json.load(r)['window']['finished_at'] is not None
    with pytest.raises(HTTPError):
        request(server, 'api/mode', {'mode':'invalid'}, server.origin)
    assert store.monitoring()['mode'] == 'debug'
    with request(server, 'api/mode', {'mode':'off'}, server.origin) as r:
        assert json.load(r)['effective']['mode'] == 'off'
    assert set(p.name for p in store.path.parent.iterdir()) == {'metrics.sqlite3', 'metrics.key'}


def test_stopping_page_only_stops_sidecar(server):
    server, store = server
    store.set_monitoring('debug')
    with request(server, 'api/stop', {}, server.origin) as r:
        assert json.load(r)['stopped'] == 'MONITOR_ONLY'
    assert store.monitoring()['mode'] == 'debug'


def test_finish_export_requires_same_origin_and_downloads_only_metadata(server):
    from io import BytesIO
    from zipfile import ZipFile
    server, _ = server
    with request(server, 'api/task', {'action':'start'}, server.origin):
        pass
    with pytest.raises(HTTPError) as error:
        request(server, 'api/finish-export', {}, 'https://attacker.example')
    assert error.value.code == 403
    with request(server, 'api/finish-export', {}, server.origin) as response:
        assert response.headers['Content-Type'] == 'application/zip'
        assert 'attachment' in response.headers['Content-Disposition']
        with ZipFile(BytesIO(response.read())) as archive:
            report = json.loads(archive.read('usage-report.json'))
    assert report['trial']['usage'] is None
    assert report['trial']['window']['finished_at'] is not None
