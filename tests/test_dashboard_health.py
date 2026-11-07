import json
from pathlib import Path
from types import SimpleNamespace
from security_runtime import dashboard_health as health


def test_component_failure_and_stale_database_are_not_green(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_CONFIG', str(tmp_path/'config.toml'))
    monkeypatch.setattr('security_runtime.connection_lifecycle.diagnostics', lambda: {'records': []})
    monkeypatch.setattr('security_runtime.install_readiness.validate_database_directory', lambda _: True)
    class Manager:
        versions = {'opengrep': '1', 'semgrep': '2', 'trivy': '3'}
        def resolve(self, name):
            if name == 'opengrep':
                raise OSError('private secret')
            return SimpleNamespace(status='READY', version=self.versions[name], path='/tools/'+name)
        def trivy_cache_dir(self): return tmp_path
        def database_freshness(self): return {'status': 'STALE'}
    result = health.collect(manager=Manager(), mcp_probe=lambda: {'status':'READY','interfaces':[]})
    assert result['product']['status'] == 'ATTENTION'
    assert result['product']['desktop_connection'] == 'UNKNOWN'
    assert result['components'][0]['status'] == 'UNKNOWN'
    assert result['databases'][0]['freshness'] == 'STALE'
    assert not result['scanner_run']
    assert 'private secret' not in json.dumps(result)


def test_refresh_reuses_snapshot_without_reprobing_or_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(health, '_CACHED', None)
    monkeypatch.setattr('security_runtime.dashboard_service.directory', lambda: tmp_path)
    calls = []
    def collect():
        calls.append(1)
        return dict(checked_at=health.time.time(), product={'status':'READY'}, mcp={'status':'READY'}, elapsed_seconds=.1, components=[])
    monkeypatch.setattr(health, 'collect', collect)
    first = health.snapshot()
    path = tmp_path/'health-history.json'
    before = path.stat().st_mtime_ns
    first['product']['status']='BROKEN'
    assert health.snapshot()['product']['status']=='READY'
    assert path.stat().st_mtime_ns==before and calls==[1]
    health._LOCK.acquire()
    try:
        assert health.snapshot()['checking']
    finally:
        health._LOCK.release()


def test_probe_failure_is_redacted(monkeypatch):
    async def fail(): raise ValueError('private token')
    monkeypatch.setattr(health, '_mcp_discover', fail)
    assert health.probe_mcp()==dict(status='UNAVAILABLE',interfaces=[],reason='MCP_PROBE_FAILED')


def test_history_retention_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr('security_runtime.dashboard_service.directory', lambda: tmp_path)
    for i in range(20):
        history=health._history(dict(checked_at=i,product={'status':'READY'},mcp={'status':'READY'},elapsed_seconds=1,components=[]))
    assert len(history)==16 and history[0]['checked_at']==4


def test_monitor_requires_authenticated_browser_and_rejects_arguments(monkeypatch):
    from test_dashboard_service import running, request
    calls=[]
    monkeypatch.setattr(health,'snapshot',lambda: calls.append(1) or {'scanner_run':False})
    with running() as server:
        assert request(server,'/api/monitor')[0]==403
        headers={'Cookie':'dashboard='+server.token}
        assert request(server,'/api/monitor?path=arbitrary',headers)[0]==400
        status,_,raw=request(server,'/api/monitor',headers)
        assert status==200 and not json.loads(raw)['scanner_run']
    assert calls==[1]
