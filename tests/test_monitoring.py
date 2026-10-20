import asyncio
import builtins
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_runtime.context_cost import ContextCostStore
from security_runtime.monitoring.host_reader import HostReader
from security_runtime.monitoring.service import MonitorService


def append(path, row):
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(row)+'\n')


def usage(path, value):
    append(path, dict(type='event_msg', timestamp='2026-10-20T13:00:00Z',
        payload=dict(type='token_count', info=dict(total_token_usage=dict(
            input_tokens=value, cached_input_tokens=value//2, output_tokens=10,
            reasoning_output_tokens=2)))))


@pytest.fixture
def source(tmp_path):
    log = tmp_path/'chat.jsonl'
    project = tmp_path/'project'
    append(log, dict(type='session_meta', payload=dict(id='PRIVATE-CHAT-ID', cwd=str(project))))
    append(log, dict(type='turn_context', payload=dict(cwd=str(project), model='test-model')))
    usage(log, 100)
    return log, project


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MONITOR', raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MODE', raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_RUN', raising=False)
    store = ContextCostStore(tmp_path/'metrics.sqlite3')
    store.set_monitoring('debug')
    return store


def test_host_reader_is_incremental_and_does_not_count_cumulative_snapshots_twice(source):
    log, project = source
    reader = HostReader(log, project)
    first = reader.poll()
    assert first['usage']['total_tokens'] == 110
    assert first['project_usage'] is None
    offset = reader.offset
    assert reader.poll()['project_samples'] == 0 and reader.offset == offset
    usage(log, 130)
    after = reader.poll()
    assert after['usage']['total_tokens'] == 140
    assert after['project_usage']['total_tokens'] == 30
    assert reader.poll()['project_usage']['total_tokens'] == 30
    assert 'PRIVATE-CHAT-ID' not in json.dumps(after)
    assert str(log) not in json.dumps(after)
    usage(log, 200)
    reader.poll()
    assert after['project_usage']['total_tokens'] == 30


def test_host_reader_waits_for_incomplete_append(source):
    log, project = source
    reader = HostReader(log, project)
    reader.poll()
    with log.open('a', encoding='utf-8') as stream:
        stream.write('{"type":"unrelated"')
    offset = reader.offset
    assert reader.poll()['status'] == 'AVAILABLE'
    assert reader.offset == offset
    with log.open('a', encoding='utf-8') as stream:
        stream.write('}\n')
    assert reader.poll()['invalid_records'] == 0
    assert reader.offset > offset


def test_project_boundaries_are_conservative_and_missing_context_not_assigned(source):
    log, project = source
    reader = HostReader(log, project)
    reader.poll()
    append(log, dict(type='turn_context', payload=dict(cwd=str(project.parent/'other'))))
    usage(log, 120)
    append(log, dict(type='turn_context', payload=dict(cwd=str(project))))
    usage(log, 150)
    assert reader.poll()['project_usage'] is None
    usage(log, 180)
    assert reader.poll()['project_usage']['input_tokens'] == 30
    append(log, dict(type='turn_context', payload={}))
    usage(log, 200)
    assert reader.poll()['project_usage']['input_tokens'] == 30


def test_reader_handles_reset_truncation_and_bad_lines_without_fabricating_usage(source):
    log, project = source
    reader = HostReader(log, project)
    reader.poll()
    usage(log, 90)
    assert reader.poll()['status'] == 'UNAVAILABLE'
    assert reader.poll()['usage'] is None
    log.write_text('{}\n', encoding='utf-8')
    assert reader.poll()['status'] == 'UNAVAILABLE'


def test_reader_unknown_and_untrusted_source_are_explicit(tmp_path):
    assert HostReader().poll()['status'] == 'NOT_CONNECTED'
    log = tmp_path/'untrusted.jsonl'
    log.write_text('{bad\n', encoding='utf-8')
    usage(log, 100)
    view = HostReader(log).poll()
    assert view['usage'] is None and view['status'] == 'PARTIAL'


def test_service_scopes_do_not_confuse_connection_with_chat(source, store):
    log, project = source
    store.record_call('get_security_summary', {}, workspace=project, elapsed_ms=15,
                      started_at=100, finished_at=100.015)
    store.record_call('get_runtime_info', {}, elapsed_ms=20, started_at=100, finished_at=100.02)
    service = MonitorService(store, project=project, chat_log=log)
    overview = service.snapshot('all')
    assert overview['calls'] == 2 and overview['usage']['total_tokens'] == 110
    chat = service.snapshot('chat')
    assert chat['calls'] is None and not chat['tools_known']
    assert chat['events'] == [] and chat['usage']['total_tokens'] == 110
    project_view = service.snapshot('project')
    assert project_view['calls'] == 1 and project_view['elapsed_ms'] == 15
    assert project_view['unassociated_project_calls'] == 1
    assert project_view['usage'] is None
    assert str(project) not in json.dumps(overview)
    assert 'PRIVATE-CHAT-ID' not in json.dumps(overview)


def test_manual_task_window_delta_stops_and_never_writes_product_task_state(source, store, monkeypatch):
    log, project = source
    import security_runtime.monitoring.service as module
    monkeypatch.setattr(module.time, 'time', lambda: 1000)
    service = MonitorService(store, project=project, chat_log=log)
    assert service.snapshot('task')['calls'] is None
    service.task('start')
    usage(log, 140)
    store.record_call('get_security_summary', {}, workspace=project, started_at=1001,
                      finished_at=1002, elapsed_ms=1000)
    monkeypatch.setattr(module.time, 'time', lambda: 1003)
    report = service.snapshot('task')
    assert report['usage']['input_tokens'] == 40 and report['calls'] == 1
    assert 'NOT_PRODUCT_TASK' in report['token_scope']
    service.task('stop')
    usage(log, 190)
    assert service.snapshot('task')['usage']['input_tokens'] == 40
    assert set(p.name for p in store.path.parent.iterdir()) <= {'chat.jsonl', 'metrics.sqlite3', 'metrics.key'}


def test_sidecar_missing_metrics_does_not_create_storage(tmp_path, source):
    log, project = source
    store = ContextCostStore(tmp_path/'missing'/'metrics.sqlite3')
    report = MonitorService(store, project=project, chat_log=log).snapshot()
    assert report['usage']['total_tokens'] == 110 and report['calls'] == 0
    assert not store.path.exists() and not store.key_path.exists()


def test_scan_entry_scope_does_not_attribute_host_tokens_or_internal_scans(source, store):
    log, project = source
    for tool, elapsed in [('scan_project', 100), ('finish_security_task', 300), ('get_runtime_info', 5)]:
        store.record_call(tool, {}, workspace=project, elapsed_ms=elapsed)
    service = MonitorService(store, project=project, chat_log=log)
    overview = service.snapshot()
    assert sum(c['elapsed_ms'] for c in overview['entry_categories']) == 405
    assert sum(c['calls'] for c in overview['entry_categories']) == 3
    report = service.snapshot('scan')
    assert report['calls'] == 1 and report['elapsed_ms'] == 100
    assert [g['tool'] for g in report['groups']] == ['scan_project']
    assert report['usage'] is None and report['attribution']['product_scan_tokens'] is None
    assert report['attribution']['development_only_tokens'] is None
    assert report['attribution']['chat_total_tokens']['total_tokens'] == 110
    assert 'NOT_ENGINE_TIME' in report['tool_scope']


def test_manual_window_time_is_monotonic_and_frozen_after_stop(source, store, monkeypatch):
    log, project = source
    import security_runtime.monitoring.service as module
    clock = [100]
    monkeypatch.setattr(module.time, 'monotonic', lambda: clock[0])
    service = MonitorService(store, project=project, chat_log=log)
    assert service.snapshot()['window_elapsed_ms'] is None
    service.task('start')
    clock[0] = 103
    assert service.snapshot('task')['window_elapsed_ms'] == 3000
    service.task('stop')
    clock[0] = 110
    assert service.snapshot('task')['window_elapsed_ms'] == 3000
    with pytest.raises(ValueError):
        service.task('stop')


def test_disabled_mode_and_bad_storage_are_contained(source, store):
    log, project = source
    service = MonitorService(store, project=project, chat_log=log)
    service.set_mode('off')
    assert store.record_call('get_runtime_info', {})['status'] == 'DISABLED'
    assert service.snapshot()['monitoring']['mode'] == 'off'
    store.path.write_bytes(b'broken metrics')
    view = service.snapshot()
    assert view['status'] == 'PARTIAL' and view['calls'] is None
    assert view['usage']['total_tokens'] == 110


def test_product_cli_works_when_all_monitoring_modules_removed(monkeypatch, capsys):
    from security_runtime import cli
    original = builtins.__import__
    def missing(name, *args, **kwargs):
        if name.rsplit('.', 1)[-1] in {'context_cost_cli', 'context_cost_mcp', 'context_cost', 'context_report', 'monitoring'}:
            raise ImportError('optional monitor removed')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', missing)
    with pytest.raises(SystemExit) as end:
        cli.main(['--version'])
    assert end.value.code == 0
    assert 'AI Security Runtime' in capsys.readouterr().out


@pytest.mark.parametrize('failure', [ImportError, RuntimeError])
def test_product_mcp_handler_unchanged_when_observer_missing_or_broken(monkeypatch, failure):
    from mcp.server.fastmcp import FastMCP
    from mcp.types import CallToolRequest
    from security_runtime.mcp_contracts import MCPRegistry
    server = FastMCP('optional-removal')
    registry = MCPRegistry(server)
    before = registry.low_level.request_handlers[CallToolRequest]
    original = builtins.__import__
    def missing(name, *args, **kwargs):
        if name.endswith('context_cost_mcp'):
            raise failure('observer missing or broken')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', missing)
    registry.observe_context_cost()
    assert registry.low_level.request_handlers[CallToolRequest] is before


def test_response_introspection_failure_cannot_change_product_reply(store, monkeypatch):
    from security_runtime import context_cost
    from security_runtime.context_cost_mcp import observe_response
    monkeypatch.setattr(context_cost, 'ContextCostStore', lambda: store)
    class Response:
        @property
        def root(self):
            raise RuntimeError('observer cannot inspect this response')
    expected = Response()
    async def call(_):
        return expected
    result = asyncio.run(observe_response(call, SimpleNamespace(params=SimpleNamespace(name='get_runtime_info')), connection_id='a'))
    assert result is expected


def test_global_workspace_claim_is_metadata_only_and_bounded(store, monkeypatch):
    from security_runtime import context_cost
    from security_runtime.context_cost_mcp import observe_response
    monkeypatch.setattr(context_cost, 'ContextCostStore', lambda: store)
    async def call(_):
        return {'status': 'AVAILABLE'}
    request = SimpleNamespace(params=SimpleNamespace(name='get_security_summary', arguments={'workspace_path':'/explicit/project', 'source':'PRIVATE_BODY'}))
    asyncio.run(observe_response(call, request, connection_id='connection'))
    assert store.snapshot()['events'][0]['workspace_hash'] is not None
    assert b'PRIVATE_BODY' not in store.path.read_bytes()
    assert b'/explicit/project' not in store.path.read_bytes()


def test_product_starts_with_monitor_source_files_physically_absent(tmp_path):
    import os
    import shutil
    import subprocess
    import sys
    import security_runtime
    source = Path(security_runtime.__file__).parent
    optional = {'monitoring', 'context_cost.py', 'context_cost_cli.py', 'context_cost_mcp.py',
                'context_report.py', 'codex_usage.py', 'token_usage.py', '__pycache__'}
    shutil.copytree(source, tmp_path/'security_runtime',
                    ignore=lambda directory, names: set(names) & optional)
    env = dict(os.environ, PYTHONPATH=str(tmp_path))
    command = ('import asyncio,json; from security_runtime.cli import main; '
               'assert main(["runtime-info","--json"])==0; '
               'from security_runtime.global_mcp import create_global_server; '
               's=create_global_server(workspaces=object(),host="codex"); '
               'names={t.name for t in asyncio.run(s.list_tools())}; '
               'assert {"get_runtime_info","scan_project","begin_security_task"} <= names')
    result = subprocess.run([sys.executable, '-c', command], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
