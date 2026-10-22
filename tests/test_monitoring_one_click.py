import asyncio
import hashlib
from io import BytesIO
import json
from pathlib import Path
import time
from types import SimpleNamespace
from urllib.request import Request, build_opener, ProxyHandler
from zipfile import ZipFile

import pytest

from security_runtime.context_cost import ContextCostStore
from security_runtime.context_cost_worker import ObservationWorker
from security_runtime.context_cost_mcp import observe_response, bind_verified_chat
from security_runtime.monitoring.host_reader import HostReader
from security_runtime.monitoring.launch import find_chat_log, start_monitor
from security_runtime.monitoring.report import report_bundle
from security_runtime.monitoring.service import MonitorService
from security_runtime.task_ownership import session_owner

CHAT = '12345678-1234-1234-1234-123456789abc'
OTHER = '23456789-1234-1234-1234-123456789abc'


def append(path, item):
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(item) + '\n')


def usage(path, count):
    append(path, dict(type='event_msg', timestamp='2026-10-21T13:00:00Z',
        payload=dict(type='token_count', info=dict(total_token_usage=dict(input_tokens=count, output_tokens=10)))))


def log(home, project, chat=CHAT, directory='2026/10/21'):
    folder = home / 'sessions' / directory
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / ('rollout-2026-10-21T10-00-00-' + chat + '.jsonl')
    append(path, dict(type='session_meta', payload=dict(id=chat, cwd=str(project))))
    usage(path, 100)
    return path


@pytest.fixture
def source(tmp_path, monkeypatch):
    for name in ('SECURITY_RUNTIME_CONTEXT_MONITOR', 'SECURITY_RUNTIME_CONTEXT_MODE', 'SECURITY_RUNTIME_CONTEXT_RUN'):
        monkeypatch.delenv(name, raising=False)
    home, project = tmp_path / 'home', tmp_path / 'project'
    project.mkdir()
    path = log(home, project)
    store = ContextCostStore(tmp_path / 'metrics.sqlite3')
    return home, project, path, store


@pytest.fixture
def observer_worker(source):
    source[3].set_monitoring('debug')  # These observation tests explicitly opt in.
    worker = ObservationWorker(lambda: source[3]).start()
    try:
        assert worker.wait_ready(3)
        yield worker
        assert worker.wait_idle(3)
    finally:
        worker.close()


def test_discovery_matches_identity_not_recency_and_rejects_duplicate(source):
    home, project, path, _ = source
    other = log(home, project, OTHER)
    append(other, {'private': 'OTHER_CHAT_BODY_MUST_NOT_BE_READ'})
    owner = session_owner('codex', CHAT)
    assert find_chat_log(owner['session'], home=home) == path
    log(home, project, CHAT, '2026/10/20')
    with pytest.raises(ValueError, match='AMBIGUOUS'):
        find_chat_log(owner['session'], home=home)


def test_discovery_does_not_open_other_chat_body(source, monkeypatch):
    home, project, path, _ = source
    other = log(home, project, OTHER)
    original = Path.open
    def guarded(candidate, *args, **kwargs):
        assert candidate != other, 'another chat was opened'
        return original(candidate, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', guarded)
    assert find_chat_log(session_owner('codex', CHAT)['session'], home=home) == path


def test_discovery_checks_header_identity_and_bounds_work(source, monkeypatch):
    home, _, path, _ = source
    owner = session_owner('codex', CHAT)
    path.write_text(json.dumps(dict(type='session_meta', payload=dict(id=OTHER)))+'\n')
    with pytest.raises(ValueError, match='IDENTITY_MISMATCH'):
        find_chat_log(owner['session'], home=home)
    import security_runtime.monitoring.launch as module
    monkeypatch.setattr(module, 'MAX_ENTRIES', 1)
    with pytest.raises(ValueError, match='DISCOVERY_LIMIT'):
        find_chat_log(owner['session'], home=home)


def test_reader_enforces_expected_identity_before_accepting_usage(source):
    _, _, path, _ = source
    reader = HostReader(path, expected_identity=session_owner('codex', OTHER)['session'])
    assert reader.poll()['status'] == 'UNAVAILABLE'
    assert reader.view()['usage'] is None


def test_late_first_usage_keeps_unmeasured_prefix_explicit(source):
    _, project, path, store = source
    path.write_text(json.dumps(dict(type='session_meta', payload=dict(id=CHAT, cwd=str(project))))+'\n')
    service = MonitorService(store, project=project, chat_log=path, chat_owner=session_owner('codex', CHAT))
    service.task('start')
    assert service.snapshot('task')['usage'] is None
    usage(path, 100)
    first = service.snapshot('task')
    assert first['window_token_prefix_unmeasured'] and first['status'] == 'PARTIAL'
    usage(path, 150)
    after = service.snapshot('task')
    assert after['usage']['input_tokens'] == 50 and after['window_token_prefix_unmeasured']


def test_parallel_observations_are_bound_only_by_validated_context(source, observer_worker):
    _, project, _, store = source
    store.set_monitoring('debug')
    async def run(chat, delay):
        async def call(request):
            bind_verified_chat(session_owner('codex', chat))
            await asyncio.sleep(delay)
            return {'status': 'AVAILABLE'}
        request = SimpleNamespace(params=SimpleNamespace(name='get_runtime_info', arguments={'workspace_path': str(project)}))
        return await observe_response(call, request, connection_id='SHARED_CONNECTION', worker=observer_worker)
    async def both():
        return await asyncio.gather(run(CHAT, .02), run(OTHER, 0))
    asyncio.run(both())
    assert observer_worker.wait_idle(3)
    events = store.snapshot()['events']
    assert len(events) == 2 and len({e['chat_hash'] for e in events}) == 2
    service = MonitorService(store, project=project, chat_owner=session_owner('codex', CHAT))
    assert service.snapshot('chat')['calls'] == 1
    raw = store.path.read_bytes()
    assert CHAT.encode() not in raw and b'SHARED_CONNECTION' not in raw


def test_conflicting_or_unvalidated_session_claim_is_never_attributed(source, observer_worker):
    _, project, _, store = source
    async def call(request):
        bind_verified_chat(session_owner('codex', CHAT))
        bind_verified_chat(session_owner('codex', OTHER))
        return {}
    request = SimpleNamespace(params=SimpleNamespace(name='get_runtime_info', arguments={'session_id': CHAT}))
    asyncio.run(observe_response(call, request, connection_id='shared', worker=observer_worker))
    assert observer_worker.wait_idle(3)
    assert 'chat_hash' not in store.snapshot()['events'][0]


def test_scoped_details_do_not_change_global_settings_and_off_is_respected(source):
    _, project, _, store = source
    from security_runtime.monitoring.active import register, unregister
    owner = session_owner('codex', CHAT)
    before = store.monitoring()
    register(store, owner, 'monitor-one')
    assert store.monitoring() == before
    assert before['mode'] == 'off'
    assert store.record_call('get_runtime_info', {}, chat_owner=owner)['status'] == 'DISABLED'
    store.set_monitoring('basic')  # Registering a page never enables collection.
    store.record_call('get_runtime_info', {}, chat_owner=owner, workspace=project,
        started_at=100, finished_at=101, mode='basic')
    store.record_call('get_runtime_info', {}, chat_owner=session_owner('codex', OTHER),
        started_at=100, finished_at=101, mode='basic')
    events = store.snapshot()['events']
    assert {e['mode'] for e in events} == {'basic', 'debug'}
    store.set_monitoring('off')
    assert store.record_call('get_runtime_info', {}, chat_owner=owner)['status'] == 'DISABLED'
    service = MonitorService(store, project=project, chat_owner=owner)
    service.task('start')
    report = service.snapshot('task')
    assert report['calls'] is None and report['collection_disabled'] and report['status'] == 'PARTIAL'
    unregister(store, owner, 'monitor-one')


def test_report_freezes_delta_separates_other_chats_and_contains_no_private_paths(source):
    _, project, path, store = source
    store.set_monitoring('debug')
    owner = session_owner('codex', CHAT)
    service = MonitorService(store, project=project, chat_log=path, chat_owner=owner)
    service.task('start')
    at = time.time()
    for chat, elapsed in [(CHAT, 10), (OTHER, 50)]:
        store.record_call('handle_hook_event', {}, chat_owner=session_owner('codex', chat),
            workspace=project, elapsed_ms=elapsed, started_at=at, finished_at=at)
    store.record_call('scan_files', {}, workspace=project, elapsed_ms=30, started_at=at, finished_at=at)
    usage(path, 160)
    report = service.finish_report()
    assert report['trial']['usage']['input_tokens'] == 60
    assert report['trial']['calls'] == 1 and report['trial']['elapsed_ms'] == 10
    assert report['trial']['unassociated_chat_calls'] == 1
    assert report['project_tools']['calls'] == 3
    usage(path, 200)
    assert service.finish_report() == report
    with ZipFile(BytesIO(report_bundle(report))) as archive:
        assert set(archive.namelist()) == {'usage-report.json', 'usage-report.html', 'README.txt'}
        exported = archive.read('usage-report.json').decode()
        assert json.loads(exported)['trial']['usage']['total_tokens'] == 60
        assert CHAT not in exported and str(project) not in exported and 'chat_hash' not in exported


def test_real_background_start_download_and_stop_without_global_mode_change(source, monkeypatch):
    home, project, path, store = source
    from security_runtime.monitoring.active import enabled
    before = store.monitoring()
    owner = session_owner('codex', CHAT)
    result = start_monitor(project, owner, store=store, home=home, open_browser=False)
    assert result['chat_binding'] == 'EXACT_SESSION_ID'
    assert store.monitoring() == before and enabled(store, owner)
    opener = build_opener(ProxyHandler({}))
    url = result['url']
    from urllib.parse import urlsplit
    parsed = urlsplit(url)
    origin = parsed.scheme+'://'+parsed.netloc
    def post(endpoint):
        request = Request(url+'api/'+endpoint, data=b'{}',
            headers={'Content-Type':'application/json', 'Origin':origin})
        return opener.open(request, timeout=5)
    try:
        usage(path, 180)
        with post('finish-export') as response:
            assert response.headers['Content-Type'] == 'application/zip'
            with ZipFile(BytesIO(response.read())) as archive:
                report = json.loads(archive.read('usage-report.json'))
        assert report['trial']['usage']['input_tokens'] == 80
        assert not enabled(store, owner)
        assert store.monitoring() == before
    finally:
        with post('stop') as response:
            assert json.load(response)['stopped'] == 'MONITOR_ONLY'


def test_mcp_entry_rejects_other_workspace_or_bad_ref_before_launch(source, monkeypatch):
    from mcp.server.fastmcp import FastMCP
    from security_runtime.mcp_contracts import MCPRegistry
    from security_runtime.monitoring.mcp import register
    from security_runtime.hook_state import HookStateStore
    from security_runtime.task_ownership import issue_session_ref
    _, project, _, _ = source
    hooks = HookStateStore(project.parent/'hooks')
    token = issue_session_ref(hooks, project, 'codex', CHAT)
    server = FastMCP('monitor-entry')
    registry = MCPRegistry(server)
    register(server, registry, application=SimpleNamespace(bound_path=lambda p: p, hooks=hooks))
    called = []
    monkeypatch.setattr('security_runtime.monitoring.launch.start_monitor', lambda root, owner: called.append(owner) or {'status':'AVAILABLE'})
    function = registry.tool('start_usage_monitor').fn
    assert function(str(project), token)['status'] == 'AVAILABLE'
    assert function(str(project.parent), token)['status'] == 'UNAVAILABLE'
    assert function(str(project), 'invalid-private-token')['status'] == 'UNAVAILABLE'
    assert called == [session_owner('codex', CHAT)]


def test_start_environment_requires_exact_host_identity(source, monkeypatch):
    from security_runtime.monitoring.launch import start_from_environment
    monkeypatch.delenv('CODEX_THREAD_ID', raising=False)
    with pytest.raises(ValueError, match='SESSION_REQUIRED'):
        start_from_environment(source[1])


def test_broken_monitor_registration_cannot_prevent_core_mcp_startup(monkeypatch):
    from security_runtime.monitoring import mcp as module
    from security_runtime.mcp_server import create_server
    def broken(*args, **kwargs):
        raise RuntimeError('optional monitor failed')
    monkeypatch.setattr(module, 'register', broken)
    server = create_server(global_mode=False)
    tools = {tool.name for tool in asyncio.run(server.list_tools())}
    assert {'get_runtime_info', 'scan_files', 'begin_security_task', 'finish_security_task'} <= tools


def test_missing_observer_does_not_change_verified_session_routing(source, monkeypatch):
    import builtins
    from security_runtime.hook_state import HookStateStore
    from security_runtime.task_ownership import issue_session_ref, verify_session_ref
    _, project, _, _ = source
    hooks = HookStateStore(project.parent / 'route-hooks')
    token = issue_session_ref(hooks, project, 'codex', CHAT)
    original = builtins.__import__
    def missing(name, *args, **kwargs):
        if name.endswith('context_cost_mcp') or name.endswith('observation'):
            raise ImportError('removed optional observer')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', missing)
    assert verify_session_ref(hooks, project, token) == session_owner('codex', CHAT)
