"""Product behavior is invariant under absent, failed or congested observation."""
import asyncio
import builtins
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from security_runtime import observation
from security_runtime.context_cost_mcp import observe_response
from security_runtime.context_cost_worker import ObservationWorker
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.ownership import issue_session_ref, session_owner, verify_session_ref


def request(name='get_runtime_info', **arguments):
    return SimpleNamespace(params=SimpleNamespace(name=name, arguments=arguments))


class Collector:
    def __init__(self, mode):
        self.mode = mode
        self.records = []

    def snapshot_settings(self):
        if self.mode == 'settings-fault':
            raise OSError('private monitoring failure')
        return dict(status='AVAILABLE', mode='debug', source='default', run='isolation')

    def offer(self, record):
        if self.mode == 'write-fault':
            raise OSError('private monitoring failure')
        if self.mode == 'full':
            return False
        self.records.append(record)
        return True


MODES = ('off', 'on', 'full', 'settings-fault', 'write-fault')


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch, tmp_path):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'runtime-state'))
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MONITOR', raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MODE', raising=False)


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('outcome', ('success', 'failure', 'cancel'))
def test_monitor_state_cannot_change_product_result_error_or_cancellation(monkeypatch, mode, outcome):
    if mode == 'off':
        monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MONITOR', '0')
    collector = Collector(mode)
    expected = ({'status': 'BUSINESS_RESULT', 'payload': ['unchanged']} if outcome == 'success'
                else ValueError('original product failure') if outcome == 'failure'
                else asyncio.CancelledError('original cancellation'))
    calls = []

    async def product(value):
        calls.append(value)
        if outcome != 'success':
            raise expected
        return expected

    incoming = request()
    invocation = observe_response(product, incoming, connection_id='connection', worker=collector)
    if outcome == 'success':
        assert asyncio.run(invocation) is expected
    else:
        with pytest.raises(type(expected)) as caught:
            asyncio.run(invocation)
        assert caught.value is expected
    assert calls == [incoming]
    assert not observation.active()
    if mode == 'off':
        assert collector.records == []


@pytest.mark.parametrize('mode', MODES)
def test_monitor_state_cannot_change_real_session_reference_validation(tmp_path, monkeypatch, mode):
    if mode == 'off':
        monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MONITOR', '0')
    project, other = tmp_path / 'project', tmp_path / 'other'
    project.mkdir()
    other.mkdir()
    hooks = HookStateStore(tmp_path / 'hooks')
    token = issue_session_ref(hooks, project, 'codex', 'private-chat')
    # Ensure rejection of the other workspace is a binding check, not just a missing key.
    issue_session_ref(hooks, other, 'codex', 'private-chat')
    collector = Collector(mode)
    expected_owner = session_owner('codex', 'private-chat')

    async def product(value):
        args = value.params.arguments
        return verify_session_ref(hooks, args['root'], args['token'])

    valid = asyncio.run(observe_response(product, request(root=project, token=token),
        connection_id='shared', workspace=project, worker=collector))
    assert valid == expected_owner
    for root, invalid in ((other, token), (project, token + 'forged')):
        with pytest.raises(ValueError, match='invalid, expired or belongs to another workspace'):
            asyncio.run(observe_response(product, request(root=root, token=invalid),
                connection_id='shared', workspace=root, worker=collector))
    assert not observation.active()
    if mode == 'on':
        assert collector.records[0]['chat_owner'] == expected_owner
        assert all(item['chat_owner'] is None for item in collector.records[1:])


@pytest.mark.parametrize('switch', ('SECURITY_RUNTIME_CONTEXT_MONITOR', 'SECURITY_RUNTIME_CONTEXT_MODE'))
def test_off_and_readonly_summary_do_not_even_access_the_collector(monkeypatch, switch):
    class Forbidden:
        def snapshot_settings(self):
            pytest.fail('disabled/read-only observer accessed its collector')

    expected = object()

    async def product(_):
        return expected

    monkeypatch.setenv(switch, '0' if switch.endswith('MONITOR') else 'off')
    assert asyncio.run(observe_response(product, request(), connection_id='c', worker=Forbidden())) is expected
    monkeypatch.delenv(switch)
    assert asyncio.run(observe_response(product, request('get_security_summary'),
        connection_id='c', worker=Forbidden())) is expected


@pytest.mark.parametrize('missing', ('observation', 'context_cost_worker', 'context_cost_capture'))
def test_missing_optional_dependency_does_not_skip_or_repeat_product_call(monkeypatch, missing):
    original = builtins.__import__
    calls = []

    def removed(name, globals=None, locals=None, fromlist=(), level=0):
        if name.rsplit('.', 1)[-1] == missing or missing in (fromlist or ()):
            raise ImportError('optional observer physically unavailable')
        return original(name, globals, locals, fromlist, level)

    async def product(_):
        calls.append('executed')
        return 'unchanged'

    monkeypatch.setattr(builtins, '__import__', removed)
    assert asyncio.run(observe_response(product, request(), connection_id='c', worker=Collector('on'))) == 'unchanged'
    assert calls == ['executed']


def test_blocked_storage_and_full_queue_cannot_delay_product_completion():
    entered, release = threading.Event(), threading.Event()

    class SlowStore:
        def monitoring(self):
            return dict(status='AVAILABLE', mode='basic', source='default', run='isolation')

        def record_observation(self, value):
            entered.set()
            if not release.wait(10):
                raise TimeoutError('test gate was not released')
            return dict(status='RECORDED')

    worker = ObservationWorker(lambda: SlowStore(), capacity=1).start()
    pool = ThreadPoolExecutor(max_workers=1)
    result = {'status': 'READY'}

    async def product(_):
        return result

    def invoke():
        return asyncio.run(observe_response(product, request(), connection_id='c', worker=worker))

    try:
        assert pool.submit(invoke).result(timeout=2) is result
        assert entered.wait(2), 'writer did not reach the controlled storage gate'
        # The writer cannot consume the next queue entry until release is set.
        assert not release.is_set()
        for _ in range(4):
            assert pool.submit(invoke).result(timeout=2) is result
        assert worker.stats()['dropped'] >= 1
        assert not release.is_set(), 'product completion must precede database recovery'

        async def cancelled(_):
            raise asyncio.CancelledError('product cancelled while storage is blocked')

        def cancel():
            with pytest.raises(asyncio.CancelledError):
                asyncio.run(observe_response(cancelled, request(), connection_id='c', worker=worker))

        pool.submit(cancel).result(timeout=2)
    finally:
        release.set()
        pool.shutdown(wait=True)
        assert worker.wait_idle(3)
        worker.close()


def bind_facts(label):
    owner = session_owner('codex', label)
    invocation = hashlib.sha256(('tool-' + label).encode()).hexdigest()
    turn = hashlib.sha256(('turn-' + label).encode()).hexdigest()
    observation.bind_chat(owner)
    observation.bind_host('codex', owner['session'], invocation, turn)
    observation.bind_product('task', 'task-' + label, relation='TASK_RECORD_READ')
    return owner, invocation, turn


def assert_facts(snapshot, expected, label):
    owner, invocation, turn = expected
    assert snapshot['session_binding'] == owner['session']
    assert snapshot['trigger_invocation_binding'] == invocation
    assert snapshot['turn_binding'] == turn
    assert snapshot['links'] == [dict(kind='task', reference='task-' + label, relation='TASK_RECORD_READ')]
    assert not snapshot['chat_conflict']


def test_overlapping_async_calls_and_followup_do_not_share_correlations():
    async def both():
        entered = asyncio.Event()
        count = 0

        async def one(label):
            nonlocal count
            capture, token = observation.begin_call()
            expected = bind_facts(label)
            count += 1
            if count == 2:
                entered.set()
            await entered.wait()
            await asyncio.sleep(0)
            snapshot = observation.end_call(capture, token)
            assert not observation.active()
            assert_facts(snapshot, expected, label)
            return snapshot

        return await asyncio.gather(one('chat-a'), one('chat-b'))

    snapshots = asyncio.run(both())
    assert len({item['call_id'] for item in snapshots}) == 2
    # A subsequent call must not inherit either previous owner or product record.
    capture, token = observation.begin_call()
    assert capture.owner is None
    clean = observation.end_call(capture, token)
    assert clean['session_binding'] is None and clean['links'] == []


def test_overlapping_threads_do_not_share_correlations():
    gate = threading.Barrier(2)

    def one(label):
        capture, token = observation.begin_call()
        expected = bind_facts(label)
        gate.wait(timeout=3)
        snapshot = observation.end_call(capture, token)
        assert not observation.active()
        assert_facts(snapshot, expected, label)
        return snapshot

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = pool.submit(one, 'thread-a'), pool.submit(one, 'thread-b')
        rows = [first.result(timeout=4), second.result(timeout=4)]
    assert len({row['call_id'] for row in rows}) == 2
    assert not observation.active()


def test_conflicting_chat_bindings_are_not_assigned_to_either_chat():
    capture, token = observation.begin_call()
    bind_facts('a')
    observation.bind_chat(session_owner('codex', 'b'))
    observation.bind_chat(session_owner('codex', 'a'))
    snapshot = observation.end_call(capture, token)
    assert capture.owner is None and snapshot['chat_conflict']
    assert snapshot['session_binding'] is None
    assert snapshot['trigger_invocation_binding'] is None and snapshot['turn_binding'] is None


def test_monitor_does_not_change_tool_schemas_instructions_or_response(monkeypatch):
    from mcp.server.fastmcp import FastMCP
    from mcp.types import CallToolRequest, CallToolRequestParams
    from security_runtime.mcp_contracts import MCPRegistry
    from security_runtime import context_cost_worker

    rows = []
    for enabled in (False, True):
        monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MONITOR', '1' if enabled else '0')
        monkeypatch.setattr(context_cost_worker, 'get_worker', lambda: Collector('on'))
        server = FastMCP('same-product', instructions='Original product instructions.')

        @server.tool()
        def sample(value: int) -> dict:
            return {'value': value}

        registry = MCPRegistry(server)
        registry.observe_context_cost()
        incoming = CallToolRequest(params=CallToolRequestParams(name='sample', arguments={'value': 7}))
        result = asyncio.run(registry.low_level.request_handlers[CallToolRequest](incoming))
        rows.append((registry.names(), registry.schemas(), registry.low_level.instructions,
                     result.model_dump(mode='json', exclude_none=True)))
    assert rows[0] == rows[1]


def test_product_runs_with_new_and_existing_observer_modules_physically_absent(tmp_path):
    import security_runtime

    source = Path(security_runtime.__file__).parent
    optional = {'monitoring', 'observation.py', 'context_cost_worker.py', 'context_cost_capture.py',
                'context_cost.py', 'context_cost_cli.py', 'context_cost_mcp.py', 'context_report.py',
                'codex_usage.py', 'token_usage.py', 'context_cost_sync.py', 'model_observation.py',
                'model_report.py', 'model_panel.py', 'collector_health.py', 'product_metrics.py', 'monitor_history.py',
                'monitor_checks.py', 'monitor_risks.py', '__pycache__'}
    shutil.copytree(source, tmp_path / 'security_runtime',
                    ignore=lambda directory, names: set(names) & optional)
    command = '''
import asyncio
from pathlib import Path
from security_runtime.cli import main
assert main(['runtime-info', '--json']) == 0
from security_runtime.global_mcp import create_global_server
server = create_global_server(workspaces=object(), host='codex')
names = {tool.name for tool in asyncio.run(server.list_tools())}
assert {'get_runtime_info', 'scan_project', 'begin_security_task'} <= names
assert 'start_usage_monitor' not in names
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.ownership import issue_session_ref, verify_session_ref, session_owner
project = Path('project').resolve()
project.mkdir()
hooks = HookStateStore(Path('hook-state').resolve())
token = issue_session_ref(hooks, project, 'codex', 'test-chat')
assert verify_session_ref(hooks, project, token) == session_owner('codex', 'test-chat')
try:
    verify_session_ref(hooks, project, token + 'forged')
except ValueError:
    pass
else:
    raise AssertionError('removal changed session authorization')
'''
    environment = dict(os.environ, PYTHONPATH=str(tmp_path),
                       SECURITY_RUNTIME_STATE_DIR=str(tmp_path / 'state'))
    completed = subprocess.run([sys.executable, '-c', command], cwd=tmp_path, env=environment,
                               capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
