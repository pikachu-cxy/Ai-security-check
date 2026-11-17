import asyncio
import os
from pathlib import Path
from queue import Queue
import sys

import pytest

from security_runtime import mcp_update_proxy as proxy
from security_runtime.mcp_tool_groups import compact_tools
from security_runtime.runtime_update_app import MIME, URI


@pytest.mark.parametrize('host', ['codex', 'cursor', 'workbuddy'])
def test_real_stdio_resource_and_no_private_tool(tmp_path, host):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    source = str(Path(__file__).resolve().parents[1] / 'src')
    env = dict(os.environ, PYTHONPATH=source, SECURITY_RUNTIME_STATE_DIR=str(tmp_path / 'state'),
               SECURITY_RUNTIME_OFFLINE='1', SECURITY_RUNTIME_GLOBAL='1')
    env.pop('__PYVENV_LAUNCHER__', None)
    env.pop('SECURITY_RUNTIME_MCP_PROXY_KEY', None)
    params = StdioServerParameters(command=sys.executable, args=['-c',
        'from security_runtime.global_mcp import create_global_server; import sys; create_global_server(host=sys.argv[1]).run()',
        host], env=env)

    async def run():
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                names = {item.name for item in (await session.list_tools()).tools}
                assert ('development_review' if host != 'cursor' else 'get_development_risks') in names
                assert proxy.RESTORE not in names
                resources = await session.list_resources()
                assert URI in {str(resource.uri) for resource in resources.resources}
                card = (await session.read_resource(URI)).contents[0]
                assert card.mimeType == MIME
                assert 'ui/open-link' in card.text and 'ui/initialize' in card.text
                assert 'window.openai' not in card.text and 'tools/call' not in card.text
                result = await session.call_tool(proxy.RESTORE, {'key': '1' * 64})
                assert result.isError
    asyncio.run(run())


def test_group_metadata_survives_only_uniform_contract():
    from mcp.types import Tool
    meta = {'ui': {'resourceUri': URI}}
    a = Tool(name='a', inputSchema={'type': 'object'}, _meta=meta)
    b = Tool(name='b', inputSchema={'type': 'object'}, _meta=meta)
    assert compact_tools([a, b], groups={'pair': ['a', 'b']})[0].meta == meta
    b.meta = None
    assert compact_tools([a, b], groups={'pair': ['a', 'b']})[0].meta is None


def test_proxy_binding_checks_real_signed_route(tmp_path):
    from threading import RLock
    from types import SimpleNamespace
    from security_runtime.global_workspace import workspace_state
    from security_runtime.hook_state import HookStateStore
    from security_runtime.tasks.ownership import issue_session_ref, session_owner
    from security_runtime.workspace_binding_status import restore_proxy_binding

    root = (tmp_path / 'project').resolve()
    root.mkdir()
    base = tmp_path / 'state'
    hooks = HookStateStore(workspace_state(root, base) / 'hooks')
    token = issue_session_ref(hooks, root, 'codex', 'demo-session')
    pool = SimpleNamespace(root=lambda value: Path(value), validate_layers=lambda _: None,
                           base=base, host='codex', sessions={}, lock=RLock())
    assert not restore_proxy_binding(pool, str(root), token[:-1] + ('1' if token[-1] != '1' else '0'))
    assert not pool.sessions
    assert restore_proxy_binding(pool, str(root), token)
    assert pool.sessions[session_owner('codex', 'demo-session')['session']] == root


class Child:
    def __init__(self, cmd, *, behavior):
        self.build = Path(cmd[0]).parent.name
        self.events = Queue()
        self.relay = None
        self.closed = False
        self.sent = []
        self.restore_key = 'test'
        self.behavior = behavior

    def send(self, message):
        self.sent.append(message)

    def close(self):
        self.closed = True

    def request(self, method, params, deadline):
        if method == 'initialize':
            return {'result': {'capabilities': {}, 'serverInfo': {'name': 'test', 'version': self.build}}}
        if method == 'tools/list':
            return {'result': {'tools': [{'name': 'extra'}]} if self.behavior == 'tools' else {'tools': []}}
        if params['name'] == 'get_runtime_info':
            return {'result': {'structuredContent': {'build_identity': {'build_id': self.build}}}}
        assert params['name'] == proxy.RESTORE
        assert params['arguments'] == {'workspace_path': '/demo', 'session_ref': 'signed', 'key': 'test'}
        return {'result': {'structuredContent': {'routing_binding_confirmed': self.behavior != 'route'}}}


@pytest.mark.parametrize('behavior', ['switch', 'tools', 'route', 'storage', 'hooks'])
def test_proxy_preserves_connection_and_never_replays_writes(monkeypatch, tmp_path, behavior):
    from types import SimpleNamespace
    old = dict(build_id='old', mcp_proxy_contract=proxy.CONTRACT, mcp_hook_identity='hooks',
               storage_contracts=['store'], state_schema='state', launcher_contract='launch')
    new = dict(old, build_id='new')
    if behavior == 'storage':
        new['storage_contracts'] = ['different']
    if behavior == 'hooks':
        new['mcp_hook_identity'] = 'other'
    active = [old]
    pointer = tmp_path / 'active.json'
    pointer.write_text('old')
    service = SimpleNamespace(active=lambda: active[0], delivery=SimpleNamespace(root=tmp_path, slot=lambda build: Path(build)))
    monkeypatch.setattr(proxy, 'package_metadata', lambda _: new)
    children = []

    def backend(cmd):
        child = Child(cmd, behavior=behavior)
        children.append(child)
        return child

    relay = proxy.Proxy(service, old, backend=backend)
    relay.init, relay.initialized = {}, True
    relay.hello = {'capabilities': {}, 'serverInfo': {'name': 'test'}}
    relay.tools = {'tools': []}
    relay.routes.add(('/demo', 'signed'))
    old_backend = relay.server
    write = {'id': 1, 'method': 'tools/call', 'params': {'name': 'write', 'arguments': {
             'workspace_path': '/demo', 'session_ref': 'signed'}}}
    relay.from_host(write)
    active[0] = new
    pointer.write_text('new build')
    relay.maybe_switch()
    assert not old_backend.closed and len(children) == 1
    relay.from_backend({'id': 1, 'result': {}})
    relay.maybe_switch()
    relay.warming.join(5)
    relay.from_host({'id': 2, 'method': 'tools/call', 'params': {'name': 'get_runtime_info'}})
    assert old_backend.sent.count(write) == 1
    if behavior == 'switch':
        assert relay.server.build == 'new' and old_backend.closed
        assert write not in relay.server.sent
    else:
        assert relay.server is old_backend and not old_backend.closed


def test_same_stdio_stream_serves_new_child_without_reopening(monkeypatch, tmp_path):
    from threading import Thread
    from types import SimpleNamespace
    import time

    worker = """
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if 'id' not in msg: continue
    method = msg['method']
    if method == 'initialize':
        result = {'serverInfo': {'name': 'fixture', 'version': sys.argv[1]}, 'capabilities': {}}
    elif method == 'tools/list':
        result = {'tools': [{'name': 'get_runtime_info'}]}
    else:
        result = {'structuredContent': {'build_identity': {'build_id': sys.argv[1]},
                                        'routing_binding_confirmed': True}}
    print(json.dumps({'id': msg['id'], 'result': result, 'jsonrpc': '2.0'}), flush=True)
"""
    pointer = tmp_path / 'active.json'
    pointer.write_text('old')
    active = dict(build_id='old', mcp_proxy_contract=proxy.CONTRACT, mcp_hook_identity='hooks',
                  storage_contracts=['store'], state_schema='state', launcher_contract='launch')
    service = SimpleNamespace(active=lambda: dict(active, build_id=pointer.read_text()),
                              delivery=SimpleNamespace(root=tmp_path, slot=lambda build: Path(build)))
    monkeypatch.setattr(proxy, 'package_metadata', lambda slot: dict(active, build_id=slot.name))
    monkeypatch.setattr(proxy, 'command', lambda slot: [sys.executable, '-u', '-c', worker, slot.name])
    front = proxy.Proxy(service, active)
    front.routes.add(('/demo', 'signed-fixture'))
    incoming, to_proxy = os.pipe()
    from_proxy, outgoing = os.pipe()
    messages = Queue()
    with (os.fdopen(incoming, 'rb') as stdin, os.fdopen(to_proxy, 'wb') as writer,
          os.fdopen(from_proxy, 'rb') as reader, os.fdopen(outgoing, 'wb') as stdout):
        runtime = Thread(target=front.run, args=(stdin, stdout), daemon=True)
        runtime.start()
        output_reader = Thread(target=proxy.read_messages, args=(reader, messages.put), daemon=True)
        output_reader.start()

        def request(identity, method, params=None):
            proxy.send(writer, dict(jsonrpc='2.0', id=identity, method=method, params=params or {}))
            result = messages.get(timeout=6)
            assert result['id'] == identity
            return result

        try:
            request(1, 'initialize')
            proxy.send(writer, dict(jsonrpc='2.0', method='notifications/initialized'))
            request(2, 'tools/list')
            args = {'name': 'get_runtime_info'}
            assert proxy.structured(request(3, 'tools/call', args))['build_identity']['build_id'] == 'old'
            pointer.write_text('new')
            for i in range(4, 40):
                build = proxy.structured(request(i, 'tools/call', args))['build_identity']['build_id']
                if build == 'new':
                    break
                time.sleep(.05)
            assert build == 'new'
        finally:
            writer.close()
            runtime.join(6)
            stdout.close()
            output_reader.join(6)
