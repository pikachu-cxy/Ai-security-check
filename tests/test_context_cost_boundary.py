import asyncio
import json

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolRequest, CallToolRequestParams

from security_runtime.mcp_contracts import MCPRegistry


def test_final_response_measured_once_in_global_router(monkeypatch):
    from security_runtime import context_cost
    calls = []

    class Store:
        def monitoring(self):
            return dict(status='AVAILABLE', mode='basic')

        def record_call(self, name, result, **metadata):
            calls.append((name, result, metadata))

    monkeypatch.setattr(context_cost, 'ContextCostStore', Store)
    child = FastMCP('child')

    @child.tool()
    def sample() -> dict:
        return {'status': 'OK', 'note': 'safe result'}

    child_registry = MCPRegistry(child)
    child_registry.observe_context_cost(workspace='private-path')
    outer = FastMCP('outer')
    registry = MCPRegistry(outer)

    async def listed():
        return await child.list_tools()

    async def routed(name, arguments):
        return await child_registry.dispatch(name, arguments, convert_result=True)

    registry.install_router(listed, routed)
    registry.observe_context_cost()
    request = CallToolRequest(params=CallToolRequestParams(name='sample', arguments={}))
    response = asyncio.run(registry.low_level.request_handlers[CallToolRequest](request))
    payload = response.root.structuredContent or json.loads(response.root.content[0].text)
    assert payload['status'] == 'OK'
    assert len(calls) == 1
    assert calls[0][1] is response.root
    assert calls[0][2]['succeeded'] is True
    assert calls[0][2]['transport'] == 'mcp'
    assert calls[0][2]['workspace'] is None


def test_metrics_failure_never_changes_result_or_cancellation(monkeypatch):
    from security_runtime import context_cost
    from security_runtime.context_cost_mcp import observe_response

    class BrokenStore:
        def monitoring(self):
            return dict(status='AVAILABLE', mode='debug')

        def record_call(self, *args, **kwargs):
            raise OSError('private exception text')

    monkeypatch.setattr(context_cost, 'ContextCostStore', BrokenStore)
    request = CallToolRequest(params=CallToolRequestParams(name='sample', arguments={}))
    expected = object()

    async def success(request):
        return expected

    assert asyncio.run(observe_response(success, request, connection_id='one')) is expected

    async def cancelled(request):
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(observe_response(cancelled, request, connection_id='one'))


def test_monitor_can_be_disabled_without_store_access(monkeypatch):
    from security_runtime import context_cost
    from security_runtime.context_cost_mcp import observe_response

    def forbidden():
        raise AssertionError('disabled observer opened a database')

    monkeypatch.setattr(context_cost, 'ContextCostStore', forbidden)
    monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MONITOR', '0')

    async def success(request):
        return 'unchanged'

    assert asyncio.run(observe_response(success, None, connection_id='one')) == 'unchanged'
