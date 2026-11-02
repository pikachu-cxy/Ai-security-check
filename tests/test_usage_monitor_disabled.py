"""Default monitoring gates must not hide risk statistics or touch usage storage."""
import argparse
import asyncio
from types import SimpleNamespace

import pytest
from mcp.server.fastmcp import FastMCP
from security_runtime.context_cost import ContextCostStore
from security_runtime.context_cost_cli import register as register_cli
from security_runtime.mcp_contracts import MCPRegistry
from security_runtime.monitoring.mcp import register
from security_runtime.monitoring.launch import start_monitor
from security_runtime.monitoring.server import serve


@pytest.fixture(autouse=True)
def disabled(monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_USAGE_MONITOR_ENABLED', raising=False)


def test_default_collection_ignores_previous_opt_in_without_writing(tmp_path, monkeypatch):
    store = ContextCostStore(tmp_path/'usage.db')
    monkeypatch.setenv('SECURITY_RUNTIME_USAGE_MONITOR_ENABLED', '1')
    assert store.set_monitoring('debug')['status'] == 'AVAILABLE'
    before = store.path.read_bytes()
    monkeypatch.delenv('SECURITY_RUNTIME_USAGE_MONITOR_ENABLED')
    monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MODE', 'debug')
    assert store.monitoring()['mode'] == 'off'
    assert store.record_call('get_findings', {})['status'] == 'DISABLED'
    assert store.set_monitoring('basic')['status'] == 'DISABLED'
    assert store.path.read_bytes() == before


def test_default_launch_does_not_discover_logs_or_create_storage(tmp_path, monkeypatch):
    monkeypatch.setattr('security_runtime.monitoring.launch.find_chat_log',
                        lambda *a, **kw: pytest.fail('must not discover logs'))
    store = ContextCostStore(tmp_path/'usage.db')
    with pytest.raises(ValueError, match='MONITOR_DISABLED_BY_DEFAULT'):
        start_monitor(tmp_path, {}, store=store)
    with pytest.raises(ValueError, match='MONITOR_DISABLED_BY_DEFAULT'):
        serve(store)
    assert not store.path.exists()


@pytest.mark.parametrize('enabled', [False, True])
def test_mcp_keeps_risk_dashboard_and_gates_usage(monkeypatch, enabled):
    if enabled:
        monkeypatch.setenv('SECURITY_RUNTIME_USAGE_MONITOR_ENABLED', '1')
    server = FastMCP('feature-gate')
    register(server, MCPRegistry(server), application=SimpleNamespace())
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert 'start_risk_dashboard' in names
    assert ('start_usage_monitor' in names) is enabled


def test_cli_hides_usage_until_explicit_opt_in(monkeypatch):
    parser = argparse.ArgumentParser()
    children = parser.add_subparsers()
    register_cli(children)
    assert 'context-usage' not in children.choices
    monkeypatch.setenv('SECURITY_RUNTIME_USAGE_MONITOR_ENABLED', '1')
    register_cli(children)
    assert 'context-usage' in children.choices
