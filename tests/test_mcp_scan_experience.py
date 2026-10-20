"""Shared MCP scanning reports measured work without expanding scope or authority."""
import asyncio
import json
import os
from pathlib import Path
import sys
import threading
from types import SimpleNamespace

import pytest

from security_runtime.hook_runtime import HookCoordinator
from security_runtime.global_mcp import create_global_server
from security_runtime.mcp_scan_progress import run_mcp_scan, scan_timing
from security_runtime.mcp_server import create_server
from test_global_integration import structured
from test_selected_scan import selection


class ProgressContext:
    request_context = SimpleNamespace(meta=SimpleNamespace(progressToken='request-token'))

    def __init__(self):
        self.events = []

    async def report_progress(self, progress, total=None, message=None):
        self.events.append((progress, total, message))


def test_progress_is_optional_bounded_and_does_not_block_the_protocol_loop():
    context = ProgressContext()
    server = SimpleNamespace(get_context=lambda: context)
    main_thread = threading.get_ident()

    def operation(progress):
        assert threading.get_ident() != main_thread
        progress.emit('SCANNER_STARTED', scanner='untrusted-secret-value', message='source-secret')
        progress.emit('SCANNER_STARTED', scanner='another-component')
        progress.emit('ARBITRARY_EVENT', message='must-not-leak')
        progress.emit('SCAN_COMPLETED')
        return 'unchanged-result'

    result, timing = asyncio.run(run_mcp_scan(server, operation))
    assert result == 'unchanged-result'
    assert len(context.events) == 3
    assert [v[0] for v in context.events] == [1, 2, 3]
    assert all(v[1] is None for v in context.events)  # No invented percentage.
    assert 'secret' not in json.dumps(context.events) and 'must-not-leak' not in json.dumps(context.events)
    assert timing['request_ms'] >= 0
    assert timing['host_analysis_ms'] is None and timing['conversation_total_ms'] is None


@pytest.mark.parametrize('failure', ['no-token', 'notification-error'])
def test_missing_or_failed_progress_never_changes_scan_result(failure):
    context = ProgressContext()
    if failure == 'no-token':
        context.request_context = SimpleNamespace(meta=None)
    else:
        async def unavailable(*args, **kwargs):
            raise OSError('client-disconnected')
        context.report_progress = unavailable
    result, _ = asyncio.run(run_mcp_scan(SimpleNamespace(get_context=lambda: context), lambda _: 'result'))
    assert result == 'result'


def test_reuse_timing_does_not_call_historical_scan_time_current_work():
    scan = dict(duration_ms=4567, scanner_diagnostics=dict(timing_ms=dict(total=5000)))
    timing = scan_timing(scan, dict(request_ms=12, host_analysis_ms=None), reused=True)
    assert timing['scan_ms'] == 0 and timing['historical_scan_ms'] == 4567
    assert timing['scan_stages_ms'] == {} and timing['host_analysis_ms'] is None


@pytest.mark.parametrize('host', ['codex', 'cursor'])
def test_both_global_hosts_route_the_same_selected_file_scan(selection, host):
    root, runtime, hooks, reader, _ = selection
    child = create_server(runtime, hook_coordinator=HookCoordinator(runtime, hooks), global_mode=False)
    context = ProgressContext()
    child.get_context = lambda: context
    pool = SimpleNamespace(host=host, root=lambda value: root,
        validate_layers=lambda value: None, admit=lambda value: (child, object()))
    server = create_global_server(workspaces=pool, host=host)
    out = structured(asyncio.run(server.call_tool('scan_files', dict(
        workspace_path=str(root), files=['demo.py'], summary=True))))
    assert out['scan_scope']['requested_files'] == ['demo.py']
    assert out['scan_scope']['target_files'] == ['demo.py']
    assert out['scan_scope']['full_project'] is False
    assert out['scan_scope']['context_files'] == ['package.json']
    assert len(reader.calls) == 1
    assert out['execution']['repair_authorized'] is False
    assert out['timing']['scan_ms'] >= 0 and out['timing']['host_analysis_ms'] is None
    assert context.events


@pytest.mark.parametrize('files', [['../outside.py'], ['demo.py', 'missing.py'], ['*.py'], ['nested']])
def test_selected_scan_rejection_never_runs_a_provider(selection, files):
    root, runtime, hooks, reader, _ = selection
    server = create_server(runtime, hook_coordinator=HookCoordinator(runtime, hooks), global_mode=False)
    out = structured(asyncio.run(server.call_tool('scan_files', dict(workspace_path=str(root), files=files))))
    assert out['status'] == 'REJECTED' and out['scanner_run'] is False
    assert not reader.calls


def test_real_stdio_reports_progress_and_same_result_without_client_progress(tmp_path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    project = tmp_path/'project'
    project.mkdir()
    (project/'App.java').write_text('class App {\n void demo() {}\n}\n')
    (project/'config.properties').write_text('setting=true\n')
    env = dict(os.environ, SECURITY_RUNTIME_WORKSPACE=str(project),
        SECURITY_RUNTIME_STATE_DIR=str(tmp_path/'state'), SECURITY_RUNTIME_OFFLINE='1',
        SECURITY_RUNTIME_GLOBAL='0', SECURITY_RUNTIME_MCP_SELF_TEST='1')
    parameters = StdioServerParameters(command=sys.executable,
        args=[str(Path(__file__).parent/'triage/mcp_fixture_server.py')], env=env)
    messages = []

    async def progress(value, total, message):
        messages.append((value, total, message))

    async def scenario():
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                first = await client.call_tool('scan_project', dict(summary=True, force_rescan=True),
                                               progress_callback=progress)
                second = await client.call_tool('scan_project', dict(summary=True, force_rescan=True))
                assert not first.isError and not second.isError
                def unpack(response):
                    data = response.structuredContent or json.loads(response.content[0].text)
                    return data.get('result', data)
                return unpack(first), unpack(second)

    first, second = asyncio.run(scenario())
    assert messages and all(total is None for _, total, _ in messages)
    assert '扫描完成' in messages[-1][2]
    assert first['timing']['progress_notifications'] > 0
    assert second['timing']['progress_notifications'] == 0
    assert first['finding_count'] == second['finding_count'] == 2
    assert first['scan_id'] != second['scan_id']
