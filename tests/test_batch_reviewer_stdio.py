"""Real scoped-reviewer CLI/stdio IPC; no scanner, model or external network.

Windows requires permission for asyncio's local socketpair. Run this test in the
local-IPC-enabled test environment; do not replace it with in-process SDK calls.
"""
import asyncio
import json
import os
from pathlib import Path
import subprocess

import pytest

from security_runtime.batch_reviewer import REVIEWER_TOOLS, HOOK_STATE_ENV
from security_runtime.hook_state import HookStateStore
from security_runtime.task_security import TaskSecurityService, _unread_context
from security_runtime.task_security_batch import TaskSecurityBatchService


def payload(result):
    data = result.structuredContent or json.loads(result.content[0].text)
    return data.get('result', data)


def test_handoff_launches_real_scoped_reviewer_stdio(tmp_path, monkeypatch):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    class NoScan:
        def scan(self, *args, **kwargs):
            pytest.fail('Batch reviewer transport must not invoke any scanner')

    root = tmp_path / 'project'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    source = root / 'routes.py'
    source.write_text('def route():\n    return None\n')
    # Actual launch must resist a same-named module in the reviewed cwd.
    shadow = root / 'security_runtime'
    shadow.mkdir()
    (shadow / '__init__.py').write_text("raise RuntimeError('untrusted cwd import')\n")
    hooks = HookStateStore(tmp_path / 'real-workspace-state' / 'hooks')
    tasks = TaskSecurityService(NoScan(), hooks)
    task_ref = tasks.begin(root, 'stdio-batch-review')['task_ref']
    source.write_text('\n'.join(f'snapshot_item_{i} = {i}' for i in range(1, 126)) + '\n')
    batches = TaskSecurityBatchService(tasks)
    packet = batches.prepare(root, task_ref, 'completed-route')
    handoff = packet['review_handoff']
    launch = handoff['launch']
    assert handoff['expected_agent_tools'] == list(REVIEWER_TOOLS)
    assert Path(launch['environment'][HOOK_STATE_ENV]) == hooks.directory.resolve()
    source.write_text('\n'.join(f'live_item_{i} = {i}' for i in range(1, 126)) + '\n')
    live_bytes = source.read_bytes()
    # Wrong-state fallback cannot accidentally find this task. The trusted
    # handoff's explicit Hook store is the only route to its frozen evidence.
    decoy_state = tmp_path / 'decoy-default-state'
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(decoy_state))
    environment = {**os.environ, **launch['environment'], 'SECURITY_RUNTIME_OFFLINE': '1'}
    parameters = StdioServerParameters(command=launch['command'], args=launch['args'],
                                        cwd=root, env=environment)
    stderr_path = tmp_path / 'reviewer-stderr.log'

    async def exercise():
        with stderr_path.open('w+', encoding='utf-8') as errors:
            async with stdio_client(parameters, errlog=errors) as (reader, writer):
                async with ClientSession(reader, writer) as client:
                    initialized = await asyncio.wait_for(client.initialize(), timeout=15)
                    assert initialized.serverInfo.name == 'AI Security Batch Reviewer'
                    listed = await asyncio.wait_for(client.list_tools(), timeout=10)
                    assert [tool.name for tool in listed.tools] == list(REVIEWER_TOOLS)
                    tool = listed.tools[0]
                    assert tool.annotations.readOnlyHint is False
                    assert tool.inputSchema['additionalProperties'] is False
                    first_response = await asyncio.wait_for(client.call_tool(REVIEWER_TOOLS[0],
                        {'path': 'routes.py', 'start_line': 1, 'end_line': 125}), timeout=10)
                    assert not first_response.isError
                    first = payload(first_response)
                    assert 'snapshot_item_' in json.dumps(first)
                    assert 'live_item_' not in json.dumps(first)
                    assert first['returned_range'] == {'start_line': 1, 'end_line': 80}
                    assert first['next_read'] == {'path': 'routes.py', 'start_line': 81, 'end_line': 125}
                    second_response = await asyncio.wait_for(
                        client.call_tool(REVIEWER_TOOLS[0], first['next_read']), timeout=10)
                    assert not second_response.isError
                    second = payload(second_response)
                    assert second['returned_range'] == {'start_line': 81, 'end_line': 125}
                    assert second['next_read'] is None and not second['has_more']
                    assert second['evidence_id'] != first['evidence_id']
                    for forbidden in ('scan_project', 'submit_security_batch_review'):
                        rejected = await asyncio.wait_for(client.call_tool(forbidden, {}), timeout=10)
                        assert rejected.isError
                    rebinding = await asyncio.wait_for(client.call_tool(REVIEWER_TOOLS[0],
                        {'path': 'routes.py', 'review_session': 'another-session'}), timeout=10)
                    assert rebinding.isError

    asyncio.run(asyncio.wait_for(exercise(), timeout=45))
    assert source.read_bytes() == live_bytes
    record = tasks.load(root, task_ref)
    assert record['phase'] == 'ACTIVE'
    assert record['static_attempts'] == 0
    assert record['batch_state']['budget']['context_reads'] == 2
    assert _unread_context(record['batch_state']['batches'][0]) == []
    assert not (decoy_state / 'scans.db').exists()
