"""Task context paging through the real global MCP router; scanners are fixtures."""
import asyncio

from security_runtime.global_mcp import create_global_server
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.mcp_server import create_server
from security_runtime.runtime import SecurityRuntime
from security_runtime.storage import SQLiteStore
from test_global_integration import installed, projects, pool_fixture, structured
from test_task_security import LedgerRuntime


def task_pool(installed, tmp_path):
    ledgers = {}

    def child(root, directory, binding):
        ledger = LedgerRuntime()
        ledgers[root] = ledger
        engine = SecurityRuntime(store=SQLiteStore(directory / 'scans.db'))
        engine.scan = ledger.scan
        core = HookCoordinator(engine, HookStateStore(directory / 'hooks'))
        return create_server(engine, hook_coordinator=core, workspace_binding=binding), core

    return pool_fixture(installed, tmp_path, child), ledgers


def call(server, name, workspace, **arguments):
    result = asyncio.run(server.call_tool(name, dict(workspace_path=str(workspace), **arguments)))
    return structured(result)


def prepare_large_task(server, root):
    ref = call(server, 'begin_security_task', root, task_key='large-source')['task_ref']
    source = root / 'large.py'
    source.write_text(''.join(f'value_{number} = {number}\n' for number in range(500)), encoding='utf-8')
    finished = call(server, 'finish_security_task', root, task_ref=ref)
    packet = call(server, 'prepare_task_security_review', root, task_ref=ref)
    return ref, packet, finished


def test_global_paging_keeps_full_static_scope_and_same_task_session(installed, projects, tmp_path):
    pool, ledgers = task_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    root = projects[0]
    try:
        ref, packet, finished = prepare_large_task(server, root)
        assert finished['static']['scope_files'] == ['large.py']
        assert ledgers[root].calls == [('large.py',)]
        page = call(server, 'read_task_review_context', root, task_ref=ref,
                    review_session=packet['review_session'], file_path='large.py',
                    start_line=1, end_line=500)
        evidence, ranges = [], []
        while True:
            assert page.get('reason_code') != 'WORKSPACE_OR_REFERENCE_REJECTED'
            assert 'workspace_readiness' not in page
            assert page['total_lines'] == 500
            assert 1 <= len(page['numbered_lines']) <= 80
            evidence.append(page['evidence_id'])
            ranges.append((page['start_line'], page['end_line']))
            if not page['has_more']:
                break
            next_read = page['next_read']
            assert next_read['task_ref'] == ref
            assert next_read['review_session'] == packet['review_session']
            assert next_read['file_path'] == 'large.py'
            page = call(server, 'read_task_review_context', root,
                        **{k: v for k, v in next_read.items() if k != 'workspace_path'})
        assert ranges[0] == (1, 80) and ranges[-1][1] == 500
        assert all(left[1] + 1 == right[0] for left, right in zip(ranges, ranges[1:]))
        assert len(evidence) == len(set(evidence)) == 7
        submitted = call(server, 'submit_task_security_review', root, task_ref=ref,
                         review_session=packet['review_session'], findings=[],
                         coverage='REVIEWED', limitations=[])
        assert submitted['status'] == 'COMPLETE'
        assert submitted['host_review']['coverage'] == 'REVIEWED'
        assert ledgers[root].calls == [('large.py',)]
    finally:
        pool.close()


def test_global_request_errors_do_not_report_broken_workspace_or_poison_session(installed, projects, tmp_path):
    pool, ledgers = task_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    root = projects[0]
    try:
        (root / 'README.md').write_text('Local documentation.', encoding='utf-8')
        ref, packet, _ = prepare_large_task(server, root)
        arguments = dict(task_ref=ref, review_session=packet['review_session'])
        invalid = call(server, 'read_task_review_context', root, **arguments,
                       file_path='large.py', start_line=0, end_line=10)
        unsupported = call(server, 'read_task_review_context', root, **arguments,
                           file_path='README.md', start_line=1, end_line=25)
        assert invalid['reason_code'] == 'TASK_CONTEXT_RANGE_INVALID'
        assert unsupported['reason_code'] == 'TASK_CONTEXT_FILE_UNSUPPORTED'
        for error in (invalid, unsupported):
            assert error['status'] == 'CONTEXT_REQUEST_REJECTED'
            assert 'workspace_readiness' not in error
            assert not error['scanner_run']
        page = call(server, 'read_task_review_context', root, **arguments,
                    file_path='large.py', start_line=1, end_line=80)
        assert page['evidence_id']
        assert ledgers[root].calls == [('large.py',)]
    finally:
        pool.close()
