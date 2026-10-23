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
    packet = call(server, 'prepare_task_security_review', root, task_ref=ref, protocol_version=3)
    return ref, packet, finished


def test_global_session_scope_requires_signed_context_not_only_observed_chat(installed,projects,tmp_path):
    from security_runtime.tasks.ownership import issue_session_ref, record_owner, session_owner
    from security_runtime.tasks.security_state import TaskSecurityStore
    pool,_=task_pool(installed,tmp_path);server=create_global_server(workspaces=pool);root=projects[0]
    try:
        # One observed conversation is not proof of this tool request's identity.
        pool.bind_session('observed-chat',root)
        first=call(server,'begin_security_task',root,task_key='one')['task_ref']
        core=pool.children[root][1];store=TaskSecurityStore(core.store,root)
        assert record_owner(store.get(first))['host']=='connection'
        token=issue_session_ref(core.store,root,'codex','actual-chat')
        second_packet=call(server,'begin_security_task',root,task_key='two',session_ref=token)
        assert 'task_ref' in second_packet, second_packet
        second=second_packet['task_ref']
        assert first!=second and record_owner(store.get(second))==session_owner('codex','actual-chat')
        wrong=issue_session_ref(core.store,root,'codex','observed-chat')
        rejected=call(server,'finish_security_task',root,task_ref=second,session_ref=wrong,skip_review_reason='foreign')
        assert rejected['status']=='INCONCLUSIVE' and store.get(second)['phase']=='ACTIVE'
        assert call(server,'finish_security_task',root,task_ref=second,session_ref=token,
            skip_review_reason='Own task stopped')['status']=='INCOMPLETE'
    finally: pool.close()


def test_global_paging_keeps_full_static_scope_and_same_task_session(installed, projects, tmp_path):
    pool, ledgers = task_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    root = projects[0]
    try:
        ref, packet, finished = prepare_large_task(server, root)
        assert finished['static']['scope_files'] == ['large.py']
        assert ledgers[root].calls == [('large.py',)]
        assert packet['protocol_version'] == 3
        binding = next(source for source in packet['plan']['sources'] if source['path'] == 'large.py')
        assert binding['total_lines'] == 500 and binding['location_version'] == 'CURRENT_TASK_END'
        arguments = dict(task_ref=ref, review_session=packet['review_session'],
                         file_path='large.py', source_version='CURRENT')
        evidence, ranges = [], []
        for low in range(1, 501, 80):
            page = call(server, 'read_task_review_context', root, **arguments,
                        start_line=low, end_line=min(low+79, 500))
            assert page.get('reason_code') != 'WORKSPACE_OR_REFERENCE_REJECTED'
            assert 'workspace_readiness' not in page
            assert page['source_ref'] == binding['source_ref']
            assert 1 <= len(page['lines']) <= 80
            evidence.append(page['evidence_id'])
            ranges.append((page['start_line'], page['start_line']+len(page['lines'])-1))
            assert page['start_line'] == low
        assert ranges[0] == (1, 80) and ranges[-1][1] == 500
        assert all(left[1] + 1 == right[0] for left, right in zip(ranges, ranges[1:]))
        assert len(evidence) == len(set(evidence)) == 7
        batch = call(server, 'submit_task_review_batch', root, task_ref=ref,
                     review_session=packet['review_session'],
                     unit_ids=[unit['unit_id'] for unit in packet['plan']['units']],
                     coverage='REVIEWED', limitations=[])
        assert batch['status'] == 'BATCH_RECORDED' and batch['coverage'] == 'REVIEWED'
        submitted = call(server, 'submit_task_security_review', root, task_ref=ref,
                         review_session=packet['review_session'], findings=[],
                         coverage='REVIEWED', limitations=[])
        assert submitted['status'] == 'COMPLETE'
        assert submitted['result_saved'] and submitted['review_progress']['coverage'] == 'REVIEWED'
        history = call(server, 'get_task_security_review', root, task_ref=ref)
        assert history['history_read_only'] and history['host_review']['coverage'] == 'REVIEWED'
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
