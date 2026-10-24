"""Typed private-state failures through the actual global MCP router.

Transport failures are injected at the real task-save boundary. Files, task
heads, queue bindings and frozen inputs are real isolated fixtures; detectors
and the user installation are fixtures, not native desktop acceptance.
"""
import json

import pytest

from security_runtime.global_mcp import create_global_server
from security_runtime.owned_workspace_storage import OwnedWorkspaceStorageError
from security_runtime.tasks.closeout_queue import CloseoutQueue
from security_runtime.tasks.security_state import TaskSecurityStore
from test_global_integration import installed, projects  # noqa: F401
from test_task_context_global_transport import call, task_pool


@pytest.mark.parametrize('state', ['BUSY', 'RETRY', 'UPGRADE_INCOMPLETE', 'UNSAFE', 'PLATFORM_UNSUPPORTED'])
def test_global_private_state_failure_preserves_original_task_and_separates_admission(
        installed, projects, tmp_path, monkeypatch, state):
    monkeypatch.setattr('security_runtime.task_closeout_worker.launch_worker', lambda *a, **k: None)
    pool, ledgers = task_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    root = projects[0]
    try:
        begun = call(server, 'begin_security_task', root, task_key='private-admission')
        assert 'task_ref' in begun, begun
        ref = begun['task_ref']
        core = pool.children[root][1]
        store = TaskSecurityStore(core.store, root)
        before = store.get(ref)
        (root / 'changed.py').write_text('changed = True\n')
        report = dict(state=state, reason_code='OWNED_WORKSPACE_STORAGE_' + state,
                      detail_code='private-source-marker', targets=['/private/source-marker'])
        original_save = TaskSecurityStore.save

        def failed_save(target, value, **kwargs):
            if value.get('task_ref') == ref:
                try:
                    raise OwnedWorkspaceStorageError(report)
                except OwnedWorkspaceStorageError as error:
                    # Model the wrapper used by tool dispatch without trusting
                    # a reason-code string from an unrelated exception.
                    raise RuntimeError('arbitrary SDK private-source-marker') from error
            return original_save(target, value, **kwargs)

        with monkeypatch.context() as scoped:
            scoped.setattr(TaskSecurityStore, 'save', failed_save)
            response = call(server, 'finish_security_task', root, task_ref=ref)
        busy = state in {'BUSY', 'RETRY'}
        retryable = busy or state == 'UPGRADE_INCOMPLETE'
        assert response['status'] == ('BUSY' if busy else 'INCONCLUSIVE')
        assert response['reason_code'] == report['reason_code']
        assert response['stage'] == 'PRIVATE_STORAGE_ADMISSION'
        assert response['retryable'] is retryable
        assert response['original_records_preserved'] and response['retry_original_request']
        assert response['baseline_recreated'] is False
        assert 'workspace_readiness' not in response and 'host_claim_status' not in response
        assert 'private-source-marker' not in json.dumps(response)
        assert 'scanner_run' not in response  # A failed save alone cannot prove this fact.
        assert store.get(ref) == before and ledgers[root].calls == []

        queue = CloseoutQueue(core.store, root)
        queued = queue.read(ref)
        assert queued and queued['input_ref'] and queued['state'] == 'QUEUED'
        resumed = call(server, 'finish_security_task', root, task_ref=ref)
        assert resumed['status'] == 'QUEUED' and resumed['job_ref'] == queued['job_ref']
        assert queue.read(ref)['input_ref'] == queued['input_ref']
        assert store.get(ref)['baseline'] == before['baseline']
    finally:
        pool.close()


def test_plain_private_state_error_text_is_not_treated_as_typed_busy(
        installed, projects, tmp_path, monkeypatch):
    monkeypatch.setattr('security_runtime.task_closeout_worker.launch_worker', lambda *a, **k: None)
    pool, _ = task_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    root = projects[0]
    try:
        begun = call(server, 'begin_security_task', root, task_key='untyped-failure')
        assert 'task_ref' in begun, begun
        ref = begun['task_ref']

        def failed_save(*args, **kwargs):
            raise ValueError('OWNED_WORKSPACE_STORAGE_BUSY private-source-marker')

        with monkeypatch.context() as scoped:
            scoped.setattr(TaskSecurityStore, 'save', failed_save)
            response = call(server, 'finish_security_task', root, task_ref=ref)
        assert response['status'] == 'INCONCLUSIVE'
        assert response['reason_code'] == 'TASK_REQUEST_REJECTED'
        assert not response.get('retryable') and 'private-source-marker' not in json.dumps(response)
    finally:
        pool.close()
