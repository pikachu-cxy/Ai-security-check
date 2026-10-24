"""Capacity diagnostics preserve exact task routing and never echo source errors."""
import pytest
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.ledger_partitions import LedgerCapacity
from security_runtime.mcp_server import create_server
from security_runtime.tasks.closeout_queue import CloseoutQueue
from security_runtime.tasks.diagnostics import (capacity_failure, runtime_compatibility_failure,
                                              TaskRuntimeRestartRequired)
from security_runtime.tasks.security import TaskSecurityService
from test_task_review_protocol_mcp import local_call
from test_task_security import service


def test_sdk_capacity_failure_keeps_original_record_and_scan_budget(service, monkeypatch):
    tasks, root, runtime = service
    server = create_server(runtime, hook_coordinator=HookCoordinator(runtime, tasks.hooks), global_mode=False)
    ref = local_call(server, 'begin_security_task', workspace_path=str(root), task_key='capacity')['task_ref']
    before = tasks.store(root).get(ref)
    def reject(self, record, end, configuration, input_ref=None, preparation_ms=0):
        assert record['task_ref'] == ref and record['baseline'] == before['baseline']
        assert record['task_owner'] == before['task_owner']
        assert end['version_ref'] and input_ref
        raise LedgerCapacity('ROW', 1117, 1000)
    monkeypatch.setattr(CloseoutQueue, 'submit', reject)
    result = local_call(server, 'finish_security_task', workspace_path=str(root), task_ref=ref)
    assert result['reason_code'] == 'TASK_RISK_LEDGER_ROW_CAPACITY'
    assert result['capacity'] == {'observed': 1117, 'maximum': 1000}
    assert result['original_task_preserved'] and not result['scanner_run']
    assert tasks.store(root).get(ref) == before and not runtime.calls
    assert CloseoutQueue(tasks.hooks, root).read(ref) is None


def test_arbitrary_untyped_exception_is_not_reflected_as_a_capacity_diagnostic():
    assert capacity_failure(ValueError('private source text')) is None
    assert runtime_compatibility_failure(TypeError('private source text')) is None


def test_sdk_runtime_compatibility_diagnostic_preserves_task_and_hides_exception(service, monkeypatch):
    tasks, root, runtime = service
    server = create_server(runtime, hook_coordinator=HookCoordinator(runtime, tasks.hooks), global_mode=False)
    ref = local_call(server, 'begin_security_task', workspace_path=str(root), task_key='loaded-runtime')['task_ref']
    before = tasks.store(root).get(ref)

    def reject(*args, **kwargs):
        raise TaskRuntimeRestartRequired() from TypeError('private source must never be returned')

    monkeypatch.setattr(TaskSecurityService, 'prepare', reject)
    result = local_call(server, 'prepare_task_security_review', workspace_path=str(root), task_ref=ref)
    assert result['reason_code'] == 'RUNTIME_RESTART_REQUIRED'
    assert result['original_task_preserved'] and result['baseline_recreated'] is False
    assert 'private source' not in str(result)
    assert tasks.store(root).get(ref) == before and not runtime.calls
