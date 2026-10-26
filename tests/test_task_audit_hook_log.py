"""Closed deferred states survive persistence and independent process reads."""
import json
import os
import subprocess
import sys

import pytest

from security_runtime.recent_hooks import Observation, RecentHookStore


@pytest.fixture(autouse=True)
def state(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))


def test_deferred_status_reason_and_execution_are_distinct_after_restart():
    code = '''
from security_runtime.recent_hooks import Observation
item=Observation('handle_hook_event', {'tool_input':{'command':'private-command'}})
item.finish(dict(status='RECORDED_PENDING', reason='TASK_CLOSEOUT_PENDING',
    scanner_skipped_reason='DEFERRED_TO_TASK_CLOSEOUT', scanner_run=False,
    task_activity_recorded=True, task_audit_complete=False, source='private-source',
    arbitrary='private-token'))
'''
    subprocess.run([sys.executable, '-c', code], check=True, env=dict(os.environ),
                   capture_output=True, text=True, timeout=30)
    command = [sys.executable, '-m', 'security_runtime.cli', 'hooks', 'recent', '--unbound', '--json']
    for _ in range(2):
        result = subprocess.run(command, check=True, env=dict(os.environ),
                                capture_output=True, text=True, timeout=30)
        packet = json.loads(result.stdout)
        row = packet['records'][0]
        assert row['handler_status'] == 'RECORDED_PENDING'
        assert row['handler_reason'] == 'TASK_CLOSEOUT_PENDING'
        assert row['scanner_skipped_reason'] == 'DEFERRED_TO_TASK_CLOSEOUT'
        assert row['completed'] and row['task_activity_recorded']
        assert row['scanner_run'] is False and row['task_audit_complete'] is False
        assert packet['completion_semantics'] == 'HOOK_HANDLER_RETURNED_ONLY'
        assert 'private' not in result.stdout
    assert b'private' not in RecentHookStore().path.read_bytes()


def test_old_unknown_history_is_not_guessed_or_rewritten():
    old = Observation('handle_hook_event', {})
    old.finish(dict(status='private-unknown', reason='private-reason'))
    before = RecentHookStore().recent(unbound=True)['records'][0]
    assert before['handler_status'] == 'UNKNOWN' and before['handler_reason'] == 'OTHER'
    current = Observation('handle_hook_event', {})
    current.finish(dict(status='RECORDED_PENDING', reason='TASK_CLOSEOUT_PENDING', scanner_run=False))
    saved = RecentHookStore().recent(unbound=True)['records']
    assert next(item for item in saved if item['diagnostic_id'] == old.record['diagnostic_id']) == before


def test_logging_failure_stays_advisory(monkeypatch):
    def fail(*args, **kwargs):
        raise OSError('private-write-error')
    monkeypatch.setattr(RecentHookStore, 'write', fail)
    item = Observation('handle_hook_event', {})
    item.finish(dict(status='RECORDED_PENDING', scanner_run=False, task_activity_recorded=True))
    assert not item.available
    assert item.record['scanner_run'] is False
