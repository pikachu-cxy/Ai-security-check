import copy
import threading
import time

import pytest

from security_runtime.task_dispatcher import autostart, execution_slot, register, recover_registered
from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.queued_closeout import enqueue, status
from security_runtime.scan_attempt import ScanAttemptStore, source_binding
from test_task_security import service


@pytest.fixture(autouse=True)
def private_state(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'dispatcher'))
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE', '1')


class Registry:
    HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_SZ = range(4)
    def __init__(self):
        self.values = {}
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def OpenKey(self, *args): return self
    def CreateKeyEx(self, *args): return self
    def QueryValueEx(self, key, name):
        if name not in self.values: raise FileNotFoundError()
        return self.values[name], self.REG_SZ
    def SetValueEx(self, key, name, reserved, kind, value): self.values[name] = value
    def DeleteValue(self, key, name): del self.values[name]


def test_login_registration_is_explicit_owned_and_removable():
    api = Registry()
    assert not autostart(registry_api=api)['configured']
    assert not api.values
    assert autostart('install', registry_api=api)['configured']
    assert autostart(registry_api=api)['configured']
    assert not autostart('remove', registry_api=api)['configured']
    assert not api.values


def test_login_registration_never_overwrites_foreign_value():
    api = Registry()
    api.values['AISecurityTaskCloseoutDispatcher'] = 'foreign program'
    with pytest.raises(ValueError, match='Unowned'):
        autostart('install', registry_api=api)
    assert api.values['AISecurityTaskCloseoutDispatcher'] == 'foreign program'


def test_global_execution_has_two_slots():
    with execution_slot() as first:
        assert first
        with execution_slot() as second:
            assert second
            with execution_slot() as third:
                assert not third


def test_registered_recovery_does_not_create_baseline(service, monkeypatch):
    old, root, engine = service
    task = TaskSecurityService(engine, old.hooks, owner=session_owner('codex', 'recover'))
    ref = task.begin(root, 'one', check_policy=POLICY)['task_ref']
    baseline = copy.deepcopy(task.load(root, ref)['baseline'])
    (root/'routes.py').write_text('version = 2\n')
    enqueue(task, root, ref, launch=False)
    register(task.hooks, root)
    recovered = []
    monkeypatch.setattr('security_runtime.task_closeout_worker.recover', lambda h,r:recovered.append(r))
    monkeypatch.setattr(TaskSecurityService, 'begin', lambda *a,**k:pytest.fail('recovery began a task'))
    assert recover_registered() == 1
    assert recovered == [root]
    assert task.load(root, ref)['baseline'] == baseline


def test_detached_process_scans_after_busy_without_another_finish(service):
    """Actual CLI child and installed local providers; no mock worker dispatch."""
    old, root, engine = service
    task = TaskSecurityService(engine, old.hooks, owner=session_owner('codex', 'process'))
    ref = task.begin(root, 'process', check_policy=POLICY)['task_ref']
    baseline = copy.deepcopy(task.load(root, ref)['baseline'])
    (root/'routes.py').write_text('version = 123\n')
    attempts = ScanAttemptStore(task.hooks, root)
    with task.hooks.lock(root):
        busy = attempts.claim('MANUAL', 'busy', source_binding({'test':True}))
    try:
        assert enqueue(task, root, ref)['status'] in {'QUEUED', 'RUNNING', 'RETRY_WAIT'}
        deadline = time.monotonic()+45
        while time.monotonic() < deadline and status(task, root, ref)['status'] != 'RETRY_WAIT':
            time.sleep(.2)
        assert status(task, root, ref)['status'] == 'RETRY_WAIT'
    finally:
        with task.hooks.lock(root):
            attempts.finish(busy, outcome='COMPLETED')
    deadline = time.monotonic()+120
    while time.monotonic() < deadline:
        result = status(task, root, ref)
        if result['status'] not in {'QUEUED', 'RUNNING', 'RETRY_WAIT'}:
            break
        time.sleep(.2)
    assert result['status'] == 'READY_FOR_REVIEW', result
    record = task.load(root, ref)
    assert record['baseline'] == baseline
    assert record['static']['scanner_runs']
    assert record['phase'] == 'READY'
