"""Real watchfiles notifications, no model, target service or scanner."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from security_runtime.development_check import DevelopmentCheckService, record_hook
from security_runtime import development_file_watch as watching
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.ownership import session_owner


@pytest.fixture
def sample(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    root = tmp_path/'project'
    root.mkdir()
    hooks = HookStateStore(tmp_path/'hooks')
    owner = session_owner('codex', 'watch-fixture')
    launched = []
    service = DevelopmentCheckService(None, hooks, owner=owner,
        scan_path_provider=tmp_path/'scans.db', launcher=lambda *_: launched.append('scan'))
    ref = service.begin(root, 'task')['check_ref']
    try:
        yield root, hooks, owner, service, ref, launched
    finally:
        watching._shutdown()


def test_metadata_begin_and_read_only_access_do_not_start_a_watcher(sample):
    root, _, owner, service, ref, launched = sample
    assert not watching.active(service.store(root), ref, owner)
    assert service.get(root, ref)['dirty_seq'] == 0
    assert launched == []


def test_real_script_changes_are_drained_before_finish_without_history_inventory(sample, monkeypatch):
    root, _, owner, service, ref, launched = sample
    for name in ('untouched.py', 'again.py', 'remove.py', 'old.py', 'atomic.py'):
        (root/name).write_text('morning = 1')
    (root/'nested').mkdir()
    monkeypatch.setattr(Path, 'rglob', lambda *_a, **_k: pytest.fail('project inventory'))
    assert watching.start_window(service.store(root), ref, owner) == 'ACTIVE'
    code = """from pathlib import Path
import os,sys
r=Path(sys.argv[1])
(r/'again.py').write_text('morning = 2')
(r/'nested'/'generated.py').write_text('generated = 1')
(r/'remove.py').unlink()
(r/'old.py').rename(r/'renamed.py')
(r/'replace.tmp').write_text('current = 3')
os.replace(r/'replace.tmp',r/'atomic.py')
"""
    subprocess.run([sys.executable, '-B', '-c', code, str(root)], check=True, timeout=10,
        **({'creationflags':subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}))
    # An external writer in the accepted task time window is included as well.
    (root/'external.py').write_text('manual = 1')
    assert launched == []
    result = service.finish(root, ref)
    paths = set(result['scope']['paths'])
    assert {'again.py','nested/generated.py','remove.py','old.py','renamed.py','atomic.py','external.py'} <= paths
    assert 'untouched.py' not in paths
    assert result['file_watch']['status'] == 'STOPPED'
    assert launched == ['scan']
    final_seq = result['dirty_seq']
    (root/'after.py').write_text('outside = 1')
    time.sleep(.15)
    assert service.get(root, ref)['dirty_seq'] == final_seq
    assert 'after.py' not in service.get(root, ref)['scope']['paths']


def test_unknown_shell_is_not_an_extra_unknown_scope_when_window_is_active(sample):
    root, hooks, owner, service, ref, launched = sample
    watching.start_window(service.store(root), ref, owner)
    result = record_hook(hooks, root, owner, scope_unknown=True, event_id='script',
                         watch_eligible=True, scan_path=service.scan_path())
    assert result['dirty_seq'] == 0 and result['scope']['scope_unknown'] is False
    (root/'app.py').write_text('value = 1')
    service.finish(root, ref)
    assert service.get(root, ref)['scope']['paths'] == ['app.py']
    assert launched == ['scan']


def test_ignored_paths_and_reads_do_not_create_edits(sample):
    root, _, owner, service, ref, launched = sample
    (root/'read.py').write_text('before = 1')
    watching.start_window(service.store(root), ref, owner)
    (root/'read.py').read_bytes()
    for directory in ('.git','node_modules','.venv','__pycache__'):
        (root/directory).mkdir()
        (root/directory/'cache.py').write_text('ignored = 1')
    result = service.finish(root, ref)
    assert result['scope']['paths'] == []
    assert result['status'] == 'NO_OBSERVED_CHANGES' and launched == []


def test_start_failure_is_bounded_safe_and_does_not_scan(sample):
    root, _, owner, service, ref, launched = sample
    def broken(_root):
        raise PermissionError('private source and secret canary')
    assert watching.start_window(service.store(root), ref, owner, backend_factory=broken) == 'FAILED'
    result = service.get(root, ref)
    assert 'FILE_WATCH_START_FAILED' in result['observation_notes']
    assert result['scope']['scope_unknown'] is True
    assert 'canary' not in json.dumps(result)
    assert launched == []


def test_capacity_and_interrupted_connection_preserve_original_record(sample, monkeypatch):
    root, _, owner, service, ref, launched = sample
    monkeypatch.setattr(watching, 'MAX_WINDOWS', 0)
    assert watching.start_window(service.store(root), ref, owner) == 'FAILED'
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        store._put(db, ref, dict(row, file_watch=dict(status='ACTIVE', lease_until=0, id='lost')))
    before = store.path.read_bytes()
    result = service.get(root, ref)
    assert store.path.read_bytes() == before and 'FILE_WATCH_INTERRUPTED' in result['observation_notes']
    watching.stop_window(store, ref, owner)
    assert service.get(root, ref)['check_ref'] == ref and launched == []


def test_two_workspaces_keep_independent_windows_and_owner_checks(sample, tmp_path):
    root, hooks, owner, service, ref, _ = sample
    other = tmp_path/'other'
    other.mkdir()
    other_owner = session_owner('codex','other-session')
    other_service = DevelopmentCheckService(None, hooks, owner=other_owner,
        scan_path_provider=tmp_path/'other.db', launcher=lambda *_: None)
    other_ref = other_service.begin(other,'task')['check_ref']
    watching.start_window(service.store(root), ref, owner)
    watching.start_window(other_service.store(other), other_ref, other_owner)
    (root/'one.py').write_text('one = 1')
    (other/'two.py').write_text('two = 2')
    assert service.finish(root,ref)['scope']['paths'] == ['one.py']
    assert other_service.finish(other,other_ref)['scope']['paths'] == ['two.py']
    with pytest.raises(ValueError):
        watching.stop_window(service.store(root),ref,other_owner)


def test_connection_close_preserves_gap_and_same_ref_on_resume(sample):
    root, _, owner, service, ref, launched = sample
    store = service.store(root)
    watching.start_window(store,ref,owner)
    watching.close_store(store)
    lost = service.get(root,ref)
    assert lost['file_watch']['status'] == 'INTERRUPTED'
    assert 'FILE_WATCH_INTERRUPTED' in lost['observation_notes'] and lost['scope']['scope_unknown']
    assert watching.start_window(store,ref,owner) == 'ACTIVE'
    (root/'resumed.py').write_text('value = 1')
    result = service.finish(root,ref)
    assert result['check_ref'] == ref and result['scope']['paths'] == ['resumed.py']
    assert 'FILE_WATCH_INTERRUPTED' in result['observation_notes']
    assert launched == ['scan']


def test_native_backend_failure_retains_gap_without_exception_content(sample):
    root, _, owner, service, ref, launched = sample
    class Broken:
        def watch(self,*_args):
            raise OSError('private exception canary')
        def close(self):
            pass
    watching.start_window(service.store(root),ref,owner,backend_factory=lambda _:Broken())
    deadline = time.monotonic()+3
    while watching.active(service.store(root),ref,owner) and time.monotonic()<deadline:
        time.sleep(.01)
    result = service.get(root,ref)
    assert 'FILE_WATCH_INTERRUPTED' in result['observation_notes'] and result['scope']['scope_unknown']
    assert 'canary' not in json.dumps(result) and launched == []


def test_path_budget_and_outside_event_are_explicit_gaps(sample, monkeypatch):
    root, _, owner, service, ref, _ = sample
    monkeypatch.setattr('security_runtime.development_check.MAX_PATHS',2)
    watching.start_window(service.store(root),ref,owner)
    for i in range(5):
        (root/f'{i}.py').write_text('value = 1')
    result = service.finish(root,ref)
    assert len(result['scope']['paths']) <= 2 and result['scope']['scope_unknown']
    assert 'FILE_WATCH_PATHS_INCOMPLETE' in result['observation_notes']
