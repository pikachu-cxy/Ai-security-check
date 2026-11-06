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


def test_finish_drains_delayed_notifications_after_first_empty_poll(sample, monkeypatch):
    root, _, owner, service, ref, launched = sample
    store = service.store(root)
    monkeypatch.setattr(watching, 'SETTLE_SECONDS', .15)

    class Delayed:
        calls = 0

        def watch(self, *_args):
            self.calls += 1
            if self.calls == 1:
                # Deterministic race: closeout starts before the OS delivers
                # its last batch. An empty poll is not a flush acknowledgement.
                window = watching._windows[watching._key(store, ref)]
                assert window.closing.wait(2)
                return 'timeout'
            time.sleep(.01)
            if self.calls == 2:
                return {(1, str(root/'late.py'))}
            return 'timeout'

        def close(self):
            pass

    backend = Delayed()
    assert watching.start_window(store, ref, owner, backend_factory=lambda _: backend) == 'ACTIVE'
    result = service.finish(root, ref)
    assert result['scope']['paths'] == ['late.py']
    assert result['file_watch']['status'] == 'STOPPED'
    assert not result['scope']['scope_unknown'] and launched == ['scan']


def test_continuous_notifications_do_not_extend_finish_budget(sample, monkeypatch):
    root, _, owner, service, ref, _ = sample
    monkeypatch.setattr(watching, 'SETTLE_SECONDS', .15)

    class Busy:
        def watch(self, *_args):
            time.sleep(.01)
            return {(2, str(root/'busy.py'))}

        def close(self):
            pass

    watching.start_window(service.store(root), ref, owner, backend_factory=lambda _: Busy())
    started = time.monotonic()
    result = service.finish(root, ref)
    assert time.monotonic()-started < 2
    assert result['scope']['paths'] == ['busy.py']
    assert 'FILE_WATCH_SETTLEMENT_TIMEOUT' in result['observation_notes']
    assert result['scope']['scope_unknown']


def test_post_tool_quiet_time_counts_before_stop(sample, monkeypatch):
    root, hooks, owner, service, ref, _ = sample
    store = service.store(root)
    monkeypatch.setattr(watching, 'SETTLE_SECONDS', .6)
    watching.start_window(store, ref, owner, invocation='shell')
    (root/'created.py').write_text('value = 1')
    record_hook(hooks, root, owner, event_id='shell', watch_eligible=True)
    time.sleep(.8)  # Independent work after PostToolUse.
    # Insufficient to start a new quiet period, sufficient to deliver an already quiet window.
    watching.stop_window(store, ref, owner, deadline=time.monotonic() + .4)
    result = service.get(root, ref)
    assert result['file_watch']['status'] == 'STOPPED'
    assert result['scope']['paths'] == ['created.py'] and not result['scope']['scope_unknown']


def test_real_script_changes_are_drained_before_finish_without_history_inventory(sample, monkeypatch):
    root, _, owner, service, ref, launched = sample
    for name in ('untouched.py', 'again.py', 'remove.py', 'old.py', 'atomic.py'):
        (root/name).write_text('morning = 1')
    (root/'nested').mkdir()
    original_rglob = Path.rglob
    def forbid_project_inventory(path, *args, **kwargs):
        if path.is_relative_to(root):
            pytest.fail('project inventory')
        return original_rglob(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'rglob', forbid_project_inventory)
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


def test_watcher_retains_paths_above_old_cap(sample):
    from types import SimpleNamespace
    root, _, _, _, _, _ = sample
    window = object.__new__(watching._Window)
    window.store = SimpleNamespace(root=root)
    window.private, window.ignored = root/'private', set()
    paths = [f'{i:05d}_' + 'a'*80 + '.py' for i in range(1501)]
    names, unknown = window.paths([(2, str(root/name)) for name in paths])
    assert names == paths and not unknown


def test_watch_diagnostic_does_not_manufacture_a_new_edit_or_reopen_saved_batch(sample):
    root, _, owner, service, ref, launched = sample
    store = service.store(root)
    service.record(root, ref, ['app.py'])
    service.finish(root, ref)
    before = store.load(ref)
    watching._gap(store, ref, 'FILE_WATCH_INTERRUPTED', status='INTERRUPTED')
    after = store.load(ref)
    assert after['dirty_seq'] == before['dirty_seq']
    assert after['finish_requested'] == before['finish_requested']
    assert after['state'] == before['state']
    assert after['observed_paths'] == before['observed_paths']
    assert after['scope_unknown']
    assert 'FILE_WATCH_INTERRUPTED' in service.get(root, ref)['observation_notes']
    assert launched == ['scan']
