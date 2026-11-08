"""Independent local processes share a watcher, never scan real projects."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from test_development_file_watch import sample
from security_runtime import development_file_watch as watching
from security_runtime import watch_control


CHILD = '''
import json, pathlib, sys, time
from security_runtime.development_check import DevelopmentCheckService
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.ownership import session_owner
from security_runtime import development_file_watch as w
base=pathlib.Path(sys.argv[1]); ref=sys.argv[2]; mode=sys.argv[3]
root=base/'project'; owner=session_owner('codex','watch-fixture'); launched=[]
s=DevelopmentCheckService(None,HookStateStore(base/'hooks'),owner=owner,
    scan_path_provider=base/'scans.db',launcher=lambda *_:launched.append('scan'))
store=s.store(root); w.SETTLE_SECONDS=.15
if mode=='race':
    print('READY',flush=True); sys.stdin.readline()
started=w.start_window(store,ref,owner,invocation='child-write')
state=store.load(ref,owner)
if mode in {'owner','race'}:
    print(json.dumps({'started':started,'id':state['file_watch']['id']}),flush=True)
    sys.stdin.readline()
else:
    (root/'child.py').write_text('value = 1\\n')
    completed=w.active(store,ref,owner,completed='child-write')
    result=s.finish(root,ref)
    state=store.load(ref,owner)
    print(json.dumps({'started':started,'completed':completed,
        'id':state['file_watch']['id'],'watch_status':state['file_watch']['status'],
        'gaps':state.get('file_watch_gaps',[]),'paths':state['observed_paths'],
        'launches':len(launched)}),flush=True)
'''


def pipe_line(proc):
    # Bound pipe waits on platforms without selectors for subprocess pipes.
    import queue
    import threading
    values = queue.Queue()
    threading.Thread(target=lambda: values.put(proc.stdout.readline()), daemon=True).start()
    return values.get(timeout=10)


def spawn(sample, mode):
    root, _, _, _, ref, _ = sample
    return subprocess.Popen([sys.executable, '-c', CHILD, str(root.parent), ref, mode],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)


def require_control():
    # Tests require loopback permission, rather than silently skipping the path.
    assert watch_control.endpoint()['port'] > 0


def test_live_owner_is_reused_and_foreign_stop_drains_actual_events(sample, monkeypatch):
    require_control()
    root, _, owner, service, ref, launched = sample
    monkeypatch.setattr(watching, 'SETTLE_SECONDS', .15)
    store = service.store(root)
    assert watching.start_window(store, ref, owner) == 'ACTIVE'
    identity = store.load(ref, owner)['file_watch']['id']
    proc = spawn(sample, 'client')
    try:
        stdout, stderr = proc.communicate(timeout=12)
        assert proc.returncode == 0, stderr
        result = json.loads(stdout)
        assert result['started'] == 'ACTIVE' and result['completed']
        assert result['id'] == identity and result['watch_status'] == 'STOPPED'
        assert result['gaps'] == [] and result['paths'] == ['child.py']
        assert result['launches'] == 1 and launched == []
    finally:
        if proc.poll() is None:
            proc.kill(); proc.wait(timeout=5)


def test_dead_owner_recovers_same_check_and_preserves_real_interruption(sample):
    require_control()
    root, _, owner, service, ref, launched = sample
    proc = spawn(sample, 'owner')
    try:
        original = json.loads(pipe_line(proc))
        assert original['started'] == 'ACTIVE'
        proc.kill(); proc.wait(timeout=5)
        store = service.store(root)
        assert watching.start_window(store, ref, owner) == 'ACTIVE'
        state = store.load(ref, owner)
        assert state['file_watch']['id'] != original['id']
        assert state['file_watch_gaps'] == ['FILE_WATCH_INTERRUPTED']
        assert state['check_ref'] == ref and launched == []
    finally:
        if proc.poll() is None:
            proc.kill(); proc.wait(timeout=5)


def test_simultaneous_processes_elect_one_owner(sample):
    require_control()
    root, _, owner, service, ref, _ = sample
    first, second = spawn(sample, 'race'), spawn(sample, 'race')
    try:
        assert pipe_line(first).strip() == pipe_line(second).strip() == 'READY'
        for proc in (first, second):
            proc.stdin.write('start\n'); proc.stdin.flush()
        rows = [json.loads(pipe_line(proc)) for proc in (first, second)]
        assert all(row['started'] == 'ACTIVE' for row in rows)
        assert rows[0]['id'] == rows[1]['id']
        assert not service.store(root).load(ref, owner).get('file_watch_gaps')
        watching.stop_window(service.store(root), ref, owner)
        assert service.store(root).load(ref, owner)['file_watch']['status'] == 'STOPPED'
    finally:
        for proc in (first, second):
            if proc.poll() is None:
                proc.stdin.write('exit\n'); proc.stdin.flush()
            proc.communicate(timeout=8)


def test_wrong_capability_and_stale_identity_cannot_control_watch(sample):
    require_control()
    root, _, owner, service, ref, _ = sample
    store = service.store(root)
    watching.start_window(store, ref, owner)
    watch = store.load(ref, owner)['file_watch']
    bad = dict(watch, control=dict(watch['control'], token='0'*64))
    assert watch_control.request(bad, 'stop', budget=.2) is None
    assert watch_control.request(dict(watch, id='stale'), 'stop', budget=.2) is None
    assert watch_control.request(watch, 'arbitrary-operation', budget=.2) is None
    assert store.load(ref, owner)['file_watch']['status'] == 'ACTIVE'
    projection = service.get(root, ref)
    assert watch['control']['token'] not in json.dumps(projection)
    assert 'control' not in projection['file_watch']


def test_local_fast_path_uses_no_rpc_and_binding_failure_keeps_local_watch(sample, monkeypatch):
    root, _, owner, service, ref, _ = sample
    monkeypatch.setattr(watching, 'SETTLE_SECONDS', .15)
    monkeypatch.setattr(watch_control, 'endpoint', lambda: (_ for _ in ()).throw(PermissionError()))
    monkeypatch.setattr(watch_control, 'request', lambda *a, **k: pytest.fail('local path made RPC'))
    store = service.store(root)
    assert watching.start_window(store, ref, owner) == 'ACTIVE'
    assert watching.start_window(store, ref, owner, invocation='one') == 'ACTIVE'
    assert watching.active(store, ref, owner, completed='one')
    watching.stop_window(store, ref, owner)
    assert store.load(ref, owner)['file_watch']['status'] == 'STOPPED'
    assert not store.load(ref, owner).get('file_watch_gaps')


def test_fresh_unreachable_owner_is_not_declared_dead_or_replaced(sample):
    root, _, owner, service, ref, _ = sample
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        row['file_watch'] = dict(id='foreign', status='ACTIVE', lease_until=store.now()+20,
                                 control=dict(pid=os.getpid()))
        store._put(db, ref, row)
    assert watching.start_window(store, ref, owner) == 'FAILED'
    row = store.load(ref, owner)
    assert row['file_watch']['id'] == 'foreign'
    assert row['file_watch_gaps'] == ['FILE_WATCH_OWNER_UNAVAILABLE']


def test_foreign_stop_respects_original_budget(sample, monkeypatch):
    root, _, owner, service, ref, _ = sample
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        row['file_watch'] = dict(id='slow', status='ACTIVE', lease_until=store.now()+20)
        store._put(db, ref, row)
    seen = []
    monkeypatch.setattr(watch_control, 'request', lambda *a, **k: seen.append(k['budget']))
    start = time.monotonic()
    watching.stop_window(store, ref, owner, deadline=start+.02)
    assert 0 <= seen[0] <= .02 and time.monotonic()-start < .2
    assert store.load(ref, owner)['file_watch_gaps'] == ['FILE_WATCH_SETTLEMENT_TIMEOUT']


def test_remote_reuse_does_not_hold_local_window_lock(sample, monkeypatch):
    root, _, owner, service, ref, _ = sample
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        row['file_watch'] = dict(id='foreign', status='ACTIVE', lease_until=store.now()+20)
        store._put(db, ref, row)
    def remote(*args, **kwargs):
        assert not watching._lock._is_owned()
        return True
    monkeypatch.setattr(watch_control, 'request', remote)
    assert watching.start_window(store, ref, owner) == 'ACTIVE'


def test_responsive_owner_with_delayed_heartbeat_can_still_drain(sample, monkeypatch):
    root, _, owner, service, ref, _ = sample
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        row['file_watch'] = dict(id='delayed', status='ACTIVE', lease_until=0)
        store._put(db, ref, row)
    def drain(*args, **kwargs):
        with store.transaction() as db:
            row = store._get(db, ref)
            row['file_watch']['status'] = 'STOPPED'
            store._put(db, ref, row)
        return True
    monkeypatch.setattr(watch_control, 'request', drain)
    watching.stop_window(store, ref, owner)
    row = store.load(ref, owner)
    assert row['file_watch']['status'] == 'STOPPED' and not row.get('file_watch_gaps')


def test_incomplete_report_keeps_observation_diagnostics_separate(sample, monkeypatch):
    from security_runtime.development_risks import DevelopmentRisks
    from security_runtime.development_views import closeout_page
    root, _, owner, service, ref, _ = sample
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        row.update(state='RUNNING', dirty_seq=1, file_watch_gaps=['FILE_WATCH_INTERRUPTED'],
                   stop_closeout_notice=dict(seq=1, scan_id=None, mode='INCOMPLETE'))
        store._put(db, ref, row)
    monkeypatch.setattr('security_runtime.dashboard_service.session_url', lambda *a: 'http://localhost/risks')
    page = closeout_page(DevelopmentRisks(service, root, ref), 0, None)
    assert page['gaps'] == ['STATIC_SCAN_INCOMPLETE']
    assert page['observation_notes'] == ['FILE_WATCH_INTERRUPTED']
