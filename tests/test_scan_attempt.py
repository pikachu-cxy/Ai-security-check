"""Actual OS workspace locks, signed fencing and immutable input lifetimes."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.models import ScanMode
from security_runtime.progress import ScanCancelled
from security_runtime.scan_attempt import (ScanAttemptStore, ScanAttemptExecution,
    ScanAttemptLost, source_binding)
from security_runtime.scan_input import capture_scan_input, scoped_request


@pytest.fixture
def sample(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    (root/'source.py').write_text('old = 1\n')
    hooks = HookStateStore(tmp_path/'state')
    clock = [100.0]
    return root, hooks, ScanAttemptStore(hooks, root, now=lambda:clock[0]), clock


def claim(sample, scope='task'):
    root, hooks, store, _ = sample
    with hooks.lock(root) as acquired:
        assert acquired
        return store.claim('TASK', scope, source_binding({'source.py':'revision'}))


def test_read_only_never_creates_state_and_mutators_require_real_lock(sample):
    root, hooks, store, _ = sample
    assert store.read()['lane'] is None and not hooks.directory.exists()
    with pytest.raises(ValueError, match='workspace lock'):
        store.claim('TASK', 'task', source_binding({}))
    assert not hooks.directory.exists()


def test_expired_generation_cannot_bind_renew_cancel_or_publish_new_worker(sample):
    root, hooks, store, clock = sample
    old = claim(sample)
    with hooks.lock(root):
        assert store.claim('HOOK', 'hook', source_binding({})) is None
    clock[0] += 601
    new = claim(sample, 'replacement')
    assert new.generation == old.generation+1 and new.attempt_id != old.attempt_id
    with hooks.lock(root):
        assert not store.finish(old, outcome='COMPLETED')
        assert not store.renew(old) and not store.cancel(old)
    assert store.is_current(new) and not store.is_current(old)
    assert 'lease_owner' not in old.receipt


def test_same_workspace_lane_is_cross_process_not_just_a_thread_mutex(sample):
    root, hooks, store, _ = sample
    lease = claim(sample)
    code = ('import json,sys;from pathlib import Path;'
        'from security_runtime.hook_state import HookStateStore;'
        'from security_runtime.scan_attempt import ScanAttemptStore,source_binding;'
        'r=Path(sys.argv[1]);h=HookStateStore(Path(sys.argv[2]));'
        's=ScanAttemptStore(h,r,now=lambda:100);'
        '\nwith h.lock(r) as ok:\n print(json.dumps({"locked":ok,"busy":s.claim("HOOK","other",source_binding({})) is None}))')
    out = subprocess.run([sys.executable,'-c',code,str(root),str(hooks.directory)],
        capture_output=True,text=True,check=True,timeout=15)
    assert json.loads(out.stdout) == dict(locked=True,busy=True)
    assert store.is_current(lease)


def test_input_id_is_bound_before_providers_and_cannot_be_replaced(sample):
    root, hooks, store, _ = sample
    lease = claim(sample)
    execution = ScanAttemptExecution(store,lease,validator=lambda view:
        (view.execution_root/'source.py').read_text() == 'old = 1\n')
    with capture_scan_input(scoped_request(root,['source.py']),private_parent=execution.private_parent,
            on_created=execution.input_created,on_removed=execution.input_removed) as view:
        assert len(store.read()['directories']) == 1
        assert store.read()['lane']['input_id'] is None
        execution.input_ready(view)
        assert store.read()['lane']['input_id'] == view.input_id
        with hooks.lock(root):
            assert not store.bind_input(lease,replace(view,input_id='si1-different'))
        path = view.execution_root.parent
    assert not path.exists() and store.read()['directories'] == []


def test_a_b_a_mutation_cannot_bind_a_scan_of_b_to_original_a(sample):
    root, hooks, store, _ = sample
    expected = hashlib.sha256((root/'source.py').read_bytes()).hexdigest()
    lease = claim(sample)
    execution = ScanAttemptExecution(store,lease,validator=lambda view:
        hashlib.sha256((view.execution_root/'source.py').read_bytes()).hexdigest() == expected)
    (root/'source.py').write_text('other = 2\n')
    with capture_scan_input(scoped_request(root,['source.py']),private_parent=execution.private_parent,
            on_created=execution.input_created,on_removed=execution.input_removed) as view:
        (root/'source.py').write_text('old = 1\n')
        with pytest.raises(ScanAttemptLost,match='SOURCE_MISMATCH'):
            execution.input_ready(view)
        assert store.read()['lane']['input_id'] is None
    assert not store.read()['directories']


def test_cancel_generation_stops_worker_without_touching_other_authority(sample):
    root, hooks, store, _ = sample
    lease = claim(sample)
    execution = ScanAttemptExecution(store,lease)
    before = set(store.path.parent.iterdir())
    with hooks.lock(root):
        assert store.cancel(lease)
    with pytest.raises(ScanCancelled):
        execution.checkpoint()
    row = store.read()['lane']
    assert row['cancel_generation'] == lease.cancel_generation+1
    assert row['state'] == 'CANCELLED'
    assert set(store.path.parent.iterdir()) == before


def test_source_bytes_are_registered_before_copy_and_orphans_only_after_expiry(sample):
    root, hooks, store, clock = sample
    lease = claim(sample)
    # Model process death after durable directory registration: no context exit.
    path = store.private_parent/('runtime-input-'+'a'*32)
    path.mkdir()
    with hooks.lock(root):
        assert store.register_directory(lease,path)
    (path/'raw.py').write_text('private_source')
    assert store.recover_cleanup() == dict(cleaned=0,pending=1)
    assert path.is_dir()
    clock[0] += 601
    assert store.recover_cleanup() == dict(cleaned=1,pending=0)
    assert not path.exists()


def test_recovery_deletion_and_normal_cleanup_never_hold_workspace_lock(sample,monkeypatch):
    import security_runtime.scan_attempt as module
    root,hooks,store,clock=sample
    lease=claim(sample)
    path=store.private_parent/('runtime-input-'+'c'*32)
    path.mkdir()
    with hooks.lock(root): store.register_directory(lease,path)
    (path/'raw.py').write_text('private')
    original=module.shutil.rmtree
    def unlocked(*args,**kwargs):
        assert not hooks.lock_held(root)
        return original(*args,**kwargs)
    monkeypatch.setattr(module.shutil,'rmtree',unlocked)
    clock[0]+=601
    assert store.recover_cleanup()==dict(cleaned=1,pending=0)


def test_failure_to_delete_keeps_signed_obligation_and_read_does_not_replay(sample,monkeypatch):
    import security_runtime.scan_attempt as module
    root,hooks,store,clock=sample
    lease=claim(sample)
    path=store.private_parent/('runtime-input-'+'d'*32)
    path.mkdir()
    with hooks.lock(root): store.register_directory(lease,path)
    (path/'raw.py').write_text('private')
    original=module.shutil.rmtree
    def denied(*args,**kwargs): raise PermissionError('simulated open handle')
    monkeypatch.setattr(module.shutil,'rmtree',denied)
    clock[0]+=601
    assert store.recover_cleanup()==dict(cleaned=0,pending=1)
    before=store.path.read_bytes()
    store.read()
    assert store.path.read_bytes()==before and path.exists()
    monkeypatch.setattr(module.shutil,'rmtree',original)
    assert store.recover_cleanup()==dict(cleaned=1,pending=0)


def test_process_death_recovers_source_rules_and_derived_subtrees_as_one_obligation(sample,tmp_path):
    root,hooks,store,clock=sample
    claim(sample)
    rules=tmp_path/'rules'
    rules.mkdir()
    (rules/'test.yml').write_text('rules: []\n')
    code = ('import os,sys;from pathlib import Path;'
        'from security_runtime.hook_state import HookStateStore;'
        'from security_runtime.scan_attempt import ScanAttemptStore,ScanAttemptExecution,AttemptLease;'
        'from security_runtime.scan_input import capture_scan_input,scoped_request;'
        'r=Path(sys.argv[1]);h=HookStateStore(Path(sys.argv[2]));s=ScanAttemptStore(h,r,now=lambda:100);'
        'row=s.read()["lane"];l=AttemptLease(**{k:row[k] for k in '
        '("attempt_id","generation","lease_owner","cancel_generation")});e=ScanAttemptExecution(s,l);'
        'c=capture_scan_input(scoped_request(r,["source.py"]),private_parent=e.private_parent,'
        'on_created=e.input_created,on_removed=e.input_removed);v=c.__enter__();'
        'rc=v.with_rules(Path(sys.argv[3]));rv=rc.__enter__();'
        'dc=rv.derive(["source.py"]);dc.__enter__();'
        'ac=rv.artifacts();a=ac.__enter__();(a/"selected.yml").write_text("private_selected_rules");'
        '(a/"findings.json").write_text("private_report");rv.assert_intact();os._exit(0)')
    subprocess.run([sys.executable,'-c',code,str(root),str(hooks.directory),str(rules)],
        check=True,capture_output=True,timeout=20)
    state=store.read()
    assert len(state['directories'])==1
    base=store.private_parent/state['directories'][0]['name']
    assert len(list(base.rglob('source.py')))==2
    assert len(list(base.rglob('test.yml')))==1
    assert len(list(base.rglob('selected.yml')))==1
    assert len(list(base.rglob('findings.json')))==1
    clock[0]+=601
    assert store.recover_cleanup()==dict(cleaned=1,pending=0)
    assert not base.exists()


def test_orphan_path_replacement_or_external_path_is_preserved(sample,tmp_path):
    root, hooks, store, clock = sample
    lease = claim(sample)
    outside = tmp_path/'unrelated'
    outside.mkdir()
    with hooks.lock(root):
        with pytest.raises(ValueError,match='managed namespace'):
            store.register_directory(lease,outside)
    path = store.private_parent/('runtime-input-'+'b'*32)
    path.mkdir()
    with hooks.lock(root): store.register_directory(lease,path)
    original = store.private_parent/'kept-original'
    path.rename(original)
    path.mkdir()
    (path/'canary').write_text('preserve')
    clock[0] += 601
    assert store.recover_cleanup() == dict(cleaned=0,pending=1)
    assert (path/'canary').read_text() == 'preserve' and outside.exists()


def test_tampered_signature_cannot_claim_or_publish(sample):
    root, hooks, store, _ = sample
    lease = claim(sample)
    envelope = json.loads(store.path.read_bytes())
    envelope['content']['lane']['state'] = 'COMPLETED'
    store.path.write_text(json.dumps(envelope))
    with pytest.raises(ValueError,match='signature'):
        store.is_current(lease)
    with hooks.lock(root):
        with pytest.raises(ValueError,match='signature'):
            store.claim('HOOK','new',source_binding({}))


def test_runtime_after_scan_uses_same_live_private_view_before_cleanup(sample,tmp_path):
    from security_runtime.runtime import SecurityRuntime
    from security_runtime.storage import SQLiteStore
    from security_runtime.scanners import ScannerRegistry
    from security_runtime.dynamic_function import NativeFunctionScanner
    root, hooks, store, _ = sample
    lease = claim(sample)
    seen = []
    def after(view,result):
        assert not hooks.lock_held(root)
        seen.append((view.input_id,view.execution_root,result.scan_id))
        view.assert_intact()
        assert (view.execution_root/'source.py').read_text() == 'old = 1\n'
    execution = ScanAttemptExecution(store,lease,after_scan=after)
    runtime = SecurityRuntime(ScannerRegistry([NativeFunctionScanner()],fallback_adapters=[]),
        SQLiteStore(tmp_path/'results.db'))
    result = runtime.scan(root,request=scoped_request(root,['source.py']),execution=execution)
    assert len(seen) == 1 and seen[0][0] == execution.input_id
    assert not seen[0][1].exists() and not store.read()['directories']
    stored = runtime.store.get_scan(result.scan_id)
    assert stored['scan_context']['execution_attempt']['publication'] == 'PENDING'
    assert stored['scan_context']['execution_attempt']['input_id'] == execution.input_id
    assert 'lease_owner' not in json.dumps(stored)
