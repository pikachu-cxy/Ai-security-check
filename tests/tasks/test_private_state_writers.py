"""Real POSIX writer admission; isolated fixtures, no host task or scanner.

The subprocess sets its own umask so these checks do not change pytest's
process-wide creation policy or the user's actual runtime state.
"""
import copy
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import select
import time
import threading

import pytest
import security_runtime

from security_runtime.hook_state import HookStateStore, atomic_bytes
from security_runtime.closeout_state import digest, encode
from security_runtime.tasks.security_state import CONTRACT, TaskSecurityStore
from test_hook_state_paths import snapshot as hook_snapshot
from test_review_metadata_compatibility import _encoded, _legacy_fixture, _task_row
from test_task_review_plan import task


pytestmark = pytest.mark.skipif(os.name == "nt", reason="Real POSIX mode bits and umask")


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def _files(directory):
    return {str(path.relative_to(directory)): (
        _mode(path), path.stat().st_mtime_ns, path.read_bytes() if path.is_file() else None)
        for path in [directory, *directory.rglob("*")]}


def _open_legacy(tmp_path, *, capacity=True):
    state, root, record = _legacy_fixture(tmp_path, capacity=capacity)
    state.path.parent.chmod(0o755)
    state.path.chmod(0o644)
    (state.path.parent / "snapshot.key").chmod(0o644)
    return state, root, record


NEW_WRITER_CHILD = r'''
import json, os, stat, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.security_state import CONTRACT, TaskSecurityStore
os.umask(0o022)
root, base = map(Path, sys.argv[2:])
root.mkdir()
hooks = HookStateStore(base)
key = hooks.key(root)
state = TaskSecurityStore(hooks, root, now=lambda:100.0)
record = dict(task_ref='ts1-'+'a'*32,contract=CONTRACT,workspace=str(root),
    review_protocol=3,generation=0,task_key='isolated-mode-writer',phase='REVIEWING',created_at=100.0)
state.save(record,new=True)
with hooks.lock(root) as acquired:
    assert acquired
    sequence = hooks.pending_activity(root,'codex','isolated-mode',mark=True)
assert sequence
directory = hooks.workspace_directory(root)
mode = lambda path: stat.S_IMODE(path.stat().st_mode)
assert key == (directory/'snapshot.key').read_bytes()
print(json.dumps(dict(directory=mode(directory),database=mode(state.path),
    key=mode(directory/'snapshot.key'),pending=mode(directory/'pending-activity.db'),
    lock=mode(directory/'workspace.lock'),base=mode(base))),flush=True)
'''


def test_new_hook_directory_and_task_database_are_private_under_real_umask022(tmp_path):
    source = str(Path(security_runtime.__file__).resolve().parent.parent)
    child = subprocess.run([sys.executable, "-I", "-B", "-c", NEW_WRITER_CHILD, source,
        str((tmp_path / "source").resolve()), str((tmp_path / "private").resolve())],
        cwd=tmp_path, capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    modes = json.loads(child.stdout)
    assert modes == dict(directory=0o700, database=0o600, key=0o600,
                         pending=0o600, lock=0o600, base=0o700)


def test_existing_key_and_hook_task_queries_do_not_upgrade_or_allocate_state(tmp_path):
    state, root, record = _open_legacy(tmp_path)
    hooks = state.hooks
    path = hooks.path(root, "codex", "isolated-read-only")
    value = hook_snapshot(root)
    path.write_text(json.dumps(value))
    path.chmod(0o644)
    pending = state.path.parent / "pending-activity.db"
    with sqlite3.connect(pending) as db:
        db.execute("CREATE TABLE pending_activity (session TEXT PRIMARY KEY,sequence TEXT NOT NULL)")
    pending.chmod(0o644)
    before = _files(state.path.parent)
    old_key = (state.path.parent / "snapshot.key").read_bytes()
    assert hooks.key(root) == old_key
    assert hooks.load(path) == (value, False)
    assert state.get(record["task_ref"])["review_capacity"]["status"] == "CAPACITY_REQUIRED"
    assert hooks.pending_activity(root, "codex", "isolated-read-only") is None
    assert _files(state.path.parent) == before
    assert not list(state.path.parent.glob("*.review-metadata.identity"))


@pytest.mark.parametrize("entry", ["save", "_save"])
def test_explicit_task_writer_tightens_legacy_storage_without_resetting_old_capacity_or_ledger(tmp_path, entry):
    state, root, old = _open_legacy(tmp_path)
    row = _task_row(state, old["task_ref"])
    ledger = _encoded(state.get(old["task_ref"])["review_ledger"])
    key = (state.path.parent / "snapshot.key").read_bytes()
    record = task()
    record.update(task_ref="ts1-" + "b" * 32, contract=CONTRACT, workspace=str(root),
        generation=0, task_key="explicit-private-writer", phase="REVIEWING", created_at=100.0)
    written = getattr(state, entry)(record, new=True)
    assert written["generation"] == 1
    assert _mode(state.path.parent) == 0o700
    assert _mode(state.path) == _mode(state.path.parent / "snapshot.key") == 0o600
    assert _task_row(state, old["task_ref"]) == row
    preserved = state.get(old["task_ref"])
    assert preserved["review_capacity"]["status"] == "CAPACITY_REQUIRED"
    assert _encoded(preserved["review_ledger"]) == ledger
    assert (state.path.parent / "snapshot.key").read_bytes() == key
    assert not list(state.path.parent.glob("*.review-metadata.identity"))


def test_explicit_hook_writer_preserves_existing_signed_task_bytes_and_budget(tmp_path):
    state, root, record = _open_legacy(tmp_path)
    row = _task_row(state, record["task_ref"])
    ledger = _encoded(state.get(record["task_ref"])["review_ledger"])
    old_key = (state.path.parent / "snapshot.key").read_bytes()
    with state.hooks.lock(root) as acquired:
        assert acquired
        sequence = state.hooks.pending_activity(root, "codex", "isolated-write", mark=True)
        state.hooks.save(state.hooks.path(root, "codex", "isolated-write"), hook_snapshot(root))
    assert sequence and _mode(state.path.parent) == 0o700
    assert _mode(state.path) == _mode(state.path.parent / "snapshot.key") == 0o600
    assert _mode(state.path.parent / "pending-activity.db") == 0o600
    assert _task_row(state, record["task_ref"]) == row
    assert _encoded(state.get(record["task_ref"])["review_ledger"]) == ledger
    assert (state.path.parent / "snapshot.key").read_bytes() == old_key


def test_generic_atomic_bytes_never_tightens_an_existing_user_parent(tmp_path):
    directory = tmp_path / "user-export"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    unrelated = directory / "unrelated.txt"
    unrelated.write_bytes(b"user-owned-export")
    unrelated.chmod(0o644)
    before = (_mode(directory), _mode(unrelated), unrelated.read_bytes())
    atomic_bytes(directory / "report.json", b'{"complete":true}')
    assert (_mode(directory), _mode(unrelated), unrelated.read_bytes()) == before
    assert _mode(directory / "report.json") == 0o600


def test_failed_task_writer_keeps_original_signed_rows_and_lifetime_spent(tmp_path):
    state, root, old = _open_legacy(tmp_path)
    row = _task_row(state, old["task_ref"])
    ledger = _encoded(state.get(old["task_ref"])["review_ledger"])
    stale = copy.deepcopy(state.get(old["task_ref"]))
    stale["generation"] -= 1
    with pytest.raises(ValueError, match="Task changed concurrently"):
        state.save(stale)
    assert _task_row(state, old["task_ref"]) == row
    assert _encoded(state.get(old["task_ref"])["review_ledger"]) == ledger
    # A failed data transaction never restores formerly public modes.
    assert _mode(state.path.parent) == 0o700
    assert _mode(state.path) == 0o600


def test_retained_ack_writer_tightens_storage_without_rewriting_the_original_task(tmp_path):
    from security_runtime.tasks.projection import enqueue

    state, root, old = _open_legacy(tmp_path)
    row = _task_row(state, old["task_ref"])
    ledger = _encoded(state.get(old["task_ref"])["review_ledger"])
    retained = enqueue(copy.deepcopy(old))
    retained["retained_for_projection"] = True
    with sqlite3.connect(state.path) as db:
        db.execute("CREATE TABLE IF NOT EXISTS retained_task_projections "
                   "(ref TEXT PRIMARY KEY,data TEXT NOT NULL,mac TEXT NOT NULL,created REAL NOT NULL)")
        db.execute("INSERT INTO retained_task_projections VALUES(?,?,?,?)",
            (old["task_ref"], encode(retained).decode(), digest(state.key(), retained), 100.0))
    candidate = copy.deepcopy(retained)
    candidate["ledger_projection"]["state"] = "APPLIED"
    updated = state.ack_retained_projection(candidate)
    assert updated["ledger_projection"]["state"] == "APPLIED"
    assert updated["ledger_projection"]["projection_id"] == retained["ledger_projection"]["projection_id"]
    assert _mode(state.path.parent) == 0o700 and _mode(state.path) == 0o600
    assert _task_row(state, old["task_ref"]) == row
    assert _encoded(state.get(old["task_ref"])["review_ledger"]) == ledger


def test_task_writer_admits_before_gc_reads_existing_strict_metadata(tmp_path):
    from test_paged_review_transactions import _create, _head, _sample
    from security_runtime.tasks.snapshot_pages import GC_CONTRACT, GC_POLICY

    sample = _sample(tmp_path)
    _create(sample)
    head = _head(sample)
    sample.state.path.parent.chmod(0o755)
    sample.state.path.chmod(0o644)
    (sample.state.path.parent / "snapshot.key").chmod(0o644)
    record = dict(sample.template, contract=GC_CONTRACT, capture_policy=GC_POLICY,
        workspace=str(sample.root), task_ref="ts1-" + "d" * 32, task_key="managed-private-writer",
        review_protocol=3, generation=0, phase="REVIEWING", created_at=100.0)
    written = sample.state.save(record, new=True)
    assert written["generation"] == 1
    assert _mode(sample.state.path.parent) == 0o700 and _mode(sample.state.path) == 0o600
    assert _head(sample) == head
    assert _task_row(sample.state, sample.legacy["task_ref"]) == sample.old_row


@contextmanager
def _directory_flock(directory):
    code = """import fcntl,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY)
fcntl.flock(fd,fcntl.LOCK_EX)
print('LOCKED',flush=True)
sys.stdin.readline()
os.close(fd)
"""
    child = subprocess.Popen([sys.executable, "-I", "-B", "-c", code, str(directory)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([child.stdout], [], [], 5)[0], "Directory-lock child did not become ready"
        assert child.stdout.readline().strip() == "LOCKED"
        yield
    finally:
        if child.poll() is None:
            child.communicate("release\n", timeout=5)
        else:
            child.communicate(timeout=5)
    assert child.returncode == 0


def test_nonblocking_hook_lock_preserves_false_on_real_directory_flock_and_recovers(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    hooks = HookStateStore(tmp_path / "private")
    hooks.key(root)
    with _directory_flock(hooks.workspace_directory(root)):
        started = time.monotonic()
        with hooks.lock(root, wait_seconds=0) as acquired:
            assert acquired is False
        assert time.monotonic() - started < .75
    with hooks.lock(root, wait_seconds=0) as acquired:
        assert acquired is True


def test_task_storage_busy_preserves_history_and_same_writer_request_can_resume(tmp_path):
    from security_runtime.owned_workspace_storage import OwnedWorkspaceStorageError

    state, root, old = _open_legacy(tmp_path)
    row = _task_row(state, old["task_ref"])
    ledger = _encoded(state.get(old["task_ref"])["review_ledger"])
    record = task()
    record.update(task_ref="ts1-" + "b" * 32, contract=CONTRACT, workspace=str(root),
        generation=0, task_key="retry-private-writer", phase="REVIEWING", created_at=100.0)
    with _directory_flock(state.path.parent):
        with pytest.raises(OwnedWorkspaceStorageError) as busy:
            state.save(record, new=True)
        assert busy.value.reason_code == "OWNED_WORKSPACE_STORAGE_BUSY"
        assert _task_row(state, old["task_ref"]) == row
        assert _encoded(state.get(old["task_ref"])["review_ledger"]) == ledger
        assert state.get(record["task_ref"]) is None
        assert _mode(state.path.parent) == 0o755 and _mode(state.path) == 0o644
    written = state.save(record, new=True)
    assert written["generation"] == 1 and written["task_ref"] == record["task_ref"]
    assert _task_row(state, old["task_ref"]) == row
    assert _encoded(state.get(old["task_ref"])["review_ledger"]) == ledger
    assert _mode(state.path.parent) == 0o700 and _mode(state.path) == 0o600


def test_new_database_replaced_by_fifo_after_admission_is_rejected_without_blocking(tmp_path):
    source = str(Path(security_runtime.__file__).resolve().parent.parent)
    code = r'''
import json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from security_runtime.hook_state import HookStateStore
root=Path(sys.argv[2]);root.mkdir()
hooks=HookStateStore(Path(sys.argv[3]))
prepare=hooks.prepare_private_writer
def race(root):
    directory=prepare(root)
    os.mkfifo(directory/'task-security.db',0o600)
    return directory
hooks.prepare_private_writer=race
try:
    hooks.prepare_database(root,'task-security.db')
except ValueError as error:
    assert str(error)=='Private workspace database cannot be verified',str(error)
    print(json.dumps(dict(rejected=True)),flush=True)
else:
    raise AssertionError('FIFO became an accepted SQLite target')
'''
    child = subprocess.run([sys.executable, "-I", "-B", "-c", code, source,
        str(tmp_path / "source"), str(tmp_path / "private")],
        cwd=tmp_path, capture_output=True, text=True, timeout=5)
    assert child.returncode == 0, child.stderr
    assert json.loads(child.stdout) == dict(rejected=True)


def test_concurrent_first_key_publication_does_not_reject_its_temporary_hardlink(tmp_path, monkeypatch):
    import errno
    import fcntl
    from security_runtime.owned_workspace_storage import OwnedHookNamespaceStorage

    root = tmp_path / "source"
    root.mkdir()
    hooks = HookStateStore(tmp_path / "private")
    admitted, link, flock = OwnedHookNamespaceStorage.admitted, os.link, fcntl.flock
    missing, linked, blocked, release = (threading.Event() for _ in range(4))

    @contextmanager
    def ordered_admitted(authority, **kwargs):
        if threading.current_thread().name == "second-key":
            # Both callers genuinely observed the key as absent. Let the
            # first writer publish its atomic link before this admission.
            missing.set()
            assert linked.wait(5)
        with admitted(authority, **kwargs) as report:
            yield report

    def ordered_link(source, target, **kwargs):
        if Path(target).name == "snapshot.key":
            assert missing.wait(5)
            result = link(source, target, **kwargs)
            linked.set()
            assert release.wait(5)
            return result
        return link(source, target, **kwargs)

    def tracked_flock(fd, flags):
        try:
            return flock(fd, flags)
        except OSError as error:
            if (threading.current_thread().name == "second-key"
                    and error.errno in {errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK}):
                blocked.set()  # Real OS refusal while the first link exists.
            raise

    def key(name):
        threading.current_thread().name = name
        return hooks.key(root)

    monkeypatch.setattr(OwnedHookNamespaceStorage, "admitted", ordered_admitted)
    monkeypatch.setattr(os, "link", ordered_link)
    monkeypatch.setattr(fcntl, "flock", tracked_flock)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(key, "first-key")
        second = pool.submit(key, "second-key")
        try:
            assert linked.wait(5)
            assert blocked.wait(5)
            assert not second.done()
        finally:
            release.set()
        keys = [first.result(timeout=10), second.result(timeout=10)]
    assert keys[0] == keys[1] and len(keys[0]) == 32
    assert not list(hooks.workspace_directory(root).glob(".key-*"))
