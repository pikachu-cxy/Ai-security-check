"""Real thread/process exclusion for page readers, publishers and collection."""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import select
import signal
import subprocess
import sys

import pytest

from security_runtime.snapshot_store import SnapshotStoreError
from security_runtime.tasks import snapshot_page_guard as guards


@pytest.fixture
def directory(tmp_path):
    path = tmp_path.resolve() / 'task-state'
    with guards.page_guard(path, create=True):
        assert guards.guard_held(path)
    return path


def enter_once(directory, *, exclusive=False):
    with guards.page_guard(directory, exclusive=exclusive, wait_seconds=0):
        return guards.guard_held(directory)


def test_shared_readers_and_exclusive_collector_use_distinct_thread_locks(directory):
    with ThreadPoolExecutor(max_workers=1) as worker:
        with guards.page_guard(directory):
            reader = worker.submit(enter_once, directory)
            if os.name == 'nt':
                with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_PAGE_STORE_BUSY$'):
                    reader.result(timeout=3)
            else:
                assert reader.result(timeout=3)
            collector = worker.submit(enter_once, directory, exclusive=True)
            with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_PAGE_STORE_BUSY$'):
                collector.result(timeout=3)
        assert worker.submit(enter_once, directory, exclusive=True).result(timeout=3)
    assert not guards.guard_held(directory)


def test_different_instances_reenter_without_releasing_or_downgrading_outer_lock(directory):
    class Records:
        def __init__(self):
            self.path = directory / 'records.db'

        @guards.guarded_read
        def read(self, callback):
            return callback()

        @guards.guarded_queue_publication
        def publish(self, callback):
            return callback()

    first, second = Records(), Records()
    with ThreadPoolExecutor(max_workers=1) as worker:
        with guards.page_guard(directory, exclusive=True):
            assert first.read(lambda: second.publish(lambda: guards.guard_held(directory)))
            with guards.page_guard(directory, exclusive=True):
                assert guards.guard_held(directory)
            # A nested shared operation must not downgrade the outer EX lock.
            with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_PAGE_STORE_BUSY$'):
                worker.submit(enter_once, directory).result(timeout=3)
        assert worker.submit(enter_once, directory, exclusive=True).result(timeout=3)


def test_shared_to_exclusive_upgrade_is_rejected_without_releasing_shared_lock(directory):
    with ThreadPoolExecutor(max_workers=1) as worker:
        with guards.page_guard(directory):
            with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_GC_LOCK_UPGRADE_REJECTED$'):
                with guards.page_guard(directory, exclusive=True):
                    pytest.fail('A shared guard cannot upgrade in place')
            assert guards.guard_held(directory)
            with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_PAGE_STORE_BUSY$'):
                worker.submit(enter_once, directory, exclusive=True).result(timeout=3)
        assert worker.submit(enter_once, directory, exclusive=True).result(timeout=3)


@pytest.mark.parametrize('create', [False, True])
def test_missing_initialized_lock_cannot_be_treated_as_legacy_or_recreated(directory, create):
    path = directory / 'snapshot-pages.gc.lock'
    path.unlink()
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_GC_GUARD_UNAVAILABLE$'):
        with guards.page_guard(directory, create=create):
            pytest.fail('An initialized lock must retain its inode')
    assert not path.exists()


@pytest.mark.parametrize('create', [False, True])
def test_replacement_lock_cannot_create_a_second_lock_domain(directory, create):
    path = directory / 'snapshot-pages.gc.lock'
    path.rename(directory / 'original-lock')
    path.write_bytes(b'0')
    path.chmod(0o600)
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_GC_GUARD_UNAVAILABLE$'):
        with guards.page_guard(directory, create=create):
            pytest.fail('A replacement inode cannot reuse the old identity')


@pytest.mark.parametrize('linked', ['directory', 'lock', 'identity'])
def test_guard_rejects_linked_directories_and_metadata(directory, linked):
    if linked == 'directory':
        alias = directory.with_name('linked-task-state')
        try:
            alias.symlink_to(directory, target_is_directory=True)
        except OSError:
            pytest.skip('Directory symlinks are unavailable')
        directory = alias
    else:
        name = 'snapshot-pages.gc.lock' if linked == 'lock' else 'snapshot-pages.gc.identity'
        path = directory / name
        saved = path.with_name(path.name + '.saved')
        path.rename(saved)
        try:
            path.symlink_to(saved)
        except OSError:
            pytest.skip('File symlinks are unavailable')
    with pytest.raises(ValueError):
        with guards.page_guard(directory):
            pytest.fail('Linked guard state must fail closed')


def child_command(script, directory):
    source = Path(guards.__file__).resolve().parents[2]
    return [sys.executable, '-I', '-c', script, str(directory), str(source)]


@pytest.mark.skipif(not hasattr(os, 'fork'), reason='Requires POSIX fork')
def test_inherited_context_exit_does_not_close_reused_child_descriptor(directory):
    script = r'''
import os, pathlib, sys, traceback
sys.path.insert(0, sys.argv[2])
from security_runtime.tasks import snapshot_page_guard as guards
directory = pathlib.Path(sys.argv[1])
context = guards.page_guard(directory, exclusive=True)
context.__enter__()
original_fd = next(iter(guards._descriptors))
pid = os.fork()
if pid == 0:
    try:
        assert not guards.guard_held(directory)
        fresh = os.open(directory/'child-resource', os.O_CREAT | os.O_WRONLY, 0o600)
        if fresh != original_fd:
            os.dup2(fresh, original_fd)
            os.close(fresh)
        context.__exit__(None, None, None)
        os.write(original_fd, b'still-open')
        os.close(original_fd)
        os._exit(0)
    except BaseException:
        traceback.print_exc()
        os._exit(1)
_, status = os.waitpid(pid, 0)
context.__exit__(None, None, None)
assert os.waitstatus_to_exitcode(status) == 0
assert (directory/'child-resource').read_bytes() == b'still-open'
'''
    result = subprocess.run(child_command(script, directory), capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert enter_once(directory, exclusive=True)


@pytest.mark.skipif(os.name == 'nt', reason='Requires POSIX SIGKILL and pipe select')
def test_killing_holder_releases_os_lock_without_deleting_lock_files(directory):
    script = r'''
import pathlib, sys, time
sys.path.insert(0, sys.argv[2])
from security_runtime.tasks.snapshot_page_guard import page_guard
with page_guard(pathlib.Path(sys.argv[1]), exclusive=True):
    print('locked', flush=True)
    time.sleep(60)
'''
    paths = [directory / name for name in ('snapshot-pages.gc.lock', 'snapshot-pages.gc.identity')]
    before = {path: (path.stat().st_ino, path.read_bytes()) for path in paths}
    holder = subprocess.Popen(child_command(script, directory), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        ready, _, _ = select.select([holder.stdout], [], [], 10)
        assert ready and holder.stdout.readline() == b'locked\n'
        with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_PAGE_STORE_BUSY$'):
            enter_once(directory, exclusive=True)
        holder.kill()
        holder.communicate(timeout=5)
        assert holder.returncode == -signal.SIGKILL
        assert enter_once(directory, exclusive=True)
        assert before == {path: (path.stat().st_ino, path.read_bytes()) for path in paths}
    finally:
        if holder.poll() is None:
            holder.kill()
        holder.communicate(timeout=5)
