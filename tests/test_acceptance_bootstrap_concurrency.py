"""Slow initial scanners never hold the task lock or publish stale baselines."""
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from security_runtime.baseline_seed import WorkspaceBaselineSeeds
from security_runtime.bootstrap_diagnostics import BaselinePreparationError
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.task_ownership import session_owner
from security_runtime.task_security import TaskSecurityService
from test_global_integration import complete_runtime, installed, projects


def blocked_seeds(installed, tmp_path):
    core = HookCoordinator(complete_runtime(), HookStateStore(tmp_path / 'concurrency-hooks'))
    started, release = threading.Event(), threading.Event()
    scan = core._scan_scope
    def blocked(*args, **kwargs):
        started.set()
        assert release.wait(20)
        return scan(*args, **kwargs)
    core._scan_scope = blocked
    return WorkspaceBaselineSeeds(integration=installed, coordinator=core), core, started, release


def test_task_can_capture_during_initial_scan_and_worker_rejects_changed_source(
        installed, projects, tmp_path):
    root = projects[0]
    seeds, core, started, release = blocked_seeds(installed, tmp_path)
    with ThreadPoolExecutor(max_workers=1) as workers:
        future = workers.submit(seeds.capture_session, root, 'startup')
        try:
            assert started.wait(10)
            tasks = TaskSecurityService(core.runtime, core.store, owner=session_owner('codex', 'native'))
            begun = tasks.begin(root, 'development')
            assert begun['status'] == 'ACTIVE'
            baseline = tasks.load(root, begun['task_ref'])['baseline']['hashes'].copy()
            (root / 'src/A.java').write_text('class A { int changed; }\n')
            assert seeds.existing_session(root, 'startup') is None
        finally:
            release.set()
        with pytest.raises(BaselinePreparationError) as caught:
            future.result(timeout=10)
        assert caught.value.code == 'BASELINE_SOURCE_CHANGED'
        assert seeds.existing_session(root, 'startup') is None
        assert tasks.load(root, begun['task_ref'])['baseline']['hashes'] == baseline


def test_late_worker_never_overwrites_session_published_by_another_writer(
        installed, projects, tmp_path):
    root = projects[0]
    seeds, core, started, release = blocked_seeds(installed, tmp_path)
    with ThreadPoolExecutor(max_workers=1) as workers:
        future = workers.submit(seeds.capture_session, root, 'startup')
        try:
            assert started.wait(10)
            other = HookCoordinator(complete_runtime(), core.store)
            published = WorkspaceBaselineSeeds(integration=installed, coordinator=other).capture_session(root, 'startup')
            path = core.store.path(root, 'codex', 'startup')
            before = path.read_bytes(), path.stat().st_mtime_ns
        finally:
            release.set()
        assert future.result(timeout=10) == published
        assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_concurrent_first_session_keys_are_published_once(tmp_path):
    root = tmp_path / 'project'; root.mkdir()
    state = tmp_path / 'hooks'
    gate = threading.Barrier(12)
    def key(_):
        gate.wait(timeout=10)
        return HookStateStore(state).key(root)
    with ThreadPoolExecutor(max_workers=12) as workers:
        keys = list(workers.map(key, range(12)))
    assert len(set(keys)) == 1 and len(keys[0]) == 32
    directory = HookStateStore(state).workspace_directory(root)
    assert not list(directory.glob('.key-*'))


def test_invalid_existing_key_is_never_replaced(tmp_path):
    root = tmp_path / 'project'; root.mkdir()
    hooks = HookStateStore(tmp_path / 'hooks')
    path = hooks.workspace_directory(root) / 'snapshot.key'
    path.parent.mkdir(parents=True)
    path.write_bytes(b'invalid-key')
    with pytest.raises(ValueError, match='Invalid local hook snapshot key'):
        hooks.key(root)
    assert path.read_bytes() == b'invalid-key'
