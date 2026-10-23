import copy
from pathlib import Path
import subprocess

import pytest

from security_runtime.task_workspaces import prepare, capability, registry, root_key
from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.security import TaskSecurityService
from test_task_security import service


@pytest.fixture(autouse=True)
def private_registry(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'user-state'))


def commit(root):
    subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(root), '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                    '-c', 'core.hooksPath=', 'commit', '-qm', 'fixture'], check=True)


def scoped(sample, name):
    return TaskSecurityService(sample[2], sample[0].hooks, owner=session_owner('codex', name))


def activate(task, prepared, key):
    root = Path(prepared['execution_root'])
    result = task.begin(root, key, check_policy=POLICY, workspace_setup_ref=prepared['isolation_ref'])
    return root, result['task_ref']


def test_two_worktrees_same_line_do_not_mix_or_invalidate(service):
    _, origin, _ = service
    commit(origin)
    a, b = scoped(service, 'a'), scoped(service, 'b')
    pa, pb = prepare(origin, 'a', a._owner()), prepare(origin, 'b', b._owner())
    ar, at = activate(a, pa, 'a')
    br, bt = activate(b, pb, 'b')
    original = (origin/'routes.py').read_bytes()
    (ar/'routes.py').write_text('version = "A"\n')
    a.finish(ar, at)
    saved = a.load(ar, at)
    (br/'routes.py').write_text('version = "B"\n')
    b.finish(br, bt)
    assert (ar/'routes.py').read_text() == 'version = "A"\n'
    assert (origin/'routes.py').read_bytes() == original
    assert a._fresh(ar, saved)
    assert a.load(ar, at)['changes'] == [{'path':'routes.py', 'change':'MODIFIED'}]
    assert b.load(br, bt)['changes'] == [{'path':'routes.py', 'change':'MODIFIED'}]


def test_dirty_seed_is_baseline_not_new_contribution(service):
    _, origin, _ = service
    commit(origin)
    (origin/'routes.py').write_text('dirty = True\n')
    subprocess.run(['git', '-C', str(origin), 'add', 'routes.py'], check=True)
    (origin/'routes.py').write_text('dirty = "unstaged"\n')
    (origin/'auth.py').unlink()
    (origin/'new.py').write_text('untracked = True\n')
    a = scoped(service, 'a')
    prepared = prepare(origin, 'a', a._owner())
    root, ref = activate(a, prepared, 'a')
    assert (root/'routes.py').read_bytes() == (origin/'routes.py').read_bytes()
    assert not (root/'auth.py').exists()
    assert (root/'new.py').exists()
    assert a.finish(root, ref)['status'] == 'NO_CHANGES'


def test_resume_retains_directory_and_baseline(service):
    _, origin, _ = service
    commit(origin)
    task = scoped(service, 'a')
    prepared = prepare(origin, 'a', task._owner())
    root, ref = activate(task, prepared, 'a')
    baseline = copy.deepcopy(task.load(root, ref)['baseline'])
    (root/'routes.py').write_text('later = True\n')
    resumed = scoped(service, 'a')
    assert resumed.begin(root, 'a', check_policy=POLICY)['task_ref'] == ref
    assert resumed.load(root, ref)['baseline'] == baseline
    assert prepare(origin, 'a', task._owner())['execution_root'] == str(root)


def test_prebaseline_edits_rejected(service):
    _, origin, _ = service
    commit(origin)
    task = scoped(service, 'a')
    prepared = prepare(origin, 'a', task._owner())
    (Path(prepared['execution_root'])/'routes.py').write_text('too_late = True\n')
    with pytest.raises(ValueError, match='edited before'):
        activate(task, prepared, 'a')


def test_second_owner_cannot_use_occupied_directory(service):
    _, origin, _ = service
    commit(origin)
    a, b = scoped(service, 'a'), scoped(service, 'b')
    prepared = prepare(origin, 'a', a._owner())
    root, ref = activate(a, prepared, 'a')
    with pytest.raises(ValueError, match='already bound'):
        b.begin(root, 'a', check_policy=POLICY, workspace_setup_ref=prepared['isolation_ref'])
    with pytest.raises(ValueError):
        b.finish(root, ref)


def test_activation_crash_does_not_create_late_baseline(service, monkeypatch):
    _, origin, _ = service
    commit(origin)
    task = scoped(service, 'a')
    prepared = prepare(origin, 'a', task._owner())
    def fail(*args, **kwargs):
        raise OSError('simulated capture crash')
    monkeypatch.setattr('security_runtime.tasks.security.capture', fail)
    from security_runtime.tasks.preimages import TaskPreimageUnavailable
    with pytest.raises(TaskPreimageUnavailable):
        activate(task, prepared, 'a')
    with pytest.raises(ValueError, match='never rebuild'):
        activate(task, prepared, 'a')


def test_non_git_copy_and_explicit_host_limitations(service, tmp_path):
    origin = tmp_path/'source'
    origin.mkdir()
    (origin/'a.py').write_text('initial = True\n')
    (origin/'.env').write_text('not copied\n')
    task = scoped(service, 'a')
    prepared = prepare(origin, 'a', task._owner())
    root, ref = activate(task, prepared, 'a')
    assert prepared['kind'] == 'SOURCE_COPY'
    assert '.env' in prepared['exclusions']
    assert not (root/'.env').exists()
    assert not prepared['automatic_host_switch']
    assert not capability()['host_write_sandbox']
    assert task.load(root, ref)['workspace_isolation']['mode'] == 'ISOLATED_DIRECTORY'


def test_wrong_activation_reference_never_claims_directory(service):
    _, origin, _ = service
    commit(origin)
    task = scoped(service, 'a')
    prepared = prepare(origin, 'a', task._owner())
    with pytest.raises(ValueError, match='reference required'):
        task.begin(prepared['execution_root'], 'a', check_policy=POLICY)
    root, ref = activate(task, prepared, 'a')
    assert ref


def test_simultaneous_workspace_preparation(service):
    from concurrent.futures import ThreadPoolExecutor
    _, origin, _ = service
    commit(origin)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(prepare, origin, name, session_owner('codex', name)) for name in ('a', 'b')]
        results = [future.result() for future in futures]
    assert all(result['state'] == 'PREPARED' for result in results)
    assert results[0]['execution_root'] != results[1]['execution_root']
