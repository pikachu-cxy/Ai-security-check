"""B-to-C scope includes all writers while access remains owner/root bound."""
import copy
import subprocess

import pytest

from security_runtime.tasks.activity import ActivityStore
from security_runtime.tasks.audit_scope import apply, LEGACY_ATTRIBUTION_REASON
from security_runtime.tasks.queued_closeout import enqueue, execute_one, status
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.task_review.results import bounded_history_result
from task_review_helpers import review_all
from test_closeout_queue import setup, private_dispatcher  # noqa: F401
from test_task_security import service  # noqa: F401
from test_task_attribution_presentation import overlapping_record


def test_overlapping_tasks_audit_all_actual_changes_and_complete_review(service):
    task, root, ref = setup(service)
    other, _, other_ref = setup(service, 'another-chat')
    baseline = copy.deepcopy(task.load(root, ref)['baseline'])
    untouched_other = copy.deepcopy(other.load(root, other_ref))
    (root/'routes.py').write_text('def route(): return 1\n')
    (root/'manual.py').write_text('def manual_change(): return 2\n')
    # The only AI path hint omits the file changed through another editor.
    ActivityStore(task.hooks, root).record(task._owner(), event_id='one-edit',
                                          paths=['routes.py'], scope_unknown=False)
    enqueue(task, root, ref, launch=False)
    assert execute_one(task, root, ref)
    assert status(task, root, ref)['status'] == 'READY_FOR_REVIEW'
    saved = task.load(root, ref)
    assert {item['path'] for item in saved['changes']} == {'routes.py', 'manual.py'}
    assert set(service[2].calls[-1]) == {'routes.py', 'manual.py'}
    assert not any(item['reason'] == LEGACY_ATTRIBUTION_REASON for item in saved['limitations'])
    end = copy.deepcopy(saved['end'])
    packet = task.prepare(root, ref, protocol_version=3)
    review_all(task, root, ref, packet)
    receipt = task.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    assert receipt['status'] == 'COMPLETE' and receipt['result_saved']
    current = task.load(root, ref)
    assert current['review']['coverage'] == 'REVIEWED'
    assert current['baseline'] == baseline
    assert current['end']['hashes'] == end['hashes']
    assert current['end']['version_ref'] == end['version_ref']
    assert other.load(root, other_ref) == untouched_other


def test_net_diff_keeps_untracked_delete_rename_config_and_dependency_changes(service):
    (service[1]/'requirements.txt').write_text('example==1.0\n')
    task, root, ref = setup(service)
    (root/'auth.py').unlink()
    (root/'service.py').rename(root/'renamed_service.py')
    (root/'untracked.py').write_text('value = 3\n')
    (root/'requirements.txt').write_text('example==2.0\n')
    (root/'settings.yaml').write_text('feature: true\n')
    enqueue(task, root, ref, launch=False)
    execute_one(task, root, ref)
    saved = task.load(root, ref)
    paths = {item['path'] for item in saved['changes']}
    assert {'auth.py', 'service.py', 'renamed_service.py', 'untracked.py',
            'requirements.txt', 'settings.yaml'} <= paths
    assert {'auth.py', 'service.py', 'renamed_service.py', 'untracked.py', 'requirements.txt'} <= set(service[2].calls[-1])


def test_worktrees_with_same_git_repository_and_filenames_keep_independent_versions(service, tmp_path):
    original, root, engine = service
    def git(*args):
        subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)
    git('add', '.')
    git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'seed')
    second = tmp_path/'second-worktree'
    git('worktree', 'add', '--detach', str(second))
    one = TaskSecurityService(engine, original.hooks, owner=session_owner('codex', 'one'))
    two = TaskSecurityService(engine, original.hooks, owner=session_owner('codex', 'two'))
    ar = one.begin(root, 'task')['task_ref']
    br = two.begin(second, 'task')['task_ref']
    (root/'routes.py').write_text('value = 1\n')
    (second/'routes.py').write_text('value = 2\n')
    one.finish(root, ar)
    two.finish(second, br)
    a, b = one.load(root, ar), two.load(second, br)
    assert a['end']['hashes']['routes.py'] != b['end']['hashes']['routes.py']
    assert one.store(root).path != two.store(second).path
    assert not a['limitations'] and not b['limitations']
    with pytest.raises(ValueError):
        one.load(second, ar)


def test_new_submission_keeps_old_attribution_diagnosis_without_quality_gate():
    record = overlapping_record()
    record['phase'] = 'REVIEWING'
    record['limitations'].append(dict(reason='ACTUAL_SOURCE_GAP'))
    apply(record)
    assert record['limitations'] == [dict(reason='ACTUAL_SOURCE_GAP')]
    assert record['historical_attribution_observations'] == [dict(reason=LEGACY_ATTRIBUTION_REASON, count=1)]


def test_reading_historical_partial_does_not_upgrade_or_rewrite():
    record = overlapping_record()
    before = copy.deepcopy(record)
    result = bounded_history_result(record)
    assert result['host_review']['coverage'] == 'PARTIAL'
    assert record == before


def test_foreign_owner_still_cannot_finish_or_submit_another_task(service):
    one, root, ref = setup(service)
    other, _, _ = setup(service, 'foreign')
    with pytest.raises(ValueError, match='session|owner'):
        other.finish(root, ref)
    assert one.load(root, ref)['phase'] == 'ACTIVE'


def test_capture_B_failure_does_not_publish_task_or_synthesize_B(service, monkeypatch):
    task, root, _ = service
    def fail(*args, **kwargs):
        raise PermissionError('source unavailable')
    monkeypatch.setattr('security_runtime.tasks.security.capture', fail)
    from security_runtime.tasks.preimages import TaskPreimageUnavailable
    with pytest.raises(TaskPreimageUnavailable, match='TASK_PREIMAGE_STORE_UNAVAILABLE'):
        task.begin(root, 'failed-before-edit')
    assert not task.store(root).records()
