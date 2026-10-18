"""Automatic task scope must not be consumed by ignored or partial inventory."""
import subprocess
from pathlib import Path

import pytest

from security_runtime.git import GitError, GitService
from security_runtime.local_evidence import EvidenceUnavailable, WorkspaceReader
from security_runtime import task_security
from test_task_security import service, begin
from task_review_helpers import read_plan


def guard_source_discovery(monkeypatch, root, message):
    """Reject recursive original-source discovery, not private-input checks."""
    original = task_security.os.walk
    def guarded(directory, *args, **kwargs):
        candidate = Path(directory).resolve()
        if candidate == root or candidate.is_relative_to(root):
            pytest.fail(message)
        return original(directory, *args, **kwargs)
    monkeypatch.setattr(task_security.os, 'walk', guarded)


def test_ignored_old_files_cannot_consume_task_budget_or_hide_new_source(service, monkeypatch):
    s, root, runtime = service
    (root / '.gitignore').write_text('.test-tmp*/\nartifacts/\n')
    old = root / '.test-tmp-review-old'
    old.mkdir()
    for number in range(1100):
        (old / f'cached{number:04d}.py').write_text('value = 1\n')
    (root / 'artifacts').mkdir()
    (root / 'artifacts' / 'generated.py').write_text('value = 2\n')
    guard_source_discovery(monkeypatch, root, 'Git inventory must not walk ignored source directories')
    (root / 'routes.py').write_text('user_dirty_before_task = 1\n')
    ref = begin(service)
    baseline = s.load(root, ref)['baseline']
    assert set(baseline['inventory']) == {'.gitignore', 'auth.py', 'routes.py', 'service.py'}
    assert baseline['inventory_complete'] and not baseline['limitations']
    (root / 'routes.py').write_text('user_dirty_before_task = 2\n')
    (root / 'z_new_source.py').write_text('new_value = 3\n')
    result = s.finish(root, ref)
    assert result['changes'] == [dict(path='routes.py', change='MODIFIED'), dict(path='z_new_source.py', change='ADDED')]
    assert runtime.calls == [('routes.py', 'z_new_source.py')]
    assert not result['limitations']
    packet = s.prepare(root, ref)
    assert {'routes.py', 'z_new_source.py'} == {unit['path'] for unit in read_plan(s, root, ref, packet)[0]}
    evidence = s.read(root, ref, packet['review_session'], 'auth.py')
    assert s.load(root, ref)['evidence'][evidence['evidence_id']]['path'] == 'auth.py'
    assert s.get(root, ref)['current_version'] is True


def test_priority_keeps_new_file_when_snapshot_read_budget_is_partial(service, monkeypatch):
    s, root, runtime = service
    monkeypatch.setattr(task_security, 'MAX_FILES', 1)
    ref = begin(service)
    assert len(s.load(root, ref)['baseline']['inventory']) == 3
    (root / 'z_new_source.py').write_text('new_value = 3\n')
    result = s.finish(root, ref)
    assert result['changes'] == [dict(path='z_new_source.py', change='ADDED')]
    assert runtime.calls == [('z_new_source.py',)]
    assert result['unverified_file_count'] == 3
    packet = s.prepare(root, ref)
    unit, = read_plan(s, root, ref, packet)[0]
    assert unit['path'] == 'z_new_source.py'
    assert unit['required_windows']
    evidence = s.read(root, ref, packet['review_session'], 'z_new_source.py')
    assert evidence['lines'] == ['new_value = 3']
    assert s.get(root, ref)['current_version'] is True


def test_partial_path_snapshots_do_not_invent_added_deleted_or_clean_result(service, monkeypatch):
    s, root, runtime = service
    snapshots = iter([(['auth.py'], [], False, [{'reason': 'INVENTORY_PATH_BUDGET'}]),
                      (['routes.py'], [], False, [{'reason': 'INVENTORY_PATH_BUDGET'}])])
    monkeypatch.setattr(task_security, '_inventory', lambda *a: next(snapshots))
    ref = begin(service)
    result = s.finish(root, ref)
    assert result['status'] == 'INCOMPLETE'
    assert result['changes'] == [] and result['unverified_file_count'] == 2
    assert runtime.calls == []
    assert '未完成' in result['development_summary']


def test_git_inventory_failure_never_falls_back_to_recursive_discovery(service, monkeypatch):
    s, root, runtime = service
    monkeypatch.setattr(GitService, '_paths', lambda *a: (_ for _ in ()).throw(GitError('fixture failure')))
    guard_source_discovery(monkeypatch, root, 'No source fallback through ignored outputs')
    ref = begin(service)
    result = s.finish(root, ref)
    assert result['status'] == 'INCOMPLETE' and runtime.calls == []
    assert any(v['reason'] == 'GIT_INVENTORY_UNAVAILABLE' for v in result['limitations'])


def test_read_failure_does_not_turn_an_existing_file_into_a_deletion(service, monkeypatch):
    s, root, runtime = service
    original = WorkspaceReader.read
    def unreadable(self, name, **kwargs):
        if name == 'auth.py':
            raise EvidenceUnavailable('FILE_CHANGED_DURING_READ')
        return original(self, name, **kwargs)
    monkeypatch.setattr(WorkspaceReader, 'read', unreadable)
    ref = begin(service)
    (root / 'routes.py').write_text('new_task_value = 4\n')
    result = s.finish(root, ref)
    assert result['changes'] == [dict(path='routes.py', change='MODIFIED')]
    assert result['unverified_file_count'] == 1
    assert runtime.calls == [('routes.py',)]


def test_starting_staged_dirty_new_deleted_and_restored_bytes_are_preserved(service):
    s, root, runtime = service
    def git(*args):
        subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)
    git('add', '--all')
    git('-c', 'commit.gpgSign=false', '-c', f'core.hooksPath={root / ".git" / "empty-hooks"}',
        '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'baseline')
    (root / 'routes.py').write_text('user_staged_before_task = 5\n')
    git('add', 'routes.py')
    (root / 'preexisting.py').write_text('user_new_before_task = 6\n')
    ref = begin(service)
    (root / 'routes.py').write_text('temporary_task_edit = 7\n')
    (root / 'routes.py').write_text('user_staged_before_task = 5\n')
    (root / 'auth.py').unlink()
    git('add', '-u', 'auth.py')
    (root / 'service.py').write_text('first_task_edit = 8\n')
    (root / 'service.py').write_text('last_task_edit = 9\n')
    (root / 'z_new_source.py').write_text('new_value = 10\n')
    git('add', 'z_new_source.py')
    result = s.finish(root, ref)
    assert result['changes'] == [dict(path='auth.py', change='DELETED'),
                                 dict(path='service.py', change='MODIFIED'),
                                 dict(path='z_new_source.py', change='ADDED')]
    assert runtime.calls == [('auth.py', 'service.py', 'z_new_source.py')]
    assert s.finish(root, ref)['status'] == 'READY' and len(runtime.calls) == 1
    packet = s.prepare(root, ref)
    evidence = s.read(root, ref, packet['review_session'], 'auth.py')
    assert s.load(root, ref)['evidence'][evidence['evidence_id']]['location_version'] == 'BEFORE_DELETION'


def test_new_ignore_rule_does_not_pretend_an_existing_file_was_deleted(service):
    s, root, runtime = service
    (root / '.gitignore').write_text('# initial policy\n')
    ref = begin(service)
    (root / '.gitignore').write_text('auth.py\n')
    result = s.finish(root, ref)
    assert result['changes'] == [dict(path='.gitignore', change='MODIFIED')]
    assert result['unverified_file_count'] == 1
    assert (root / 'auth.py').exists()
    assert runtime.calls == [('.gitignore',)]


def test_non_git_fallback_prunes_runtime_test_temporary_directories(tmp_path):
    root = tmp_path / 'plain-source'
    root.mkdir()
    (root / 'main.py').write_text('value = 1\n')
    temporary = root / '.test-tmp-old'
    temporary.mkdir()
    for number in range(1100):
        (temporary / f'cached{number:04d}.py').write_text('value = 2\n')
    snapshot = task_security.capture(root)
    assert snapshot['inventory'] == ['main.py']
    assert snapshot['inventory_complete'] and not snapshot['limitations']


def test_git_inventory_applies_capacity_before_statting_the_tail(service, monkeypatch):
    s, root, _ = service
    monkeypatch.setattr(task_security, 'MAX_INVENTORY_PATHS', 1)
    monkeypatch.setattr(GitService, '_paths', lambda *a: ['auth.py', 'routes.py', 'service.py'])
    from pathlib import Path
    original = Path.lstat
    inspected = []

    def observed(path, *args, **kwargs):
        if path.parent == root and path.name in {'auth.py', 'routes.py', 'service.py'}:
            inspected.append(path.name)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'lstat', observed)
    names, _, complete, limitations = task_security._inventory(root, set())
    assert names == ['auth.py'] and inspected == ['auth.py']
    assert not complete and limitations[-1]['pending_count_unknown'] is True


def test_truncated_inventory_reports_unknown_tail_instead_of_zero_pending(tmp_path, monkeypatch):
    (tmp_path/'first.py').write_text('value = 1\n')
    (tmp_path/'second.py').write_text('value = 2\n')
    monkeypatch.setattr(task_security, 'MAX_INVENTORY_PATHS', 1)
    snapshot = task_security.capture(tmp_path)
    stats = snapshot['capture_stats']
    assert snapshot['inventory_complete'] is False
    assert stats['inventory_total_file_count'] is None
    assert stats['pending_hash_file_count'] is None
    assert stats['pending_body_file_count'] is None
    assert stats['known_pending_hash_file_count'] == 0
    assert stats['hash_complete'] is False


def test_static_scope_is_complete_while_large_context_packet_stays_bounded(service):
    s, root, runtime = service
    ref = begin(service)
    names = []
    for number in range(210):
        name = 'module_' + 'a' * 120 + f'_{number:03d}.py'
        names.append(name)
        (root / name).write_text('value = 1\n')
    result = s.finish(root, ref)
    assert result['changed_file_count'] == 210
    assert set(runtime.calls[0]) == set(names)
    packet = s.prepare(root, ref)
    assert packet['static']['scope_file_count'] == 210
    assert 'scope_files' not in packet['static']
    assert set(s.load(root, ref)['static']['scope_files']) == set(names)
    units, _ = read_plan(s, root, ref, packet)
    assert {unit['path'] for unit in units} == set(names)
    from security_runtime.task_review_plan import DEFAULT_LIMITS
    assert len(__import__('json').dumps(packet, ensure_ascii=False).encode()) <= DEFAULT_LIMITS['response_bytes']
