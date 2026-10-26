"""Control reads authenticate task headers without hydrating source snapshots."""
import sqlite3
import time

import pytest

from security_runtime.tasks.attribution import observe_start, overlapping_tasks
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.queued_closeout import status
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.snapshot_pages import POINTER
from test_task_snapshot_gc import sample, record


def saved(sample, index=1):
    state = sample[4]
    value = state.save(record(sample, index=index), new=True)
    return state.get(value['task_ref'])


def test_headers_keep_control_and_default_reads_keep_complete_sources(sample, monkeypatch):
    state = sample[4]
    full = saved(sample)
    assert state.get(full['task_ref']) == full
    monkeypatch.setattr('security_runtime.tasks.snapshot_pages.unpack',
                        lambda *args: pytest.fail('Control read loaded source pages'))
    head = state.get(full['task_ref'], headers=True)
    assert head['baseline'][POINTER] == full['baseline'][POINTER]
    assert 'hashes' not in head['baseline'] and 'preimages' not in head['baseline']
    for key in ('task_ref', 'task_owner', 'phase', 'generation', 'created_at'):
        assert head[key] == full[key]
    assert state.records(headers=True) == [head]


def test_pending_hook_ack_keeps_authenticated_head_without_source_reads(sample, monkeypatch):
    from security_runtime.tasks.hook_activity import _record_task_hook
    root, hooks, clock, _, state, _ = sample
    clock[0] = time.time()
    full = saved(sample)
    before = state.path.read_bytes()
    monkeypatch.setattr('security_runtime.tasks.snapshot_pages.unpack',
                        lambda *args: pytest.fail('Edit acknowledgement loaded source pages'))
    head, recording = _record_task_hook(hooks, root,
        dict(status='RECORDED_PENDING', security_task_ref=full['task_ref']), None)
    assert recording == 'ACTIVITY_RECORDED'
    assert head['baseline'][POINTER] == full['baseline'][POINTER]
    assert head['task_owner'] == full['task_owner']
    assert 'hashes' not in head['baseline']
    assert state.path.read_bytes() == before


def test_pending_hook_ack_rejects_tampered_control_without_loading_sources(sample):
    from security_runtime.tasks.hook_activity import _record_task_hook
    root, hooks, _, _, state, _ = sample
    full = saved(sample)
    with sqlite3.connect(state.path) as db:
        db.execute("UPDATE security_tasks SET data=replace(data, 'ACTIVE', 'COMPLETE')")
    with pytest.raises(ValueError, match='cannot be verified'):
        _record_task_hook(hooks, root,
            dict(status='RECORDED_PENDING', security_task_ref=full['task_ref']), None)


def test_header_reads_reject_modified_signed_control(sample):
    state = sample[4]
    full = saved(sample)
    with sqlite3.connect(state.path) as db:
        db.execute("UPDATE security_tasks SET data=replace(data, 'ACTIVE', 'COMPLETE')")
    for read in (lambda: state.get(full['task_ref'], headers=True),
                 lambda: state.records(headers=True)):
        with pytest.raises(ValueError, match='cannot be verified'):
            read()


def test_expired_headers_do_not_recreate_or_recover_tasks(sample):
    state, clock = sample[4], sample[2]
    full = saved(sample)
    clock[0] += 31 * 86400
    before = state.path.read_bytes()
    assert state.get(full['task_ref'], headers=True) is None
    assert state.records(headers=True) == []
    assert state.path.read_bytes() == before


def test_reading_a_header_does_not_make_corrupt_source_readable(sample):
    state = sample[4]
    full = saved(sample)
    from security_runtime.tasks.snapshot_pages import _store
    from security_runtime.snapshot_store import SnapshotStoreError
    with sqlite3.connect(_store(state).path) as db:
        db.execute('UPDATE objects SET body=?', (b'tampered',))
    assert state.get(full['task_ref'], headers=True)['phase'] == 'ACTIVE'
    with pytest.raises((ValueError, SnapshotStoreError)):
        state.get(full['task_ref'])


def test_header_attribution_matches_full_record_attribution(sample):
    state, clock = sample[4], sample[2]
    first = saved(sample)
    clock[0] += 1
    second = saved(sample, index=2)
    full = state.records()
    heads = state.records(headers=True)
    assert observe_start(full, clock[0]) == observe_start(heads, clock[0])
    ids = lambda values: [v['task_ref'] for v in values]
    assert ids(overlapping_tasks(second, full, clock[0])) == ids(
        overlapping_tasks(second, heads, clock[0])) == [first['task_ref']]


def test_owner_check_remains_required_without_loading_source(sample, monkeypatch):
    root, hooks, _, _, state, _ = sample
    full = saved(sample)
    other = TaskSecurityService(None, hooks, now=state.now, owner=session_owner('codex', 'other'))
    monkeypatch.setattr('security_runtime.tasks.snapshot_pages.unpack',
                        lambda *args: pytest.fail('Owner precheck loaded source pages'))
    with pytest.raises(ValueError):
        other.load_header(root, full['task_ref'])


def test_status_reads_never_load_source_pages_or_dispatch_work(sample, monkeypatch):
    root, _, _, _, state, service = sample
    full = saved(sample)
    monkeypatch.setattr('security_runtime.tasks.snapshot_pages.unpack',
                        lambda *args: pytest.fail('Queue status loaded source pages'))
    assert status(service, root, full['task_ref'])['status'] == 'NOT_QUEUED'


def test_routing_uses_authenticated_headers_and_rejects_other_owner(sample, monkeypatch):
    from security_runtime.workspace_application import WorkspaceApplication
    from security_runtime.tasks.ownership import issue_session_ref
    root, hooks, clock, owner, state, _ = sample
    clock[0] = time.time()
    full = saved(sample)
    token = issue_session_ref(hooks, root, 'codex', 'gc-integration')
    app = WorkspaceApplication(None, hooks, scan_path_provider=lambda: root/'unused.db')
    monkeypatch.setattr('security_runtime.tasks.snapshot_pages.unpack',
                        lambda *args: pytest.fail('Routing precheck loaded source pages'))
    service = app.task_service(full['task_ref'], token, str(root))
    assert service._owner() == owner
    foreign = issue_session_ref(hooks, root, 'codex', 'other')
    with pytest.raises(ValueError):
        app.task_service(full['task_ref'], foreign, str(root))
    assert app.issued_tasks[full['task_ref']] == owner


@pytest.mark.parametrize('headers', [None, 1, 'false'])
def test_header_option_requires_explicit_boolean(sample, headers):
    state = sample[4]
    with pytest.raises(ValueError):
        state.records(headers=headers)
    with pytest.raises(ValueError):
        state.get('ts1-'+'1'*32, headers=headers)
