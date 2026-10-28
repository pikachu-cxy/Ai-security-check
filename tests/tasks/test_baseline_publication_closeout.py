"""Locator publication must not invalidate the original closeout identity."""
import copy

import pytest
import os

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Opt-in capture publication requires POSIX private-state guarantees")

from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.baseline_identity import baseline_snapshot, baseline_fingerprint
from security_runtime.tasks.closeout_queue import CloseoutQueue
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.queued_closeout import enqueue, execute_one, status
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks import baseline_publication as publisher
from test_task_security import service


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'runtime-state'))


def setup(service, monkeypatch):
    original, root, engine = service
    task = TaskSecurityService(engine, original.hooks, owner=session_owner('codex', 'publisher-closeout'),
        frozen_body_contexts=True, capture_sources=True)
    with monkeypatch.context() as schedule:
        schedule.setattr(publisher, 'advance', publisher.status)
        ref = task.begin(root, 'same-original-task', check_policy=POLICY)['task_ref']
    assert task.baseline_publication_status(root, ref)['state'] == 'RESERVED'
    return task, root, ref, engine


def test_original_queued_request_survives_later_locator_publication(service, monkeypatch):
    task, root, ref, engine = setup(service, monkeypatch)
    before = task.load(root, ref)
    (root / 'routes.py').write_text('value = 2\n')
    queued = enqueue(task, root, ref, launch=False)
    queue = CloseoutQueue(task.hooks, root)
    claim_before = copy.deepcopy(queue.read(ref))
    assert claim_before['baseline_digest'] == baseline_fingerprint(before)
    assert task.advance_baseline_publication(root, ref)['state'] == 'PUBLISHED'
    current = task.load(root, ref)
    assert current['baseline'] != before['baseline']
    assert baseline_snapshot(current) == baseline_snapshot(before)
    assert queue.read(ref) == claim_before  # Never rewrite an existing queue.
    assert execute_one(task, root, ref)
    assert status(task, root, ref)['status'] == 'READY_FOR_REVIEW'
    assert len(engine.calls) == 1
    assert status(task, root, ref)['job_ref'] == queued['job_ref']


@pytest.mark.parametrize('operation', ['enqueue', 'foreground'])
def test_publication_during_end_capture_is_not_a_baseline_change(service, monkeypatch, operation):
    task, root, ref, engine = setup(service, monkeypatch)
    before = task.load(root, ref)
    (root / 'routes.py').write_text('value = 2\n')
    if operation == 'enqueue':
        import security_runtime.tasks.queued_closeout as module
        original = module.capture_end
        def captured(*args, **kwargs):
            end = original(*args, **kwargs)
            assert task.advance_baseline_publication(root, ref)['state'] == 'PUBLISHED'
            return end
        monkeypatch.setattr(module, 'capture_end', captured)
        assert enqueue(task, root, ref, launch=False)['status'] == 'QUEUED'
        execute_one(task, root, ref)
        assert status(task, root, ref)['status'] == 'READY_FOR_REVIEW'
    else:
        import security_runtime.tasks.end_versions as module
        original = module.capture_end
        def captured(*args, **kwargs):
            end = original(*args, **kwargs)
            assert task.advance_baseline_publication(root, ref)['state'] == 'PUBLISHED'
            return end
        monkeypatch.setattr(module, 'capture_end', captured)
        assert task.finish(root, ref)['status'] == 'READY'
    assert len(engine.calls) == 1
    assert baseline_snapshot(task.load(root, ref)) == baseline_snapshot(before)


def test_identity_still_includes_original_hashes_limits_context_and_donor(service, monkeypatch):
    task, root, ref, _ = setup(service, monkeypatch)
    before = task.load(root, ref)
    assert task.advance_baseline_publication(root, ref)['state'] == 'PUBLISHED'
    current = task.load(root, ref)
    assert baseline_fingerprint(current) == baseline_fingerprint(before)
    for name in ('hashes', 'limitations', 'paged_entries', 'frozen_body_context'):
        changed = copy.deepcopy(current)
        value = changed['baseline'].get(name)
        if name == 'hashes':
            value['routes.py'] = '0' * 64
        elif name == 'limitations':
            value.append({'reason': 'NEW_COVERAGE_GAP'})
        elif name == 'paged_entries':
            value['ref'] = 'ws2-' + 'f' * 32
        else:
            value['mac'] = 'f' * 64
        assert baseline_fingerprint(changed) != baseline_fingerprint(current)
