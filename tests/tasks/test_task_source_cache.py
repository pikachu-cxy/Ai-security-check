"""Disposable source caching cannot replace source or evidence checks."""
import copy
from types import SimpleNamespace

import pytest

from security_runtime.tasks.source_cache import TaskSourceCache
from security_runtime.workspace_application import WorkspaceApplication
from task_review_helpers import review_all
from test_task_security import service  # noqa: F401


def key(*, task='task', version=2, path='source.py', sha='hash', session='session'):
    return ('workspace', task, session, 'CURRENT_TASK_END', path, sha, version)


def test_single_entry_is_version_bound_and_returns_independent_lists():
    cache = TaskSourceCache()
    cache.put(key(), ['password = "[REDACTED_SECRET]"'], [1])
    body, truncated = cache.get(key())
    body[0] = 'caller mutation'
    truncated.clear()
    assert cache.get(key()) == (['password = "[REDACTED_SECRET]"'], [1])
    for other in (key(task='other'), key(version=1), key(version=3), key(path='other.py'),
                  key(sha='changed'), key(session='other')):
        assert cache.get(other) is None
    cache.put(key(task='other'), ['new sanitized body'], [])
    assert cache.get(key()) is None
    assert cache.get(key(task='other')) == (['new sanitized body'], [])


def test_capacity_expiry_and_task_discard_are_cache_misses():
    clock = [10]
    cache = TaskSourceCache(maximum_bytes=1500, ttl_seconds=5, now=lambda: clock[0])
    cache.put(key(), ['sanitized'], [])
    assert cache.get(key()) is not None
    cache.discard_task('workspace', 'another')
    assert cache.get(key()) is not None
    clock[0] = 15
    assert cache.get(key()) is None
    cache.put(key(), ['x' * 2000], [])
    assert cache.get(key()) is None
    cache.put(key(), ['sanitized'], [])
    cache.discard_task('workspace', 'task')
    assert cache.get(key()) is None


def application_task(sample):
    old, root, runtime = sample
    application = WorkspaceApplication(runtime, old.hooks,
        binding=SimpleNamespace(root=str(root)), scan_path_provider=lambda: root / 'scan.db')
    tasks = application.task_service(workspace=str(root))
    ref = tasks.begin(root, 'cached-review')['task_ref']
    (root / 'added.py').write_text('password = "fixture-private-value"\n' +
        ''.join(f'public_value_{i} = "readable_{i}"\n' for i in range(200)), encoding='utf-8')
    packet = tasks.prepare(root, ref)
    return application, tasks, root, ref, packet


def test_new_services_reuse_sanitization_but_always_read_source_and_charge_delivery(service, monkeypatch):
    from security_runtime import task_review
    application, tasks, root, ref, packet = application_task(service)
    original_sanitize = task_review.safe_source
    original_read = task_review.WorkspaceReader.read
    calls = dict(reads=0, sanitizations=0)

    def sanitize(*args, **kwargs):
        calls['sanitizations'] += 1
        return original_sanitize(*args, **kwargs)

    def read(reader, path, *args, **kwargs):
        calls['reads'] += 1
        return original_read(reader, path, *args, **kwargs)

    monkeypatch.setattr(task_review, 'safe_source', sanitize)
    monkeypatch.setattr(task_review.WorkspaceReader, 'read', read)
    first = tasks.read(root, ref, packet['review_session'], 'added.py', 1, 80)
    restarted = application.task_service(ref, workspace=str(root))
    assert restarted is not tasks and restarted.source_cache is tasks.source_cache
    second = restarted.read(root, ref, packet['review_session'], 'added.py', 81, 160)
    before_duplicate = restarted.load(root, ref)
    duplicate = restarted.read(root, ref, packet['review_session'], 'added.py', 1, 80)
    after_duplicate = restarted.load(root, ref)

    assert calls == dict(reads=3, sanitizations=1)
    assert 'fixture-private-value' in repr(first)
    assert 'readable_0' in repr(first)
    assert second['start_line'] == 81 and len(second['lines']) == 80
    assert duplicate['status'] == 'ALREADY_DELIVERED'
    assert duplicate['evidence_refs'] == [first['evidence_id']]
    assert after_duplicate['evidence'] == before_duplicate['evidence']
    assert after_duplicate['review_ledger']['reads'] == 2
    assert after_duplicate['review_ledger']['source_bytes'] == before_duplicate['review_ledger']['source_bytes']
    assert after_duplicate['review_ledger']['navigation_bytes'] > before_duplicate['review_ledger']['navigation_bytes']


def test_cached_body_never_hides_changed_current_source(service):
    _, tasks, root, ref, packet = application_task(service)
    tasks.read(root, ref, packet['review_session'], 'added.py', 1, 80)
    before = tasks.store(root).path.read_bytes()
    (root / 'added.py').write_text('changed after caching\n', encoding='utf-8')
    with pytest.raises(ValueError, match='source changed'):
        tasks.read(root, ref, packet['review_session'], 'added.py', 81, 160)
    assert tasks.store(root).path.read_bytes() == before


def test_baseline_reads_still_use_original_preimage_verification(service, monkeypatch):
    from security_runtime.tasks.preimages import TaskPreimageUnavailable
    tasks, root, _ = service
    tasks.source_cache = TaskSourceCache()
    ref = tasks.begin(root, 'before-cache-boundary')['task_ref']
    (root / 'routes.py').write_text('changed = True\n', encoding='utf-8')
    packet = tasks.prepare(root, ref)
    tasks.read(root, ref, packet['review_session'], 'routes.py', 1, 1, 'BEFORE_TASK')

    def unavailable(*args, **kwargs):
        raise TaskPreimageUnavailable('TASK_PREIMAGE_CONTENT_UNVERIFIED')

    monkeypatch.setattr(tasks, 'before_lines', unavailable)
    before = copy.deepcopy(tasks.load(root, ref)['evidence'])
    from security_runtime.tasks.security import TaskContextError
    with pytest.raises(TaskContextError) as rejected:
        tasks.read(root, ref, packet['review_session'], 'routes.py', 1, 1, 'BEFORE_TASK')
    assert rejected.value.reason_code == 'TASK_PREIMAGE_CONTENT_UNVERIFIED'
    assert tasks.load(root, ref)['evidence'] == before


@pytest.mark.parametrize('close', ['submit', 'skip'])
def test_terminal_task_discards_cached_body(service, close):
    _, tasks, root, ref, packet = application_task(service)
    tasks.read(root, ref, packet['review_session'], 'added.py', 1, 80)
    record = tasks.load(root, ref)
    cache_key = (str(root), ref, packet['review_session'], 'CURRENT_TASK_END',
                 'added.py', record['end']['hashes']['added.py'], record['baseline']['redaction_version'])
    assert tasks.source_cache.get(cache_key) is not None
    if close == 'submit':
        review_all(tasks, root, ref, packet)
        assert tasks.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])['result_saved']
    else:
        tasks.skip(root, ref, 'Explicit test close')
    assert tasks.source_cache.get(cache_key) is None
