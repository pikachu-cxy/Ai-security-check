"""Pre-baseline absence, reconnect isolation and unchanged risk/coverage gates."""
import copy
import json
import subprocess
import sys
import time

import pytest

from security_runtime.tasks import ownership as own
from security_runtime.tasks.attribution import overlapping_tasks
from security_runtime.tasks.security import TaskSecurityService
from task_review_helpers import review_all
from test_task_security import service  # noqa: F401

REASON = 'CONCURRENT_TASK_ATTRIBUTION_UNAVAILABLE'


@pytest.fixture
def timeline(service, monkeypatch):
    legacy, root, runtime = service
    clock, observed = [time.time()], ['writer-start']
    monkeypatch.setattr(own, 'writer_identity', lambda: dict(pid=12345, stamp='writer-start'))
    monkeypatch.setattr(own, 'process_stamp', lambda pid: observed[0])
    options = dict(now=lambda: clock[0])
    old = TaskSecurityService(runtime, legacy.hooks, owner=own.connection_owner(), **options)
    new = TaskSecurityService(runtime, legacy.hooks, owner=own.connection_owner(), **options)
    return old, new, root, runtime, clock, observed


def expire(timeline):
    old, _, root, _, clock, observed = timeline
    ref = old.begin(root, 'old')['task_ref']
    clock[0] += own.LEASE_SECONDS + 1
    observed[0] = False
    return ref


def finish_review(tasks, root, ref):
    (root/'routes.py').write_text('def route(): return 1\n')
    result = tasks.finish(root, ref)
    assert not any(item['reason'] == REASON for item in result['limitations'])
    packet = tasks.prepare(root, ref, protocol_version=3)
    review_all(tasks, root, ref, packet)
    assert tasks.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])['result_saved']
    result = tasks.get(root, ref)
    assert result['host_review']['coverage'] == 'REVIEWED'
    return result


@pytest.mark.parametrize('observed', [False, 'reused-pid-start'])
def test_disconnected_before_baseline_is_excluded_without_touching_original(timeline, observed):
    old, new, root, runtime, _, state = timeline
    ref = expire(timeline)
    state[0] = observed
    before = copy.deepcopy(old.load(root, ref))
    fresh = new.begin(root, 'new')['task_ref']
    assert 'attribution_start' not in new.load(root, fresh)
    finish_review(new, root, fresh)
    assert old.load(root, ref) == before
    assert old.load(root, ref)['phase'] == 'ACTIVE' and len(runtime.calls) == 1
    with pytest.raises(ValueError, match='another session'):
        new.skip(root, ref, 'A disconnected task is not adopted')


@pytest.mark.parametrize('observed', [None, 'writer-start'])
def test_expired_but_live_or_unknown_writer_does_not_limit_diff_audit(timeline, observed):
    _, new, root, _, _, state = timeline
    expire(timeline)
    state[0] = observed
    fresh = new.begin(root, 'new')['task_ref']
    assert 'attribution_start' not in new.load(root, fresh)
    finish_review(new, root, fresh)


@pytest.mark.parametrize('host', ['codex', 'cursor', None])
def test_host_session_or_unowned_task_is_not_retired_by_mcp_exit(timeline, host):
    old, new, root, runtime, clock, state = timeline
    owner = own.session_owner(host, 'chat') if host else None
    host_tasks = TaskSecurityService(runtime, old.hooks, owner=owner, now=lambda: clock[0])
    ref = host_tasks.begin(root, 'host')['task_ref']
    clock[0] += own.LEASE_SECONDS + 1
    state[0] = False
    original = host_tasks.load(root, ref)
    fresh = new.begin(root, 'new')['task_ref']
    finish_review(new, root, fresh)
    assert host_tasks.load(root, ref) == original


@pytest.mark.parametrize('field,value', [
    ('writer', None), ('writer', {'pid': True, 'stamp': 'x'}),
    ('writer', {'pid': 1, 'stamp': None}), ('writer', {'pid': 1, 'stamp': ''}),
    ('lease_until', None), ('lease_until', float('nan')), ('activity_at', float('inf')),
    ('activity_at', 0), ('generation', True), ('review_protocol', 2),
    ('static_attempts', 1), ('end', {'hashes': {}}), ('review', {'coverage': 'PARTIAL'}),
    ('phase', 'STATIC_RUNNING'), ('phase', 'READY'), ('phase', 'REVIEWING'),
])
def test_incomplete_legacy_or_inflight_facts_cannot_prove_disconnection(timeline, field, value):
    from security_runtime.tasks.attribution import observe_start
    old, _, root, _, clock, _ = timeline
    ref = expire(timeline)
    record = copy.deepcopy(old.load(root, ref))
    record[field] = value
    # Activity far in the past is valid only with a full recorded lease.
    if field == 'activity_at' and value == 0:
        record['lease_until'] = 1
    assert not observe_start([record], clock[0])['disconnected']


def test_recently_dead_writer_is_not_disconnected_until_its_lease_expires(timeline):
    old, new, root, _, clock, state = timeline
    old.begin(root, 'old')
    state[0] = False
    clock[0] += own.LEASE_SECONDS - 1
    fresh = new.begin(root, 'new')['task_ref']
    clock[0] += 2
    finish_review(new, root, fresh)


def test_death_first_seen_at_finish_cannot_erase_real_overlap(timeline):
    old, new, root, _, clock, state = timeline
    old.begin(root, 'old')
    fresh = new.begin(root, 'new')['task_ref']
    (root/'service.py').write_text('overlapping_edit = True\n')
    clock[0] += own.LEASE_SECONDS + 1
    state[0] = False
    finish_review(new, root, fresh)


@pytest.mark.parametrize('mode', ['save', 'hook', 'new-task', 'missing-witness', 'wrong-boundary'])
def test_activity_or_missing_author_witness_does_not_create_audit_gap(timeline, mode):
    from security_runtime.tasks.hook_activity import _record_task_hook
    old, new, root, _, clock, _ = timeline
    ref = expire(timeline)
    fresh = new.begin(root, 'new')['task_ref']
    clock[0] += 1
    if mode == 'save':
        old.store(root).save(old.load(root, ref))
    elif mode == 'hook':
        task, status = _record_task_hook(old.hooks, root,
            dict(host='connection', session_id=old._owner()['session'], status='DEFERRED',
                 workspace_mutation_observed=True, execution={'scanner_run': False}, delta={},
                 hook_scope_files=['routes.py']), None, expected_task_ref=ref)
        assert status == 'RECORDED' and task['task_ref'] == ref
    elif mode == 'new-task':
        old.begin(root, 'reconnected-work')
    else:
        record = new.load(root, fresh)
        if mode == 'missing-witness':
            record.pop('attribution_start', None)
        else:
            record['attribution_start'] = dict(contract='task-attribution-start-v1', observed_at=record['created_at']+1)
        new.store(root).save(record)
    finish_review(new, root, fresh)


def test_change_during_baseline_capture_invalidates_witness(timeline, monkeypatch):
    from security_runtime.tasks import security as task_security
    old, new, root, _, _, _ = timeline
    ref = expire(timeline)
    capture = task_security.capture
    def race(*args, **kwargs):
        result = capture(*args, **kwargs)
        old.store(root).save(old.load(root, ref))
        return result
    with monkeypatch.context() as patch:
        patch.setattr(task_security, 'capture', race)
        fresh = new.begin(root, 'new')['task_ref']
    finish_review(new, root, fresh)


def test_retry_keeps_original_witness_and_cannot_recapture_after_death(timeline):
    old, new, root, _, clock, state = timeline
    old.begin(root, 'old')
    fresh = new.begin(root, 'new')['task_ref']
    baseline = copy.deepcopy(new.load(root, fresh))
    clock[0] += own.LEASE_SECONDS + 1
    state[0] = False
    assert new.begin(root, 'new')['task_ref'] == fresh
    assert new.load(root, fresh) == baseline
    finish_review(new, root, fresh)


@pytest.mark.parametrize('closed_at,expected', [(999.0, False), (1000.0, False), (1000.1, True)])
def test_closed_task_interval_boundaries_are_unchanged(closed_at, expected):
    record = dict(task_ref='current', created_at=1000.0)
    other = dict(task_ref='old', created_at=900.0, closed_at=closed_at)
    assert bool(overlapping_tasks(record, [other, record], 1001.0)) == expected


@pytest.mark.parametrize('start', [None, [], ['invalid'], {'contract': 'unknown'},
    {'contract': 'task-attribution-start-v1', 'observed_at': 1000, 'disconnected': []}])
def test_malformed_optional_witness_keeps_original_overlap(start):
    record = dict(task_ref='current', created_at=1000.0, attribution_start=start)
    other = dict(task_ref='old', created_at=900.0)
    assert overlapping_tasks(record, [other], 1001.0) == [other]


@pytest.mark.parametrize('path', ['routes.py', 'service.py'])
def test_live_parallel_edits_on_same_or_different_file_are_in_complete_diff(timeline, path):
    old, new, root, _, _, _ = timeline
    old.begin(root, 'live')
    fresh = new.begin(root, 'new')['task_ref']
    (root/path).write_text('other_task_edit = True\n')
    finish_review(new, root, fresh)


@pytest.mark.parametrize('live', [False, True])
def test_actual_review_coverage_still_controls_original_risk_closure(timeline, monkeypatch, live):
    from security_runtime.tasks.risk_ledger import TaskRiskLedger
    old, new, root, _, _, state = timeline
    expire(timeline)
    if live:
        state[0] = 'writer-start'
    fresh = new.begin(root, 'new')['task_ref']
    result = finish_review(new, root, fresh)
    record = new.load(root, fresh)
    refs = [key for key, value in record['evidence'].items()
            if value['path'] == 'routes.py' and value['location_version'] == 'CURRENT_TASK_END']
    ledger = TaskRiskLedger(old.hooks, root)
    monkeypatch.setattr(ledger, 'read_origins', lambda refs: {
        'original:risk': dict(source='HOST_TASK_REVIEW', required_source_paths=['routes.py'])})
    updates = ledger.validate_host(record, [dict(original_task_ref='original', finding_id='risk',
        evidence_refs=refs[:1], outcome='CODE_REVIEWED_RESOLVED',
        rationale='Current issued source contains the selected change.',
        tests='Synthetic regression of the existing coverage gate.')], result['host_review']['coverage'])
    assert updates['original:risk']['status'] == 'CODE_REVIEWED_RESOLVED'
    assert not updates['original:risk']['production_safety_verified']


def test_actual_exited_process_and_new_mcp_connection_cannot_adopt_task(service, monkeypatch):
    from security_runtime.hook_runtime import HookCoordinator
    from security_runtime.mcp_server import create_server
    from security_runtime.tasks.queued_closeout import execute_one
    from test_task_ownership import call
    monkeypatch.setattr('security_runtime.task_closeout_worker.launch_worker', lambda *a, **k: None)
    legacy, root, runtime = service
    script = '''
import json, sys, time
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.ownership import connection_owner, LEASE_SECONDS
from pathlib import Path
service=TaskSecurityService(None, HookStateStore(Path(sys.argv[2])), owner=connection_owner(),
    now=lambda: time.time()-LEASE_SECONDS-10)
print(json.dumps(service.begin(sys.argv[1], 'exited-process')))
'''
    process = subprocess.run([sys.executable, '-c', script, str(root), str(legacy.hooks.directory)],
        check=False, capture_output=True, text=True, timeout=30)
    assert process.returncode == 0, process.stderr
    ref = json.loads(process.stdout)['task_ref']
    before = legacy.store(root).get(ref)
    if before['writer']['stamp'] is None:
        assert own.writer_gone(before['writer']) is False
        pytest.skip('Native process birth identity is unavailable; disconnection stays unproven')
    assert own.writer_gone(before['writer'])
    core = HookCoordinator(runtime, legacy.hooks)
    server = create_server(runtime, hook_coordinator=core, global_mode=False)
    fresh = call(server, 'begin_security_task', workspace_path=str(root), task_key='new')['task_ref']
    original = legacy.store(root).get(fresh)
    with pytest.raises(Exception, match='another session'):
        call(server, 'finish_security_task', workspace_path=str(root), task_ref=ref)
    (root/'routes.py').write_text('value = 1\n')
    result = call(server, 'finish_security_task', workspace_path=str(root), task_ref=fresh)
    assert result['status'] == 'QUEUED' and not runtime.calls
    tasks = TaskSecurityService(runtime, core.store, owner=own.record_owner(original))
    assert execute_one(tasks, root, fresh)
    status = call(server, 'get_task_closeout_status', workspace_path=str(root), task_ref=fresh)
    assert status['status'] == 'READY_FOR_REVIEW' and status['job_ref'] == result['job_ref']
    reviewed = call(server, 'get_task_security_review', workspace_path=str(root), task_ref=fresh)
    assert reviewed['status'] == 'READY' and reviewed['limitations']['total_count'] == 0
    assert tasks.load(root, fresh)['baseline'] == original['baseline']
    assert runtime.calls == [('routes.py',)]
    assert legacy.store(root).get(ref) == before


@pytest.mark.parametrize('code,output,error,expected', [
    (0, 'Wed Oct 21 08:00:00 2026\n', '', 'darwin-Wed Oct 21 08:00:00 2026'),
    (1, '', '', False),
    (1, '', 'permission denied', None),
    (0, 'unexpected', '', None),
])
def test_darwin_process_creation_probe_preserves_unknown_and_absent(
        monkeypatch, code, output, error, expected):
    monkeypatch.setattr(own.os, 'name', 'posix')
    monkeypatch.setattr(own.sys, 'platform', 'darwin')
    monkeypatch.setattr(own.Path, 'is_dir', lambda self: False)
    seen = []
    def run(command, **options):
        seen.append((command, options))
        return subprocess.CompletedProcess(command, code, output, error)
    monkeypatch.setattr(subprocess, 'run', run)
    assert own.process_stamp(12345) == expected
    assert seen[0][0] == ['/bin/ps', '-p', '12345', '-o', 'lstart=']
    assert seen[0][1]['timeout'] == 1 and seen[0][1]['env']['LC_ALL'] == 'C'
    assert own.process_stamp(True) is None and len(seen) == 1


def test_darwin_process_probe_timeout_keeps_writer_unknown(monkeypatch):
    monkeypatch.setattr(own.os, 'name', 'posix')
    monkeypatch.setattr(own.sys, 'platform', 'darwin')
    monkeypatch.setattr(own.Path, 'is_dir', lambda self: False)
    def timeout(command, **options):
        raise subprocess.TimeoutExpired(command, options['timeout'])
    monkeypatch.setattr(subprocess, 'run', timeout)
    assert own.process_stamp(12345) is None
    assert not own.writer_gone({'pid': 12345, 'stamp': 'previous'})
