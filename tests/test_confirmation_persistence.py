"""Signed pending handoff survives service recreation; grants do not."""
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from test_remediation import setup, UNSAFE, FIXED, CANARY
from test_hook_runtime import repo
from test_confirmation import pending, state
from security_runtime.remediation import RemediationService, CONFIRMATION_TTL
from security_runtime.hook_runtime import HookCoordinator

pytestmark = pytest.mark.parametrize('setup', ['ask_before_fix'], indirect=True)


def restart(setup):
    old = setup[3]
    return RemediationService(old.store, registry=old.registry, hooks=old.hooks,
                              config=old.config, directory=old.state.directory)


def confirm(service, setup, approve=True, **changes):
    data = pending(setup)
    args = dict(ref=data['confirmation_ref'], task_ref=data['task_ref'], root=setup[0], approve=approve)
    args.update(changes)
    return service.confirm(**args)


@pytest.mark.parametrize('approve', [True, False])
def test_signed_pending_survives_service_a_recreation_and_consumes_once(setup, approve):
    record = next(iter(state(setup).values()))
    service_b = restart(setup)
    assert not hasattr(service_b, 'confirmations')
    assert not service_b.authorized and not service_b.prepared
    out = confirm(service_b, setup, approve)
    assert out['status'] == ('AUTHORIZED' if approve else 'DECLINED')
    assert next(iter(state(setup).values()))['confirmation_expires_at_epoch'] == record['confirmation_expires_at_epoch']
    assert confirm(restart(setup), setup)['reason_code'] == 'CONFIRMATION_ALREADY_CONSUMED'
    if approve:
        args = out['prepare']['arguments']
        assert service_b.prepare(args['remediation_ref'], args['task_ref'], setup[0])['status'] == 'READY_FOR_HOST_FIX'
        assert restart(setup).prepare(args['remediation_ref'], args['task_ref'], setup[0])['reason_code'] == 'REPAIR_GRANT_STALE'
    else:
        assert not {'prepare', 'verify'} & out.keys()
        assert (setup[0] / 'A.java').read_text() == UNSAFE
        assert not setup[2].calls


def test_recreated_hook_does_not_expire_valid_pending_or_renew_deadline(setup):
    root, runtime, _, old, _, _ = setup
    before = next(iter(state(setup).values()))
    new = restart(setup)
    result = HookCoordinator(runtime, old.hooks, cooldown_ms=0).handle('FILE_CHANGED', root, 'codex', 'session')
    assert new.on_hook(result, root, 'session', host='codex')['feedback_required'] is False
    assert state(setup)[before['family_key']] == before
    assert confirm(new, setup)['status'] == 'AUTHORIZED'


@pytest.mark.parametrize('clock', ['expired', 'backward', 'nan'])
def test_cross_service_clock_failure_never_renews(setup, monkeypatch, clock):
    import security_runtime.remediation as module
    row = next(iter(state(setup).values()))
    value = {'expired': row['confirmation_expires_at_epoch'],
             'backward': row['confirmation_issued_at_epoch'] - 1, 'nan': float('nan')}[clock]
    monkeypatch.setattr(module.time, 'time', lambda: value)
    out = confirm(restart(setup), setup)
    assert out['reason_code'] == 'CONFIRMATION_EXPIRED_OR_CHANGED_REFRESH_REQUIRED'
    assert out['diagnostic_reason'] == 'CONFIRMATION_EXPIRED'
    assert next(iter(state(setup).values()))['phase'] == 'EXPIRED'


@pytest.mark.parametrize('field', ['confirmation_expires_at_epoch', 'confirmation_hash', 'host_id',
                                 'session_id', 'workspace_id', 'host_session_namespace'])
def test_unsigned_persistent_metadata_tampering_rejected_without_echo(setup, field):
    root, _, _, old, _, _ = setup
    path = old.state.path(root, 'codex', 'session')
    envelope = json.loads(path.read_bytes())
    next(iter(envelope['records'].values()))[field] = CANARY
    path.write_text(json.dumps(envelope))
    out = confirm(restart(setup), setup)
    assert out['diagnostic_reason'] == 'CONFIRMATION_STATE_INVALID'
    assert CANARY not in json.dumps(out) and str(root) not in json.dumps(out)


@pytest.mark.parametrize('kind', ['source', 'unrelated', 'policy', 'revision', 'task', 'family', 'scan'])
def test_cross_service_rechecks_original_bindings(setup, kind):
    root, runtime, _, old, _, _ = setup
    expected = 'CONFIRMATION_TASK_CHANGED'
    if kind == 'source':
        (root / 'A.java').write_text(UNSAFE + '// changed\n'); expected = 'CONFIRMATION_SNAPSHOT_CHANGED'
    elif kind == 'unrelated':
        (root / 'Other.java').write_text('class Other {}'); expected = 'CONFIRMATION_SNAPSHOT_CHANGED'
    elif kind in {'policy', 'revision'}:
        old.config.write('report_only' if kind == 'policy' else 'ask_before_fix'); expected = 'CONFIRMATION_POLICY_CHANGED'
    else:
        data = runtime.store.latest_scan(root)
        origin_id = data['scan_id']
        if kind == 'family': data['findings'][0]['technical_details']['rule_id'] = 'other.rule'
        elif kind == 'task': data['findings'][0]['id'] = 'different-member'
        else: data['scan_id'] = 'different-scan'
        with runtime.store._connect() as db:
            db.execute('UPDATE scans SET data=? WHERE id=?', (json.dumps(data), origin_id))
    out = confirm(restart(setup), setup)
    assert out['reason_code'] == 'CONFIRMATION_EXPIRED_OR_CHANGED_REFRESH_REQUIRED'
    assert out['diagnostic_reason'] == expected
    assert not setup[2].calls


@pytest.mark.parametrize('kind', ['workspace', 'token', 'session', 'family', 'task'])
def test_foreign_or_modified_capability_fails_closed(setup, tmp_path, kind):
    parts = pending(setup)['confirmation_ref'].split('.')
    changes = {}
    if kind == 'workspace': changes['root'] = tmp_path
    elif kind == 'task': changes['task_ref'] = 'T01'
    else:
        index = {'token':3,'session':1,'family':2}[kind]
        parts[index] = ('a' if parts[index][0] != 'a' else 'b') + parts[index][1:]
        changes['ref'] = '.'.join(parts)
    out = confirm(restart(setup), setup, **changes)
    assert out['reason_code'] == 'CONFIRMATION_REJECTED_REFRESH_REQUIRED'
    assert 'diagnostic_reason' in out and pending(setup)['confirmation_ref'] not in json.dumps(out)
    assert next(iter(state(setup).values()))['phase'] == 'PENDING_CONFIRMATION'


def test_deadline_bound_signed_state_and_no_sensitive_persistence(setup):
    row = next(iter(state(setup).values()))
    assert row['confirmation_expires_at_epoch'] - row['confirmation_issued_at_epoch'] == CONFIRMATION_TTL
    assert row['workspace_id'] == setup[3].state.workspace_directory(setup[0]).name
    assert row['host_session_namespace'] == setup[3].state.path(setup[0], 'codex', 'session').stem
    text = json.dumps(row)
    assert UNSAFE not in text and CANARY not in text
    assert pending(setup)['confirmation_ref'] not in text
    assert not {'source', 'secret', 'prompt', 'transcript', 'scanner_prose'} & row.keys()


@pytest.mark.parametrize('expires', [None, True, '900', float('inf'), 'too-long'])
def test_even_signed_invalid_deadline_cannot_authorize(setup, expires):
    root, _, _, service, _, _ = setup
    path = service.state.path(root, 'codex', 'session')
    with service.state.lock(root) as acquired:
        assert acquired
        key = service.state.key(root)
        rows = service._read(path, key)
        row = next(iter(rows.values()))
        row['confirmation_expires_at_epoch'] = row['confirmation_issued_at_epoch'] + 901 if expires == 'too-long' else expires
        service._save(path, rows, key)
    assert confirm(restart(setup), setup)['diagnostic_reason'] == 'CONFIRMATION_EXPIRED'


def test_persistent_pending_budget_cannot_reset_by_recreation(setup):
    root, _, _, service, _, _ = setup
    row = next(iter(state(setup).values()))
    with service.state.lock(root) as acquired:
        assert acquired
        key = service.state.key(root)
        for session in ['session', 'second']:
            rows = {session + str(i): dict(row, family_key=session+str(i)) for i in range(16)}
            service._save(service.state.path(root, 'codex', session), rows, key)
        new = restart(setup)
        assert new._pending(service.state.path(root, 'codex', 'third'), dict(row),
                            row['last_snapshot_digest'], key, 'ask_before_fix')['reason_code'] == 'CONFIRMATION_BUDGET_EXCEEDED'


def test_cross_service_concurrent_consumption_issues_only_one_grant(setup):
    services = [restart(setup), restart(setup)]
    barrier = Barrier(2)
    def consume(service):
        barrier.wait(timeout=10)
        return confirm(service, setup)
    with ThreadPoolExecutor(max_workers=2) as executor:
        outputs = list(executor.map(consume, services))
    assert sum(out.get('status') == 'AUTHORIZED' for out in outputs) == 1
    loser = next(out for out in outputs if out.get('status') != 'AUTHORIZED')
    assert loser['reason_code'] in {'REMEDIATION_BUSY', 'CONFIRMATION_ALREADY_CONSUMED'}
    assert sum(len(service.authorized) for service in services) == 1
