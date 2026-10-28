"""Legacy scanner consumers never read or overwrite product epoch bindings."""
import copy

import pytest
from security_runtime.product_epoch_capture import platform_supported

pytestmark = pytest.mark.skipif(not platform_supported(), reason="Historical product epochs require POSIX descriptor observations")

from security_runtime.baseline_seed import WorkspaceBaselineSeeds
from security_runtime.bootstrap_diagnostics import BaselinePreparationError
from security_runtime.closeout_persistence import hook_revision
from security_runtime.closeout_state import CloseoutStateStore
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.private_authority import revision
from security_runtime.remediation_recovery import refresh_confirmation
from test_closeout_regression import closeout_fixture
from test_confirmation import pending, state
from test_hook_runtime import repo  # noqa: F401
from test_remediation import setup  # noqa: F401
from test_secret_recheck_coverage import secret_engine  # noqa: F401


def product_session(hooks, root, runtime, *, host='codex', session='session', keep_scanner=True):
    path = hooks.path(root, host, session)
    cache = hooks.scan_path(root, host, session)
    if path.exists():
        if keep_scanner:
            cache.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            path.rename(cache)
        else:
            path.unlink()
    coordinator = HookCoordinator(runtime, hooks)
    for _ in range(32):
        result = coordinator.handle_lifecycle('SESSION_START', root, host, session)
        if result['baseline_publish_status'] == 'PUBLISHED':
            break
    else:
        pytest.fail('Product session did not bind its finite observation')
    value, corrupt = hooks.load(path)
    assert not corrupt and value['schema_version'] == 'hook-product-epoch-v1'
    return path, cache, path.read_bytes(), value


def test_closeout_prepare_and_run_use_strict_cache_and_preserve_main_epoch(secret_engine, tmp_path):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    path, cache, original, epoch = product_session(service.hooks, root, service.runtime)
    prepared = service.prepare(root, host='codex', session='session')
    assert len(prepared['original_recheck_scope']) == 2
    job = service._store(root).get(prepared['closeout_ref'], service._workspace(root))
    assert job['details']['scanner_cache_kind'] == 'SCAN_SESSION'
    assert job['details']['product_epoch_binding'] == hook_revision(service._read_key(root), epoch)
    result = service.run(prepared['closeout_ref'], root)
    assert result['status'] == 'COMPLETED' and result['receipt']['risk_fix_complete']
    assert path.read_bytes() == original
    retained, corrupt = service.hooks.load(cache)
    assert not corrupt and retained['schema_version'] == 'hook-v1'
    assert retained['families'] == {}
    assert retained['last_result']['delta']['resolved'] == 2


def test_product_only_session_does_not_supply_scanner_families(secret_engine, tmp_path):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    path, cache, original, _ = product_session(service.hooks, root, service.runtime, keep_scanner=False)
    result = service.prepare(root, ['fixture.ts'], host='codex', session='session')
    assert result['original_recheck_scope'] == []
    assert not cache.exists() and path.read_bytes() == original


def test_target_before_ack_closeout_recovery_replays_strict_cache_without_scanning(
        secret_engine, tmp_path, monkeypatch):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    path, cache, original, _ = product_session(service.hooks, root, service.runtime)
    service.hooks.pending_activity(root, 'codex', 'session', mark=True)
    prepared = service.prepare(root, ['fixture.ts'], host='codex', session='session')
    acknowledge = CloseoutStateStore.acknowledge_effect

    def unavailable(*args, **kwargs):
        raise OSError('Fixture source acknowledgement unavailable')

    monkeypatch.setattr(CloseoutStateStore, 'acknowledge_effect', unavailable)
    first = service.run(prepared['closeout_ref'], root)
    assert first['status'] == 'NEEDS_RETRY'
    assert first['receipt']['persistence_sync']['state'] == 'PENDING'
    assert path.read_bytes() == original
    monkeypatch.setattr(CloseoutStateStore, 'acknowledge_effect', acknowledge)
    monkeypatch.setattr(service.runtime, 'scan', lambda *a, **k: pytest.fail('Recovery must not rescan'))
    recovered = service.run(prepared['closeout_ref'], root)
    assert recovered['status'] == 'COMPLETED' and recovered['recovered']
    assert recovered['receipt']['persistence_sync']['state'] == 'APPLIED'
    assert recovered['receipt']['risk_fix_complete']
    assert path.read_bytes() == original
    assert service.hooks.load(cache)[0]['families'] == {}


def test_historical_main_cache_effect_does_not_retarget_or_modify_a_product_epoch(secret_engine, tmp_path):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    path, cache, original, epoch = product_session(service.hooks, root, service.runtime)
    cache_bytes = cache.read_bytes()
    authority = service.closures._authority(root)
    with service.hooks.lock(root) as acquired:
        assert acquired
        value = authority.read()
        before = revision(value)
        effect = dict(file=path.name, host=epoch['host'], session_id=epoch['session_id'],
            workspace_id=epoch['workspace_id'], expected_version=revision(epoch))
        value['outbox'][revision(effect)] = effect
        authority.save(value, before)
        assert service.closures.reconcile_caches(root)['state'] == 'APPLIED'
    assert path.read_bytes() == original
    assert cache.read_bytes() == cache_bytes


def test_product_epoch_revision_fences_ref_policy_and_comparison_cursor(secret_engine, tmp_path):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    _, _, _, epoch = product_session(service.hooks, root, service.runtime)
    key = service._read_key(root)
    original = hook_revision(key, epoch)
    for name, value in [('epoch_ref', 'pe1-'+'f'*32), ('policy_digest', 'f'*64),
                        ('last_processed_ref', 'f'*64)]:
        other = dict(epoch, **{name: value})
        assert hook_revision(key, other) != original


@pytest.mark.parametrize('explicit_coordinator', [False, True])
def test_product_epoch_cannot_be_returned_or_recaptured_as_legacy_scanner_seed(
        secret_engine, tmp_path, monkeypatch, explicit_coordinator):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    root = secret_engine[0]
    path, _, original, _ = product_session(service.hooks, root, service.runtime)
    core = HookCoordinator(service.runtime, service.hooks)
    if not explicit_coordinator:
        monkeypatch.setattr('security_runtime.hook_runtime.HookCoordinator', lambda: core)
    seeds = WorkspaceBaselineSeeds(coordinator=core if explicit_coordinator else None)
    monkeypatch.setattr(core, '_scan_scope', lambda *a, **k: pytest.fail('Epoch cannot trigger seed recapture'))
    operations = [lambda: seeds.capture_session(root, 'session')]
    if explicit_coordinator:
        operations.append(lambda: seeds.existing_session(root, 'session'))
    for operation in operations:
        with pytest.raises(BaselinePreparationError, match='BASELINE_COVERAGE_INSUFFICIENT'):
            operation()
    assert path.read_bytes() == original


@pytest.mark.parametrize('setup', ['ask_before_fix'], indirect=True)
@pytest.mark.parametrize('keep_scanner', [False, True])
def test_confirmation_recovery_uses_only_real_strict_scanner_cache(setup, keep_scanner):
    root, runtime, _, remediation, _, _ = setup
    path, _, original, _ = product_session(remediation.hooks, root, runtime, keep_scanner=keep_scanner)
    before = copy.deepcopy(state(setup))
    current = runtime.store.latest_scan(root)
    output = refresh_confirmation(remediation, pending(setup)['task_ref'], current['scan_id'], root)
    if keep_scanner:
        assert output['status'] == 'PENDING_CONFIRMATION'
        assert output['issues_edit_grant'] is False
    else:
        assert output['diagnostic_reason'] == 'CONFIRMATION_RECOVERY_HOOK_SCAN_NOT_CURRENT'
        assert state(setup) == before
    assert path.read_bytes() == original
    assert not remediation.authorized and not remediation.prepared
