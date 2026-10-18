"""Closure facts, legacy fences and exact-session cache delivery recover safely."""
import copy
from dataclasses import asdict

import pytest

from security_runtime.closeout_state import digest, encode
from security_runtime.hook_state import atomic_bytes
from security_runtime.private_authority import revision
from test_secret_recheck_coverage import secret_engine, recheck  # noqa: F401
from test_closeout_regression import closeout_fixture


def test_cache_failure_retains_signed_fact_and_recovers_only_original_session(secret_engine,tmp_path,monkeypatch):
    service,findings,run = closeout_fixture(secret_engine,tmp_path)
    root = secret_engine[0]
    closure = service.closures
    results = recheck(secret_engine,findings,run)
    path = service.hooks.path(root,'codex','session')
    before, _ = service.hooks.load(path)
    original_save = service.hooks.save
    monkeypatch.setattr(service.hooks,'save',lambda *a: (_ for _ in ()).throw(OSError('cache target failed')))
    with pytest.raises(OSError,match='cache target failed'):
        closure.record(root,[asdict(row) for row in findings],results,source='MANUAL_INDEPENDENT_RECHECK')
    authority = closure._authority(root)
    saved = authority.read()
    assert len(saved['records']) == 2 and len(saved['outbox']) == 1
    assert service.hooks.load(path)[0] == before
    private_before = {str(p):p.read_bytes() for p in authority.directory.rglob('*') if p.is_file()}
    assert len(closure.statuses(root)) == 2
    assert {str(p):p.read_bytes() for p in authority.directory.rglob('*') if p.is_file()} == private_before
    monkeypatch.setattr(service.hooks,'save',original_save)
    with service.hooks.lock(root) as held:
        assert held
        assert closure.reconcile_caches(root) == dict(state='APPLIED',pending=0)
    assert not service.hooks.load(path)[0]['families']
    assert authority.read()['records'] == saved['records']


def test_old_cache_effect_cannot_replace_a_newer_snapshot(secret_engine,tmp_path,monkeypatch):
    service,findings,run = closeout_fixture(secret_engine,tmp_path)
    root = secret_engine[0]
    closure = service.closures
    original_save = service.hooks.save
    monkeypatch.setattr(service.hooks,'save',lambda *a: (_ for _ in ()).throw(OSError('cache failed')))
    with pytest.raises(OSError):
        closure.record(root,[asdict(row) for row in findings],recheck(secret_engine,findings,run),
                       source='MANUAL_INDEPENDENT_RECHECK')
    monkeypatch.setattr(service.hooks,'save',original_save)
    path = service.hooks.path(root,'codex','session')
    newer, _ = service.hooks.load(path)
    newer['last_completed_at'] += 1
    original_save(path,newer)
    newer_bytes = path.read_bytes()
    with service.hooks.lock(root) as held:
        assert held
        closure.reconcile_caches(root)
    assert path.read_bytes() == newer_bytes
    assert closure._authority(root).read()['outbox'] == {}


def test_legacy_closure_data_is_authenticated_preserved_and_fenced(secret_engine,tmp_path):
    service,findings,run = closeout_fixture(secret_engine,tmp_path)
    root = secret_engine[0]
    closure = service.closures
    originals = [asdict(row) for row in findings]
    results = recheck(secret_engine,findings,run)
    # Create the exact historical envelope using a real previously accepted
    # closure fact, then move only these disposable fixture facts to old layout.
    closure.record(root,originals,results,source='MANUAL_INDEPENDENT_RECHECK')
    authority = closure._authority(root)
    records = copy.deepcopy(closure._read(root))
    legacy = encode(dict(records=records,mac=digest(service.hooks.key(root),records)))
    # A second fresh private store holds an actual v1 layout, never live state.
    from security_runtime.hook_state import HookStateStore
    from security_runtime.risk_closure import RiskClosureService
    hooks = HookStateStore(tmp_path/'old-private')
    old_closure = RiskClosureService(hooks)
    old_authority = old_closure._authority(root)
    atomic_bytes(old_authority.old,encode(dict(records=records,mac=digest(hooks.key(root),records))))
    old_bytes = old_authority.old.read_bytes()
    assert old_closure._read(root) == records and old_authority.old.is_file()
    old_closure.record(root,originals,results,source='MANUAL_INDEPENDENT_RECHECK')
    assert old_authority.old.is_dir() and old_authority.receipt.is_file()
    assert old_authority.backup.read_bytes() == old_bytes
    assert old_authority.moved.read_bytes() == old_bytes
    before = old_authority.path.read_bytes()
    with pytest.raises(OSError): atomic_bytes(old_authority.old,legacy)
    assert old_authority.path.read_bytes() == before and old_closure._read(root) == records
