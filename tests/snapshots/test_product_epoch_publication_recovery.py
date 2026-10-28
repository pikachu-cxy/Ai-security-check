"""Real epoch publication and validated SessionStart recovery boundaries."""
import asyncio
from types import SimpleNamespace

import pytest
from security_runtime.product_epoch_capture import platform_supported

pytestmark = pytest.mark.skipif(not platform_supported(), reason="Historical product epochs require POSIX descriptor observations")

from security_runtime.global_mcp import GlobalWorkspaces, create_global_server
from security_runtime.global_workspace import read_bootstrap
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.mcp_server import create_server
from security_runtime.product_epoch_service import ProductEpochService
from security_runtime.tasks.ownership import session_owner
from test_global_integration import complete_runtime, projects  # noqa: F401


@pytest.fixture
def connection(projects, tmp_path):
    root = projects[0]
    runtime = complete_runtime()
    home = tmp_path/'connector-home'
    home.mkdir()
    # Installation ownership/fingerprints have their own integration tests.
    # Keep these actual transport/OS-lock tests independent of concurrent builds.
    integration = SimpleNamespace(home=home,
        configuration_status=lambda: {'overall': 'CONFIGURED'},
        inspect_project=lambda _root: [])

    def child(target, directory, binding):
        core = HookCoordinator(runtime, HookStateStore(directory/'hooks'))
        return create_server(runtime, hook_coordinator=core,
            workspace_binding=binding, global_mode=False), core

    pool = GlobalWorkspaces(base=tmp_path/'routing', integration=integration,
        child_factory=child)
    _, core = pool.admit(root)
    server = create_global_server(workspaces=pool)
    try:
        yield root, pool, server, core, runtime
    finally:
        pool.close()


def session_start(server, root, session):
    return asyncio.run(server.call_tool('handle_readiness_event', dict(
        event='SessionStart', workspace_path=str(root), session_id=session,
        permission_mode='default'))).structuredContent


def epoch_owner(service, ref):
    with service.store.db() as (db, key):
        return dict(service.store.load(db, key, ref=ref,
            policy=service.policy_digest)['issuer_owner'])


def seal(core, root, owner):
    product = ProductEpochService(core.store, root)
    status = product.ensure(owner)
    for _ in range(100):
        if status['state'] == 'SEALED':
            break
        status = product.step(owner)
    assert status['state'] == 'SEALED'
    product.close()
    return product, status


def test_sealed_epoch_publication_busy_recovers_on_same_real_session_start(connection):
    root, pool, server, core, runtime = connection
    session = 'publication-recovery'
    owner = session_owner('codex', session)
    product, sealed = seal(core, root, owner)
    ref = sealed['epoch_ref']
    original = product.lookup(ref, ['src/A.java'])
    primary = core.store.path(root, 'codex', session)
    # This is the real workspace OS lock, held by the caller while the real
    # executor attempts only the short session publication from another thread.
    with core.store.lock(root) as acquired:
        assert acquired
        first = session_start(server, root, session)
        assert first['status'] == 'DEGRADED'
        assert first['workspace_readiness']['reason_code'] == 'BASELINE_BUSY'
        assert not primary.exists()
    shared = pool.epoch_jobs.jobs[root]
    failed = pool.jobs[(root, pool.bind_session(session, root))]
    assert shared.result()['epoch_ref'] == ref
    for _ in range(3):
        assert pool.bootstrap(root, session)['status'] == 'DEGRADED'
        assert pool.jobs[(root, pool.bind_session(session, root))] is failed
    second = session_start(server, root, session)
    assert second['status'] == 'READY'
    assert second['host_claim_status'] == 'VALID'
    assert second['workspace_readiness']['product_epoch']['epoch_ref'] == ref
    assert pool.jobs[(root, pool.bind_session(session, root))] is not failed
    assert pool.epoch_jobs.jobs[root] is shared
    assert product.lookup(ref, ['src/A.java']) == original
    assert epoch_owner(product, ref) == owner
    state, corrupt = core.store.load(primary)
    assert not corrupt and state['epoch_ref'] == ref
    assert state['policy_digest'] == sealed['policy_digest']
    assert not runtime.calls
    assert second['security_proof'] is False
    assert second['workspace_readiness']['task_baseline_ready'] is False


def test_initial_ensure_capacity_pause_resumes_the_existing_epoch(connection, monkeypatch):
    from security_runtime import product_epoch_store
    root, pool, server, core, runtime = connection
    session = 'capacity-recovery'
    owner = session_owner('codex', session)
    product = ProductEpochService(core.store, root)
    original = product.ensure(owner)
    limit = product_epoch_store.MAX_DATABASE_BYTES
    monkeypatch.setattr(product_epoch_store, 'MAX_DATABASE_BYTES', product.store.path.stat().st_size-1)
    first = session_start(server, root, session)
    assert first['status'] == 'DEGRADED'
    readiness = first['workspace_readiness']
    assert readiness['reason_code'] == 'BASELINE_CAPACITY_WAIT'
    assert readiness['product_epoch']['state'] == 'WAITING_CAPACITY'
    assert readiness['product_epoch']['epoch_ref'] == original['epoch_ref']
    assert not core.store.path(root, 'codex', session).exists()
    monkeypatch.setattr(product_epoch_store, 'MAX_DATABASE_BYTES', limit)
    recovered = session_start(server, root, session)
    assert recovered['status'] == 'READY'
    assert recovered['workspace_readiness']['product_epoch']['epoch_ref'] == original['epoch_ref']
    assert epoch_owner(product, original['epoch_ref']) == owner
    assert not runtime.calls


def test_real_no_progress_pause_is_presented_and_resumes_original_epoch(connection, monkeypatch):
    from security_runtime import product_epoch_jobs
    root, pool, server, core, runtime = connection
    session = 'progress-recovery'
    owner = session_owner('codex', session)
    blocked = {'value': True}
    enumerate_source = ProductEpochService._enumerate

    def no_entries(current, db, key, header, deadline, units):
        if blocked['value']:
            return units
        return enumerate_source(current, db, key, header, deadline, units)

    monkeypatch.setattr(ProductEpochService, '_enumerate', no_entries)
    monkeypatch.setattr(product_epoch_jobs, 'MAX_NO_PROGRESS_TURNS', 2)
    first = session_start(server, root, session)
    assert first['status'] == 'DEGRADED'
    readiness = first['workspace_readiness']
    assert readiness['reason_code'] == first['bootstrap_reason'] == 'BASELINE_PROGRESS_WAIT'
    assert readiness['product_epoch']['state'] == 'WAITING_PROGRESS'
    ref = readiness['product_epoch']['epoch_ref']
    assert read_bootstrap(root, base=pool.base)['reason_code'] == 'BASELINE_PROGRESS_WAIT'
    from security_runtime.integration_readiness import readiness_message
    message = readiness_message(first['status'], readiness['reason_code'])
    assert '没有进展' in message and '具体原因未能确定' not in message
    product = ProductEpochService(core.store, root)
    assert product.status(epoch_ref=ref)['state'] == 'ENUMERATING'
    assert epoch_owner(product, ref) == owner
    blocked['value'] = False
    second = session_start(server, root, session)
    assert second['status'] == 'READY'
    assert second['workspace_readiness']['product_epoch']['epoch_ref'] == ref
    assert epoch_owner(product, ref) == owner
    assert not runtime.calls


def test_missing_epoch_history_is_not_recreated_by_session_start(connection):
    root, pool, server, core, runtime = connection
    session = 'missing-history'
    product, sealed = seal(core, root, session_owner('codex', session))
    product.store.path.unlink()
    first = session_start(server, root, session)
    assert first['status'] == 'DEGRADED'
    assert first['workspace_readiness']['reason_code'] == 'BASELINE_HISTORY_UNAVAILABLE'
    failed = pool.jobs[(root, pool.bind_session(session, root))]
    shared = pool.epoch_jobs.jobs[root]
    for _ in range(2):
        repeated = session_start(server, root, session)
        assert repeated['status'] == 'DEGRADED'
        assert pool.jobs[(root, pool.bind_session(session, root))] is failed
        assert pool.epoch_jobs.jobs[root] is shared
        assert not product.store.path.exists()
        assert not core.store.path(root, 'codex', session).exists()
    assert not runtime.calls


def test_publication_retry_requires_the_original_epoch_history(connection):
    root, pool, server, core, runtime = connection
    session = 'publication-history-lost'
    product, _ = seal(core, root, session_owner('codex', session))
    with core.store.lock(root) as acquired:
        assert acquired
        first = session_start(server, root, session)
        assert first['status'] == 'DEGRADED'
    failed = pool.jobs[(root, pool.bind_session(session, root))]
    product.store.path.unlink()
    repeated = session_start(server, root, session)
    assert repeated['status'] == 'DEGRADED'
    assert pool.jobs[(root, pool.bind_session(session, root))] is failed
    assert not product.store.path.exists()
    assert not core.store.path(root, 'codex', session).exists()
    assert not runtime.calls


@pytest.fixture(autouse=True)
def explicit_legacy_comparison_mode(monkeypatch):
    initialize = GlobalWorkspaces.__init__
    def legacy_initialize(self, *args, **kwargs):
        kwargs.setdefault("task_audit_mode", False)
        initialize(self, *args, **kwargs)
    monkeypatch.setattr(GlobalWorkspaces, "__init__", legacy_initialize)
