"""Global product observations are shared, with read-only cold diagnostics."""
import asyncio
from types import SimpleNamespace

import pytest
from security_runtime.product_epoch_capture import platform_supported

pytestmark = pytest.mark.skipif(not platform_supported(), reason="Historical product epochs require POSIX descriptor observations")

from security_runtime.global_mcp import GlobalWorkspaces, create_global_server
from security_runtime.global_workspace import workspace_state
from security_runtime.hook_state import HookStateStore
from security_runtime.product_epoch_service import ProductEpochService
from security_runtime.tasks.ownership import session_owner
from test_global_integration import installed, projects, pool_fixture, ready
from test_codex_host_claims import connected, claims


def query(server, path):
    return asyncio.run(server.call_tool('get_product_epoch_status',
        {'workspace_path': str(path)})).structuredContent


def bytes_and_times(parent):
    return {p: (p.read_bytes(), p.stat().st_mtime_ns)
            for p in parent.rglob('*') if p.is_file()}


def test_cold_query_and_rejected_root_never_admit_or_create_state(tmp_path, monkeypatch):
    root, home = tmp_path/'project', tmp_path/'codex-home'
    root.mkdir(); home.mkdir()
    (root/'pyproject.toml').write_text('[project]\nname="fixture"\n')
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'runtime'))
    pool = GlobalWorkspaces(base=tmp_path/'routing', integration=SimpleNamespace(home=home))
    for name in ('admit', 'bootstrap'):
        monkeypatch.setattr(pool, name, lambda *a, **k: pytest.fail('Read-only query cannot admit'))
    server = create_global_server(workspaces=pool)
    before, paths = bytes_and_times(tmp_path), set(tmp_path.rglob('*'))
    try:
        for _ in range(2):
            result = query(server, root)
            assert result['path_status'] == 'ALLOWED'
            assert result['state_modified'] is False
            assert result['strict_task_preimage_eligible'] is False
            assert query(server, home)['path_status'] == 'REJECTED'
        assert bytes_and_times(tmp_path) == before
        assert set(tmp_path.rglob('*')) == paths
        assert not pool.children and not pool.sessions and not pool.jobs and not pool.epoch_jobs.jobs
    finally:
        pool.close()


def test_three_new_sessions_use_one_root_epoch_without_full_tree_capture(
        installed, projects, tmp_path, monkeypatch):
    pool = pool_fixture(installed, tmp_path)
    root = projects[0]
    try:
        _, core = pool.admit(root)
        monkeypatch.setattr(core, 'snapshot_capture',
            lambda *a, **k: pytest.fail('Product baseline must not use legacy full-tree capture'))
        for name in ('first', 'second', 'third'):
            pool.bootstrap(root, name)
        results = [ready(pool, root, name) for name in ('first', 'second', 'third')]
        assert all(r['status'] == 'READY' for r in results), [
            (r['status'], r.get('reason_code'), r.get('baseline_status')) for r in results]
        refs = {r['product_epoch']['epoch_ref'] for r in results}
        assert len(refs) == len(pool.epoch_jobs.jobs) == 1
        assert all(r['task_baseline_ready'] is False for r in results)
        assert all(r['product_epoch']['consistency'] == 'OBSERVED_ONLY' for r in results)
        assert all(r['product_epoch']['strict_task_preimage_eligible'] is False for r in results)
        server = create_global_server(workspaces=pool)
        before = bytes_and_times(pool.base)
        for _ in range(2):
            status = query(server, root)
            assert status['epoch_status']['epoch_ref'] in refs
            assert status['epoch_status']['state'] == 'SEALED'
            assert not status['state_modified'] and not status['scanner_run']
        assert bytes_and_times(pool.base) == before
    finally:
        pool.close()


def test_sealed_query_does_not_advance_or_restart_an_epoch(tmp_path, monkeypatch):
    root, home = tmp_path/'project', tmp_path/'codex-home'
    root.mkdir(); home.mkdir()
    (root/'pyproject.toml').write_text('[project]\nname="fixture"\n')
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'runtime'))
    pool = GlobalWorkspaces(base=tmp_path/'routing', integration=SimpleNamespace(home=home))
    try:
        hooks = HookStateStore(workspace_state(root, pool.base)/'hooks')
        service = ProductEpochService(hooks, root)
        owner = session_owner('codex', 'creator')
        status = service.ensure(owner)
        for _ in range(100):
            if status['state'] == 'SEALED':
                break
            status = service.step(owner)
        assert status['state'] == 'SEALED'
        server = create_global_server(workspaces=pool)
        before = bytes_and_times(pool.base)
        (root/'later.py').write_text('later = True\n')
        result = query(server, root)
        assert result['epoch_status']['epoch_ref'] == status['epoch_ref']
        assert result['epoch_status']['counts'] == status['counts']
        assert bytes_and_times(pool.base) == before
        assert not pool.children and not pool.sessions and not pool.jobs
    finally:
        pool.close()


def test_real_per_edit_before_is_independent_of_global_product_readiness(connected, projects, monkeypatch):
    from security_runtime.tasks.security import TaskSecurityService
    server, pool, _ = connected
    root = projects[1]
    _, core = pool.admit(root)
    for index in range(600):
        (root/f'module_{index}.py').write_text('value = 1\n')
    actor = session_owner('codex', 'pending-product')
    product = ProductEpochService(core.store, root)
    original_epoch = product.ensure(actor)['epoch_ref']
    tasks = TaskSecurityService(core.runtime, core.store, owner=actor)
    begun = tasks.begin(root, 'independent-real-before')
    assert begun['status'] == 'ACTIVE'
    task_ref = begun['task_ref']
    (root/'src/A.java').write_text('class A { int edited; }\n')
    monkeypatch.setattr(pool, 'bootstrap',
        lambda *a, **k: pytest.fail('An original task before does not wait for product readiness'))
    args = claims(root)
    args.update(session_id='pending-product', tool_name='Edit', tool_input={'path':'src/A.java'})
    result = asyncio.run(server.call_tool('handle_hook_event', args)).structuredContent
    assert result['scanner_run'] is True
    assert result['security_task_ref'] == task_ref
    assert tasks.before_lines(root, tasks.load(root, task_ref), 'src/A.java') == ['class A {}']
    assert product.status()['epoch_ref'] == original_epoch
    assert core.store.load(core.store.path(root, 'codex', 'pending-product'))[0] is None
    assert core.store.scan_path(root, 'codex', 'pending-product').is_file()


@pytest.fixture(autouse=True)
def explicit_legacy_comparison_mode(monkeypatch):
    initialize = GlobalWorkspaces.__init__
    def legacy_initialize(self, *args, **kwargs):
        kwargs.setdefault("task_audit_mode", False)
        initialize(self, *args, **kwargs)
    monkeypatch.setattr(GlobalWorkspaces, "__init__", legacy_initialize)
