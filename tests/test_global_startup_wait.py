"""Real router/worker ordering, isolated from the user's native trial records."""
import asyncio
import json
import threading

from security_runtime.global_mcp import create_global_server
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from test_global_integration import (
    _Child, complete_runtime, installed, projects, pool_fixture,
)


def startup(root):
    return dict(event='SessionStart', workspace_path=str(root), session_id='startup')


def blocked_pool(installed, tmp_path):
    started, release = threading.Event(), threading.Event()
    calls = []

    def factory(root, directory, binding):
        core = HookCoordinator(complete_runtime(), HookStateStore(directory / 'hooks'))
        original = core._scan_scope

        def scan(*args, **kwargs):
            calls.append(root)
            started.set()
            assert release.wait(10)
            return original(*args, **kwargs)

        core._scan_scope = scan
        return _Child(binding).server, core

    return pool_fixture(installed, tmp_path, factory), started, release, calls


def test_session_start_waits_for_pre_edit_publication(installed, projects, tmp_path):
    pool, started, release, calls = blocked_pool(installed, tmp_path)
    root = projects[0]
    original = (root / 'src/A.java').read_bytes()
    server = create_global_server(workspaces=pool)

    async def exercise():
        task = asyncio.create_task(server.call_tool('handle_readiness_event', startup(root)))
        assert await asyncio.to_thread(started.wait, 5)
        assert not task.done()
        release.set()
        return await task

    try:
        response = asyncio.run(exercise())
        assert response.structuredContent['status'] == 'READY'
        core = pool.children[root][1]
        snapshot, _ = core.store.load(core.store.path(root, 'codex', 'startup'))
        assert snapshot['last_result']['status'] == 'PRE_EXISTING_BASELINE'
        assert (root / 'src/A.java').read_bytes() == original
        assert calls == [root]
        assert 'hookSpecificOutput' not in json.loads(response.content[0].text)
        assert pool.bootstrap(root, 'startup')['status'] == 'READY'
        assert calls == [root]
    finally:
        release.set()
        pool.close()


def test_startup_timeout_keeps_worker_and_exposes_gap(installed, projects, tmp_path, monkeypatch):
    monkeypatch.setattr('security_runtime.global_mcp.BOOTSTRAP_WAIT_SECONDS', .02)
    pool, started, release, calls = blocked_pool(installed, tmp_path)
    root = projects[0]
    server = create_global_server(workspaces=pool)
    try:
        response = asyncio.run(server.call_tool('handle_readiness_event', startup(root)))
        assert response.structuredContent['status'] == 'INITIALIZING'
        assert response.structuredContent['security_proof'] is False
        payload = json.loads(response.content[0].text)
        assert payload['hookSpecificOutput']['hookEventName'] == 'SessionStart'
        assert '若本轮实际编辑' in payload['hookSpecificOutput']['additionalContext']
        assert payload['continue'] is True
        future = pool.jobs[(root, pool.bind_session('startup', root))]
        assert not future.cancelled()
        release.set()
        assert future.result(timeout=10)['status'] == 'READY'
        assert pool.bootstrap(root, 'startup')['status'] == 'READY'
        assert calls == [root]
    finally:
        release.set()
        pool.close()


def test_startup_failure_is_explicit_without_retry_or_raw_exception(installed, projects, tmp_path):
    pool = pool_fixture(installed, tmp_path)
    root = projects[0]
    calls = []

    def fail(*args):
        calls.append(root)
        return {'status': 'DEGRADED', 'reason_code': 'BASELINE_CHECK_INCONCLUSIVE', 'security_proof': False}

    pool._initialize = fail
    server = create_global_server(workspaces=pool)
    try:
        response = asyncio.run(server.call_tool('handle_readiness_event', startup(root)))
        assert response.structuredContent['status'] == 'DEGRADED'
        payload = json.loads(response.content[0].text)
        assert '不能证明' in payload['systemMessage']
        assert payload['systemMessage'] in payload['hookSpecificOutput']['additionalContext']
        assert response.structuredContent['security_proof'] is False
        assert calls == [root]
        assert pool.bootstrap(root, 'startup')['status'] == 'DEGRADED'
        assert calls == [root]
    finally:
        pool.close()
