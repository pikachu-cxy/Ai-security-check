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
        payload=json.loads(response.content[0].text)
        assert response.structuredContent['task_session_ref'] in payload['hookSpecificOutput']['additionalContext']
        assert response.structuredContent['task_session_ref'] not in payload['systemMessage']
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
        context = payload['hookSpecificOutput']['additionalContext']
        assert '仅当本轮实际修改了源代码或配置' in context
        assert '该改动的检查在总结时仍未完成' in context
        assert '不能称检查通过' in context and '普通聊天、只读操作和未改动文件的操作不展示' in context
        assert '其他轮次不重复沿用' in context
        assert '不得伪造检查结果、重放检查事件或补建编辑后的基线' in context
        assert '用户已明确要求或当前开发任务已包含的测试、构建与验收仍按原授权执行' in context
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
        assert '自动安全检查未启动' in payload['systemMessage']
        assert '具体原因未能确定' in payload['systemMessage']
        assert '保留当前会话和已有任务记录' in payload['systemMessage']
        assert '新建聊天' not in payload['systemMessage']
        assert payload['systemMessage'] in payload['hookSpecificOutput']['additionalContext']
        assert response.structuredContent['security_proof'] is False
        assert calls == [root]
        assert pool.bootstrap(root, 'startup')['status'] == 'DEGRADED'
        assert calls == [root]
    finally:
        pool.close()
