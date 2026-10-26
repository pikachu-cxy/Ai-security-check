"""Check feedback neither grants new operations nor cancels authorized work."""
import asyncio
import copy
import json

import pytest

from security_runtime.baseline_seed import WorkspaceBaselineSeeds
from security_runtime.bootstrap_diagnostics import BaselinePreparationError
from security_runtime.global_mcp import create_global_server
from security_runtime.hook_reply_context import (
    CHECK_OPERATION_BOUNDARIES, CONTROL_DELIMITER, MAX_CONTEXT_BYTES,
    MAX_CONTEXT_CHARS, render_check_gap_context, render_hook_context,
)
from test_codex_host_claims import claims
from test_global_integration import installed, projects, pool_fixture, ready


def assert_operation_boundary(context):
    assert CHECK_OPERATION_BOUNDARIES in context
    # Keep both halves: check feedback cannot create authority, but an existing
    # development/testing request must not be revoked by that feedback either.
    assert '不得伪造检查结果、重放检查事件或补建编辑后的基线' in context
    assert '检查状态本身不授予额外扫描、构建或测试权限' in context
    assert '不得仅因检查异常或复查结束而擅自追加这些操作' in context
    assert '用户已明确要求或当前开发任务已包含的测试、构建与验收仍按原授权执行' in context
    assert '无需重复确认' in context
    assert '不运行构建测试' not in context
    assert '不安排构建或测试' not in context
    assert '或自动运行构建和测试' not in context


def test_local_check_gap_keeps_authorized_work_and_never_issues_an_action():
    summary = dict(status='INCONCLUSIVE', coverage='UNKNOWN', scanner_run=False)
    original = copy.deepcopy(summary)
    message = '本次修改的安全检查尚未完成，原有任务记录保留。'

    rendered = render_check_gap_context(summary, message)
    notice, encoded = rendered.split(CONTROL_DELIMITER, 1)
    control = json.loads(encoded)

    assert notice.startswith('用户提示\n' + message)
    assert_operation_boundary(notice)
    assert control['scanner_run'] is False
    assert 'remediation' not in control
    assert '仅当本轮实际修改源代码或配置' in notice
    assert '普通聊天、只读或未改动文件时不展示' in notice
    assert summary == original
    assert len(rendered) <= MAX_CONTEXT_CHARS
    assert len(rendered.encode('utf-8')) <= MAX_CONTEXT_BYTES


def test_resolved_feedback_preserves_security_receipt_without_cancelling_builds():
    receipt = dict(status='SCANNER_VERIFIED_RESOLVED', phase='CLOSED',
                   task_ref='task.exact', grant_id='grant.exact')
    decision = dict(action='NONE', reason_code='SCANNER_VERIFIED_RESOLVED',
                    security_verification=receipt,
                    verification_summary=dict(security='原问题安全复查已通过。'))
    original = copy.deepcopy(decision)

    rendered = render_hook_context({}, decision, '原问题安全复查已通过。')
    notice, encoded = rendered.split(CONTROL_DELIMITER, 1)
    control = json.loads(encoded)

    assert_operation_boundary(notice)
    assert '不暂停原开发任务' in notice
    assert '不因安全复查结束而追加测试推荐、执行选择或新的修复确认' in notice
    assert '不推断业务兼容性或生产安全' in notice
    assert control['remediation']['security_verification'] == receipt
    assert control['remediation']['action'] == 'NONE'
    assert not {'prepare', 'verify', 'confirmation_ref', 'remediation_ref'} & control['remediation'].keys()
    assert decision == original
    assert len(rendered) <= MAX_CONTEXT_CHARS
    assert len(rendered.encode('utf-8')) <= MAX_CONTEXT_BYTES


@pytest.mark.parametrize('entry', ['handle_hook_event', 'handle_readiness_event'])
def test_legacy_global_gap_keeps_task_permissions_without_rescan_or_fabricated_baseline(
        installed, projects, tmp_path, monkeypatch, entry):
    root = projects[0]
    pool = pool_fixture(installed, tmp_path)
    pool.task_audit_mode = False  # Only explicit legacy comparison mode creates this baseline.
    captures = []

    def busy(*args, **kwargs):
        captures.append(True)
        raise BaselinePreparationError('BASELINE_BUSY')

    # Inject the failure at today's comparison-worker entry, independent of
    # whether the test platform supports its full-source capture provider.
    monkeypatch.setattr(pool.epoch_jobs, 'start', busy)
    try:
        assert ready(pool, root, 's')['status'] == 'DEGRADED'
        core = pool.children[root][1]
        assert core.runtime.calls == []
        snapshot_path = core.store.path(root, 'codex', 's')
        assert not snapshot_path.exists()

        def unexpected_scan(*args, **kwargs):
            pytest.fail('A check-gap presentation cannot start another scan')

        monkeypatch.setattr(core.runtime, 'scan', unexpected_scan)
        server = create_global_server(workspaces=pool)
        if entry == 'handle_hook_event':
            (root / 'src/A.java').write_text('class A { int afterEdit; }\n')
            arguments = claims(root)
            arguments.update(tool_name='apply_patch', tool_input={})
        else:
            arguments = dict(event='SessionStart', workspace_path=str(root),
                             session_id='s', permission_mode='default')

        reply = asyncio.run(server.call_tool(entry, arguments))
        payload = json.loads(reply.content[0].text)
        context = payload['hookSpecificOutput']['additionalContext']

        assert_operation_boundary(context)
        assert '不取消当前开发任务核查' in context
        assert '已有任务沿用原引用' in context
        assert reply.structuredContent.get('scanner_run') is not True
        if entry == 'handle_hook_event':
            assert reply.structuredContent['scanner_run'] is False
        else:
            assert reply.structuredContent['security_proof'] is False
        plan = reply.structuredContent['reply_plan']
        assert plan['grants_authority'] is False
        assert plan['required_actions'] == []
        assert captures == [True]
        assert not snapshot_path.exists()
    finally:
        pool.close()
