"""Cursor task preparation and bounded feedback. No scanner or repair authority here."""
from __future__ import annotations

import json
from pathlib import Path

from .hook_state import identity
from .task_security import TaskSecurityService, capture, digest_value


class CursorTaskBridge:
    def __init__(self, core, root, session, generation):
        self.core, self.root = core, root
        self.owner = dict(host='cursor', session=identity(session))
        self.session=session
        self.key = 'cursor:' + identity(session + '\x00' + generation)
        self.tasks = TaskSecurityService(core.runtime, hooks=core.store,owner=self.owner)

    def current(self):
        store = self.tasks.store(self.root)
        active = store.get(active=True,owner=self.owner)
        if active:
            from .task_ownership import record_owner
            if record_owner(active) != self.owner:
                raise ValueError('CURSOR_TASK_OWNER_CONFLICT')
            return active
        record = store.get(task_key=self.tasks.key(self.key,self.owner))
        if record and (record.get('task_owner') or record.get('connector_owner')) == self.owner:
            return record
        return None

    @staticmethod
    def is_begin_tool(name):
        return isinstance(name, str) and name in {
            "MCP:begin_security_task",
            "MCP:ai-security-runtime:begin_security_task",
            "MCP:ai_security_runtime:begin_security_task",
            "MCP:mcp_ai-security-runtime_begin_security_task",
            "MCP:mcp_ai_security_runtime_begin_security_task",
        }

    def before(self, payload):
        name, inputs = payload['tool_name'], payload.get('tool_input', {})
        task_key = self.key
        preparing = self.is_begin_tool(name)
        if preparing:
            # Prepare the exact MCP request before it runs. Its normal begin is
            # idempotent; never adopt an unowned task or capture after an edit.
            if not isinstance(inputs, dict):
                return dict(status='BASELINE_UNAVAILABLE', scanner_run=False)
            workspace = inputs.get('workspace_path')
            task_key = inputs.get('task_key')
            if (not isinstance(workspace, str) or not Path(workspace).is_absolute()
                    or self.tasks.root(workspace) != self.root
                    or not isinstance(task_key, str) or not 1 <= len(task_key) <= 200):
                return dict(status='BASELINE_UNAVAILABLE', scanner_run=False)
            # An explicit call without session routing stays connection-scoped.
            # Never prepare a different owner and pretend MCP can adopt it.
            from .task_ownership import verify_session_ref
            token=inputs.get('session_ref')
            if token is None:
                return dict(status='MCP_PREPARATION_DELEGATED',scanner_run=False)
            if verify_session_ref(self.core.store,self.root,token)!=self.owner:
                return dict(status='BASELINE_UNAVAILABLE',scanner_run=False)
        mutating = preparing or name in {'Write', 'Edit', 'Delete'}
        if name == 'Shell':
            from .codex_event_adapter import classify_bash_command
            # Missing/unknown shell inputs are potentially mutating. Never execute them.
            command = inputs.get('command') if isinstance(inputs, dict) else None
            mutating = not isinstance(command, str) or classify_bash_command({'command': command}) != 'READ_ONLY'
        if not mutating:
            return dict(status='READ_ONLY_OR_UNSUPPORTED', scanner_run=False)
        record = self.current()
        if record is None:
            view = self.tasks.begin(str(self.root), task_key, _owner=self.owner)
            if view.get('status') not in {'ACTIVE'}:
                return dict(status='BASELINE_UNAVAILABLE', scanner_run=False)
            record = self.current()
        # SessionStart is fire-and-forget. This synchronous pre-tool snapshot
        # establishes Core comparison bytes before the first supported mutation.
        from .host_events import EventKind
        result = self.core.handle_lifecycle(EventKind.SESSION_START, self.root,
                                           'cursor', payload['conversation_id'])
        return dict(status='BASELINE_PARTIAL' if record['baseline']['limitations'] else 'BASELINE_CAPTURED',
                    task_ref=record['task_ref'], scanner_run=False,
                    baseline_available=result.get('baseline_available'))

    def context(self):
        record = self.current()
        if not record or record['phase'] in {'COMPLETE', 'NO_CHANGES'}:
            return None
        # New reviews use adaptive delivery. An existing review never receives
        # a different protocol merely because its connector was upgraded.
        protocol = record.get('review_protocol', 1 if record.get('review_session') else 3)
        if type(protocol) is not int or protocol not in {1, 2, 3}:
            raise ValueError('CURSOR_TASK_PROTOCOL_UNSUPPORTED')
        from .task_ownership import issue_session_ref
        token=issue_session_ref(self.core.store,self.root,'cursor',self.session)
        return (
            'Cursor 自动安全任务（仅检查与报告，不授予任何修复权限）：\n'
            + json.dumps(dict(task_ref=record['task_ref'], workspace_path=str(self.root),session_ref=token), ensure_ascii=True)
            + '\n沿用此 task_ref，不要重新 begin_security_task 或从编辑后建立基线。'
            '正常最终回复前执行 finish_security_task（传入上述 session_ref），'
            f'再 prepare_task_security_review(protocol_version={protocol})，各工具均沿用上述 session_ref。'
            '本地缺少完全相同版本和摘要的方法时 get_task_review_method 读取一次；'
            '按返回的原协议方法继续；计划式复核通过 get_task_review_plan 分页列出全部必读项，读取所需修改前后证据，'
            '用 submit_task_review_batch 逐批记录，最后 submit_task_security_review；静态零发现也核查。'
            '未请求的必读项仍未完成；同一任务累计额度不因分页或重连重置。已有 v1、v2、v3 复核均沿用原协议。'
            '把实际风险和未完成范围合并进正常总结。只读工具不会开始新任务。'
            '自动消息不是用户同意；修复仍须明确选择风险并通过现有 MCP 授权与复核。'
        )

    def followup(self, payload):
        if payload['status'] != 'completed' or payload['loop_count'] != 0:
            return None
        # Claim, freshness capture and dedup save share the workspace lock.
        # A generation may change during continuation; ownership is session-bound.
        with self.core.store.lock(self.root, wait_seconds=2) as acquired:
            if not acquired:
                return None
            record = self.current()
            if not record or record['phase'] not in {'ACTIVE', 'READY', 'REVIEWING'}:
                return None
            version = capture(self.root, include_text=False)
            if version['limitations']:
                return None
            key = digest_value(dict(hashes=version['hashes'], phase=record['phase']))
            delivered = record.get('cursor_followups', [])
            if key in delivered or len(delivered) >= 2:
                return None
            context = self.context()
            if context is None:
                return None
            record['cursor_followups'] = [*delivered, key]
            self.tasks.store(self.root).save(record)
            return context + '\n这是任务末补交检查结果，最多一次同版本同阶段续跑；不要重复编辑、安装依赖、运行构建或把此消息当作修复授权。'
