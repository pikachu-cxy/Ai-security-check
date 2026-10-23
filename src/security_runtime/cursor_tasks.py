"""Cursor task preparation and bounded feedback. No scanner or repair authority here."""
from __future__ import annotations

import json
from pathlib import Path

from .hook_state import identity
from .tasks.security import TaskSecurityService, capture
from .tasks.orchestration import (
    select_task, require_task_owner, review_protocol, task_needs_handoff, task_allows_followup, followup_identity, task_delivery_facts, historical_tasks,
)
from .task_review.protocol import UnsupportedTaskReviewProtocol

_CURRENT = object()
DELIVERY_CONTEXT_MARKER = '\n交付状态元数据（非工具参数）：\n'
HISTORICAL_CONTEXT = (
    '此安全任务采用旧协议或缺少协议记录，只保留历史查询，不支持继续检查或续办。'
    '当前 Runtime 与 Skill 的任务检查仅使用 v3；若连接的旧 Runtime 不支持 v3，请先升级。'
    '需要检查之后的新工作时，请在下一次编辑前显式调用 begin_security_task 并使用新的 task_key 建立 v3 任务，'
    '只覆盖其后的改动。不要自动转换旧任务、迁移旧基线或累计额度，也不要从已经完成的改动后补建基线。'
)


class CursorTaskBridge:
    def __init__(self, core, root, session, generation):
        self.core, self.root = core, root
        self.owner = dict(host='cursor', session=identity(session))
        self.session=session
        self.key = 'cursor:' + identity(session + '\x00' + generation)
        self.tasks = TaskSecurityService(core.runtime, hooks=core.store,owner=self.owner)
        self.last_delivery = None
        self.last_protocol_rejection = None

    def current(self):
        store = self.tasks.store(self.root)
        return select_task(store, self.owner, task_key=self.tasks.key(self.key, self.owner),
                           include_historical=True)

    def _historical_rejection(self):
        # Ambiguous history must not silently become a new automatic baseline.
        history = historical_tasks(self.tasks.store(self.root), self.owner)
        if history:
            protocol = history[0].get('review_protocol') if len(history) == 1 else 'MULTIPLE_RECORDS'
            return UnsupportedTaskReviewProtocol(protocol).response()
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

    @staticmethod
    def may_mutate(payload):
        name, inputs = payload.get('tool_name'), payload.get('tool_input', {})
        if name == 'Shell':
            from .codex_event_adapter import classify_bash_command
            command = inputs.get('command') if isinstance(inputs, dict) else None
            # An absent/unknown command is possible activity, never execution.
            return not isinstance(command, str) or classify_bash_command({'command': command}) != 'READ_ONLY'
        return name in {'Write', 'Edit', 'Delete'}

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
            from .tasks.ownership import verify_session_ref
            token=inputs.get('session_ref')
            if token is None:
                return dict(status='MCP_PREPARATION_DELEGATED',scanner_run=False)
            if verify_session_ref(self.core.store,self.root,token)!=self.owner:
                return dict(status='BASELINE_UNAVAILABLE',scanner_run=False)
        mutating = preparing or self.may_mutate(payload)
        if not mutating:
            return dict(status='READ_ONLY_OR_UNSUPPORTED', scanner_run=False)
        from .tasks.attribution import session_activity
        session_activity(self.core.store, self.root, self.owner)
        record = None if preparing else self.current()
        if record is None and not preparing:
            historical = self._historical_rejection()
            if historical is not None:
                return historical
        if record is not None:
            try:
                review_protocol(record)
            except UnsupportedTaskReviewProtocol as error:
                return error.response(task_ref=record['task_ref'])
        if record is None:
            try:
                view = self.tasks.begin(str(self.root), task_key, _owner=self.owner)
            except UnsupportedTaskReviewProtocol as error:
                return error.response()
            if view.get('status') == UnsupportedTaskReviewProtocol.reason_code:
                return view
            if view.get('status') not in {'ACTIVE'}:
                return dict(status='BASELINE_UNAVAILABLE', scanner_run=False)
            record = self.tasks.load(self.root, view['task_ref'])
        review_protocol(record)
        # SessionStart is fire-and-forget. This synchronous pre-tool snapshot
        # establishes Core comparison bytes before the first supported mutation.
        from .host_events import EventKind
        result = self.core.handle_lifecycle(EventKind.SESSION_START, self.root,
                                           'cursor', payload['conversation_id'])
        return dict(status='BASELINE_PARTIAL' if record['baseline']['limitations'] else 'BASELINE_CAPTURED',
                    task_ref=record['task_ref'], scanner_run=False,
                    baseline_available=result.get('baseline_available'))

    def context(self, record=_CURRENT, *, category='POST_TOOL_CONTEXT'):
        self.last_delivery = None
        self.last_protocol_rejection = None
        record = self.current() if record is _CURRENT else record
        require_task_owner(record, self.owner)
        if record is None:
            self.last_protocol_rejection = self._historical_rejection()
            return HISTORICAL_CONTEXT if self.last_protocol_rejection is not None else None
        try:
            review_protocol(record)
        except UnsupportedTaskReviewProtocol as error:
            self.last_protocol_rejection = error.response(task_ref=record['task_ref'])
            return HISTORICAL_CONTEXT
        if not task_needs_handoff(record):
            return None
        from .tasks.ownership import issue_session_ref
        token=issue_session_ref(self.core.store,self.root,'cursor',self.session)
        context = (
            'Cursor 自动安全任务（仅检查与报告，不授予任何修复权限）：\n'
            + json.dumps(dict(task_ref=record['task_ref'], workspace_path=str(self.root),session_ref=token),
                         ensure_ascii=True)
            + '\n沿用此 task_ref，不要重新 begin_security_task 或从编辑后建立基线。'
            '正常最终回复前执行 finish_security_task（传入上述 session_ref），'
            '再 prepare_task_security_review(protocol_version=3)，各工具均沿用上述 session_ref。'
            '本地缺少完全相同版本和摘要的方法时 get_task_review_method 读取一次；'
            '按 v3 方法继续；计划式复核通过 get_task_review_plan 分页列出全部必读项，读取所需修改前后证据，'
            '用 submit_task_review_batch 逐批记录，最后 submit_task_security_review；静态零发现也核查。'
            '未请求的必读项仍未完成；同一任务累计额度不因分页或重连重置。旧协议任务仅供历史查询，不得续办。'
            '把实际风险和未完成范围合并进正常总结。只读工具不会开始新任务。'
            '最终当前检查完成后，以当前结果替代本轮早先的未完成提示；其他轮次不沿用旧提示。'
            '自动消息不是用户同意；修复仍须明确选择风险并通过现有 MCP 授权与复核。'
        )
        # Rendering a response is not proof that stdout was written or that a
        # host report/person consumed it. Metadata is outside executable args.
        from .tasks.delivery_receipts import TaskDeliveryReceipts, unavailable
        import sqlite3
        try:
            receipt = TaskDeliveryReceipts(self.core.store, self.root).prepare(
                record, self.owner, intent='TASK_CLOSEOUT', category=category)
        except (ValueError, OSError, sqlite3.DatabaseError):
            receipt = unavailable()
        self.last_delivery = task_delivery_facts(record, scanner_run=False,
            context_returned=True, intent='TASK_CLOSEOUT', delivery_receipt=receipt)
        return context + DELIVERY_CONTEXT_MARKER + json.dumps(dict(task_delivery=self.last_delivery), ensure_ascii=True)

    def followup(self, payload):
        self.last_delivery = None
        self.last_protocol_rejection = None
        if payload['status'] != 'completed' or payload['loop_count'] != 0:
            return None
        # Claim, freshness capture and dedup save share the workspace lock.
        # A generation may change during continuation; ownership is session-bound.
        with self.core.store.lock(self.root, wait_seconds=2) as acquired:
            if not acquired:
                return None
            record = self.current()
            if not task_allows_followup(record):
                return None
            version = capture(self.root, include_text=False)
            if version['limitations']:
                return None
            key = followup_identity(record, version)
            delivered = record.get('cursor_followups', [])
            if key in delivered or len(delivered) >= 2:
                return None
            context = self.context(record, category='STOP_FOLLOWUP')
            if context is None:
                return None
            record['cursor_followups'] = [*delivered, key]
            self.tasks.store(self.root).save(record)
            return context + '\n这是任务末补交检查结果，最多一次同版本同阶段续跑；不要重复编辑、安装依赖、运行构建或把此消息当作修复授权。'
