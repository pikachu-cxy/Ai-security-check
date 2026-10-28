"""Local Cursor command transport for the shared task/check services."""
from __future__ import annotations

from .cursor_event_adapter import CursorHostEventAdapter, EVENTS
from .cursor_tasks import CursorTaskBridge
from .host_events import EventKind
from .host_event_runtime import handle_normalized_event
from .recent_hooks import Observation, CURRENT
from .tasks.hook_activity import _record_task_hook
from .tasks.orchestration import task_allows_followup, task_delivery_facts


GAP = ('本次 Cursor 自动安全任务未能建立或读取编辑前的任务记录。'
       '仅当本轮实际修改源代码或配置，且总结时相关检查仍未完成，才在正常开发总结中简短说明一次；'
       '普通聊天、只读或无实际改动时不展示。最终当前检查完成后不保留旧提示，其他轮次不重复沿用。'
       '检查未完成不等于发现漏洞或编辑失败；不要从编辑后补建基线，'
       '不要把此消息当成修复授权或反复尝试。')


def _gap_context(bindings, root, payload, result):
    from .cursor_gap_notices import claim_gap_notice
    try:
        first = claim_gap_notice(bindings.store, root, payload['conversation_id'], payload['generation_id'])
        result['gap_notice_recording'] = 'RECORDED'
    except (ValueError, OSError, TypeError, KeyError, RecursionError):
        # Lost presentation bookkeeping cannot prove that the check completed.
        result['gap_notice_recording'] = 'UNAVAILABLE'
        first = True
    return GAP if first else None


def handle_automatic_event(payload, *, core=None, bindings=None, project_dir=None, remote=False, store=None,
                           delivery_observer=None):
    from .cursor_hook import CursorBindings, coordinator
    adapter = CursorHostEventAdapter(automatic=True)
    event = payload.get('hook_event_name') if isinstance(payload, dict) else 'UNKNOWN'
    if event not in EVENTS:
        event = 'UNKNOWN'
    output = {'permission': 'allow'} if event == 'preToolUse' else {}
    result = dict(status='INCONCLUSIVE', reason='INVALID_HOST_CLAIMS', scanner_run=False)
    obs = Observation('cursor', payload, store, host='cursor', event=event)
    token = CURRENT.set(obs)
    binding_verified = False
    may_mutate = False
    try:
        diag = adapter.validate_claims(payload, event)
        diag['cursor_task_begin_tool'] = CursorTaskBridge.is_begin_tool(payload.get('tool_name')) if isinstance(payload, dict) else False
        obs.stage('HOOK_RECEIVED', **diag)
        if diag['host_claim_status'] != 'VALID' or remote:
            result.update(diag, reason='CURSOR_REMOTE_NOT_SUPPORTED' if remote else 'INVALID_HOST_CLAIMS')
            return output, result
        may_mutate = event == 'postToolUse' and CursorTaskBridge.may_mutate(payload)
        from .cursor_integration import cursor_home
        root = adapter.resolve(payload, project_dir=project_dir, excluded=(cursor_home(),),
                               diagnostics=diag, on_resolved=obs.bind)
        bindings = bindings or CursorBindings()
        if event == 'postToolUse':
            diag.update(bindings.verify_feedback(root, payload['conversation_id'], payload['generation_id']))
        else:
            diag.update(bindings.accept(root, payload['conversation_id'], payload.get('generation_id') or None))
        diag.update(workspace_claim_match=True, session_claim_match=True)
        binding_verified = True
        obs.stage('CLAIMS_VALID', **diag)
        core = core or coordinator(root, automatic=True)
        bridge = CursorTaskBridge(core, root, payload['conversation_id'], payload.get('generation_id') or '')
        if event == 'preToolUse':
            result = bridge.before(payload)
        elif event == 'postToolUse':
            # Startup context can be missed when a chat outlives its MCP process.
            # Reissue only after feedback claims have been verified. Compact
            # handles reuse this exact owner's record and refresh before expiry.
            if getattr(core, 'task_audit_mode', False):
                from .tasks.ownership import issue_session_ref, session_context
                session_ref = issue_session_ref(core.store, root, 'cursor', bridge.session, compact=True)
                output['additional_context'] = session_context(session_ref)
            if not may_mutate and getattr(core, 'task_audit_mode', False):
                result = dict(status='NOT_APPLICABLE', scanner_run=False,
                              scanner_skipped_reason='READ_ONLY_ACTIVITY')
                result.update(diag, automatic_connector=True)
                return output, result
            if getattr(core, 'task_audit_mode', False):
                from .codex_event_adapter import edit_path_hints
                from .task_audit_mode import task_activity
                paths, unknown = edit_path_hints(payload.get('tool_name'), payload.get('tool_input'), root)
                result = task_activity(core.store, root, 'cursor', bridge.session, paths=paths,
                    scope_unknown=unknown, event_id=payload.get('tool_use_id'),
                    scan_path=getattr(getattr(core.runtime, 'store', None), 'path', None))
                if not result.get('security_task_ref'):
                    result.update(diag, automatic_connector=True)
                    return output, result
            else:
                from .tasks.attribution import session_activity
                session_activity(core.store, root, bridge.owner)
            record = bridge.current(headers=True)
            context = bridge.context(record)
            if context:
                output['additional_context'] = '\n'.join(filter(None, (output.get('additional_context'), context)))
            result = bridge.last_protocol_rejection or dict(
                status='DELIVERED' if output else 'NOT_APPLICABLE', scanner_run=False)
            if not context and may_mutate and record is None:
                gap = _gap_context(bindings, root, payload, result)
                if gap:
                    output['additional_context'] = '\n'.join(filter(None, (output.get('additional_context'), gap)))
                    result['status'] = 'DELIVERED'
            if bridge.last_delivery is not None:
                result['task_delivery'] = bridge.last_delivery
                result['response_prepared'] = True
        elif event == 'stop':
            message = bridge.followup(payload)
            from .tasks.attribution import session_activity
            idle = (not message and payload['status'] == 'completed' and payload['loop_count'] == 0
                    and core.store.pending_activity(root, 'cursor', bridge.session) is None)
            if not getattr(core, 'task_audit_mode', False):
                session_activity(core.store, root, bridge.owner, idle=idle)
            if message:
                output['followup_message'] = message
            result = dict(status='FOLLOWUP' if message else 'NOT_APPLICABLE', scanner_run=False)
            if message and bridge.last_delivery is not None:
                result['task_delivery'] = bridge.last_delivery
                result['response_prepared'] = True
        else:
            normalized = adapter.normalize(payload, root, binding_diagnostics=diag)
            result, _ = handle_normalized_event(normalized, coordinator=core, lifecycle=True)
            if normalized.kind == EventKind.SESSION_START:
                from .tasks.ownership import issue_session_ref, session_context
                session_ref=issue_session_ref(core.store,root,'cursor',payload['conversation_id'],compact=True)
                output['additional_context']=session_context(session_ref)
            if (normalized.kind == EventKind.WORKSPACE_ACTIVITY
                    and not result.get('development_check_ref')
                    and normalized.operation.value != 'READ_ONLY'):
                record = bridge.current(headers=True)
                if task_allows_followup(record):
                    task, recording = _record_task_hook(core.store, root, result, None,
                                                     expected_task_ref=record['task_ref'])
                    result['hook_check_recording'] = recording
                    if task:
                        result['task_delivery'] = task_delivery_facts(task,
                            scanner_run=result.get('execution', {}).get('scanner_run'), recording=recording)
            result['scanner_run'] = result.get('execution', {}).get('scanner_run', False)
        result.update(diag, automatic_connector=True)
        if bridge.last_delivery is not None and delivery_observer is not None:
            receipt = bridge.last_delivery.get('delivery_receipt') or {}
            if receipt.get('recording') == 'RECORDED':
                delivery_observer.bind(core.store, root, bridge.owner, receipt)
        return output, result
    except Exception:
        # Host tool execution stays advisory; no exception text, source or tool
        # arguments are reflected into context or persisted diagnostics.
        result = dict(status='INCONCLUSIVE', reason='CURSOR_AUTOMATIC_TASK_UNAVAILABLE', scanner_run=False)
        obs.stage('HANDLER_ERROR')
        if event == 'postToolUse' and binding_verified and may_mutate and not output.get('additional_context'):
            gap = _gap_context(bindings, root, payload, result)
            if gap:
                output['additional_context'] = gap
        return output, result
    finally:
        obs.finish(result)
        CURRENT.reset(token)
