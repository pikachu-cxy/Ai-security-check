"""Local Cursor command transport for the shared task/check services."""
from __future__ import annotations

from .cursor_event_adapter import CursorHostEventAdapter, EVENTS
from .cursor_tasks import CursorTaskBridge
from .host_events import EventKind
from .host_event_runtime import handle_normalized_event
from .recent_hooks import Observation, CURRENT
from .task_hook_activity import _record_task_hook


GAP = ('本次 Cursor 自动安全任务未能建立或读取编辑前的任务记录。'
       '请在正常开发总结中说明自动检查未完成；不要从编辑后补建基线，'
       '不要把此消息当成修复授权或反复尝试。')


def handle_automatic_event(payload, *, core=None, bindings=None, project_dir=None, remote=False, store=None):
    from .cursor_hook import CursorBindings, coordinator
    adapter = CursorHostEventAdapter(automatic=True)
    event = payload.get('hook_event_name') if isinstance(payload, dict) else 'UNKNOWN'
    if event not in EVENTS:
        event = 'UNKNOWN'
    output = {'permission': 'allow'} if event == 'preToolUse' else {}
    result = dict(status='INCONCLUSIVE', reason='INVALID_HOST_CLAIMS', scanner_run=False)
    obs = Observation('cursor', payload, store, host='cursor', event=event)
    token = CURRENT.set(obs)
    try:
        diag = adapter.validate_claims(payload, event)
        diag['cursor_task_begin_tool'] = CursorTaskBridge.is_begin_tool(payload.get('tool_name')) if isinstance(payload, dict) else False
        obs.stage('HOOK_RECEIVED', **diag)
        if diag['host_claim_status'] != 'VALID' or remote:
            result.update(diag, reason='CURSOR_REMOTE_NOT_SUPPORTED' if remote else 'INVALID_HOST_CLAIMS')
            return output, result
        from .cursor_integration import cursor_home
        root = adapter.resolve(payload, project_dir=project_dir, excluded=(cursor_home(),),
                               diagnostics=diag, on_resolved=obs.bind)
        bindings = bindings or CursorBindings()
        if event == 'postToolUse':
            diag.update(bindings.verify_feedback(root, payload['conversation_id'], payload['generation_id']))
        else:
            diag.update(bindings.accept(root, payload['conversation_id'], payload.get('generation_id') or None))
        diag.update(workspace_claim_match=True, session_claim_match=True)
        obs.stage('CLAIMS_VALID', **diag)
        core = core or coordinator(root, automatic=True)
        bridge = CursorTaskBridge(core, root, payload['conversation_id'], payload.get('generation_id') or '')
        if event == 'preToolUse':
            result = bridge.before(payload)
        elif event == 'postToolUse':
            context = bridge.context()
            if context:
                output['additional_context'] = context
            elif payload['tool_name'] in {'Write', 'Edit', 'Delete', 'Shell'} and bridge.current() is None:
                output['additional_context'] = GAP
            result = dict(status='DELIVERED' if output else 'NOT_APPLICABLE', scanner_run=False)
        elif event == 'stop':
            message = bridge.followup(payload)
            if message:
                output['followup_message'] = message
            result = dict(status='FOLLOWUP' if message else 'NOT_APPLICABLE', scanner_run=False)
        else:
            normalized = adapter.normalize(payload, root, binding_diagnostics=diag)
            result, _ = handle_normalized_event(normalized, coordinator=core, lifecycle=True)
            if normalized.kind == EventKind.WORKSPACE_ACTIVITY:
                record = bridge.current()
                if record and record['phase'] in {'ACTIVE', 'READY', 'REVIEWING'}:
                    _, recording = _record_task_hook(core.store, root, result, None,
                                                     expected_task_ref=record['task_ref'])
                    result['hook_check_recording'] = recording
            result['scanner_run'] = result.get('execution', {}).get('scanner_run', False)
        result.update(diag, automatic_connector=True)
        return output, result
    except Exception:
        # Host tool execution stays advisory; no exception text, source or tool
        # arguments are reflected into context or persisted diagnostics.
        result = dict(status='INCONCLUSIVE', reason='CURSOR_AUTOMATIC_TASK_UNAVAILABLE', scanner_run=False)
        obs.stage('HANDLER_ERROR')
        if event == 'postToolUse':
            output = {'additional_context': GAP}
        return output, result
    finally:
        obs.finish(result)
        CURRENT.reset(token)
