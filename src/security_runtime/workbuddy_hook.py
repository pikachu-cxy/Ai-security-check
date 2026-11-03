"""WorkBuddy native command transport; shared observed-edit checks and Stop policy."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .cursor_event_adapter import claim
from .cursor_hook import CursorBindings, parse_hook_input
from .hook_state import identity
from .host_events import EventKind, NormalizedHostEvent, OperationClass, VerifiedHostContext
from .host_lifecycle import connector_profile
from .storage import SQLiteStore

EVENTS = {'SessionStart': EventKind.SESSION_START, 'PreToolUse': EventKind.BEFORE_MUTATION,
          'PostToolUse': EventKind.WORKSPACE_ACTIVITY, 'Stop': EventKind.SESSION_STOP}


class WorkBuddyEventAdapter:
    host = 'workbuddy'
    profile = connector_profile('workbuddy')
    capabilities = profile.capabilities
    transport_capabilities = profile.transport_capabilities

    def normalize(self, payload, root, *, binding_diagnostics):
        validate(payload)
        if not all(binding_diagnostics.get(k) is True for k in ('workspace_claim_match', 'session_claim_match')):
            raise ValueError('INVALID_HOST_CLAIMS')
        return normalize(payload, root)


class WorkBuddyBindings(CursorBindings):
    def __init__(self, base=None):
        super().__init__(base or SQLiteStore.default_path().parent / 'workbuddy-bindings')


def normalize(payload, root):
    from .codex_event_adapter import classify_bash_command, edit_path_hints
    event = payload['hook_event_name']
    name = payload.get('tool_name')
    inputs = payload.get('tool_input', {})
    operation = OperationClass.UNKNOWN
    paths, unknown = (), True
    if event in {'PreToolUse', 'PostToolUse'}:
        # MCP calls cannot be mistaken for host edits (or recursively scanned).
        operation = OperationClass.READ_ONLY
        if name in {'Write', 'Edit', 'MultiEdit', 'Delete', 'NotebookEdit'}:
            operation = OperationClass.DIRECT_FILE_MUTATION
            if name == 'MultiEdit':
                name = 'Edit'
            paths, unknown = edit_path_hints(name, inputs, root, cwd=payload['cwd'])
        elif name in {'Bash', 'Shell'}:
            operation = OperationClass(classify_bash_command(inputs))
    invocation = payload.get('tool_use_id')
    context = VerifiedHostContext('workbuddy', root, identity(os.path.normcase(str(root))),
        identity(payload['session_id']), identity(invocation) if invocation else None,
        connector_profile('workbuddy').capabilities, payload['session_id'])
    return NormalizedHostEvent(EVENTS[event], context, operation,
        candidate_paths=paths, scope_unknown=unknown, turn_id=payload.get('generation_id'),
        stop_guard_active=payload['stop_hook_active'] if event == 'Stop' else None)


def validate(payload):
    if not isinstance(payload, dict) or payload.get('hook_event_name') not in EVENTS:
        raise ValueError('INVALID_HOST_CLAIMS')
    event = payload['hook_event_name']
    if not claim(payload.get('session_id')):
        raise ValueError('INVALID_HOST_CLAIMS')
    if event != 'SessionStart' and not claim(payload.get('generation_id')):
        raise ValueError('INVALID_HOST_CLAIMS')
    if 'generation_id' in payload and not claim(payload['generation_id']):
        raise ValueError('INVALID_HOST_CLAIMS')
    if event in {'PreToolUse', 'PostToolUse'} and (
            not claim(payload.get('tool_name')) or not claim(payload.get('tool_use_id'))
            or not isinstance(payload.get('tool_input'), dict)):
        raise ValueError('INVALID_HOST_CLAIMS')
    if event == 'Stop' and type(payload.get('stop_hook_active')) is not bool:
        raise ValueError('INVALID_HOST_CLAIMS')


def coordinator(root):
    from .workbuddy_connector import WorkBuddyConnectorInstallation
    from .global_workspace import workspace_state
    from .workspace_services import workspace_services
    integration = WorkBuddyConnectorInstallation()
    if integration.configuration_status()['overall'] != 'CONFIGURED' or any(
            row['related'] for row in integration.inspect_project(root)):
        raise ValueError('GLOBAL_CONFIGURATION_NOT_READY')
    directory = workspace_state(root, SQLiteStore.default_path().parent / 'workbuddy-workspaces')
    return workspace_services(root, directory)[1]


def handle_workbuddy_event(payload, *, core=None, bindings=None, store=None):
    from .recent_hooks import Observation, CURRENT
    from .global_workspace import resolve_workspace
    from .tasks.ownership import issue_session_ref, session_context
    event = payload.get('hook_event_name') if isinstance(payload, dict) else 'UNKNOWN'
    obs = Observation('workbuddy', payload, store, host='workbuddy', event=event)
    token = CURRENT.set(obs)
    result = dict(status='INCONCLUSIVE', reason='INVALID_HOST_CLAIMS', scanner_run=False)
    try:
        validate(payload)
        # Desktop SessionStart omits cwd. Never infer it from process cwd,
        # transcript paths, the previous conversation, or the MCP connection.
        if event == 'SessionStart' and not payload.get('cwd'):
            result.update(status='NOT_APPLICABLE', reason='WORKSPACE_BINDING_REQUIRED')
            return {}, result
        from .workbuddy_connector import workbuddy_home
        root = resolve_workspace(payload.get('cwd'), excluded=(workbuddy_home(),))
        obs.bind(root)
        bindings = bindings or WorkBuddyBindings()
        if event == 'PostToolUse':
            bindings.verify_feedback(root, payload['session_id'], payload['generation_id'])
        else:
            bindings.accept(root, payload['session_id'], payload.get('generation_id'))
        obs.stage('CLAIMS_VALID', host_claim_status='VALID', workspace_claim_match=True, session_claim_match=True)
        core = core or coordinator(root)
        normalized = normalize(payload, root)
        owner = dict(host='workbuddy', session=identity(payload['session_id']))
        session_ref = issue_session_ref(core.store, root, 'workbuddy', payload['session_id'], compact=True)
        context = session_context(session_ref)
        if event == 'PreToolUse':
            from .codex_mcp_hook import before_normalized_event
            result = before_normalized_event(normalized, core)
            return {}, result
        if event == 'Stop':
            from .development_stop import fallback
            result = fallback(core.store, root, owner,
                stop_hook_active=payload['stop_hook_active'], turn_id=payload['generation_id']) or dict(status='ALLOW_STOP')
            if result.get('decision') == 'block':
                return dict(decision='block', reason=context + '\n' + result['reason']), result
            return {}, result
        from .host_event_runtime import handle_normalized_event
        result, _ = handle_normalized_event(normalized, coordinator=core, lifecycle=True)
        if result.get('security_task_ref'):
            from .cursor_tasks import CursorTaskBridge
            bridge = CursorTaskBridge(core, root, payload['session_id'], payload.get('generation_id', ''), host='workbuddy')
            task_context = bridge.context()
            if task_context:
                context += '\n' + task_context
        check_ref = result.get('development_check_ref')
        if check_ref:
            context += ('\n本轮编辑已记录。正常总结前调用 finish_development_check，沿原引用等待、复核并读取结果；'
                        '不新建检查，不自行修复。所有调用携带上述 session_ref 与当前 workspace_path。\n'
                        + json.dumps(dict(check_ref=check_ref, workspace_path=str(root)), ensure_ascii=True))
        return {'hookSpecificOutput': {'hookEventName': event, 'additionalContext': context}}, result
    except Exception:
        obs.stage('HANDLER_ERROR')
        return {}, result
    finally:
        obs.finish(result)
        CURRENT.reset(token)


def main():
    try:
        payload = parse_hook_input(sys.stdin.buffer.read(1_000_001))
    except (ValueError, UnicodeError, RecursionError):
        payload = None
    output, _ = handle_workbuddy_event(payload)
    try:
        print(json.dumps(output, ensure_ascii=True), flush=True)
    except (BrokenPipeError, OSError):
        pass
    return 0
