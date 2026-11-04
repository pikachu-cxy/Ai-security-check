"""WorkBuddy command transport; all checks/reviews use the shared services."""
from __future__ import annotations

import json
import sys

from .host_tool_events import normalize_tool_event, validate_context, before_normalized_event
from .host_lifecycle import connector_profile

EVENTS = ('SessionStart', 'PreToolUse', 'PostToolUse', 'Stop')
TOOLS = {'write_to_file': 'Write', 'replace_in_file': 'Edit',
         'execute_command': 'Bash', 'Write': 'Write', 'Edit': 'Edit',
         'Bash': 'Bash', 'apply_patch': 'apply_patch'}


def handle(payload, *, core=None, root=None):
    from .global_workspace import resolve_workspace, workspace_state
    from .storage import SQLiteStore
    from .workspace_services import workspace_services
    from .workbuddy_integration import WorkBuddyConnectorInstallation
    from .tasks.ownership import issue_session_ref, session_context, session_owner
    from .host_event_runtime import handle_normalized_event
    from .development_stop import fallback

    if not isinstance(payload, dict) or payload.get('hook_event_name') not in EVENTS:
        raise ValueError('INVALID_HOST_EVENT')
    root = root or resolve_workspace(payload.get('cwd'), allow_empty=True)
    session = validate_context(payload, root)
    event = payload['hook_event_name']
    turn = payload.get('generation_id')
    if turn is not None and (not isinstance(turn, str) or not 0 < len(turn) <= 500):
        raise ValueError('INVALID_TURN')
    if type(payload.get('stop_hook_active', False)) is not bool:
        raise ValueError('INVALID_STOP_GUARD')
    if core is None:
        integration = WorkBuddyConnectorInstallation()
        if integration.configuration_status()['overall'] != 'CONFIGURED':
            raise ValueError('GLOBAL_CONFIGURATION_NOT_READY')
        if any(row['related'] for row in integration.inspect_project(root)):
            raise ValueError('LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR')
        directory = workspace_state(root, SQLiteStore.default_path().parent / 'workbuddy-workspaces')
        _, core, _ = workspace_services(root, directory, admitted=True)
    if event == 'Stop':
        result = fallback(core.store, root, session_owner('workbuddy', session),
            stop_hook_active=payload.get('stop_hook_active', False), turn_id=turn)
        if result and result.get('decision') == 'block':
            return dict(decision='block', reason=result['reason'])
        return {}
    tool = TOOLS.get(payload.get('tool_name'))
    if event == 'SessionStart' or tool is not None:
        args = dict(event=event, workspace_path=str(root), session_id=session,
            tool_name=tool, tool_input=payload.get('tool_input'),
            tool_use_id=payload.get('tool_use_id'), turn_id=turn)
        normalized = normalize_tool_event(args, root, host='workbuddy',
            capabilities=connector_profile('workbuddy').capabilities)
        if event == 'PreToolUse':
            before_normalized_event(normalized, core)
        else:
            handle_normalized_event(normalized, coordinator=core, lifecycle=True)
    token = issue_session_ref(core.store, root, 'workbuddy', session, compact=True)
    return {'hookSpecificOutput': {'hookEventName': event,
                                  'additionalContext': session_context(token)}}


def main():
    try:
        raw = sys.stdin.buffer.read(100_001)
        if len(raw) > 100_000:
            raise ValueError('HOOK_INPUT_TOO_LARGE')
        output = handle(json.loads(raw))
    except Exception:
        # An integration failure must not block the user's edit command.
        output = {'systemMessage': '本次 WorkBuddy 安全检查接入未完成；正常开发可继续。'}
    print(json.dumps(output, ensure_ascii=True))
    return 0
