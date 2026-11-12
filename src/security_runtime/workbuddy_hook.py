"""WorkBuddy command transport; all checks/reviews use the shared services."""
from __future__ import annotations

import json
import re
import sys

from .host_tool_events import normalize_tool_event, validate_context
from .host_lifecycle import connector_profile

EVENTS = ('SessionStart', 'PreToolUse', 'PostToolUse', 'Stop')
# Only stable codes leave the process. Host paths, session values and free text
# must never reach the transcript, so anything else collapses to a generic code.
DIAGNOSTIC = re.compile(r'[A-Z][A-Z0-9_]{2,63}')
TOOLS = {'write_to_file': 'Write', 'replace_in_file': 'Edit',
         'execute_command': 'Bash', 'Write': 'Write', 'Edit': 'Edit',
         'Bash': 'Bash', 'apply_patch': 'apply_patch'}

# Native tool invocation details belong to this adapter, not the audit service.
AUDIT_DISPATCH_HINT = (
    'WorkBuddy 子任务交接：使用当前 Agent 工具实际支持的后台选项（如 run_in_background=true）让开发并行继续。'
    '首次创建只要求子任务等待完整 child_call，不传准备阶段的 audit_token、不让它提前 claim。'
    'stream_started 的 agent_ref 使用 Agent 返回的实际任务 ID，不使用自选 name；'
    '随后用当前工具的续接参数（如 resume）和同一个实际 ID 交付完整 child_call，不把名称当续接 ID。'
    '子任务只按完整 child_call 调用，claim 成功前不 read/submit/recover；参数错误修正一次，不能循环重试。'
    '向子任务一并传达：submit 必须沿用领取的 batch_id，生成非空稳定 request_id 并在重试时复用；'
    '严格使用领取返回的 submission_contract 和实际 schema，observations 不省略必填 title/description/impact/fix_advice，'
    '每个 business_reviews 保留该文件领取到的 evidence_refs；不猜扫描编号、不调用父任务复核接口。'
    'registration、child_call 和 audit_token 仅用于必要工具/子任务交接，不写聊天报告或工作日志。')


def handle(payload, *, core=None, root=None):
    from .global_workspace import resolve_workspace, workspace_state
    from .storage import SQLiteStore
    from .workspace_services import workspace_services
    from .workbuddy_integration import WorkBuddyConnectorInstallation
    from .tasks.ownership import issue_session_ref, session_owner
    from .host_development import session_context, audit_context, reconnect_context
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
    # Command hooks exit before the host performs the edit. Only PostToolUse
    # can record its path hints; an in-process watcher cannot span these calls.
    if event == 'PreToolUse':
        return {}
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
            stop_hook_active=payload.get('stop_hook_active', False), turn_id=turn, automatic=True, session_id=session)
        if result and result.get('decision') == 'block':
            return dict(decision='block', reason=result['reason'])
        return {'systemMessage': result['systemMessage']} if result and result.get('systemMessage') else {}
    result = {}
    tool = TOOLS.get(payload.get('tool_name'))
    if event == 'SessionStart' or tool is not None:
        args = dict(event=event, workspace_path=str(root), session_id=session,
            tool_name=tool, tool_input=payload.get('tool_input'),
            tool_use_id=payload.get('tool_use_id'), turn_id=turn)
        normalized = normalize_tool_event(args, root, host='workbuddy',
            capabilities=connector_profile('workbuddy').capabilities)
        result, _ = handle_normalized_event(normalized, coordinator=core, lifecycle=True)
    token = issue_session_ref(core.store, root, 'workbuddy', session, compact=True)
    context = session_context(token, root)
    if event == 'SessionStart':
        note = reconnect_context(core, root, session_owner('workbuddy', session))
        if note:
            context += '\n'+note
    if event == 'PostToolUse':
        note = audit_context(core, root, session_owner('workbuddy', session), result)
        if note:
            context += '\n'+note+'\n'+AUDIT_DISPATCH_HINT
    return {'hookSpecificOutput': {'hookEventName': event,
                                  'additionalContext': context}}


def reason_code(exc):
    """Map a failure to a stable code without echoing paths or session values."""
    if isinstance(exc, json.JSONDecodeError):
        return 'INVALID_HOST_PAYLOAD'
    text = str(exc).strip()
    if DIAGNOSTIC.fullmatch(text):
        return text
    if isinstance(exc, OSError):
        return 'HOST_IO_FAILED'
    return 'UNEXPECTED_FAILURE'


def main():
    try:
        raw = sys.stdin.buffer.read(100_001)
        if len(raw) > 100_000:
            raise ValueError('HOOK_INPUT_TOO_LARGE')
        output = handle(json.loads(raw))
    except Exception as exc:
        # An integration failure must not block the user's edit command, but the
        # reason has to stay observable: a bare "not ready" hides real conflicts.
        output = {'systemMessage': '本次 WorkBuddy 安全检查接入未完成（原因：%s）；正常开发可继续。'
                                  % reason_code(exc)}
    print(json.dumps(output, ensure_ascii=True))
    return 0
