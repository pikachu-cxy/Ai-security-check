"""Shared native tool-event translation and edit-window handling, without host transport."""
from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath

from .hook_state import identity
from .host_events import EventKind, NormalizedHostEvent, OperationClass, VerifiedHostContext
from .workspace import WorkspaceResolver

EVENTS = {'SessionStart': EventKind.SESSION_START, 'PreToolUse': EventKind.BEFORE_MUTATION,
          'PostToolUse': EventKind.WORKSPACE_ACTIVITY, 'Stop': EventKind.SESSION_STOP}


def classify_bash_command(tool_input) -> str:
    """Classify command shape without persisting or echoing command text."""
    if not isinstance(tool_input, dict):
        return 'UNKNOWN'
    command = tool_input.get('command') or tool_input.get('cmd')
    if not isinstance(command, str) or not command.strip() or len(command) > 12000:
        return 'UNKNOWN'
    from .shell_classification import classify_command
    return classify_command(command)


def edit_path_hints(tool, inputs, root, *, cwd=None, require_patch_body=False):
    """Extract bounded path hints without reading files or trusting edit success.

    A failed tool can still provide a hint. Unknown or truncated scope remains
    explicit, and patch bodies never enter the activity ledger.
    """
    values = []
    unknown = False
    directory = Path(cwd) if cwd is not None else root
    if not directory.is_absolute() or not directory.is_relative_to(root):
        return (), True
    if tool == 'apply_patch':
        patch = inputs if isinstance(inputs, str) else None
        if isinstance(inputs, dict):
            # Native Codex Hooks use command; retain older patch/input wrappers.
            patch = next((inputs[name] for name in ('patch', 'input', 'command')
                          if isinstance(inputs.get(name), str)), None)
        if isinstance(patch, str):
            if len(patch) > 262144 or len(patch.encode('utf-8', errors='replace')) > 262144:
                return (), True
            lines = patch.splitlines()
            framed = lines[:1] == ['*** Begin Patch'] and lines[-1:] == ['*** End Patch']
            unknown = not framed
            headers = lines[1:-1] if framed else lines
            for line in headers:
                for prefix in ('*** Add File: ', '*** Update File: ', '*** Delete File: ', '*** Move to: '):
                    if line.startswith(prefix):
                        values.append(line[len(prefix):])
                        break
                else:
                    if line.lstrip().startswith('***') and line != '*** End of File':
                        unknown = True
        elif isinstance(inputs, dict):
            # Older hosts expose only the target path; it is still a hint.
            values.append(inputs.get('file_path') or inputs.get('path'))
            unknown = require_patch_body
    elif tool in {'Edit', 'Write', 'Delete'} and isinstance(inputs, dict):
        values.append(inputs.get('file_path') or inputs.get('path'))
    selected, size = [], 0
    for value in values:
        if (not isinstance(value, str) or not value or len(value) > 4096
                or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
                or value.startswith(('\\\\', '//'))):
            unknown = True
            continue
        path = Path(value)
        if '..' in path.parts or '..' in PureWindowsPath(value).parts:
            unknown = True
            continue
        try:
            relative = (path if path.is_absolute() else directory / value.replace('\\', '/')).relative_to(root).as_posix()
        except ValueError:
            unknown = True
            continue
        if (not relative or relative == '.' or ':' in relative or relative.startswith('/')
                or PureWindowsPath(relative).drive):
            unknown = True
            continue
        if relative in selected:
            continue
        cost = len(relative.encode('utf-8'))
        if len(selected) >= 1000 or size + cost > 64000:
            unknown = True
            break
        selected.append(relative)
        size += cost
    return tuple(selected), unknown or not bool(selected)


def validate_context(payload, workspace):
    """Shared cwd/session validation, including connected PreToolUse."""
    cwd = payload.get('cwd')
    if not isinstance(cwd,str) or WorkspaceResolver().resolve(
            cwd, allow_non_git_explicit=True, allow_non_git_source=True).path != workspace:
        raise ValueError('Host event does not belong to configured workspace')
    session = payload.get('session_id')
    if not isinstance(session,str) or not session or len(session)>500:
        raise ValueError('Invalid host session identity')
    # Ignore transcript_path, tool_input/response, model and assistant text.
    # None is source data for commands, metadata state or model prompts.
    return session



def normalize_tool_event(arguments, root, *, host, capabilities):
    """Translate already validated transport claims; does not authorize an event."""
    expected = arguments.get('event')
    if expected not in EVENTS:
        raise ValueError('Unsupported host event')
    operation = OperationClass.UNKNOWN
    if expected in {'PreToolUse', 'PostToolUse'}:
        tool = arguments.get('tool_name')
        if tool not in {'Bash', 'apply_patch', 'Edit', 'Write'}:
            raise ValueError('Unsupported host activity')
        operation = (OperationClass(classify_bash_command(arguments.get('tool_input')))
                     if tool == 'Bash' else OperationClass.DIRECT_FILE_MUTATION)
    invocation = arguments.get('tool_use_id')
    context = VerifiedHostContext(host, root, identity(os.path.normcase(str(root))),
        identity(arguments['session_id']), identity(invocation) if invocation else None,
        capabilities, arguments['session_id'])
    codex_pre_patch = host == 'codex' and expected == 'PreToolUse' and arguments.get('tool_name') == 'apply_patch'
    candidates, unknown = (edit_path_hints(arguments.get('tool_name'), arguments.get('tool_input'), root,
                                          cwd=arguments.get('workspace_path'), require_patch_body=codex_pre_patch)
                           if expected in {'PreToolUse', 'PostToolUse'} else ((), True))
    if codex_pre_patch and not unknown:
        from .development_check import clean_paths
        _, unknown = clean_paths(candidates, tolerant=True)
    return NormalizedHostEvent(EVENTS[expected], context, operation,
        turn_id=arguments.get('turn_id'),
        candidate_paths=candidates, scope_unknown=unknown,
        complete_patch_paths=codex_pre_patch and not unknown,
        mutation_hint=True if operation == OperationClass.DIRECT_FILE_MUTATION else None,
        stop_guard_active=arguments.get('stop_hook_active', False) if expected == 'Stop' else None)


def before_normalized_event(event, coordinator):
    """Only validated native metadata reaches task-window registration."""
    from .host_events import EventKind, OperationClass
    if event.kind != EventKind.BEFORE_MUTATION:
        raise ValueError('Native pre-tool event required')
    if event.operation == OperationClass.READ_ONLY:
        return dict(status='NOT_STARTED', scanner_run=False, source_modified=False,
                    baseline_created=False, reason_code='READ_ONLY_ACTIVITY')
    from .development_check import record_hook, DevelopmentCheckStore, projection
    from .development_file_watch import start_window
    context = event.context
    owner = dict(host=context.host, session=context.session_binding)
    result = record_hook(coordinator.store, context.workspace, owner,
        scope_unknown=False, prepare_only=True, turn_id=event.turn_id,
        scan_path=getattr(getattr(coordinator.runtime, 'store', None), 'path', None))
    if result.get('check_ref') and not event.complete_patch_paths:
        store = DevelopmentCheckStore(coordinator.store, context.workspace)
        watch_status = start_window(store, result['check_ref'], owner, invocation=context.invocation_binding)
        result = projection(store, store.load(result['check_ref'], owner))
        if watch_status != 'ACTIVE':
            result['file_watch_start_failed'] = True
    return result


