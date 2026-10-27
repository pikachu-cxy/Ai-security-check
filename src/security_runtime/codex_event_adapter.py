"""Codex raw claims and tool semantics; no snapshot, scanner or risk decisions."""
from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath

from .codex_host_claims import diagnostics, schema_diagnostics
from .hook_state import identity, no_links
from .host_events import (EventKind, HostCapabilities, NormalizedHostEvent,
                          OperationClass, VerifiedHostContext)
from .host_lifecycle import connector_profile


def classify_bash_command(tool_input) -> str:
    """Classify command shape without persisting or echoing command text."""
    if not isinstance(tool_input, dict):
        return 'UNKNOWN'
    command = tool_input.get('command') or tool_input.get('cmd')
    if not isinstance(command, str) or not command.strip() or len(command) > 12000:
        return 'UNKNOWN'
    from .shell_classification import classify_command
    return classify_command(command)


def edit_path_hints(tool, inputs, root, *, cwd=None):
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
            unknown = not (lines and lines[0] == '*** Begin Patch' and lines[-1] == '*** End Patch')
            for line in lines:
                for prefix in ('*** Add File: ', '*** Update File: ', '*** Delete File: ', '*** Move to: '):
                    if line.startswith(prefix):
                        values.append(line[len(prefix):])
                        break
        elif isinstance(inputs, dict):
            # Older hosts expose only the target path; it is still a hint.
            values.append(inputs.get('file_path') or inputs.get('path'))
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


class CodexEventAdapter:
    host = 'codex'
    profile = connector_profile('codex')
    capabilities = profile.capabilities
    from .codex_host_claims import EVENTS as mcp_events
    events = {'SessionStart': EventKind.SESSION_START, 'PreToolUse': EventKind.BEFORE_MUTATION,
              'PostToolUse': EventKind.WORKSPACE_ACTIVITY, 'Stop': EventKind.SESSION_STOP}

    def validate_claims(self, arguments, expected, schema=None):
        return (schema_diagnostics(arguments, expected, schema) if schema is not None
                else diagnostics(arguments, expected))

    def accept_invocation(self, arguments, root, diag, guard):
        return guard.accept(arguments, root, diag)

    def normalize(self, arguments, root, *, binding_diagnostics=None, legacy=False):
        """Called only after binding/replay validation in the transport adapter.

        Legacy command translation retains its previous identity requirements;
        connected MCP always uses the full event-specific claims contract.
        """
        expected = arguments.get('event')
        if expected not in self.events:
            raise ValueError('Unsupported Codex event')
        if not legacy and (not isinstance(binding_diagnostics, dict)
                or binding_diagnostics.get('host_claim_status') != 'VALID'
                or binding_diagnostics.get('workspace_claim_match') is not True
                or binding_diagnostics.get('session_claim_match') is not True):
            raise ValueError('Validated Codex binding required')
        if not legacy and self.validate_claims(arguments, expected)['host_claim_status'] != 'VALID':
            raise ValueError('Invalid Codex claims')
        operation = OperationClass.UNKNOWN
        if expected in {'PreToolUse', 'PostToolUse'}:
            tool = arguments.get('tool_name')
            if tool not in {'Bash', 'apply_patch', 'Edit', 'Write'}:
                raise ValueError('Unsupported Codex activity')
            operation = (OperationClass(classify_bash_command(arguments.get('tool_input')))
                         if tool == 'Bash' else OperationClass.DIRECT_FILE_MUTATION)
        invocation = arguments.get('tool_use_id')
        context = VerifiedHostContext(self.host, root, identity(os.path.normcase(str(root))),
            identity(arguments['session_id']), identity(invocation) if invocation else None,
            self.capabilities, arguments['session_id'])
        if not legacy:
            try:
                from .observation import bind_chat, bind_host
                bind_chat(dict(host=self.host, session=context.session_binding))
                turn = arguments.get('turn_id')
                bind_host(self.host, context.session_binding, context.invocation_binding,
                          identity(turn) if turn else None)
            except Exception:
                pass  # Optional attribution never changes validated Hook behavior.
        candidates, unknown = (edit_path_hints(arguments.get('tool_name'), arguments.get('tool_input'), root,
                                              cwd=arguments.get('workspace_path'))
                               if expected in {'PreToolUse', 'PostToolUse'} else ((), True))
        return NormalizedHostEvent(self.events[expected], context, operation,
            candidate_paths=candidates, scope_unknown=unknown,
            mutation_hint=True if operation == OperationClass.DIRECT_FILE_MUTATION else None,
            stop_guard_active=arguments.get('stop_hook_active', False) if expected == 'Stop' else None)

    def bind_project(self, arguments, *, binding, guard=None, expected=None, legacy=False):
        """Preserve the existing project cwd/adapter and invocation checks."""
        expected = expected or arguments.get('event')
        diag = None if legacy else self.validate_claims(arguments, expected)
        if diag is not None and diag['host_claim_status'] != 'VALID':
            return None, diag, 'INVALID_HOST_CLAIMS'
        if binding is None:
            return None, diag, 'WORKSPACE_BINDING_REQUIRED'
        try:
            workspace = arguments['workspace_path']
            if not Path(workspace).is_absolute():
                raise ValueError('Absolute cwd required')
            root = Path(binding.root)
            candidate = Path(os.path.abspath(workspace))
            if not candidate.is_relative_to(root):
                raise ValueError('Host cwd outside bound workspace')
            no_links(candidate)
            from .hook_adapters import CodexHookAdapter
            payload = dict(hook_event_name=arguments['event'], cwd=workspace,
                session_id=arguments['session_id'], tool_name=arguments.get('tool_name'))
            if arguments['event'] == 'PreToolUse':
                CodexHookAdapter.validate_context(payload, root)
            else:
                CodexHookAdapter().translate(payload, root)
            reason = self.accept_invocation(arguments, root, diag, guard) if guard is not None else None
            if reason:
                return None, diag, reason
            return self.normalize(arguments, root, binding_diagnostics=diag, legacy=legacy), diag, None
        except Exception:
            if diag is not None:
                diag.update(host_claim_status='REJECTED', workspace_claim_match=False)
            return None, diag, 'HOST_CLAIMS_REJECTED'

    @staticmethod
    def legacy_classification(event):
        # Preserve the existing Codex diagnostics ABI for direct file tools.
        return ('POSSIBLE_WORKSPACE_MUTATION' if event.operation == OperationClass.DIRECT_FILE_MUTATION
                else event.operation.value)


def handle_legacy_stop_event(event, workspace_path, session_id, stop_hook_active, *, binding, guard):
    """Preserve the old standalone Stop transport contract without new authority."""
    from .host_continuation import allowed
    try:
        if (any(not isinstance(v, str) or not v.strip() or len(v) > limit or '${' in v or
                any(ord(c) < 32 for c in v) for v, limit in zip((event, workspace_path, session_id), (32, 4096, 500)))
                or event != 'Stop' or type(stop_hook_active) is not bool):
            return allowed('INCONCLUSIVE')
        if binding is None:
            return allowed('INCONCLUSIVE')
        root = Path(binding.root)
        if workspace_path.startswith(('\\\\', '//')) or not Path(workspace_path).is_absolute():
            return allowed('INCONCLUSIVE')
        candidate = Path(os.path.abspath(workspace_path))
        if not candidate.is_relative_to(root):
            return allowed('INCONCLUSIVE')
        no_links(candidate)
        no_links(root)
        return guard.handle(root, session_id, stop_hook_active)
    except Exception:
        return allowed('INCONCLUSIVE')
