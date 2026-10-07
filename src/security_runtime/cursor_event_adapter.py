"""Cursor's documented local command Hook claims, not Host attestation."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .hook_state import identity, no_links
from .host_events import EventKind, HostCapabilities, NormalizedHostEvent, OperationClass, VerifiedHostContext

EVENTS = {'sessionStart': EventKind.SESSION_START, 'afterFileEdit': EventKind.WORKSPACE_ACTIVITY,
          'afterShellExecution': EventKind.WORKSPACE_ACTIVITY, 'stop': EventKind.SESSION_STOP,
          'postToolUse': None}  # Delivery only; never normalize into Core activity.


@dataclass(frozen=True)
class CursorTransportCapabilities:
    supports_detection: bool = True
    supports_advisory_remediation: bool = True
    supports_user_visible_feedback: bool = False
    supports_agent_continuation: bool = False
    supports_stop_followup: bool = False
    supports_post_edit_context: bool = False
    supports_mcp: bool = True
    supports_live_remediation_continuation: bool = False
    supports_remote_workspace: bool = False


def claim(value):
    return (isinstance(value, str) and 0 < len(value) <= 500 and bool(value.strip())
            and not any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value))


def generation_diagnostics(arguments):
    """Opaque strings have no UUID/template shape. Never return their value."""
    value = arguments.get('generation_id')
    if 'generation_id' not in arguments:
        reason = 'MISSING'
    elif not isinstance(value, str):
        reason = 'INVALID_TYPE'
    elif len(value) > 500:
        reason = 'OVERSIZED'
    elif any(ord(c) < 32 for c in value):
        reason = 'CONTROL_CHARACTER'
    elif any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        reason = 'INVALID_UNICODE'
    elif not value.strip():
        reason = 'EMPTY'
    else:
        reason = 'VALID'
    not_yet = arguments.get('hook_event_name') == 'sessionStart' and (
        'generation_id' not in arguments or value == '')
    return dict(generation_id_present='generation_id' in arguments,
        generation_id_type_valid=isinstance(value, str),
        generation_id_length=min(len(value), 501) if isinstance(value, str) else None,
        generation_id_shape_valid=reason == 'VALID',
        generation_id_validation_reason='NOT_YET_AVAILABLE' if not_yet else reason,
        generation_state='NOT_YET_AVAILABLE' if not_yet else 'AVAILABLE' if reason == 'VALID' else 'INVALID')


class CursorHostEventAdapter:
    host = 'cursor'
    transport_capabilities = CursorTransportCapabilities()
    capabilities = HostCapabilities(supports_session_start=True, supports_native_file_edit=True,
        supports_shell_post_event=True, supports_tool_input=True, supports_stop=True,
        supports_global_install=True)

    def validate_claims(self, arguments, expected, schema=None):
        args = arguments if isinstance(arguments, dict) else {}
        missing, invalid = [], []
        required = ('conversation_id', 'hook_event_name', 'workspace_roots')
        if expected != 'sessionStart':
            required += ('generation_id',)
        for key in required:
            if key not in args:
                missing.append(key)
        for key in ('conversation_id', 'generation_id'):
            unavailable = key == 'generation_id' and expected == 'sessionStart' and args.get(key) == ''
            if key in args and not unavailable and not claim(args[key]):
                invalid.append(key)
        if args.get('hook_event_name') != expected or expected not in EVENTS:
            invalid.append('hook_event_name')
        roots = args.get('workspace_roots')
        # Multi-root attribution has no reliable invocation->root binding here.
        if 'workspace_roots' in args and (not isinstance(roots, list) or len(roots) > 1
                or roots and (not isinstance(roots[0], str) or not roots[0].strip() or len(roots[0]) > 4096
                or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in roots[0]))):
            invalid.append('workspace_roots')
        if 'session_id' in args and (not claim(args['session_id']) or args['session_id'] != args.get('conversation_id')):
            invalid.append('session_id')
        if expected == 'sessionStart' and not claim(args.get('session_id')):
            (missing if 'session_id' not in args else invalid).append('session_id')
        if expected == 'afterFileEdit' and not isinstance(args.get('file_path'), str):
            (missing if 'file_path' not in args else invalid).append('file_path')
        if expected == 'afterShellExecution' and (not isinstance(args.get('command'), str)
                or len(args['command']) > 32000 or '\x00' in args['command']):
            (missing if 'command' not in args else invalid).append('command')
        if expected == 'stop':
            if args.get('status') not in {'completed', 'aborted', 'error'}:
                invalid.append('status')
            if type(args.get('loop_count')) is not int or not 0 <= args['loop_count'] <= 100:
                invalid.append('loop_count')
        if expected == 'postToolUse':
            fields = ('tool_name', 'tool_use_id')
            for field in fields:
                if not claim(args.get(field)):
                    (missing if field not in args else invalid).append(field)
            if args.get('tool_name') != 'Write':
                invalid.append('tool_name')
        return dict(host='cursor', host_claim_status='INVALID' if missing or invalid else 'VALID',
            missing_claims=sorted(set(missing)), invalid_claims=sorted(set(invalid)),
            event_schema='cursor-'+expected+'-v1' if expected in EVENTS else 'UNKNOWN',
            workspace_claim_match=None, session_claim_match=None,
            turn_claim_present=claim(args.get('generation_id')), tool_use_claim_present=False,
            workspace_root_count=min(len(roots), 10000) if isinstance(roots, list) else None,
            workspace_roots_validation_reason='MISSING' if 'workspace_roots' not in args else
                'INVALID_TYPE' if not isinstance(roots, list) else 'EMPTY_HOST_LIST' if not roots else
                'MULTI_ROOT_UNSUPPORTED' if len(roots) > 1 else
                'INVALID_ROOT' if 'workspace_roots' in invalid else 'VALID',
            **generation_diagnostics(args))

    def resolve(self, arguments, *, project_dir=None, excluded=(), diagnostics=None, on_resolved=None):
        diag = diagnostics if diagnostics is not None else {}
        diag.update(cursor_workspace_source='CURSOR_PROJECT_DIR', cursor_workspace_anchor='CURSOR_PROJECT_DIR',
            cursor_project_dir_present=project_dir is not None, workspace_sources_match=None,
            cursor_project_dir_valid=False, file_path_absolute=None,
            file_path_containment=None, cursor_workspace_resolution_stage='CURSOR_PROJECT_DIR')
        # Never use process cwd: user Hook commands run in the config directory.
        from .cursor_workspace import resolve_cursor_workspace, path_shape
        if project_dir is None:
            diag['workspace_binding_reason'] = 'CURSOR_PROJECT_DIR_REQUIRED'
            raise ValueError('CURSOR_PROJECT_DIR_REQUIRED')
        root = resolve_cursor_workspace(project_dir, excluded=excluded, diagnostics=diag, prefix='cursor_project_dir')
        diag.update(cursor_project_dir_valid=True,
            cursor_project_workspace_hash=identity(os.path.normcase(str(root))))
        diag.update(workspace_claim_hash=identity(os.path.normcase(str(root))),
                    resolved_workspace_hash=identity(os.path.normcase(str(root))),
                    workspace_claim_match=True)
        if on_resolved is not None:
            on_resolved(root)  # Diagnostic partition only; grants no binding.
        roots = arguments['workspace_roots']
        # resolve() is also used directly: malformed corroboration cannot bypass admission.
        if self.validate_claims(arguments, arguments['hook_event_name'])['host_claim_status'] != 'VALID':
            raise ValueError('INVALID_HOST_CLAIMS')
        diag['cursor_workspace_resolution_stage'] = 'WORKSPACE_ROOTS'
        if not roots:
            diag.update(workspace_roots_state='EMPTY_HOST_LIST', workspace_root_relative=None,
                workspace_root_corroboration='EMPTY_HOST_LIST', workspace_binding_reason='EMPTY_HOST_LIST')
        else:
            shape = path_shape(roots[0])
            diag.update({'workspace_root_'+key: value for key, value in shape.items()})
            diag.update(workspace_root_relative=not shape['is_absolute'],
                workspace_roots_state='SINGLE_ABSOLUTE' if shape['is_absolute'] else 'SINGLE_RELATIVE')
            if shape['path_style'] == 'FILE_URI':
                diag['workspace_binding_reason'] = 'URI_STYLE_PATH'
                raise ValueError('URI_STYLE_PATH')
            if shape['is_absolute']:
                corroboration = resolve_cursor_workspace(roots[0], excluded=excluded, diagnostics=diag)
                diag['workspace_claim_hash'] = identity(os.path.normcase(str(corroboration)))
                diag['workspace_sources_match'] = corroboration == root
                diag['workspace_root_corroboration'] = 'MATCHED' if corroboration == root else 'MISMATCH'
            else:
                # Host metadata only. No cwd resolution, concatenation or filesystem lookup.
                diag.update(workspace_root_corroboration='UNVERIFIED_RELATIVE',
                    workspace_binding_reason='WORKSPACE_ROOT_RELATIVE_UNVERIFIED')
                corroboration = root
            if corroboration != root:
                diag['workspace_claim_match'] = False
                diag['cursor_workspace_rejection_detail'] = 'CURSOR_PROJECT_DIR_MISMATCH'
                diag['workspace_binding_reason'] = 'CURSOR_WORKSPACE_SOURCE_MISMATCH'
                raise ValueError('CURSOR_WORKSPACE_SOURCE_MISMATCH')
            if shape['is_absolute']:
                diag.update(cursor_workspace_source='CORROBORATED', workspace_binding_reason='MATCHED')
        if arguments['hook_event_name'] == 'afterFileEdit':
            diag['cursor_workspace_resolution_stage'] = 'FILE_CONTAINMENT'
            raw = arguments['file_path']
            path = Path(raw)
            diag['file_path_absolute'] = path.is_absolute()
            if not path.is_absolute() or '..' in path.parts:
                diag['file_path_containment'] = False
                raise ValueError('WORKSPACE_OUTSIDE_ALLOWED_ROOT')
            no_links(path)
            path = path.resolve(strict=True)
            if not path.is_file() or not path.is_relative_to(root):
                diag['file_path_containment'] = False
                raise ValueError('WORKSPACE_OUTSIDE_ALLOWED_ROOT')
            diag['file_path_containment'] = True
            # A file inside a nested repository is a different security workspace.
            diag['cursor_workspace_resolution_stage'] = 'FILE_WORKSPACE'
            if resolve_cursor_workspace(str(path.parent), excluded=excluded) != root:
                diag['workspace_claim_match'] = False
                diag['cursor_workspace_rejection_detail'] = 'NESTED_REPO_CONFLICT'
                raise ValueError('CURSOR_FILE_WORKSPACE_MISMATCH')
        diag['cursor_workspace_resolution_stage'] = 'COMPLETE'
        return root

    def normalize(self, arguments, root, *, binding_diagnostics):
        event = arguments.get('hook_event_name')
        if event == 'postToolUse':
            raise ValueError('DELIVERY_EVENT_NOT_CORE_ACTIVITY')
        diag = self.validate_claims(arguments, event)
        if (diag['host_claim_status'] != 'VALID' or binding_diagnostics.get('workspace_claim_match') is not True
                or binding_diagnostics.get('session_claim_match') is not True):
            raise ValueError('INVALID_HOST_CLAIMS')
        operation = OperationClass.UNKNOWN
        if event == 'afterFileEdit':
            operation = OperationClass.DIRECT_FILE_MUTATION
        elif event == 'afterShellExecution':
            # Reuse precisely the shipped classifier; commands remain ephemeral.
            from .codex_event_adapter import classify_bash_command
            operation = OperationClass(classify_bash_command({'command': arguments['command']}))
        session = arguments['conversation_id']
        context = VerifiedHostContext('cursor', root, identity(os.path.normcase(str(root))),
            identity(session), None, self.capabilities, session)
        return NormalizedHostEvent(EVENTS[event], context, operation,
            mutation_hint=True if operation == OperationClass.DIRECT_FILE_MUTATION else None,
            stop_guard_active=arguments['loop_count'] > 0 if event == 'stop' else None)

    @staticmethod
    def output(event, result):
        if event == 'sessionStart':
            import json
            return {'additional_context': json.dumps({k: result.get(k) for k in
                ('status', 'coverage', 'baseline_available')}, ensure_ascii=True)}
        # Neither post event documents agent context output. Stop followup exists,
        # but cannot recreate live MCP Ticket authority in a command subprocess.
        return {}
