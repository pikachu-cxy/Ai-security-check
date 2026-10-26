"""Codex event claims: bounded validation and connection-local replay rejection.

Claims establish consistency, not authenticated host provenance or edit authority.
Only identifier hashes are retained; neither arguments nor transcripts are stored.
"""
from __future__ import annotations

import hashlib
import os
import threading

EVENTS = {'handle_readiness_event': 'SessionStart', 'handle_hook_event': 'PostToolUse',
          'handle_stop_event': 'Stop'}
LIMITS = dict(event=32, workspace_path=4096, session_id=500, turn_id=500,
              tool_use_id=500, tool_name=64)
PERMISSIONS = {'default', 'acceptEdits', 'plan', 'dontAsk', 'bypassPermissions'}


def diagnostics(arguments, event):
    """Return fixed field names and booleans, never rejected values or keys."""
    args = arguments if isinstance(arguments, dict) else {}
    required = ['event', 'workspace_path', 'session_id']
    if event == 'PostToolUse':
        required += ['turn_id', 'tool_use_id', 'tool_name']
    if event == 'Stop':
        required += ['stop_hook_active']
    missing = [key for key in required if key not in args or args[key] is None]
    invalid = []
    for key, limit in LIMITS.items():
        if key not in args or args[key] is None:
            continue
        value = args[key]
        if (not isinstance(value, str) or not value.strip() or len(value) > limit
                or '${' in value or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
            invalid.append(key)
    if args.get('event') != event and 'event' not in missing + invalid:
        invalid.append('event')
    if event == 'PostToolUse' and (not isinstance(args.get('tool_name'), str)
                                 or args['tool_name'] not in {'Bash', 'apply_patch', 'Edit', 'Write'}):
        if 'tool_name' not in missing + invalid:
            invalid.append('tool_name')
    if args.get('permission_mode') is not None and (not isinstance(args['permission_mode'], str)
                                                  or args['permission_mode'] not in PERMISSIONS):
        invalid.append('permission_mode')
    if event == 'Stop' and 'stop_hook_active' not in missing and type(args['stop_hook_active']) is not bool:
        invalid.append('stop_hook_active')
    if 'tool_input' in args and args['tool_input'] is not None and not isinstance(args['tool_input'], dict):
        patch = args['tool_input']
        if (args.get('tool_name') != 'apply_patch' or not isinstance(patch, str)
                or len(patch) > 262144 or len(patch.encode('utf-8', errors='replace')) > 262144):
            invalid.append('tool_input')
    return dict(host_claim_status='INVALID' if missing or invalid else 'VALID',
                missing_claims=missing, invalid_claims=invalid, event_schema='codex-' + event + '-v1',
                workspace_claim_match=None, session_claim_match=None,
                turn_claim_present=isinstance(args.get('turn_id'), str) and bool(args['turn_id']),
                tool_use_claim_present=isinstance(args.get('tool_use_id'), str) and bool(args['tool_use_id']))


def schema_diagnostics(arguments, event, schema):
    from jsonschema import Draft202012Validator
    result = diagnostics(arguments, event)
    if not isinstance(arguments, dict):
        result['invalid_claims'].append('input_shape')
    else:
        errors = list(Draft202012Validator(schema).iter_errors(arguments))
        for error in errors:
            if error.validator == 'additionalProperties':
                result['invalid_claims'].append('unexpected_fields')
            elif error.path:
                # Nested input keys and validation messages could contain source.
                field = next(iter(error.path))
                if field in schema.get('properties', {}):
                    result['invalid_claims'].append(field)
        if errors:
            result['host_claim_status'] = 'INVALID'
    result['invalid_claims'] = sorted(set(result['invalid_claims']))
    if result['invalid_claims']:
        result['host_claim_status'] = 'INVALID'
    return result


class CodexClaimGuard:
    """No eviction: exhaustion fails closed; restart discards this live context.

    Tool-use ids may not be reused under another session, turn, tool or workspace.
    Independent calls in the same turn are allowed. This does not authenticate an
    MCP client or claim historical replay protection across process restarts.
    """
    def __init__(self, limit=4096):
        self.limit = limit
        self.sessions = {}
        self.invocations = {}
        self.lock = threading.RLock()

    @staticmethod
    def _hash(value):
        return hashlib.sha256(value.encode('utf-8')).hexdigest()

    def accept(self, args, root, diag):
        workspace = self._hash(os.path.normcase(str(root)))
        session = self._hash(args['session_id'])
        with self.lock:
            diag['workspace_claim_match'] = True
            if session in self.sessions and self.sessions[session] != workspace:
                diag.update(host_claim_status='REJECTED', session_claim_match=False)
                return 'SESSION_WORKSPACE_MISMATCH'
            diag['session_claim_match'] = True
            if args['event'] == 'PostToolUse':
                invocation = self._hash(args['tool_use_id'])
                if invocation in self.invocations:
                    prior = self.invocations[invocation]
                    diag['host_claim_status'] = 'REJECTED'
                    diag['invalid_claims'] = ['tool_use_id']
                    diag['workspace_claim_match'] = prior[0] == workspace
                    diag['session_claim_match'] = prior[1] == session
                    return 'TOOL_USE_CLAIM_REPLAYED'
                if len(self.invocations) >= self.limit:
                    diag['host_claim_status'] = 'REJECTED'
                    return 'HOST_CLAIM_BUDGET_EXCEEDED'
            if session not in self.sessions and len(self.sessions) >= 64:
                diag['host_claim_status'] = 'REJECTED'
                return 'SESSION_CONNECTION_BUDGET_EXCEEDED'
            self.sessions[session] = workspace
            if args['event'] == 'PostToolUse':
                self.invocations[invocation] = (workspace, session, self._hash(args['turn_id']),
                                                self._hash(args['tool_name']))
        return None
