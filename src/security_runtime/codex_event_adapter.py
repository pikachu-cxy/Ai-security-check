"""Codex raw claims and tool semantics; no snapshot, scanner or risk decisions."""
from __future__ import annotations

import os
from pathlib import Path

from .codex_host_claims import diagnostics, schema_diagnostics
from .hook_state import identity, no_links
from .host_events import OperationClass
from .host_lifecycle import connector_profile

from .host_tool_events import EVENTS, classify_bash_command, edit_path_hints, normalize_tool_event


class CodexEventAdapter:
    host = 'codex'
    profile = connector_profile('codex')
    capabilities = profile.capabilities
    from .codex_host_claims import EVENTS as mcp_events
    events = EVENTS

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
        event = normalize_tool_event(arguments, root, host=self.host, capabilities=self.capabilities)
        context = event.context
        if not legacy:
            try:
                from .observation import bind_chat, bind_host
                bind_chat(dict(host=self.host, session=context.session_binding))
                turn = arguments.get('turn_id')
                bind_host(self.host, context.session_binding, context.invocation_binding,
                          identity(turn) if turn else None)
            except Exception:
                pass  # Optional attribution never changes validated Hook behavior.
        return event

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
