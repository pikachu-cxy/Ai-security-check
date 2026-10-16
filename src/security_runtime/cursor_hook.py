"""Bounded Cursor stdio ingress. Security decisions use the existing Core only."""
from __future__ import annotations

import hmac
import hashlib
import json
import os
import sys
from pathlib import Path

from .cursor_event_adapter import CursorHostEventAdapter, EVENTS
from .global_workspace import workspace_state, source_snapshot
from .hook_state import HookStateStore, atomic_bytes, identity, no_links
from .storage import SQLiteStore


class CursorBindings:
    """Persistent bounded root/session bindings; no raw identities or authority."""
    def __init__(self, base=None):
        self.base = Path(base or SQLiteStore.default_path().parent / 'cursor-bindings').absolute()
        self.store = HookStateStore(self.base)

    def accept(self, root, session, generation=None):
        from .cursor_event_adapter import claim
        if not claim(session) or generation is not None and not claim(generation):
            raise ValueError('INVALID_HOST_CLAIMS')
        no_links(self.base)
        with self.store.lock(self.base, wait_seconds=2) as locked:
            if not locked:
                raise ValueError('HOST_CLAIM_BUDGET_EXCEEDED')
            path = self.base / 'bindings.json'
            no_links(path)
            key = self.store.key(self.base)
            value = dict(sessions={}, roots=[], sequence=0)
            if path.exists():
                if path.stat().st_size > 64000:
                    raise ValueError('HOST_CLAIM_BUDGET_EXCEEDED')
                signed = json.loads(path.read_bytes())
                signature = signed.pop('signature')
                if not hmac.compare_digest(signature, hmac.new(key, encode(signed), hashlib.sha256).hexdigest()):
                    raise ValueError('WORKSPACE_REFERENCE_STALE')
                value = signed
                if (set(value) not in ({'sessions', 'roots', 'sequence'}, {'sessions', 'roots', 'sequence', 'generations'})
                        or not isinstance(value['sessions'], dict)
                        or not isinstance(value['roots'], list) or type(value['sequence']) is not int
                        or len(value['sessions']) > 64 or len(value['roots']) > 16):
                    raise ValueError('WORKSPACE_REFERENCE_STALE')
            generations = value.setdefault('generations', {})
            def digest(v):
                return isinstance(v, str) and len(v) == 64 and all(c in '0123456789abcdef' for c in v)
            if (not isinstance(generations, dict) or len(generations) > 64
                    or not all(digest(s) and digest(w) for s, w in value['sessions'].items())
                    or not all(digest(w) for w in value['roots'])
                    or not all(s in value['sessions'] and digest(g) for s, g in generations.items())):
                raise ValueError('WORKSPACE_REFERENCE_STALE')
            sid, wid = identity(session), identity(os.path.normcase(str(root)))
            if sid in value['sessions'] and value['sessions'][sid] != wid:
                raise ValueError('SESSION_WORKSPACE_MISMATCH')
            if sid not in value['sessions'] and len(value['sessions']) >= 64:
                raise ValueError('SESSION_CONNECTION_BUDGET_EXCEEDED')
            if wid not in value['roots'] and len(value['roots']) >= 16:
                raise ValueError('WORKSPACE_CONNECTION_BUDGET_EXCEEDED')
            value['sessions'][sid] = wid
            if wid not in value['roots']:
                value['roots'].append(wid)
            value['sequence'] += 1
            # A generation is turn-scoped observation, never an invocation ID or
            # authorization. New user messages legitimately change it.
            previous = generations.get(sid)
            if generation is not None:
                current = identity(generation)
                generations[sid] = current
                state = 'OBSERVED' if previous is None else 'UNCHANGED' if previous == current else 'UPDATED'
            else:
                state = 'NOT_YET_AVAILABLE' if previous is None else 'RETAINED'
            atomic_bytes(path, encode({**value, 'signature': hmac.new(key, encode(value), hashlib.sha256).hexdigest()}))
            return dict(generation_binding_status=state)

    def verify_feedback(self, root, session, generation):
        """Delivery cannot create/advance a binding or turn it into authority."""
        path = self.base / 'bindings.json'
        no_links(path)
        if not path.is_file() or path.stat().st_size > 64000:
            raise ValueError('WORKSPACE_SESSION_BINDING_MISSING')
        with self.store.lock(self.base, wait_seconds=2) as locked:
            if not locked:
                raise ValueError('HOST_CLAIM_BUDGET_EXCEEDED')
            key_path = self.store.workspace_directory(self.base) / 'snapshot.key'
            no_links(key_path)
            key = key_path.read_bytes()
            value = json.loads(path.read_bytes())
            signature = value.pop('signature')
            if len(key) != 32 or not hmac.compare_digest(signature, hmac.new(key, encode(value), hashlib.sha256).hexdigest()):
                raise ValueError('WORKSPACE_REFERENCE_STALE')
            sid, wid = identity(session), identity(os.path.normcase(str(root)))
            if value.get('sessions', {}).get(sid) != wid:
                raise ValueError('WORKSPACE_SESSION_MISMATCH')
            if value.get('generations', {}).get(sid) != identity(generation):
                raise ValueError('WORKSPACE_REFERENCE_STALE')
        return dict(generation_binding_status='UNCHANGED')


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def coordinator(root, *, automatic=False):
    if automatic:
        from .workspace_services import workspace_services
        from .cursor_connector import CursorConnectorInstallation
        integration = CursorConnectorInstallation()
        if integration.configuration_status()['overall'] != 'CONFIGURED' or any(
                row['related'] for row in integration.inspect_project(root)):
            raise ValueError('GLOBAL_CONFIGURATION_NOT_READY')
        directory = workspace_state(root, SQLiteStore.default_path().parent / 'cursor-workspaces')
        _, core, _ = workspace_services(root, directory)
        return core
    from .hook_runtime import HookCoordinator
    from .runtime import SecurityRuntime
    from .scanners import ScannerRegistry, SemgrepAdapter, GitleaksAdapter
    from .toolchain import ToolManager
    from .workspace import WorkspaceResolver
    from .global_workspace import resolve_workspace
    directory = workspace_state(root, SQLiteStore.default_path().parent / 'cursor-workspaces')
    manager = ToolManager()
    runtime = SecurityRuntime(ScannerRegistry([SemgrepAdapter(manager), GitleaksAdapter(manager)],
        tool_manager=manager, fallback_adapters=[]), SQLiteStore(directory / 'scans.db'))
    return HookCoordinator(runtime, HookStateStore(directory / 'hooks'),
        workspace_resolver=resolve_workspace,
        snapshot_capture=None if WorkspaceResolver().resolve(root, allow_non_git_source=True).is_git else source_snapshot)


def handle_cursor_event(payload, *, core=None, bindings=None, project_dir=None, remote=False, store=None, remediation=None,
                        feedback=None, automatic=False):
    if automatic:
        from .cursor_automatic import handle_automatic_event
        return handle_automatic_event(payload, core=core, bindings=bindings, project_dir=project_dir,
                                      remote=remote, store=store)
    from .recent_hooks import Observation, CURRENT
    from .host_event_runtime import handle_normalized_event
    from .host_events import EventKind
    adapter = CursorHostEventAdapter()
    raw_event = payload.get('hook_event_name') if isinstance(payload, dict) else None
    event = raw_event if isinstance(raw_event, str) and raw_event in EVENTS else 'UNKNOWN'
    obs = Observation('cursor', payload, store, host='cursor', event=event)
    token = CURRENT.set(obs)
    result = dict(status='INCONCLUSIVE', coverage='UNKNOWN', scanner_run=False, reason='INVALID_HOST_CLAIMS')
    validated = False
    diag = {}
    root = None
    try:
        diag = adapter.validate_claims(payload, event)
        diag.update(cursor_project_dir_present=project_dir is not None)
        obs.stage('HOOK_RECEIVED', **diag)
        if diag['host_claim_status'] != 'VALID':
            roots_reason = diag.get('workspace_roots_validation_reason')
            if roots_reason == 'MULTI_ROOT_UNSUPPORTED':
                result.update(workspace_rejection_reason='CURSOR_MULTI_ROOT_UNSUPPORTED', workspace_roots_state='MULTI_ROOT')
            result.update(diag)
            obs.stage('CLAIMS_REJECTED', **diag)
            return adapter.output(event, result), result
        if remote:
            raise ValueError('CURSOR_REMOTE_NOT_SUPPORTED')
        from .cursor_integration import cursor_home
        root = adapter.resolve(payload, project_dir=project_dir, excluded=(cursor_home(),),
            diagnostics=diag, on_resolved=obs.bind)
        obs.bind(root)
        bindings = bindings or CursorBindings()
        if event == 'postToolUse':
            diag.update(bindings.verify_feedback(root, payload['conversation_id'], payload['generation_id']))
            diag.update(workspace_claim_match=True, session_claim_match=True)
            obs.stage('CLAIMS_VALID', **diag)
            validated = True
            result.update(diag, status='NOT_SCANNED', reason='HOST_CAPABILITY_UNAVAILABLE',
                security_feedback_delivery_status='HOST_CAPABILITY_UNAVAILABLE_ON_OBSERVED_PATH')
            return {}, result
        diag.update(bindings.accept(root, payload['conversation_id'],
            payload.get('generation_id') or None))
        diag.update(workspace_claim_match=True, session_claim_match=True)
        obs.stage('CLAIMS_VALID', **diag)
        normalized = adapter.normalize(payload, root, binding_diagnostics=diag)
        validated = True
        core = core or coordinator(root)
        if normalized.kind == EventKind.WORKSPACE_ACTIVITY and remediation is None and hasattr(core.runtime, 'store'):
            from .remediation import RemediationService
            from .remediation_policy import RemediationConfig
            from .remediation_transport import AdvisoryTransportConfig
            remediation = RemediationService(core.runtime.store, hooks=core.store,
                config=RemediationConfig(),
                transport=AdvisoryTransportConfig(supports_agent_continuation=
                    adapter.transport_capabilities.supports_live_remediation_continuation))
        result, decision = handle_normalized_event(normalized, coordinator=core, remediation=remediation, lifecycle=True)
        if decision is not None:
            result['remediation'] = decision
        result.update(diag, security_feedback_pending=False, security_feedback_count=0,
            security_feedback_delivery_status='HOST_CAPABILITY_UNAVAILABLE_ON_OBSERVED_PATH', scanner_run=result.get('execution', {}).get('scanner_run', False),
            tool_name='Shell' if event == 'afterShellExecution' else 'Write' if event == 'afterFileEdit' else 'UNKNOWN',
            tool_classification=normalized.operation.value,
            invocation_identity_status='UNAVAILABLE_CONTENT_RECONCILIATION_ONLY',
            continuation_status='PENDING_CURSOR_CONTINUATION_CAPABILITY')
        return adapter.output(event, result), result
    except (ValueError, OSError, KeyError, TypeError):
        if validated:
            result.update(reason='HANDLER_EXCEPTION', status='ERROR')
            obs.stage('HANDLER_ERROR')
            return adapter.output(event, result), result
        from .global_workspace import workspace_rejection
        from .cursor_workspace import REJECTIONS
        exc = sys.exc_info()[1]
        reason = str(exc) if str(exc) in {'CURSOR_REMOTE_NOT_SUPPORTED', 'CURSOR_WORKSPACE_SOURCE_MISMATCH',
            'CURSOR_FILE_WORKSPACE_MISMATCH', 'CURSOR_PROJECT_DIR_REQUIRED'} | REJECTIONS else workspace_rejection(exc, 'RESOLVING_ROOT')
        result.update(diag, reason=reason, host_claim_status='REJECTED', workspace_rejection_reason=reason,
            workspace_binding_reason=reason,
            workspace_claim_match=diag.get('workspace_claim_match', False),
            session_claim_match=False if reason == 'WORKSPACE_SESSION_MISMATCH' else None)
        obs.stage('CLAIMS_REJECTED', **result)
        return adapter.output(event, result), result
    except Exception:
        result.update(reason='HANDLER_EXCEPTION', status='ERROR')
        obs.stage('HANDLER_ERROR')
        return adapter.output(event, result), result
    finally:
        obs.finish(result)
        CURRENT.reset(token)


def main(*, automatic=False):
    # Cursor sends edits/output/transcript metadata; parse bounded input, never
    # persist them, and never open transcript_path or execute command text.
    raw = sys.stdin.buffer.read(1_000_001)
    try:
        if len(raw) > 1_000_000:
            raise ValueError()
        from .codex_integration import unique_json
        payload = unique_json(raw)
    except (ValueError, UnicodeError, RecursionError):
        payload = None
    output, _ = handle_cursor_event(payload, project_dir=os.getenv('CURSOR_PROJECT_DIR'),
        remote=os.getenv('CURSOR_CODE_REMOTE') == 'true', automatic=automatic)
    print(json.dumps(output, ensure_ascii=True))
    return 0  # Advisory post Hooks never block the Host or fabricate success.


if __name__ == '__main__':
    raise SystemExit(main())
