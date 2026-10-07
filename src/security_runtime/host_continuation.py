"""Bounded Stop fallback for an existing, unconsumed POLICY_AUTO handoff.

Opaque references stay connection-local. Signed records remain authoritative;
this guard neither issues authority nor performs preparation or verification.
"""
from __future__ import annotations

import hmac
import json
import time
from pathlib import Path

from .hook_state import identity, no_links
from .remediation_guard import digest

MAX_CONTINUATIONS = 2
MAX_HANDOFFS = 32
CONTINUATION_WINDOW = 900  # guard eligibility only; never renew a repair grant
GUIDANCE = (
    'SECURITY_AUTO_REMEDIATION_CONTINUATION_REQUIRED. '
    'Runtime has already authorized this exact bounded repair. User confirmation is not required. '
    'The authorized workflow is incomplete. Immediately call prepare_task_fix with the existing '
    'Runtime-issued handoff below. Do not ask the user for approval. Do not repeat the insecure edit. '
    'Follow the existing preparation and security verification protocol; no additional repair authority is issued. ')


def allowed(status='ALLOW_STOP', *, count=0):
    return {'status': status, 'continuation_phase': 'NONE', 'host_continuation_attempt_count': count,
            'max_host_continuations': MAX_CONTINUATIONS,
            'execution': {'scanner_run': False, 'model': False, 'source_modified': False,
                          'target_build': False, 'network': False, 'grant_issued': False}}


class HostContinuationGuard:
    def __init__(self, remediation):
        self.remediation = remediation
        self.handoffs = {}

    def remember(self, path, record, snapshot, arguments):
        """Retain the exact issued handoff, never reconstruct a bearer token."""
        if record.get('authorization_kind', 'POLICY_AUTO') != 'POLICY_AUTO':
            return
        # This optional fallback cannot interfere with normal grant issuance.
        try:
            key_path = path.parent / 'snapshot.key'
            no_links(key_path)
            if key_path.stat().st_size != 32:
                return
            key = key_path.read_bytes()
            mode, policy = self.remediation._policy_binding(key)
            if mode != 'smart_auto' or len(json.dumps(arguments)) > 4096:
                return
            now = time.monotonic()
            for token, item in list(self.handoffs.items()):
                if now >= item['deadline'] or (item['path'] == path and item['family'] == record['family_key']):
                    self.handoffs.pop(token, None)
            if len(self.handoffs) >= MAX_HANDOFFS:
                self.handoffs.pop(next(iter(self.handoffs)))  # forgetting never grants authority
            self.handoffs[record['token_hash']] = {
                'path': path, 'family': record['family_key'], 'arguments': dict(arguments),
                'snapshot': snapshot, 'policy': policy, 'deadline': now + CONTINUATION_WINDOW}
        except (ValueError, OSError, KeyError, TypeError):
            return

    def _current(self, root, session, item, record, key, host):
        service = self.remediation
        return (record['phase'] == 'OFFERED' and record.get('last_action') == 'AUTO_FIX'
                and record.get('authorization_kind', 'POLICY_AUTO') == 'POLICY_AUTO'
                and record.get('host_id') == identity(host) and record.get('session_id') == identity(session)
                and record['family_key'] == item['family']
                and record.get('last_snapshot_digest') == item['snapshot']
                and record.get('token_hash') not in service.prepared
                and time.monotonic() < item['deadline']
                and service._allowed(record, key)
                and service._policy_binding(key)[1] == item['policy']
                and service._snapshot(root) == item['snapshot']
                and service._guard(root, record, key) and service._member_current(record, root))

    def handle(self, root, session, stop_hook_active, *, host='codex'):
        """No scans. Fail closed to automatic continuation, quiet in Hook text."""
        service = self.remediation
        path = service.state.path(root, host, session)
        candidates = [item for item in list(self.handoffs.values()) if item['path'] == path]
        if not candidates:
            return allowed()
        try:
            with service.state.lock(root) as acquired:
                if not acquired:
                    return allowed('INCONCLUSIVE')
                for item in candidates:
                    args = item['arguments']
                    current_path, key, rows, record = service._reference(root, args['remediation_ref'], args['task_ref'])
                    if (current_path != path or len(key) != 32 or record['phase'] != 'OFFERED'
                            or record.get('token_hash') in service.prepared):
                        continue
                    binding = digest(key, json.dumps([record['token_hash'], item['snapshot'], item['policy'],
                                                      'AUTO_FIX_PREPARE_REQUIRED']).encode())
                    previous = record.get('host_continuation')
                    count = 0
                    if previous is not None:
                        if (not isinstance(previous, dict) or set(previous) != {'binding', 'attempt_count', 'status', 'stop_hook_active'}
                                or not isinstance(previous['binding'], str) or not hmac.compare_digest(previous['binding'], binding)
                                or type(previous['attempt_count']) is not int or not 1 <= previous['attempt_count'] <= MAX_CONTINUATIONS
                                or previous['status'] not in {'CONTINUATION_REQUIRED', 'HOST_CONTINUATION_EXHAUSTED'}
                                or type(previous['stop_hook_active']) is not bool):
                            return allowed('INCONCLUSIVE')
                        count = previous['attempt_count']
                        if previous['status'] == 'HOST_CONTINUATION_EXHAUSTED':
                            # This is an allow-only branch: no freshness/source
                            # reads or repeated writes are needed after exhaustion.
                            return allowed('HOST_CONTINUATION_EXHAUSTED', count=count)
                    if not self._current(root, session, item, record, key, host):
                        continue
                    # An already-active Stop with no attempt by this guard could
                    # be another Hook's continuation. Do not join that loop.
                    if stop_hook_active and count == 0:
                        return allowed('STOP_ALREADY_ACTIVE')
                    # Recheck after membership/evidence freshness reads. No scan.
                    if not self._current(root, session, item, record, key, host):
                        return allowed('INCONCLUSIVE')
                    if count >= MAX_CONTINUATIONS:
                        if previous['status'] != 'HOST_CONTINUATION_EXHAUSTED':
                            previous.update(status='HOST_CONTINUATION_EXHAUSTED', stop_hook_active=stop_hook_active)
                            service._save(path, rows, key)
                        return allowed('HOST_CONTINUATION_EXHAUSTED', count=count)
                    count += 1
                    service._observe_cycle('mark_token', record.get('token_hash'), 'host_continuation_observed',
                                           root=root, source='STOP_GUARD')
                    record['host_continuation'] = {'binding': binding, 'attempt_count': count,
                        'status': 'CONTINUATION_REQUIRED', 'stop_hook_active': stop_hook_active}
                    service._save(path, rows, key)
                    result = allowed('CONTINUATION_REQUIRED', count=count)
                    result.update(continuation_phase='AUTO_FIX_PREPARE_REQUIRED', decision='block',
                                  reason=GUIDANCE + json.dumps({'mcp_tool': 'prepare_task_fix', 'arguments': args},
                                                              ensure_ascii=True, separators=(',', ':')))
                    return result
            return allowed()
        except Exception:
            # Never echo rejected host claims, state, source, tokens or errors.
            return allowed('INCONCLUSIVE')


def handle_stop_event(event, workspace_path, session_id, stop_hook_active, *, binding, guard):
    """Backward-compatible raw Codex entry point; Core uses normalized Stop."""
    from .codex_event_adapter import handle_legacy_stop_event
    return handle_legacy_stop_event(event, workspace_path, session_id, stop_hook_active,
                                    binding=binding, guard=guard)
