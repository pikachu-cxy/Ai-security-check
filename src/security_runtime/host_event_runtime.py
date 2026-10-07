"""Normalized event dispatch; the existing coordinator remains the only scanner core."""
from __future__ import annotations

import time

from .host_events import EventKind, NormalizedHostEvent, OperationClass
from .hooks import HookEvent


def inconclusive(reason):
    return {'status': 'INCONCLUSIVE', 'coverage': 'UNKNOWN', 'scan_id': None,
            'delta': dict(new=0, persisting=0, resolved=0,
                          additional_occurrences=0, removed_occurrences=0),
            'execution': dict(scanner_run=False, ai_called=False,
                              network_required=False, source_modified=False, target_build=False),
            'baseline_available': False, 'duration_ms': 0, 'reason': reason,
            'next_step': 'Hook check was not completed. Verify the connected server workspace binding and refresh host claims.'}


def handle_normalized_event(event: NormalizedHostEvent, *, coordinator, remediation=None,
                            started=None, continuation=None, lifecycle=False):
    """Return core result and optional existing remediation decision.

    This is an internal boundary; raw arguments cannot assert a verified context.
    A mutation hint never substitutes for the coordinator's filesystem evidence.
    No model, build or Deep verification is invoked here.
    """
    if not isinstance(event, NormalizedHostEvent):
        raise ValueError('Normalized host event required')
    event.__post_init__()
    event.context.__post_init__()
    context = event.context
    from .recent_hooks import observe
    normalized = event.diagnostics()
    if lifecycle:
        normalized['event_dispatch_route'] = {EventKind.SESSION_START:'SESSION_BASELINE',
            EventKind.WORKSPACE_ACTIVITY:'WORKSPACE_RECONCILIATION',
            EventKind.SESSION_STOP:'SESSION_FINALIZATION'}[event.kind]
    observe('CLAIMS_VALID', **normalized)
    if event.kind == EventKind.SESSION_STOP and continuation is not None:
        result = continuation.handle(context.workspace, context._session,
                                     event.stop_guard_active, host=context.host)
        return {**result, **normalized}, None
    if event.kind == EventKind.WORKSPACE_ACTIVITY and event.operation == OperationClass.READ_ONLY:
        result = inconclusive('READ_ONLY_ACTIVITY')
        result.update(status='NOT_SCANNED', coverage='NOT_APPLICABLE', scanner_run=False,
            workspace_mutation_observed=False, changed_file_count=0,
            scanner_trigger_reason=None, scanner_skipped_reason='READ_ONLY_ACTIVITY')
        if lifecycle:
            result.update(scanner_invocation_count=0, mutation_event_dropped=False)
        observe('READ_ONLY_SKIPPED', scanner_run=False, **normalized)
        return {**result, **normalized}, None
    mapped = {EventKind.SESSION_START: HookEvent.SESSION_START,
              EventKind.WORKSPACE_ACTIVITY: HookEvent.FILE_CHANGED,
              EventKind.SESSION_STOP: HookEvent.AGENT_STOP}[event.kind]
    if event.kind == EventKind.WORKSPACE_ACTIVITY:
        observe('RECONCILIATION_STARTED', **normalized)
    result = (coordinator.handle_lifecycle(event.kind, context.workspace, context.host, context._session)
              if lifecycle else coordinator.handle(mapped, context.workspace, context.host, context._session))
    decision = None
    if event.kind == EventKind.WORKSPACE_ACTIVITY:
        result.setdefault('workspace_mutation_observed', None)
        result.setdefault('changed_file_count', None)
        result['normalized_scanner_trigger_reason'] = ('WORKSPACE_CONTENT_DELTA'
            if result['workspace_mutation_observed'] is True else None)
        result['scanner_skipped_reason'] = result['status'] if not result['execution']['scanner_run'] else None
        if remediation is not None:
            decision = remediation.on_hook(result, context.workspace, context._session,
                host=context.host, event_started=started, initial_scan_finished=time.perf_counter(),
                workspace_context=context)
    result.update(normalized)
    return result, decision
