"""Normalized event dispatch; the existing coordinator remains the only scanner core."""
from __future__ import annotations

import time
import sqlite3

from .host_events import EventKind, NormalizedHostEvent, OperationClass
from .hooks import HookEvent
from .host_event_journal import EventClaim, HostEventJournal


def _event_task(hooks, root, context):
    from .task_orchestration import select_task
    from .task_security_state import TaskSecurityStore
    task = select_task(TaskSecurityStore(hooks, root),
        dict(host=context.host, session=context.session_binding), hook=True)
    return task['task_ref'] if task else None


def _claim_result(claim, normalized, context, *, reason=None):
    result = inconclusive(reason or claim.state)
    result.update(normalized, event_processing=claim.facts(), session_id=context.session_binding,
        scanner_skipped_reason=reason or claim.state, workspace_mutation_observed=None,
        changed_file_count=None)
    if claim.task_ref is not None:
        result['security_task_ref'] = claim.task_ref
    return result


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
    from .task_attribution import session_activity
    owner = dict(host=context.host, session=context.session_binding)
    if event.kind != EventKind.SESSION_STOP:
        session_activity(coordinator.store, context.workspace, owner)
    if event.kind == EventKind.SESSION_STOP and continuation is not None:
        result = continuation.handle(context.workspace, context._session,
                                     event.stop_guard_active, host=context.host)
        if result.get('status') == 'ALLOW_STOP' and result.get('decision') != 'block':
            idle = (not event.stop_guard_active and coordinator.store.pending_activity(
                context.workspace, context.host, context._session) is None)
            session_activity(coordinator.store, context.workspace, owner, idle=idle)
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
    journal, claim = None, None
    recovered_publication = None
    if event.kind == EventKind.WORKSPACE_ACTIVITY:
        recover = getattr(coordinator, 'recover_publications', None)
        if callable(recover):
            recovered_publication = recover(context.workspace, context.host, context._session)
    if HostEventJournal.applicable(event):
        try:
            journal = HostEventJournal(coordinator.store, context.workspace)
            target = _event_task(coordinator.store, context.workspace, context)
            claim = journal.claim(event, task_ref=target)
            if claim.state != 'CLAIMED':
                if (claim.state == 'ALREADY_COMPLETED' and recovered_publication is not None
                        and recovered_publication.get('recovered_result') is not None):
                    result = recovered_publication['recovered_result']
                    result['original_execution'] = dict(result['execution'])
                    result['execution'] = dict(result['execution'], scanner_run=False)
                    result.update(normalized, event_processing=claim.facts(),
                                  publication_recovered=True, scanner_run=False)
                    return result, None
                return _claim_result(claim, normalized, context), None
            # Existing sequence-based pending state is retained. Admission and
            # dispatch are separate so a stale pre-dispatch worker is fenced.
            coordinator.store.pending_activity(context.workspace, context.host, context._session, mark=True)
            from .closeout_state import CloseoutStateStore
            from .hook_state import identity
            jobs = CloseoutStateStore(coordinator.store.workspace_directory(context.workspace) / 'closeout.db',
                                      lambda: coordinator.store.key(context.workspace))
            previous = jobs.latest(context.workspace_identity, identity(context.host+'\0'+context._session))
            if previous and previous['status'] != 'COMPLETED':
                jobs.mark_pending(previous['closeout_ref'], previous['workspace_id'])
            if not journal.start(claim):
                return _claim_result(claim, normalized, context, reason='EVENT_CLAIM_LOST'), None
        except (ValueError, OSError, sqlite3.DatabaseError):
            unavailable = EventClaim(None, 'JOURNAL_UNAVAILABLE')
            return _claim_result(unavailable, normalized, context), None
    mapped = {EventKind.SESSION_START: HookEvent.SESSION_START,
              EventKind.WORKSPACE_ACTIVITY: HookEvent.FILE_CHANGED,
              EventKind.SESSION_STOP: HookEvent.AGENT_STOP}[event.kind]
    if event.kind == EventKind.WORKSPACE_ACTIVITY:
        observe('RECONCILIATION_STARTED', **normalized)
    try:
        task_binding = {'expected_task_ref':claim.task_ref} if claim is not None else {}
        result = (coordinator.handle_lifecycle(event.kind, context.workspace, context.host, context._session, **task_binding)
                  if lifecycle else coordinator.handle(mapped, context.workspace, context.host, context._session, **task_binding))
    except Exception:
        if journal is not None and claim is not None:
            try:
                journal.uncertain(claim)
            except (ValueError, OSError, sqlite3.DatabaseError):
                pass  # The dispatched row still prevents automatic replay.
        raise
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
    if journal is not None and claim is not None:
        try:
            completed = journal.complete(claim, result)
        except (ValueError, OSError, sqlite3.DatabaseError):
            completed = False
        result['event_processing'] = dict(claim.facts(),
            state='COMPLETED' if completed else 'COMPLETION_PENDING')
        if not completed:
            # Execution may have committed; never discard it or run it again
            # just because its event acknowledgement failed.
            try:
                coordinator.store.pending_activity(context.workspace, context.host, context._session, mark=True)
            except (ValueError, OSError, sqlite3.DatabaseError):
                pass
    elif event.kind == EventKind.WORKSPACE_ACTIVITY:
        result['event_processing'] = EventClaim(None, 'CONTENT_RECONCILIATION_ONLY').facts()
    result.update(normalized)
    if event.kind == EventKind.SESSION_STOP and result.get('status') in {
            'SESSION_FINALIZED', 'REUSED_LAST_RESULT', 'NO_CHANGE'}:
        idle = (not event.stop_guard_active and coordinator.store.pending_activity(
            context.workspace, context.host, context._session) is None)
        session_activity(coordinator.store, context.workspace, owner, idle=idle)
    return result, decision
