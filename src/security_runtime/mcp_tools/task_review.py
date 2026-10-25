"""Development review tool registration; v3 business rules stay in task services."""
from __future__ import annotations

from typing import Literal
from mcp.types import ToolAnnotations
from ..task_review.protocol import PROTOCOL_VERSION
from ..task_review import contract as task_review_models


def register(server, registry, *, application):
    bound_path = application.bound_path
    task_service = application.task_service
    native_binding_required = application.native_binding_required
    issued_tasks = application.issued_tasks
    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def begin_security_task(task_key: str, workspace_path: str | None = None, session_ref: str | None = None,
                            workspace_setup_ref: str | None = None) -> dict:
        """Before the first source/config edit of an actual development task, snapshot the current workspace (including existing dirty files). Unique task_key per task, no prompt/source. No scan/model/build/edit. Never call for ordinary chat or restart after editing to fake a baseline."""
        native_binding_required(workspace_path, session_ref)
        service=task_service(session_ref=session_ref,workspace=workspace_path)
        from ..tasks.activity import POLICY
        result=service.begin(bound_path(workspace_path),task_key,check_policy=POLICY,background_closeout=True,
                             workspace_setup_ref=workspace_setup_ref)
        if result.get('task_ref'):
            if len(issued_tasks)>=64: issued_tasks.pop(next(iter(issued_tasks)))
            issued_tasks[result['task_ref']]=service._owner()
        return result

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def prepare_task_workspace(task_key: str, workspace_path: str | None = None,
                               session_ref: str | None = None) -> dict:
        """Explicitly prepare a separate task directory from current dirty sources. No baseline yet.
        Open the returned directory in the host before begin_security_task with its setup reference.
        Does not move this chat, constrain Shell writes, merge, or migrate an existing task.
        """
        from ..task_workspaces import prepare
        native_binding_required(workspace_path, session_ref)
        service = task_service(session_ref=session_ref, workspace=workspace_path)
        return prepare(bound_path(workspace_path), task_key, service._owner())

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_task_isolation_capabilities() -> dict:
        """Describe implemented directory isolation separately from unsupported host write boundaries."""
        from ..task_workspaces import capability
        return capability()

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def switch_security_task(from_task_ref: str | None, expected_routing_generation: int,
                             to_task_ref: str | None = None, new_task_key: str | None = None,
                             workspace_path: str | None = None, session_ref: str | None = None) -> dict:
        """Explicitly suspend/switch/resume this session's task. New work captures its baseline before editing; resume never recaptures. No scan, repair or cross-session adoption."""
        from ..tasks.lifecycle import switch
        native_binding_required(workspace_path, session_ref)
        service = task_service(session_ref=session_ref, workspace=workspace_path)
        result = switch(service, bound_path(workspace_path), from_task_ref, to_ref=to_task_ref,
                        new_key=new_task_key, generation=expected_routing_generation)
        if result.get('task_ref'):
            if len(issued_tasks) >= 64:
                issued_tasks.pop(next(iter(issued_tasks)))
            issued_tasks[result['task_ref']] = service._owner()
        return result

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def finish_security_task(task_ref: str, workspace_path: str | None = None, skip_review_reason: str | None = None,
                             session_ref: str | None = None) -> dict:
        """Before the development summary, compare against the exact task baseline. No actual changes: no checks/message. Actual changes: one bounded static check of task scope, then prepare_task_security_review even with zero scanner alerts. No repairs, model, target builds or Stop continuation."""
        if skip_review_reason is not None:
            service = task_service(task_ref,session_ref,workspace_path)
            from ..tasks.closeout_queue import CloseoutQueue, PENDING
            root = service.root(bound_path(workspace_path))
            service.load(root, task_ref)
            row = CloseoutQueue(service.hooks, root).read(task_ref)
            if row and row['state'] in PENDING:
                from ..tasks.queued_closeout import cancel
                result = cancel(service, root, task_ref)
                if result['status'] == 'BUSY':
                    return result
            return service.skip(root, task_ref, skip_review_reason)
        service = task_service(task_ref,session_ref,workspace_path)
        root = service.root(bound_path(workspace_path))
        if service.load(root, task_ref).get('closeout_dispatch') == 'BACKGROUND_V1':
            from ..tasks.queued_closeout import enqueue
            return enqueue(service, root, task_ref)
        return service.finish(root, task_ref)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_task_closeout_status(task_ref: str, workspace_path: str | None = None,
                                session_ref: str | None = None) -> dict:
        """Read this owner's saved queue status; never dispatch, recapture or scan."""
        from ..tasks.queued_closeout import status
        return status(task_service(task_ref,session_ref,workspace_path), bound_path(workspace_path), task_ref)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def wait_task_closeout(task_ref: str, workspace_path: str | None = None,
                          session_ref: str | None = None, timeout_seconds: int = 10) -> dict:
        """Wait at most 30 seconds for saved queue progress. Does not execute scans or a model."""
        import time
        from ..tasks.queued_closeout import status
        from ..tasks.closeout_queue import PENDING
        if type(timeout_seconds) is not int or not 0 <= timeout_seconds <= 30:
            raise ValueError('Wait timeout must be between 0 and 30 seconds')
        service = task_service(task_ref,session_ref,workspace_path)
        deadline = time.monotonic()+timeout_seconds
        while True:
            result = status(service, bound_path(workspace_path), task_ref)
            if result['status'] not in PENDING or time.monotonic() >= deadline:
                return result
            time.sleep(min(0.25, max(0, deadline-time.monotonic())))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def cancel_task_closeout(task_ref: str, workspace_path: str | None = None,
                            session_ref: str | None = None) -> dict:
        """Explicitly cancel only this owner's queued static work; preserve task and baseline."""
        from ..tasks.queued_closeout import cancel
        return cancel(task_service(task_ref,session_ref,workspace_path), bound_path(workspace_path), task_ref)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def prepare_task_security_review(task_ref: str, workspace_path: str | None = None, session_ref: str | None = None,
                                     protocol_version: Literal[3] = PROTOCOL_VERSION,
                                     resume_capacity: bool = False) -> dict:
        """Prepare protocol 3 only, preserving the original pre-edit baseline and cumulative allowances. An unfinished background closeout with changed sources queues a bounded new end snapshot on the SAME task; follow queue progress, then prepare again. Old evidence stays historical and must not approve the new version. Reads never start recovery; cancelled, completed and incompatible work is not automatically restarted. resume_capacity=true explicitly retries only an original INCOMPLETE legacy paged-record byte diagnosis before any plan/evidence delivery, after owner and unchanged-source checks; it retains the closure reason and does not restart scans or reconstruct a baseline. Use only when the user authorizes resuming that capacity-blocked task. Page all required fragments, read actual before/current evidence and submit batches. No budget reset or repair authority."""
        return task_service(task_ref,session_ref,workspace_path).prepare(bound_path(workspace_path), task_ref,
            protocol_version=protocol_version, resume_capacity=resume_capacity)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def get_task_review_plan(task_ref: str, review_session: str, cursor: int = 0, limit: int = 10,
                              workspace_path: str | None = None, session_ref: str | None = None) -> dict:
        """Page the current version-3 task's required review units. For v3 follow next_cursor across all window_fragment items, including multiple fragments of the same unit_id. Use the returned cursor and exact task/session; omitted pages remain required work. This reads the plan without rescanning, starting a new task or resetting cumulative budgets."""
        from ..tasks.security import TaskContextError
        try:
            return task_service(task_ref,session_ref,workspace_path).review_plan(bound_path(workspace_path),
                task_ref, review_session, cursor, limit)
        except TaskContextError as exc:
            return exc.response(task_ref, review_session)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def get_task_review_method(task_ref: str, review_session: str, workspace_path: str | None = None,
                                session_ref: str | None = None) -> dict:
        """Get the canonical method for this exact version-3 review session when its advertised version/hash is unavailable locally. Retrieve once and reuse within the same method version; source evidence and plan coverage remain separate. No scan, task restart or repair authority."""
        from ..tasks.security import TaskContextError
        try:
            return task_service(task_ref,session_ref,workspace_path).review_method(bound_path(workspace_path),
                task_ref, review_session)
        except TaskContextError as exc:
            return exc.response(task_ref, review_session)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def submit_task_review_batch(task_ref: str, review_session: str, unit_ids: list[str], coverage: str,
                                  limitations: list[str], workspace_path: str | None = None,
                                  session_ref: str | None = None) -> dict:
        """Record reasoning completion for exact version-3 plan units after their required current/before evidence has been read. Report REVIEWED or PARTIAL with explicit limitations. Batch completion never substitutes for the final submit_task_security_review, erases other pending work, resets task budgets or grants repair authority."""
        from ..tasks.security import TaskContextError
        try:
            return task_service(task_ref,session_ref,workspace_path).submit_batch(bound_path(workspace_path),
                task_ref, review_session, unit_ids, coverage, limitations)
        except TaskContextError as exc:
            return exc.response(task_ref, review_session)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def read_task_review_context(task_ref: str, review_session: str, file_path: str,
                                 start_line: int = 1, end_line: int = 80, workspace_path: str | None = None,
                                 source_version: str = 'CURRENT', session_ref: str | None = None) -> dict:
        """Read a v3 captured before/current source window, at most 80 lines.

        Follow next_range/unread_ranges with the exact task/session/version.
        Oversized lines use start_char/end_char/line_chars: zero-based half-open
        Unicode codepoint offsets. Repeat the same next_range to receive the
        next unread fragment; only all fragments together cover a whole line.
        ALREADY_DELIVERED reuses only real issued evidence. Finite task-wide
        source/navigation/control allowances never reset on pagination or
        reconnect. Missing source and unread ranges remain gaps. No old-protocol
        reads, .env content, links, path escapes, commands or network.
        """
        from ..tasks.security import TaskContextError
        try:
            return task_service(task_ref,session_ref,workspace_path).read(bound_path(workspace_path), task_ref, review_session, file_path, start_line, end_line, source_version)
        except TaskContextError as exc:
            return exc.response(task_ref, review_session)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def submit_task_security_review(task_ref: str, review_session: str, findings: task_review_models.TaskReviewFindings,
                                     coverage: task_review_models.ReviewCoverage, limitations: task_review_models.TaskReviewLimitations, workspace_path: str | None = None,
                                    risk_resolutions: list[dict] | None = None, session_ref: str | None = None,
                                    risk_attributions: task_review_models.RiskAttributions | None = None) -> dict:
        """Submit host reasoning with Runtime-issued evidence_id strings: primary_evidence and task_evidence are strings; evidence_refs is an array of strings, never file/line objects. REVIEW_CONTINUE_REQUIRED saves no final result: follow next_action and finish readable ranges and unit reasoning on the same task/session, then resubmit findings. On field_errors correct the same active task/review version without rescanning or replacing its baseline. Follow the saved terminal receipt's next_action, preserving completion_revision and the original session_ref, for the bounded current delivery; then merge its full development_summary into the normal response. Saving never proves exploitability or grants repair authority."""
        try:
            return task_service(task_ref,session_ref,workspace_path).submit(bound_path(workspace_path), task_ref, review_session, findings, coverage, limitations, risk_resolutions, risk_attributions)
        except task_review_models.TaskReviewInputError as exc:
            return exc.response()

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_task_security_review(task_ref: str, workspace_path: str | None = None, finding_offset: int = 0,
                                 finding_limit: int = 20, completion_revision: int | None = None,
                                 session_ref: str | None = None) -> dict:
        """Read saved results without scans, writes or model calls. Default history reads never repeat a repair choice. For current development delivery follow the terminal next_action with its completion_revision and original session_ref; Runtime verifies the original owner, terminal revision and current source before showing complete risk text and valid choices. Both paths combine static then host findings, at most 3 complete records and 64KB; follow next_action pages. RESULT_DETAIL_LIMIT explicitly withholds oversized details. No review-budget reset or repair authority."""
        return task_service(task_ref,session_ref,workspace_path).get(bound_path(workspace_path), task_ref,
            finding_offset, finding_limit, completion_revision=completion_revision)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_task_risk_ledger(task_ref: str, workspace_path: str | None = None, offset: int = 0, limit: int = 30) -> dict:
        """Read per-original-finding outcomes and current-source freshness. No scan, edits or repair authority. Native checks and host code review remain distinct; use exact original task_ref."""
        return task_service(task_ref).risk_ledger(bound_path(workspace_path), task_ref, offset, limit)
