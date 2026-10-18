"""Development review tool registration; v3 business rules stay in task services."""
from __future__ import annotations

from typing import Literal
from mcp.types import ToolAnnotations
from ..task_review_protocol import PROTOCOL_VERSION
from .. import task_review_contract as task_review_models


def register(server, registry, *, application):
    bound_path = application.bound_path
    task_service = application.task_service
    native_binding_required = application.native_binding_required
    issued_tasks = application.issued_tasks
    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def begin_security_task(task_key: str, workspace_path: str | None = None, session_ref: str | None = None) -> dict:
        """Before the first source/config edit of an actual development task, snapshot the current workspace (including existing dirty files). Unique task_key per task, no prompt/source. No scan/model/build/edit. Never call for ordinary chat or restart after editing to fake a baseline."""
        native_binding_required(workspace_path, session_ref)
        service=task_service(session_ref=session_ref,workspace=workspace_path)
        result=service.begin(bound_path(workspace_path),task_key)
        if result.get('task_ref'):
            if len(issued_tasks)>=64: issued_tasks.pop(next(iter(issued_tasks)))
            issued_tasks[result['task_ref']]=service._owner()
        return result

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def finish_security_task(task_ref: str, workspace_path: str | None = None, skip_review_reason: str | None = None,
                             session_ref: str | None = None) -> dict:
        """Before the development summary, compare against the exact task baseline. No actual changes: no checks/message. Actual changes: one bounded static check of task scope, then prepare_task_security_review even with zero scanner alerts. No repairs, model, target builds or Stop continuation."""
        if skip_review_reason is not None:
            return task_service(task_ref,session_ref,workspace_path).skip(bound_path(workspace_path), task_ref, skip_review_reason)
        return task_service(task_ref,session_ref,workspace_path).finish(bound_path(workspace_path), task_ref)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def prepare_task_security_review(task_ref: str, workspace_path: str | None = None, session_ref: str | None = None,
                                     protocol_version: Literal[3] = PROTOCOL_VERSION) -> dict:
        """Prepare protocol 3 only, preserving the original pre-edit baseline, source snapshot, evidence and cumulative allowances. Older protocols are unsupported and older tasks remain read-only. Page all required fragments, read actual before/current evidence and submit batches; resume only the same owner/snapshot/ledger. No scan reset or repair authority."""
        return task_service(task_ref,session_ref,workspace_path).prepare(bound_path(workspace_path), task_ref,
            protocol_version=protocol_version)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def get_task_review_plan(task_ref: str, review_session: str, cursor: int = 0, limit: int = 10,
                              workspace_path: str | None = None, session_ref: str | None = None) -> dict:
        """Page the current version-3 task's required review units. For v3 follow next_cursor across all window_fragment items, including multiple fragments of the same unit_id. Use the returned cursor and exact task/session; omitted pages remain required work. This reads the plan without rescanning, starting a new task or resetting cumulative budgets."""
        from ..task_security import TaskContextError
        try:
            return task_service(task_ref,session_ref,workspace_path).review_plan(bound_path(workspace_path),
                task_ref, review_session, cursor, limit)
        except TaskContextError as exc:
            return exc.response(task_ref, review_session)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def get_task_review_method(task_ref: str, review_session: str, workspace_path: str | None = None,
                                session_ref: str | None = None) -> dict:
        """Get the canonical method for this exact version-3 review session when its advertised version/hash is unavailable locally. Retrieve once and reuse within the same method version; source evidence and plan coverage remain separate. No scan, task restart or repair authority."""
        from ..task_security import TaskContextError
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
        from ..task_security import TaskContextError
        try:
            return task_service(task_ref,session_ref,workspace_path).submit_batch(bound_path(workspace_path),
                task_ref, review_session, unit_ids, coverage, limitations)
        except TaskContextError as exc:
            return exc.response(task_ref, review_session)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def read_task_review_context(task_ref: str, review_session: str, file_path: str,
                                 start_line: int = 1, end_line: int = 80, workspace_path: str | None = None,
                                 source_version: str = 'CURRENT', session_ref: str | None = None) -> dict:
        """Read a v3 sanitized before/current source window, at most 80 lines. Follow next_range/unread_ranges using the exact task/session/version. ALREADY_DELIVERED reuses only real issued evidence. Plan-derived finite source/navigation/control allowances and size-scheduled batches never reset on pagination or reconnect. Missing source, unread ranges and incomplete coverage remain gaps. No old-protocol reads, .env content, links, path escapes, commands or network."""
        from ..task_security import TaskContextError
        try:
            return task_service(task_ref,session_ref,workspace_path).read(bound_path(workspace_path), task_ref, review_session, file_path, start_line, end_line, source_version)
        except TaskContextError as exc:
            return exc.response(task_ref, review_session)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def submit_task_security_review(task_ref: str, review_session: str, findings: task_review_models.TaskReviewFindings,
                                     coverage: task_review_models.ReviewCoverage, limitations: task_review_models.TaskReviewLimitations, workspace_path: str | None = None,
                                    risk_resolutions: list[dict] | None = None, session_ref: str | None = None) -> dict:
        """Submit host reasoning with Runtime-issued evidence_id strings: primary_evidence and task_evidence are strings; evidence_refs is an array of strings, never file/line objects. See packet submission_contract for a complete candidate example. On field_errors correct the same active task/review version without rescanning or replacing its baseline. Runtime validates structure/version, never proves exploitability or grants repair authority. Merge development_summary into the normal response."""
        try:
            return task_service(task_ref,session_ref,workspace_path).submit(bound_path(workspace_path), task_ref, review_session, findings, coverage, limitations, risk_resolutions)
        except task_review_models.TaskReviewInputError as exc:
            return exc.response()

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_task_security_review(task_ref: str, workspace_path: str | None = None, finding_offset: int = 0, finding_limit: int = 20) -> dict:
        """Read saved task results with current-source freshness, without scans or model calls. History combines static then host findings into bounded history pages (finding_offset/limit; next_action), at most 3 complete records and 64KB. This history-only allowance does not renew source-review budgets. Explicit RESULT_DETAIL_LIMIT means the local record could not fit; never present it as complete. No repair authority."""
        return task_service(task_ref).get(bound_path(workspace_path), task_ref, finding_offset, finding_limit)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_task_risk_ledger(task_ref: str, workspace_path: str | None = None, offset: int = 0, limit: int = 30) -> dict:
        """Read per-original-finding outcomes and current-source freshness. No scan, edits or repair authority. Native checks and host code review remain distinct; use exact original task_ref."""
        return task_service(task_ref).risk_ledger(bound_path(workspace_path), task_ref, offset, limit)
