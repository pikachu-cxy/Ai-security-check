"""Technical feedback and independent user handling transport registrations."""
from __future__ import annotations

import secrets
import time
from typing import Literal
from mcp.types import ToolAnnotations
from ..feedback_contract import FindingEvidenceReference


def register(server, registry, *, application, runtime_engine, check_scan):
    bound_path = application.bound_path
    task_service = application.task_service
    feedback_sessions = {}
    from ..task_risk_feedback import TaskRiskFeedbackService
    task_risk_feedback = TaskRiskFeedbackService()

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def prepare_task_risk_feedback(task_ref: str, finding_id: str, workspace_path: str | None = None,
                                   session_ref: str | None = None) -> dict:
        """Read a bounded sanitized review packet for an original HOST_TASK_REVIEW risk. Use the exact original finding and task refs; same owner only. No scans, source edits, task restart, or repair authority. The feedback token is local to this MCP connection and expires after 900 seconds."""
        return task_risk_feedback.prepare(task_service(task_ref, session_ref, workspace_path),
                                         bound_path(workspace_path), task_ref, finding_id)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def submit_task_risk_feedback(task_ref: str, finding_id: str, feedback_ref: str, verdict: str,
                                  rationale: str, counterevidence: list[str], evidence_refs: list[str],
                                  current_protections: list[str] | None = None, unknowns: list[str] | None = None,
                                  workspace_path: str | None = None, session_ref: str | None = None) -> dict:
        """Record HOST_CODE_REVIEW_NOT_SCANNER_PROOF feedback with FALSE_POSITIVE, STILL_RISK or NEEDS_CONTEXT. Complete unchanged issued source evidence is required to fold a false positive; masked secret values and missing context cannot justify folding. Preserve original risk status and audit; this grants no edits or repairs."""
        return task_risk_feedback.submit(task_service(task_ref, session_ref, workspace_path),
            bound_path(workspace_path), task_ref, finding_id, feedback_ref, verdict, rationale,
            counterevidence, evidence_refs, current_protections, unknowns)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def mark_task_risk_false_positive(task_ref: str, finding_id: str, reason: str,
                                      user_requested: bool = False, workspace_path: str | None = None,
                                      session_ref: str | None = None) -> dict:
        """Legacy opinion-only note, USER_REPORT_NOT_CONFIRMED; user_requested must be true. For an explicit user decision to mark false positive or stop reminders use set_task_risk_disposition EXCLUDE instead. This note alone never proves safety, changes handling, or authorizes repair."""
        return task_risk_feedback.mark(task_service(task_ref, session_ref, workspace_path),
            bound_path(workspace_path), task_ref, finding_id, reason, user_requested=user_requested)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def set_task_risk_disposition(task_ref: str, finding_id: str,
                                  disposition: Literal['EXCLUDE', 'DEFER', 'RESTORE'], reason: str = '',
                                  user_requested: bool = False, until: str | None = None,
                                  request_id: str | None = None, workspace_path: str | None = None,
                                  session_ref: str | None = None) -> dict:
        """Save the user's explicit decision for one original task risk: EXCLUDE stops repeat reminders, DEFER postpones handling (optional ISO-8601 until), RESTORE resumes handling. user_requested must be literal true; no Agent agreement or safety expertise is required. Reasons are optional. Preserve independent technical assessment and history; exclusion is not proof of safety, resolution or permission to repair. Only announce success after the saved response. Use request_id to safely retry the same decision."""
        if user_requested is not True:
            from ..feedback_contract import FeedbackInputError
            raise FeedbackInputError()
        service = task_service(task_ref, session_ref, workspace_path)
        result = task_risk_feedback.set_disposition(
            service, bound_path(workspace_path),
            task_ref, finding_id, disposition, reason, user_requested=user_requested,
            until=until, request_id=request_id)
        # The application saves and replays its exact release obligation.
        return result

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def revoke_task_risk_feedback(task_ref: str, finding_id: str, reason: str,
                                  user_requested: bool = False, workspace_path: str | None = None,
                                  session_ref: str | None = None) -> dict:
        """On explicit user request only, revoke a technical feedback mark without deleting its audit. user_requested must be true. For the user's saved handling choice use set_task_risk_disposition RESTORE instead; this tool does not revoke that independent choice. Preserves original risk status; no edit authority."""
        return task_risk_feedback.revoke(task_service(task_ref, session_ref, workspace_path),
            bound_path(workspace_path), task_ref, finding_id, reason, user_requested=user_requested)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_task_risk_feedback(task_ref: str, finding_id: str, workspace_path: str | None = None,
                               event_offset: int = 0, event_limit: int = 2,
                               session_ref: str | None = None) -> dict:
        """Read current task-risk feedback and bounded audit pages without checks or writes. Changed source/configuration automatically unfolds a past host-confirmed false positive. Follow audit_page.next_offset for more events."""
        return task_risk_feedback.get(task_service(task_ref, session_ref, workspace_path), bound_path(workspace_path),
                                     task_ref, finding_id, event_offset, event_limit)

    def finding_feedback(scan_id):
        check_scan(scan_id)
        from ..finding_feedback import FindingFeedbackService
        return FindingFeedbackService(runtime_engine().store,
            runtime_engine().store.get_scan(scan_id)['target_profile']['path'])

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def prepare_finding_feedback(scan_id: str, finding_id: str,
                                 related_files: list[str] | None = None) -> dict:
        """Review a selected suspected false positive using bounded current redacted evidence. No scan, model call, suppression rule or repair. Returns a connection-local handoff; after reconnection prepare again for the same finding."""
        data = finding_feedback(scan_id).prepare(scan_id, finding_id, related_files)
        if data['status'] != 'READY':
            return data
        for key, value in list(feedback_sessions.items()):
            if time.monotonic() - value['created'] > 900:
                feedback_sessions.pop(key, None)
        if len(feedback_sessions) >= 64:
            feedback_sessions.pop(next(iter(feedback_sessions)))
        token = secrets.token_urlsafe(32)
        feedback_sessions[token] = dict(scan_id=scan_id, finding_id=data['finding_id'],
            context_hash=data['packet']['context_hash'], related_files=related_files or [],
            created=time.monotonic())
        return dict(data, feedback_session=token, expires_in_seconds=900)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def submit_finding_feedback(scan_id: str, finding_id: str, feedback_session: str,
                                context_hash: str, verdict: str, reason: str,
                                evidence_refs: list[FindingEvidenceReference], confidence: str = 'HIGH',
                                unknowns: list[str] | None = None,
                                context_complete: bool = False) -> dict:
        """Save HOST_CODE_REVIEW opinion independently from user handling decisions. Every evidence_refs item requires exactly file, start_line, end_line and claim; use ranges issued by prepare_finding_feedback, never line_start/line_end. Runtime validates references/versions, not semantic truth. A complete current high-confidence counterevidence review may reduce repeat reminders. User EXCLUDE/DEFER does not require Agent agreement. Never authorizes repair or marks a risk fixed."""
        service = finding_feedback(scan_id)
        session = feedback_sessions.get(feedback_session)
        if (session is None or time.monotonic() - session['created'] > 900
                or (session['scan_id'], session['finding_id'], session['context_hash'])
                != (scan_id, finding_id, context_hash)):
            raise ValueError('Invalid or expired feedback handoff; prepare the selected finding again')
        data = service.submit(scan_id, finding_id, context_hash=context_hash, verdict=verdict,
            reason=reason, evidence_refs=[ref.model_dump() for ref in evidence_refs], confidence=confidence, unknowns=unknowns,
            context_complete=context_complete, related_files=session['related_files'])
        feedback_sessions.pop(feedback_session, None)
        return data

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def mark_finding_false_positive(scan_id: str, finding_id: str, reason: str,
                                    user_requested: bool = False) -> dict:
        """Legacy opinion-only note for an explicit request to record a suspected false positive. For the user's decision to mark false positive or stop reminders use set_finding_disposition EXCLUDE instead. This note alone keeps handling unchanged and grants no repair authority. Do not use for deferred fixes or an agent's own conclusion."""
        if user_requested is not True:
            raise ValueError('An explicit user false-positive request is required')
        return finding_feedback(scan_id).user_mark(scan_id, finding_id, reason)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def set_finding_disposition(scan_id: str, finding_id: str,
                                disposition: Literal['EXCLUDE', 'DEFER', 'RESTORE'], reason: str = '',
                                user_requested: bool = False, until: str | None = None,
                                request_id: str | None = None) -> dict:
        """Save the user's explicit decision for one selected scanner finding: EXCLUDE stops repeat reminders, DEFER postpones handling (optional ISO-8601 until), RESTORE resumes handling. user_requested must be literal true; no Agent agreement or security justification is required. Reasons are optional. Keep independent technical assessment, raw findings and history. Exclusion is neither proof of safety nor a fix or repair grant. Announce success only after the saved response. Reuse request_id when retrying the same decision."""
        if user_requested is not True:
            from ..feedback_contract import FeedbackInputError
            raise FeedbackInputError()
        return finding_feedback(scan_id).set_disposition(scan_id, finding_id, disposition, reason,
            user_requested=user_requested, until=until, request_id=request_id)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def revoke_finding_feedback(scan_id: str, finding_id: str, reason: str,
                                source: str = 'ALL', user_requested: bool = False) -> dict:
        """Revoke the selected HUMAN opinion, AI review or both on the user's explicit request. For a saved handling choice use set_finding_disposition RESTORE instead; independent user choices survive technical opinion revocation. Retains audit history and raw findings; does not scan or edit code."""
        if user_requested is not True:
            raise ValueError('An explicit user revocation request is required')
        return finding_feedback(scan_id).revoke(scan_id, finding_id, reason, source)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_finding_feedback(scan_id: str, finding_id: str,
                             include_history: bool = False) -> dict:
        """Read user opinion, current host review, freshness and optional history for one exact finding. No new scan or review; raw findings remain available even when a valid false-positive review folds reminders."""
        return finding_feedback(scan_id).status(scan_id, finding_id, include_history)

    for feedback_name in ('prepare_finding_feedback', 'submit_finding_feedback',
                          'mark_finding_false_positive', 'revoke_finding_feedback',
                          'get_finding_feedback', 'set_finding_disposition'):
        registry.harden((feedback_name,))

    registry.harden(('prepare_task_risk_feedback', 'submit_task_risk_feedback',
        'mark_task_risk_false_positive', 'revoke_task_risk_feedback',
        'get_task_risk_feedback', 'set_task_risk_disposition'))
