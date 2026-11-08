"""Lightweight observed-edit checks; strict task audits remain a separate API."""
from mcp.types import ToolAnnotations
from pydantic import Field
from typing import Annotated, Literal
from ..development_risks import Observation, ScannerReview, BusinessReview, ScanId
from ..development_views import EvidenceWindow
from ..performance_trace import timed_review


TOOLS = frozenset({'manage_development_audit', 'process_development_audit', 'get_development_config', 'begin_development_check', 'record_development_changes',
                   'declare_development_outputs',
                   'finish_development_check', 'get_development_check',
                   'complete_development_check', 'wait_development_check',
                   'get_development_deliveries', 'get_development_result',
                   'read_development_risk_context', 'submit_development_review',
                   'get_development_risks', 'prepare_development_risk_fix',
                   'submit_development_risk_resolution', 'set_development_risk_disposition'})


def register(server, registry, *, application):
    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_development_config() -> dict:
        """Read effective user TOML preferences and adapter support; no writes or scan."""
        from ..user_config import describe_config
        return describe_config()

    def risks(check_ref, workspace_path, session_ref):
        from ..development_risks import DevelopmentRisks
        service = application.development_service(check_ref, session_ref, workspace_path)
        return DevelopmentRisks(service, application.bound_path(workspace_path), check_ref)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def manage_development_audit(check_ref: str, action: Literal['prepare','status','started','cancel','unsupported','failed',
                                 'stream_prepare','stream_started','stream_cancel','stream_status','stream_authorize_paths','stream_rotate','stream_failed'],
                                 workspace_path: str | None = None, session_ref: str | None = None,
                                 audit_id: str | None = None, agent_ref: str | None = None,
                                 audit_token: str | None = None,
                                 related_paths: Annotated[list[str], Field(max_length=50)] | None = None) -> dict:
        """Manage a read-only business audit during development. Prefer stream_prepare, actually spawn a host subagent, then stream_started with its real ID. Pass the task-scoped capability to that child for direct process_development_audit calls; edits queue incremental work without cancelling the task. stream_status preserves pending/interrupted facts and does not dispatch a model. Legacy unprefixed actions retain their version-bound handoff contract."""
        if action.startswith('stream_'):
            from ..audit_stream_service import manage
            return manage(risks(check_ref, workspace_path, session_ref), action.removeprefix('stream_'),
                          agent_ref=agent_ref, related_paths=related_paths or [], audit_token=audit_token)
        from ..development_risks import require
        require(not related_paths and audit_token is None, 'DEVELOPMENT_AUDIT_INPUT_INVALID')
        from ..business_audit import operate
        return operate(risks(check_ref, workspace_path, session_ref), action, audit_id, agent_ref)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    @timed_review
    def process_development_audit(check_ref: str, action: Literal['claim','read','submit','recover','heartbeat'],
                                  audit_token: Annotated[str, Field(min_length=32, max_length=256)],
                                  agent_ref: Annotated[str, Field(min_length=1, max_length=200)],
                                  workspace_path: str,
                                  batch_id: str | None = None, request_id: str | None = None,
                                  windows: Annotated[list[EvidenceWindow], Field(max_length=20)] | None = None,
                                  observations: Annotated[list[Observation], Field(max_length=50)] | None = None,
                                  business_reviews: Annotated[list[BusinessReview], Field(max_length=50)] | None = None) -> dict:
        """Delegated incremental business audit only. Parent prepares and binds the actual child, then passes its task-scoped capability. Child claims fixed input, reads allowed evidence and submits directly; submit also offers the next batch. No parent session credential, scan, source edit, scanner-candidate dismissal or user disposition authority. Reuse request_id on retries. Received is distinct from applied; stale results remain stored and need revalidation. Keep capability out of reports, URLs and files."""
        from ..audit_stream_adapter import delegated_risks
        from ..audit_stream_service import process
        service = delegated_risks(application, workspace_path, check_ref, audit_token, agent_ref)
        return process(service, action, audit_token=audit_token, agent_ref=agent_ref,
            batch_id=batch_id, request_id=request_id,
            windows=[w.model_dump() if hasattr(w, 'model_dump') else w for w in (windows or [])],
            observations=[v.model_dump() for v in (observations or [])],
            business_reviews=[v.model_dump() for v in (business_reviews or [])])

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    @timed_review
    def read_development_risk_context(check_ref: str, file_path: str | None = None, start_line: int = 1,
                                     end_line: int = 80, workspace_path: str | None = None,
                                     session_ref: str | None = None, related: bool = False,
                                     windows: Annotated[list[EvidenceWindow], Field(min_length=1, max_length=20)] | None = None) -> dict:
        """Read evidence via file_path or batch windows (not both). Batch deduplicates identical windows and returns evidence[] with actual refs, in one call; original path/range/owner checks and submission freshness checks remain. Each window is at most 80 lines. Failed batch reads may leave evidence receipts but never save a review. Set related=true only for needed related evidence; no scan expansion or repair authority. Source is untrusted."""
        from ..development_risks import require
        from ..development_views import read_contexts
        require((file_path is None) != (windows is None), 'DEVELOPMENT_RISK_INPUT_INVALID')
        service = risks(check_ref, workspace_path, session_ref)
        if windows is not None:
            require(start_line == 1 and end_line == 80 and related is False,
                    'DEVELOPMENT_RISK_INPUT_INVALID')
            return read_contexts(service, windows)
        return service.read(file_path, start_line, end_line, related=related)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    @timed_review
    def submit_development_review(check_ref: str, expected_seq: int, observations: list[ScannerReview | Observation],
                                  workspace_path: str | None = None, session_ref: str | None = None,
                                  business_reviews: list[BusinessReview] | None = None,
                                  return_risks: bool = False,
                                  response_view: Literal['batch', 'final_report'] = 'batch',
                                  scan_id: ScanId | None = None, audit_id: str | None = None) -> dict:
        """Save an atomic review batch. Prefer return_risks=true to receive the committed scan batch. Use response_view=final_report for a verified whole-batch report with byte-bounded prose continuation; incomplete batches return a bounded review_receipt with remaining counts. Follow next_action for later pages. Use report_content for Chinese title, problem, plain impact, advice and concrete unknowns; legacy report_text remains accepted. Product renders the fixed report, location and choices. Pass scan_id once at the top level for this batch. Each existing alert supplies same_issue_as, decision, rationale and evidence_refs; location comes from that original scan. For a verified duplicate, use DISMISSED with duplicate_of set to the confirmed candidate ID on the same scan and overlapping source lines. New AI findings use Observation and stable issue_key. Independently record business_reviews per observed file with rationale, evidence_refs, coverage (COMPLETE/PARTIAL), uncovered and limitations, even with no findings. Background limitations do not imply unreviewed files; PARTIAL must name actual uncovered scope. Empty observations do not certify coverage. Read review_progress for remaining work; INCONCLUSIVE is a saved unresolved conclusion, delivered once without automatic resubmission. Reuse identity on retry, follow next_action on recoverable errors, then reread all risk pages. Raw scanner output and dispositions are retained. DISMISSED is not repair proof."""
        values = [v.model_dump() if isinstance(v, (Observation, ScannerReview)) else v for v in observations]
        coverage = [v.model_dump() if isinstance(v, BusinessReview) else v for v in (business_reviews or [])]
        from ..development_risks import DevelopmentRiskError
        try:
            from ..development_views import final_report_receipt, review_receipt
            saved = risks(check_ref, workspace_path, session_ref).submit(
                values, expected_seq, business_reviews=coverage, scan_id=scan_id, audit_id=audit_id,
                return_risks=return_risks or response_view == 'final_report', final_report=response_view == 'final_report')
            result = saved if saved.get('review_saved') else review_receipt(saved)
            if response_view == 'final_report':
                result = final_report_receipt(result)
            if session_ref and result.get('next_action'):
                result['next_action']['arguments']['session_ref'] = session_ref
            return result
        except DevelopmentRiskError as error:
            action = getattr(error, 'recovery', None)
            if action is None:
                raise
            from mcp.types import CallToolResult, TextContent
            import json
            from ..development_reporting import EVIDENCE_RECOVERY
            if session_ref is not None:
                action['arguments']['session_ref'] = session_ref
            data = dict(status='INCONCLUSIVE', reason_code=error.reason_code,
                item_index=getattr(error, 'item_index', None),
                recoverable=error.reason_code in {
                    'DEVELOPMENT_RISK_VERSION_STALE', 'DEVELOPMENT_RISK_SCAN_VERSION_STALE',
                    'DEVELOPMENT_RISK_LINK_UNKNOWN', 'DEVELOPMENT_RISK_EVIDENCE_REQUIRED',
                    'DEVELOPMENT_RISK_EVIDENCE_UNKNOWN', 'DEVELOPMENT_RISK_EVIDENCE_STALE',
                    'DEVELOPMENT_RISK_LOCATION_UNREAD'},
                message=EVIDENCE_RECOVERY, next_action=action,
                scanner_run=False, source_modified=False, repair_authorized=False,
                review_saved=False, security_proof=False)
            return CallToolResult(isError=True, structuredContent=data,
                content=[TextContent(type='text', text=json.dumps(data, ensure_ascii=False))])

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    @timed_review
    def get_development_risks(check_ref: str, workspace_path: str | None = None,
                              session_ref: str | None = None, offset: int = 0, limit: int | None = None,
                              include_history: bool = False, view: Literal['summary', 'full', 'review', 'batch', 'closeout', 'final_report'] = 'summary',
                              include_evidence: bool = False, expected_seq: int | None = None,
                              scan_id: str | None = None, report_digest: str | None = None) -> dict:
        """For a short Stop notice, view=closeout resolves the saved REVIEW/REPORT/INCOMPLETE handoff; follow its next_action and deliver report_text and session_url. Never start a scan. For pending review, view=review reads current-scan candidates and bounded untrusted evidence; omitted limit uses the configured response byte budget. Continue the same view at next_offset. Batch missing windows via read_development_risk_context(windows=[...]) and inspect per-window errors. For a saved batch, use view=batch with its expected_seq and scan_id; follow final_report continuations with their report_digest and character offset. For historical lookup, summary/full read ledger risks and dispositions; include_history adds historical batches, include_evidence adds bounded evidence."""
        from ..development_views import pending_review_context, risk_summary
        service = risks(check_ref, workspace_path, session_ref)
        from ..development_risks import require
        if view == 'closeout':
            from ..development_views import closeout_page
            require(not include_history and not include_evidence, 'DEVELOPMENT_RISK_INPUT_INVALID')
            result = closeout_page(service, offset, limit, expected_seq=expected_seq, scan_id=scan_id)
            if session_ref and result.get('next_action'):
                result['next_action']['arguments']['session_ref'] = session_ref
            return result
        if view in {'batch', 'final_report'}:
            require(expected_seq is not None and not include_history and not include_evidence,
                    'DEVELOPMENT_RISK_INPUT_INVALID')
            result = service.get(offset, limit, include_history=False, batch_version=(expected_seq, scan_id),
                                 whole_report=view == 'final_report', report_digest=report_digest)
            if session_ref and result.get('next_action'):
                result['next_action']['arguments']['session_ref'] = session_ref
            return result
        if view == 'review':
            require(not include_history, 'DEVELOPMENT_RISK_INPUT_INVALID')
            require(expected_seq is not None or scan_id is None, 'DEVELOPMENT_RISK_INPUT_INVALID')
            result = service.get(offset, limit, include_history=False, review_only=True,
                                 batch_version=(expected_seq, scan_id) if expected_seq is not None else None)
            if session_ref and result.get('next_action'):
                result['next_action']['arguments']['session_ref'] = session_ref
            return result
        require(expected_seq is None and scan_id is None, 'DEVELOPMENT_RISK_INPUT_INVALID')
        result = service.get(offset, 20 if limit is None else limit, include_history=include_history)
        if include_evidence and result.get('candidates_ready'):
            _, result['evidence'] = pending_review_context(service, result)
            current = service.current_check()
            require((current['dirty_seq'], current.get('scan_id')) == (result['dirty_seq'], result['scan_id']),
                    'DEVELOPMENT_RISK_VERSION_STALE')
        if view == 'full':
            return dict(result, view='full')
        result = risk_summary(result)
        result['detail_access']['arguments'].update(workspace_path=workspace_path,
            session_ref=session_ref, offset=offset, limit=limit, include_history=include_history)
        return result

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def set_development_risk_disposition(check_ref: str, risk_id: str,
                                         user_requested: bool, decision: str | None = None,
                                         workspace_path: str | None = None,
                                         session_ref: str | None = None, disposition: str | None = None,
                                         reason: str = '', expected_seq: int | None = None,
                                         expected_revision: str | None = None, request_id: str | None = None) -> dict:
        """Persist explicit selected-risk user choice: DEFER, EXCLUDE, RESTORE. Suppress reminders without deleting observations or claiming repair. AI technical dismissal belongs in submit_development_review, not a fabricated user choice."""
        from ..development_risks import require
        require(not (decision and disposition and decision != disposition), 'DEVELOPMENT_RISK_DISPOSITION_CONFLICT')
        return risks(check_ref, workspace_path, session_ref).disposition(
            risk_id, decision or disposition, user_requested, reason=reason,
            expected_seq=expected_seq, expected_revision=expected_revision, request_id=request_id)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def prepare_development_risk_fix(check_ref: str, risk_id: str, proposal: str,
                                     preserve: list[str], evidence_refs: list[str], user_requested: bool,
                                     impact_summary: str, critical_unknowns: list[str],
                                     workspace_path: str | None = None, session_ref: str | None = None,
                                     repair_paths: list[str] | None = None) -> dict:
        """Prepare one unified development risk after explicit user authorization of this exact proposal. Explicitly provide repair_paths for every file to edit, with current evidence for each. Never infer the edit scope from the finding location. Resolve business choices and critical unknowns first. Proceed only when ready_for_host_fix=true and returned scope covers the entire proposed edit; on failure or scope mismatch do not edit. Existing prepared repairs retain their original scope and cannot be silently replaced. No scanner or edit."""
        return risks(check_ref, workspace_path, session_ref).prepare_fix(
            risk_id, proposal, preserve, evidence_refs, user_requested,
            impact_summary=impact_summary, critical_unknowns=critical_unknowns, repair_paths=repair_paths)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def submit_development_risk_resolution(check_ref: str, risk_id: str, repair_ref: str,
                                           outcome: str, evidence_refs: list[str], rationale: str,
                                           workspace_path: str | None = None, session_ref: str | None = None) -> dict:
        """Recheck the ORIGINAL risk against new evidence after its authorized repair. Outcomes: CODE_REVIEWED_RESOLVED, STILL_PRESENT, INCONCLUSIVE. Explain how evidence removes original cause and preserves behavior. Host review never claims SCANNER_VERIFIED_RESOLVED; a new zero-alert scan alone cannot close the risk. Run ordinary development closeout separately for edited files."""
        return risks(check_ref, workspace_path, session_ref).resolve(
            risk_id, repair_ref, outcome, evidence_refs, rationale)

    def offered(result):
        # One public development result; legacy raw scan detail remains explicit.
        if 'development_result' in result:
            result.pop('static_result', None)
        # Response preparation is not report submission. This in-memory hint
        # only avoids a redundant Stop continuation in this connection.
        if result.get('closeout_wait') and result.get('status') in {'QUEUED', 'RUNNING'}:
            if len(application.development_result_offers) >= 128:
                application.development_result_offers.pop()
            application.development_result_offers.add(
                (result['check_ref'], result['dirty_seq'], 'WAITING'))
        delivery = result.get('delivery', {})
        ref = delivery.get('check_ref', result.get('check_ref'))
        seq = delivery.get('scanned_seq', result.get('scanned_seq'))
        if ref and seq and ('development_result' in result or 'static_result' in result or delivery):
            if len(application.development_result_offers) >= 128:
                application.development_result_offers.pop()
            application.development_result_offers.add((ref, seq))
        return result

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def begin_development_check(task_key: str, workspace_path: str | None = None,
                                session_ref: str | None = None) -> dict:
        """Start an actual coding task's lightweight edit record. Metadata only: no project inventory, baseline, source snapshot or scan. Use a short task key, never prompt/source. Ordinary chat needs no check. If native context provides a valid session_ref, pass it FROM CREATION and consistently on every subsequent call. Reuse this chat’s Hook check_ref instead of creating another. A connection-scoped record is not automatically adopted by chat Stop. Retain the returned check_ref."""
        service = application.development_service(session_ref=session_ref, workspace=workspace_path)
        result = service.begin(application.bound_path(workspace_path), task_key)
        application.remember_development_check(result, service.owner)
        return result

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def record_development_changes(check_ref: str, paths: list[str],
                                   workspace_path: str | None = None, session_ref: str | None = None,
                                   scope_unknown: bool = False, event_id: str | None = None) -> dict:
        """Record paths observed during AI editing when Hooks cannot supply them. Include both old/new rename paths and deleted paths. Paths are bounded workspace-relative hints; set scope_unknown for incomplete observations. Metadata only: never starts a worker, scans the project, or creates a before-image. Finish once after editing to check the combined scope."""
        service = application.development_service(check_ref, session_ref, workspace_path)
        return service.record(application.bound_path(workspace_path), check_ref, paths,
                              scope_unknown=scope_unknown, event_id=event_id)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def declare_development_outputs(check_ref: str, paths: list[str],
                                    workspace_path: str | None = None, session_ref: str | None = None) -> dict:
        """Declare exact generated-output files/directories for this check only, ideally before running tests/builds. Replace paths with [] to revoke it. Only declare outputs known from the actual command/tool configuration; do not infer from names or use this to suppress source changes. Explicitly recorded and Git-tracked files remain inputs. Paths must be workspace-relative, bounded and non-symlink, never the workspace itself. Preserves the observed journal and historical results; no scan, global ignore rule or repair authority. Closeout reports exclusions; unverifiable declarations retain inputs."""
        service = application.development_service(check_ref, session_ref, workspace_path)
        return service.declare_outputs(application.bound_path(workspace_path), check_ref, paths)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    async def finish_development_check(check_ref: str, workspace_path: str | None = None,
                                       session_ref: str | None = None,
                                       wait_seconds: Annotated[int, Field(ge=0, le=25)] = 0) -> dict:
        """Close the observed-edit batch and schedule scoped background work once. Default wait_seconds=0 dispatches immediately. Opt into 1-25 seconds of asynchronous waiting to receive the normal saved result directly, without client polling code. Waiting only reads the original check/owner/version; new edits, terminal state or the time budget stop it. If still pending, continue get_development_check on the same ref, never refinish to wait. No baseline, scope expansion, host review certification or repair authority."""
        from ..development_check import MAX_FINISH_WAIT_SECONDS
        if type(wait_seconds) is not int or not 0 <= wait_seconds <= MAX_FINISH_WAIT_SECONDS:
            raise ValueError('DEVELOPMENT_WAIT_INVALID')
        service = application.development_service(check_ref, session_ref, workspace_path)
        return offered(await service.finish_and_wait(application.bound_path(workspace_path), check_ref, wait_seconds))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_development_check(check_ref: str, workspace_path: str | None = None,
                              session_ref: str | None = None) -> dict:
        """Read this owner's saved lightweight check status, scope, versions, findings and gaps. Never scans, rehashes source, or launches a worker. Saved results cover their observed input version only. Analyze relevant risks before the normal development summary; zero static alerts do not prove all code safe."""
        service = application.development_service(check_ref, session_ref, workspace_path)
        return offered(service.get(application.bound_path(workspace_path), check_ref))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    async def complete_development_check(check_ref: str, workspace_path: str | None = None,
                                          session_ref: str | None = None) -> dict:
        """Submit the observed batch once; product chooses its bounded wait. Timeout/cancellation leaves durable work and versioned deliveries intact. Continue wait_development_check on the SAME ref, never resubmit to wait. No project baseline or repair authority."""
        service = application.development_service(check_ref, session_ref, workspace_path)
        return offered(await service.complete(application.bound_path(workspace_path), check_ref))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    async def wait_development_check(check_ref: str, workspace_path: str | None = None,
                                      session_ref: str | None = None) -> dict:
        """Await saved progress using the product's communication budget. Read-only: never submits, retries, scans or starts a worker. A per-call timeout is not task completion: follow next_action until terminal state or wait_deadline_exceeded. Then review saved findings, or report the actual incomplete check. Returns original scope/version/findings/gaps; cancellation does not cancel background work."""
        service = application.development_service(check_ref, session_ref, workspace_path)
        return offered(await service.wait_saved(application.bound_path(workspace_path), check_ref))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_development_deliveries(workspace_path: str | None = None, session_ref: str | None = None,
                                    offset: int = 0, limit: int = 20) -> dict:
        """Page this verified owner's pending result deliveries, including older scan versions. Reads do not acknowledge display, start work or grant repairs. Follow the issued get_development_result arguments; keep original owner/workspace."""
        service = application.development_service(session_ref=session_ref, workspace=workspace_path)
        return service.deliveries(application.bound_path(workspace_path), offset=offset, limit=limit)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_development_result(check_ref: str, scanned_seq: int, workspace_path: str | None = None,
                                session_ref: str | None = None) -> dict:
        """Read an original saved version from this owner's outbox, even after later edits/scans. Never substitutes current content or acknowledges user display. Analyze saved scope, gaps and existing risk handling before reporting."""
        service = application.development_service(check_ref, session_ref, workspace_path)
        return offered(service.saved_result(application.bound_path(workspace_path), check_ref, scanned_seq))

    registry.harden(TOOLS)
