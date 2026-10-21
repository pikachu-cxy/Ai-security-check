"""Explicit scan, triage and read-only discovery tool registrations."""
from __future__ import annotations

import logging
import secrets
import time
from typing import Literal
from mcp.types import ToolAnnotations
from ..integration_state import DogfoodEvent
from ..explicit_scan import ExplicitScanBusy, cancelled_scan
from ..progress import ScanCancelled
from .presentation import _agent_finding, _agent_result, selected_scope_summary
from ..mcp_scan_progress import run_mcp_scan, scan_timing

logger = logging.getLogger(__name__)


def register(server, registry, *, application, runtime_engine, hook_coordinator,
             remediation, include_functional_verification, check_scan, event):
    bound_path = application.bound_path
    binding = application.binding
    triage_sessions = {}
    def register_handoff(data, task_binding=None, continuation_args=None):
        expired=[key for key,value in triage_sessions.items() if time.monotonic()-value[2]>900]
        for key in expired: triage_sessions.pop(key,None)
        if len(triage_sessions)>=64: triage_sessions.pop(next(iter(triage_sessions)))
        token=secrets.token_urlsafe(32)
        triage_sessions[token]=(data['scan_id'],{p['finding_id']:p['context_hash'] for p in data['packets']},
                                time.monotonic(),task_binding,continuation_args)
        data['triage_session']=token
        data['triage_session_expires_in_seconds']=900
        return data

    @server.tool()
    async def scan_diff(workspace_path: str | None = None, mode: str = "quick", path: str | None = None, summary: bool = True) -> dict:
        """Scan changed files in a local Git repository. workspace_path is the project directory; path is its legacy directory alias, not a file/glob/scan target. Prefer workspace_path and omit path. For explicitly selected files use scan_files."""
        if mode not in {"quick", "feature"}:
            raise ValueError("mode must be quick or feature")
        if workspace_path is not None and path is not None and workspace_path != path:
            raise ValueError("Specify only one workspace path")
        logger.info("scan_diff started")
        root = bound_path(workspace_path if workspace_path is not None else path)
        from ..target import DiscoveryLimitError
        try:
            result, timing = await run_mcp_scan(server, lambda progress: application.scan(root, mode, progress=progress))
        except DiscoveryLimitError as exc:
            return exc.to_dict()
        except ExplicitScanBusy as exc:
            return exc.to_dict()
        except ScanCancelled:
            return cancelled_scan()
        event(DogfoodEvent(binding.integration_id if binding else "generic-mcp", result.target_profile.path,
                           mode, result.duration_ms, len(result.findings), result.coverage), connected=True)
        logger.info("scan_diff finished scan_id=%s", result.scan_id)
        return scan_response(result, summary, timing)

    @server.tool()
    async def scan_project(workspace_path: str | None = None, path: str | None = None, summary: bool = True,
                           force_rescan: bool = False) -> dict:
        """Check a full local project, reusing only explicitly revalidated complete proof. Set force_rescan=true for an explicit rescan. workspace_path is the project directory; path is its legacy directory alias, never a file/glob. For selected files use scan_files; never expand a file request to the project."""
        if workspace_path is not None and path is not None and workspace_path != path:
            raise ValueError("Specify only one workspace path")
        root = bound_path(workspace_path if workspace_path is not None else path)
        from ..target import DiscoveryLimitError
        try:
            result, timing = await run_mcp_scan(server, lambda progress: application.scan_project(
                root, force_rescan=force_rescan, progress=progress))
        except DiscoveryLimitError as exc:
            return exc.to_dict()
        except ExplicitScanBusy as exc:
            return exc.to_dict()
        except ScanCancelled:
            return cancelled_scan()
        if not isinstance(result, dict):
            event(DogfoodEvent(binding.integration_id if binding else "generic-mcp", result.target_profile.path,
                               "release", result.duration_ms, len(result.findings), result.coverage), connected=True)
        return scan_response(result, summary, timing)

    @server.tool()
    async def scan_files(files: list[str], workspace_path: str | None = None, summary: bool = True) -> dict:
        """Scan 1-100 exact workspace-relative files using '/' separators. No globs, directories, traversal or absolute paths; no implicit project expansion. Reports requested files, actual targets, supporting context and exclusions. Never proves whole-project coverage."""
        root = bound_path(workspace_path)
        from ..target import DiscoveryLimitError
        from ..scan_request import ScanInputError
        try:
            result, timing = await run_mcp_scan(server, lambda progress: application.scan_files(root, files, progress=progress))
        except DiscoveryLimitError as exc:
            return exc.to_dict()
        except ExplicitScanBusy as exc:
            return exc.to_dict()
        except ScanCancelled:
            return cancelled_scan()
        except ScanInputError as exc:
            return dict(status='REJECTED', reason_code=exc.reason_code, scanner_run=False,
                        source_modified=False, repair_authorized=False)
        return scan_response(result, summary, timing)

    registry.harden(('scan_files', 'scan_project', 'scan_diff'))

    def scan_response(result, summary, timing):
        data = _agent_result(result, summary=summary)
        diagnostics = result.get('scanner_diagnostics', {}) if isinstance(result, dict) else result.scanner_diagnostics
        reused = isinstance(result, dict)
        # A reuse request performs no new scan publication. Historical records
        # can predate the post-save publication receipt attached in memory.
        data['execution_publication'] = (dict(scope='HISTORICAL_EXECUTION_ONLY',
            publication='HISTORICAL', current_execution=False, current_task_proof=False)
            if reused else diagnostics.get('execution_publication',
                dict(publication='UNAVAILABLE', current_task_proof=False)))
        data['timing'] = scan_timing(result, timing, reused=reused)
        runs = result['scanner_runs'] if reused else result.scanner_runs
        ran = not reused and any((run.get('status') if isinstance(run, dict) else run.status)
                                in {'SUCCESS', 'FAILED', 'TIMEOUT'} for run in runs)
        data['execution'] = dict(scanner_run=ran, result_reused=reused,
                                 host_review_completed=False, repair_authorized=False)
        if reused:
            data['result_reuse'] = result['result_reuse']
        elif diagnostics.get('reuse_check'):
            data['result_reuse'] = diagnostics['reuse_check']
        if diagnostics.get('selected_scope'):
            data['scan_scope'] = (selected_scope_summary(diagnostics['selected_scope'])
                                  if summary else diagnostics['selected_scope'])
        return data

    @server.tool()
    def get_findings(scan_id: str, include_evidence: bool = False, finding_id: str | None = None, context_lines: int = 5,
                     view: str = 'summary', offset: int = 0, limit: int | None = None) -> list[dict] | dict:
        """List findings/review state; opt into bounded redacted local evidence, optionally for one existing scanner id. Evidence distinguishes original EXACT code from STALE/unverifiable current_context. quality.finding_id remains review-only."""
        check_scan(scan_id)
        from ..mcp_views import page_bounds, finding_summary, paged
        page_limit = page_bounds(view, offset, limit, evidence=include_evidence)
        if not 0 <= context_lines <= 20:
            raise ValueError('Context lines must be between 0 and 20')
        from ..local_evidence import LocalEvidenceService
        local_evidence = LocalEvidenceService(runtime_engine().store.get_scan(scan_id)) if include_evidence else None
        if binding:
            event(DogfoodEvent(binding.integration_id, binding.root), connected=True)
        from ..triage import TriageService
        triage_view=TriageService(runtime_engine().store).view(scan_id)
        rows={row['finding_id']:row for row in triage_view['findings']}
        from ..finding_quality import FindingQualityService
        from ..storage import ReadOnlySQLiteStore
        try:
            quality = FindingQualityService(ReadOnlySQLiteStore(runtime_engine().store.path)).view(scan_id)
            quality_rows = {r['scanner_finding_id']: r for r in quality['findings']}
        except ValueError:
            quality_rows = {}
        originals = [f for f in runtime_engine().get_findings(scan_id)
                     if finding_id is None or f['id'] == finding_id]
        if finding_id is not None and not originals:
            raise ValueError('Finding does not belong to this scan')
        selected = originals if view == 'full' else originals[offset:offset+page_limit]
        found=[]
        from ..finding_feedback import FindingFeedbackService
        feedback = FindingFeedbackService(runtime_engine().store,
            runtime_engine().store.get_scan(scan_id)['target_profile']['path'])
        for finding in selected:
            row=rows[finding['id']]
            item=_agent_finding(finding)
            if finding['id'] in quality_rows:
                item['quality'] = quality_rows[finding['id']]
            else:
                item['quality_diagnostic'] = 'QUALITY_REVIEW_UNAVAILABLE'
            item['triage_status']=row['triage_status']
            item['triage']=row['triage']
            item['false_positive_review'] = feedback.status(scan_id, finding['id'])
            review = item['false_positive_review']
            if ((review.get('disposition') or {}).get('reassessment_required')
                    or not (review.get('agent_review_current') or review.get('technical_assessment_current')
                            or review.get('technical_false_positive')) and not review.get('folded')):
                item['review_continuation'] = {'tool': 'prepare_finding_feedback',
                    'arguments': {'scan_id': scan_id, 'finding_id': finding['id']},
                    'purpose': 'Review this scanner candidate before asking the user to judge security. For a saved decision, notify only after new material risk evidence. Obey an explicit raw-scan-only request.'}
            if row['triage_status']=='VALID':
                item.update(verdict=row['triage']['verdict'],triage_confidence=row['triage']['confidence'],exploitability=row['triage']['exploitability'])
            if local_evidence is not None:
                item['local_evidence'] = local_evidence.detail(finding, context_lines)
            found.append(finding_summary(item) if view == 'summary' else item)
        if view == 'full': return found
        return paged(found, len(originals), offset, page_limit, tool='get_findings', arguments={
            'scan_id':scan_id, 'view':view, 'include_evidence':include_evidence,
            'finding_id':finding_id, 'context_lines':context_lines})

    @server.tool()
    def prepare_triage(scan_id: str, finding_ids: list[str] | None = None, categories: list[str] | None = None, limit: int = 5,
                       pending_only: bool = False, retry_failed: bool = False) -> dict:
        """Return bounded redacted UNTRUSTED_CODE evidence to this host agent; does not invoke AI."""
        check_scan(scan_id)
        from ..triage import TriageService
        data=TriageService(runtime_engine().store).prepare(scan_id,finding_ids,categories,limit,
            pending_only=pending_only,retry_failed=retry_failed)
        return register_handoff(data, continuation_args={'scan_id':scan_id,
            'finding_ids':finding_ids,'categories':categories,'limit':min(limit,5),
            'pending_only':True,'retry_failed':retry_failed})

    @server.tool()
    def submit_triage(scan_id: str, results: list[dict], triage_session: str, compact: bool = True) -> dict:
        """Validate structured host analysis and evidence references; preserves every raw finding."""
        check_scan(scan_id)
        session=triage_sessions.get(triage_session)
        if session is None or session[0]!=scan_id or time.monotonic()-session[2]>900:
            raise ValueError('Invalid or expired triage handoff session; prepare evidence again')
        if not results or len(results)>20 or any(not isinstance(item,dict) or
            session[1].get(item.get('finding_id'))!=item.get('context_hash') for item in results):
            raise ValueError('Triage result does not belong to this evidence handoff')
        if session[3] is not None:
            from ..task_triage import TaskTriageService
            reference,workspace=session[3]
            resolved=TaskTriageService(runtime_engine().store).resolve(reference,workspace,
                bound_workspace=binding.root if binding else None)
            if resolved['status']!='RESOLVED':
                raise ValueError('Task changed or reference expired; refresh get_security_summary and prepare again')
        from ..triage import TriageService
        data=TriageService(runtime_engine().store).submit(scan_id,results,compact=compact)
        if session[3] is not None:
            data['execution']={'host_result_accepted':True,'accepted_records':data['accepted'],
                               'patch_applied':False,'target_build':False,'tests_or_scanner_recheck':False}
        for item in results: session[1].pop(item['finding_id'],None)
        if compact:
            data['handoff_remaining'] = len(session[1])
            if session[3] is not None:
                data['continuation']={'tool':'prepare_task_triage','arguments':{
                    'task_ref':session[3][0],'workspace_path':session[3][1],
                    'limit':5,'include_existing_reviews':False}}
            else:
                data['continuation']={'tool':'prepare_triage','arguments':session[4]}
        return data

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_runtime_info(view: Literal['full', 'summary'] = 'full') -> dict:
        """Read runtime capabilities. Opt into summary for discovery; full remains the default. Check required tool subset, not exact count; never scans or writes state."""
        from ..host_guidance import runtime_info
        from ..delivery_manifest import delivery_manifest
        from ..runtime_info_view import runtime_info_view
        info = runtime_info(remediation_config=remediation.config,
                            include_functional_verification=include_functional_verification)
        info['host_connector'] = getattr(binding, 'host', None)
        info['delivery_manifest'] = delivery_manifest(info, registry.tools())
        return runtime_info_view(info, view)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_runtime_guidance(topic: Literal['core', 'runtime-workflow', 'task-review',
                                            'risk-decisions', 'repair-impact', 'deep-audit']) -> dict:
        """Read one fixed bundled method with version/hash and reuse that identity. No workspace, source, URL, network, scan, writes or repair authority. When matching local content exists, do not fetch it again."""
        from ..guidance_catalog import get_runtime_guidance as load_guidance
        return load_guidance(topic)

    registry.harden(('get_runtime_guidance',))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_professional_guidance() -> dict:
        """Read product-owned versioned deep-audit guidance. No workspace/source/URL input, network, scan, repair permission or writes. Ordinary Hooks do not invoke this tool."""
        from ..professional_guidance import get_professional_guidance as load_guidance
        return load_guidance()

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_scan_preparation_status() -> dict:
        """Read current component diagnoses, repair guidance and background progress; no download or scan.
        component_health.notify reports new faults/recovery once across connections.
        If notify=false, do not repeat prior alerts. Explicit status questions may
        still describe current availability. receipt/current_readiness reflect
        current checks; background_status/background_receipt are historical and
        must not be described as an active stalled job. No pending scan is resumed.
        Readiness is not project scan proof.
        """
        from ..background_preparation import read_preparation_status
        return read_preparation_status()

    registry.harden(('get_professional_guidance',))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_security_summary(workspace_path: str | None = None, scan_id: str | None = None, details: bool = False) -> dict:
        """Read workspace tasks without scans, AI or writes. User 'continue first' selects that response's recommended_tasks[0].continuation; never resolve T01 against a new summary."""
        from ..security_summary import SecuritySummaryService
        from ..storage import ReadOnlySQLiteStore, SQLiteStore
        path = application.scan_path_provider()
        return SecuritySummaryService(ReadOnlySQLiteStore(path), hooks=hook_coordinator.store).get(
            workspace_path, scan_id, details=details, bound_workspace=binding.root if binding else None)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def prepare_task_triage(task_ref: str, workspace_path: str | None = None, limit: int = 5, retry_failed: bool = False,
                            include_existing_reviews: bool = False) -> dict:
        """Continue the displayed task using its task_ref, never T01 or user UUIDs. Host analyzes packets then submit_triage; no model invocation here."""
        from ..task_triage import TaskTriageService
        from ..storage import ReadOnlySQLiteStore, SQLiteStore
        from ..triage import TriageService
        path=application.scan_path_provider()
        service=TaskTriageService(ReadOnlySQLiteStore(path))
        resolved=service.resolve(task_ref,workspace_path,bound_workspace=binding.root if binding else None)
        if resolved['status']!='RESOLVED': return resolved
        data=service.prepare(resolved,TriageService(runtime_engine().store),limit=limit,retry_failed=retry_failed,
                             include_existing_reviews=include_existing_reviews)
        return register_handoff(data,(task_ref,resolved['workspace'])) if data['packets'] else data

    @server.tool()
    def get_triage(scan_id: str, view: str = 'summary', offset: int = 0, limit: int | None = None) -> dict:
        """Independent triage coverage and grouped view; never changes scan coverage."""
        check_scan(scan_id)
        from ..triage import TriageService
        from ..mcp_views import page_bounds, paged
        page_limit=page_bounds(view,offset,limit)
        data=TriageService(runtime_engine().store).view(scan_id)
        if view == 'full': return data
        rows=data.pop('findings')
        selected=rows[offset:offset+page_limit]
        if view == 'summary':
            selected=[{k:v for k,v in row.items() if k!='triage'} | {
                'verdict':(row['triage'] or {}).get('verdict'),
                'priority':(row['triage'] or {}).get('priority')} for row in selected]
        data.pop('dependency_groups',None)
        return data | paged(selected,len(rows),offset,page_limit,tool='get_triage',
            arguments={'scan_id':scan_id,'view':view})
