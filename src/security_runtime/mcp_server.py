"""MCP protocol interface; all operations delegate to SecurityRuntime."""
from __future__ import annotations

import logging
import os
import secrets
import time
from dataclasses import asdict
from pathlib import Path

from .logging_utils import mcp_log_level
from .runtime import SecurityRuntime
from .integration_state import DogfoodEvent, IntegrationStateStore, WorkspaceBinding
from .workspace import WorkspaceResolver

logger = logging.getLogger(__name__)


def _agent_finding(finding: dict) -> dict:
    return {key: finding[key] for key in ("id", "category", "severity", "confidence", "plain_title", "file_path", "line_start", "impact", "fix_advice", "technical_details", "triage_status", "verdict", "triage_confidence", "exploitability", "triage") if key in finding}


def _agent_result(result) -> dict:
    return {
        "scan_id": result.scan_id,
        "workspace": result.target_profile.path,
        "status": result.status,
        "execution_state": result.execution_state,
        "coverage_scope": result.coverage_scope,
        "capability_results": result.capability_results,
        "capability_details": result.capability_details,
        "rule_coverage": {key:value for key,value in result.rule_coverage.items() if key!='scope_files'},
        "coverage": result.coverage,
        "summary": result.summary,
        "findings": [_agent_finding(f.__dict__) for f in result.findings],
        "recommendation": result.release_status,
        "duration_ms": result.duration_ms,
        "scanner_runs": [asdict(run) for run in result.scanner_runs],
    }


def create_server(runtime: SecurityRuntime | None = None):
    try:
        from mcp.server.fastmcp import FastMCP
        from mcp.server.fastmcp import server as fastmcp_server
    except ImportError as exc:
        raise ImportError("Install MCP support with: pip install -e '.[mcp]'") from exc
    # The SDK's generic Settings.lifespan annotation references FastMCP. Rebuild
    # it with the defining module's namespace before BaseSettings reads fields.
    fastmcp_server.Settings.model_rebuild(_types_namespace=vars(fastmcp_server))
    engine = runtime or SecurityRuntime()
    binding = WorkspaceBinding.from_environment()
    server = FastMCP("AI Security Runtime", log_level=mcp_log_level())
    # Connection-local opaque handoffs hold hashes only, never packet source.
    triage_sessions={}

    def bound_path(value: str | None) -> str | None:
        if binding is None:
            return value
        candidate = Path(value) if value is not None else Path(binding.root)
        if not candidate.is_absolute():
            candidate = Path(binding.root) / candidate
        resolved = WorkspaceResolver().resolve(candidate, allow_non_git_explicit=True).path
        if resolved != Path(binding.root):
            raise ValueError("Requested workspace is outside this MCP connection")
        return binding.root

    def check_scan(scan_id: str) -> None:
        if binding is None:
            return
        scan = engine.store.get_scan(scan_id)
        if scan is None or Path(scan["target_profile"]["path"]).resolve() != Path(binding.root):
            raise ValueError("Scan does not belong to this MCP workspace")

    def check_finding(finding_id: str) -> None:
        if binding is None:
            return
        record = engine.store.get_finding(finding_id)
        if record is None or Path(record[1]["target_profile"]["path"]).resolve() != Path(binding.root):
            raise ValueError("Finding does not belong to this MCP workspace")

    def event(value: DogfoodEvent, *, connected: bool = False) -> None:
        if os.getenv("SECURITY_RUNTIME_MCP_SELF_TEST") == "1":
            return
        try:
            state = IntegrationStateStore()
            state.event(value)
            if connected and binding is not None and binding.integration_id in {"cursor", "workbuddy"} and os.getenv("SECURITY_RUNTIME_MCP_SELF_TEST") != "1":
                state.client_invoked(binding.integration_id, Path(binding.root))
        except Exception as exc:
            logger.warning("dogfood_event_failed reason=%s", type(exc).__name__)

    @server.tool()
    def scan_diff(workspace_path: str | None = None, mode: str = "quick", path: str | None = None) -> dict:
        """Scan changed files in a local Git repository."""
        if mode not in {"quick", "feature"}:
            raise ValueError("mode must be quick or feature")
        if workspace_path is not None and path is not None and workspace_path != path:
            raise ValueError("Specify only one workspace path")
        logger.info("scan_diff started")
        root = bound_path(workspace_path if workspace_path is not None else path)
        result = engine.scan(root, mode)
        event(DogfoodEvent(binding.integration_id if binding else "generic-mcp", result.target_profile.path,
                           mode, result.duration_ms, len(result.findings), result.coverage), connected=True)
        logger.info("scan_diff finished scan_id=%s", result.scan_id)
        return _agent_result(result)

    @server.tool()
    def scan_project(workspace_path: str | None = None, path: str | None = None) -> dict:
        """Run a full local project scan."""
        if workspace_path is not None and path is not None and workspace_path != path:
            raise ValueError("Specify only one workspace path")
        root = bound_path(workspace_path if workspace_path is not None else path)
        result = engine.scan(root, "release")
        event(DogfoodEvent(binding.integration_id if binding else "generic-mcp", result.target_profile.path,
                           "release", result.duration_ms, len(result.findings), result.coverage), connected=True)
        return _agent_result(result)

    @server.tool()
    def get_findings(scan_id: str) -> list[dict]:
        """Retrieve findings from a previous scan."""
        check_scan(scan_id)
        if binding:
            event(DogfoodEvent(binding.integration_id, binding.root), connected=True)
        from .triage import TriageService
        view=TriageService(engine.store).view(scan_id)
        rows={row['finding_id']:row for row in view['findings']}
        found=[]
        for finding in engine.get_findings(scan_id):
            row=rows[finding['id']]
            item=_agent_finding(finding)
            item['triage_status']=row['triage_status']
            item['triage']=row['triage']
            if row['triage_status']=='VALID':
                item.update(verdict=row['triage']['verdict'],triage_confidence=row['triage']['confidence'],exploitability=row['triage']['exploitability'])
            found.append(item)
        return found

    @server.tool()
    def prepare_triage(scan_id: str, finding_ids: list[str] | None = None, categories: list[str] | None = None, limit: int = 20) -> dict:
        """Return bounded redacted UNTRUSTED_CODE evidence to this host agent; does not invoke AI."""
        check_scan(scan_id)
        from .triage import TriageService
        data=TriageService(engine.store).prepare(scan_id,finding_ids,categories,limit)
        expired=[key for key,value in triage_sessions.items() if time.monotonic()-value[2]>900]
        for key in expired: triage_sessions.pop(key,None)
        if len(triage_sessions)>=64: triage_sessions.pop(next(iter(triage_sessions)))
        token=secrets.token_urlsafe(32)
        triage_sessions[token]=(scan_id,{packet['finding_id']:packet['context_hash'] for packet in data['packets']},time.monotonic())
        data['triage_session']=token
        data['triage_session_expires_in_seconds']=900
        return data

    @server.tool()
    def submit_triage(scan_id: str, results: list[dict], triage_session: str) -> dict:
        """Validate structured host analysis and evidence references; preserves every raw finding."""
        check_scan(scan_id)
        session=triage_sessions.get(triage_session)
        if session is None or session[0]!=scan_id or time.monotonic()-session[2]>900:
            raise ValueError('Invalid or expired triage handoff session; prepare evidence again')
        if not results or len(results)>20 or any(not isinstance(item,dict) or
            session[1].get(item.get('finding_id'))!=item.get('context_hash') for item in results):
            raise ValueError('Triage result does not belong to this evidence handoff')
        from .triage import TriageService
        data=TriageService(engine.store).submit(scan_id,results)
        for item in results: session[1].pop(item['finding_id'],None)
        return data

    @server.tool()
    def get_triage(scan_id: str) -> dict:
        """Independent triage coverage and grouped view; never changes scan coverage."""
        check_scan(scan_id)
        from .triage import TriageService
        return TriageService(engine.store).view(scan_id)

    @server.tool()
    def generate_fix(finding_id: str) -> dict:
        """Create a safe coding task without editing source."""
        check_finding(finding_id)
        result = engine.generate_fix(finding_id)
        if binding:
            event(DogfoodEvent(binding.integration_id, binding.root, fix_generated=True), connected=True)
        return result

    @server.tool()
    def verify(finding_id: str, workspace_path: str | None = None) -> dict:
        """Recheck a finding with its originating scanner."""
        check_finding(finding_id)
        result = engine.verify(finding_id, bound_path(workspace_path))
        if binding:
            event(DogfoodEvent(binding.integration_id, binding.root, verify_result=result["status"]), connected=True)
        return result

    return server


def serve() -> None:
    create_server().run(transport="stdio")
