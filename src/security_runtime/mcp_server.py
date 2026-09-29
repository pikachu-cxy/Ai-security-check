"""MCP protocol interface; all operations delegate to SecurityRuntime."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from .logging_utils import mcp_log_level
from .runtime import SecurityRuntime
from .integration_state import DogfoodEvent, IntegrationStateStore, WorkspaceBinding
from .workspace import WorkspaceResolver

logger = logging.getLogger(__name__)


def _agent_finding(finding: dict) -> dict:
    return {key: finding[key] for key in ("id", "severity", "confidence", "plain_title", "file_path", "line_start", "impact", "fix_advice") if key in finding}


def _agent_result(result) -> dict:
    return {
        "scan_id": result.scan_id,
        "workspace": result.target_profile.path,
        "status": result.status,
        "coverage": result.coverage,
        "summary": result.summary,
        "findings": [_agent_finding(f.__dict__) for f in result.findings],
        "recommendation": result.release_status,
        "duration_ms": result.duration_ms,
        "scanner_runs": [{"scanner": run.scanner, "status": run.status} for run in result.scanner_runs],
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

    def bound_path(value: str | None) -> str | None:
        if binding is None:
            return value
        candidate = Path(value) if value is not None else Path(binding.root)
        if not candidate.is_absolute():
            candidate = Path(binding.root) / candidate
        resolved = WorkspaceResolver().resolve(candidate).path
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
        try:
            state = IntegrationStateStore()
            state.event(value)
            if connected and binding is not None and binding.integration_id in {"cursor", "workbuddy"}:
                prior = state.get(binding.integration_id, Path(binding.root))
                if prior:
                    verified = WorkspaceBinding.create(Path(binding.root), binding.integration_id,
                        created_at=prior["installed_at"], last_verified_at=datetime.now(timezone.utc).isoformat())
                    state.save(verified, "CONNECTED", prior["config_path"], prior["command_path"])
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
        return [_agent_finding(finding) for finding in engine.get_findings(scan_id)]

    @server.tool()
    def generate_fix(finding_id: str) -> dict:
        """Create a safe coding task without editing source."""
        check_finding(finding_id)
        result = engine.generate_fix(finding_id)
        if binding:
            event(DogfoodEvent(binding.integration_id, binding.root, fix_generated=True))
        return result

    @server.tool()
    def verify(finding_id: str, workspace_path: str | None = None) -> dict:
        """Recheck a finding with its originating scanner."""
        check_finding(finding_id)
        result = engine.verify(finding_id, bound_path(workspace_path))
        if binding:
            event(DogfoodEvent(binding.integration_id, binding.root, verify_result=result["status"]))
        return result

    return server


def serve() -> None:
    create_server().run(transport="stdio")
