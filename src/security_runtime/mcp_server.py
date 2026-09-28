"""MCP protocol interface; all operations delegate to SecurityRuntime."""
from __future__ import annotations

import logging
from pathlib import Path

from .runtime import SecurityRuntime

logger = logging.getLogger(__name__)


def create_server(runtime: SecurityRuntime | None = None):
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise ImportError("Install MCP support with: pip install -e '.[mcp]'") from exc
    engine = runtime or SecurityRuntime()
    server = FastMCP("AI Security Runtime")

    @server.tool()
    def scan_diff(path: str = ".", mode: str = "quick") -> dict:
        """Scan changed files in a local Git repository."""
        if mode not in {"quick", "feature"}:
            raise ValueError("mode must be quick or feature")
        logger.info("scan_diff started")
        result = engine.scan(path, mode)
        logger.info("scan_diff finished scan_id=%s", result.scan_id)
        return {"scan_id": result.scan_id, "summary": result.summary, "findings": [f.__dict__ for f in result.findings], "recommendation": result.release_status}

    @server.tool()
    def scan_project(path: str = ".") -> dict:
        """Run a full local project scan."""
        result = engine.scan(path, "release")
        return result.to_dict()

    @server.tool()
    def get_findings(scan_id: str) -> list[dict]:
        """Retrieve findings from a previous scan."""
        return engine.get_findings(scan_id)

    @server.tool()
    def generate_fix(finding_id: str) -> dict:
        """Create a safe coding task without editing source."""
        return engine.generate_fix(finding_id)

    @server.tool()
    def verify(finding_id: str) -> dict:
        """Recheck a finding with its originating scanner."""
        return engine.verify(finding_id)

    return server


def serve() -> None:
    create_server().run(transport="stdio")
